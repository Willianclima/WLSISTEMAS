import fs from "fs";
import path from "path";
import crypto from "crypto";
import type pg from "pg";
import { getPostgresPool } from "./postgres";

export const MIGRATION_ADVISORY_LOCK_KEY = "748291038472619";

export interface MigrationRecord {
  id: string;
  applied_at?: string;
  checksum: string;
}

export interface MigrationClientLike {
  query<T extends pg.QueryResultRow = any>(text: string, params?: any[]): Promise<pg.QueryResult<T>>;
  release(destroy?: boolean | Error): void;
}

export interface MigrationPoolLike {
  connect(): Promise<MigrationClientLike>;
}

export interface MigratorOptions {
  pool?: MigrationPoolLike;
  migrationsDir?: string;
  advisoryLockKey?: string;
  dryRun?: boolean;
  logger?: Pick<Console, "log" | "warn" | "error">;
}

export interface RunMigrationsResult {
  applied: string[];
  skipped: string[];
  pending: string[];
}

export class MigrationChecksumError extends Error {
  public readonly migrationId: string;
  public readonly recordedChecksum: string;
  public readonly currentChecksum: string;

  constructor(migrationId: string, recordedChecksum: string, currentChecksum: string) {
    super(
      `[Aura Migrator] Divergência de checksum na migration já aplicada "${migrationId}". ` +
      `Checksum registrado: ${recordedChecksum} | Checksum atual: ${currentChecksum}. ` +
      `Execução interrompida sem modificar o histórico.`
    );
    this.name = "MigrationChecksumError";
    this.migrationId = migrationId;
    this.recordedChecksum = recordedChecksum;
    this.currentChecksum = currentChecksum;
  }
}

export function computeMigrationChecksum(sqlContent: string): string {
  return crypto.createHash("sha256").update(sqlContent, "utf8").digest("hex");
}

function stripSqlComments(sql: string): string {
  let out = "";
  let i = 0;
  let inSingleQuote = false;
  let dollarTag: string | null = null;

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (dollarTag) {
      if (sql.startsWith(dollarTag, i)) {
        out += dollarTag;
        i += dollarTag.length;
        dollarTag = null;
        continue;
      }
      out += ch;
      i++;
      continue;
    }

    if (inSingleQuote) {
      out += ch;
      if (ch === "'" && next === "'") {
        out += next;
        i += 2;
        continue;
      }
      if (ch === "'") {
        inSingleQuote = false;
      }
      i++;
      continue;
    }

    if (ch === "-" && next === "-") {
      while (i < sql.length && sql[i] !== "\n") {
        i++;
      }
      continue;
    }

    if (ch === "/" && next === "*") {
      i += 2;
      while (i < sql.length && !(sql[i] === "*" && sql[i + 1] === "/")) {
        i++;
      }
      i += 2;
      out += " ";
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      out += ch;
      i++;
      continue;
    }

    if (ch === "$") {
      const match = sql.slice(i).match(/^\$[a-zA-Z0-9_]*\$/);
      if (match) {
        dollarTag = match[0];
        out += dollarTag;
        i += dollarTag.length;
        continue;
      }
    }

    out += ch;
    i++;
  }

  return out;
}

/**
 * Splits a SQL script into individual statements, preserving single-quoted literals,
 * comments, and dollar-quoted PL/pgSQL blocks (e.g. DO $$ ... $$;).
 */
export function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = "";
  let i = 0;
  let inSingleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;
  let dollarTag: string | null = null;

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (inLineComment) {
      current += ch;
      if (ch === "\n") {
        inLineComment = false;
      }
      i++;
      continue;
    }

    if (inBlockComment) {
      current += ch;
      if (ch === "*" && next === "/") {
        current += next;
        inBlockComment = false;
        i += 2;
        continue;
      }
      i++;
      continue;
    }

    if (dollarTag) {
      if (sql.startsWith(dollarTag, i)) {
        current += dollarTag;
        i += dollarTag.length;
        dollarTag = null;
        continue;
      }
      current += ch;
      i++;
      continue;
    }

    if (inSingleQuote) {
      current += ch;
      if (ch === "'" && next === "'") {
        current += next;
        i += 2;
        continue;
      }
      if (ch === "'") {
        inSingleQuote = false;
      }
      i++;
      continue;
    }

    if (ch === "-" && next === "-") {
      inLineComment = true;
      current += ch;
      i++;
      continue;
    }

    if (ch === "/" && next === "*") {
      inBlockComment = true;
      current += "/*";
      i += 2;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      current += ch;
      i++;
      continue;
    }

    if (ch === "$") {
      const match = sql.slice(i).match(/^\$[a-zA-Z0-9_]*\$/);
      if (match) {
        dollarTag = match[0];
        current += dollarTag;
        i += dollarTag.length;
        continue;
      }
    }

    if (ch === ";") {
      const trimmed = current.trim();
      if (trimmed.length > 0 && stripSqlComments(trimmed).trim().length > 0) {
        statements.push(`${trimmed};`);
      }
      current = "";
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  const trailing = current.trim();
  if (trailing.length > 0 && stripSqlComments(trailing).trim().length > 0) {
    statements.push(trailing);
  }

  return statements;
}

function assertTransactionalCompatibility(file: string, statements: string[]): void {
  const forbiddenPatterns = [
    /\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b/i,
    /\bDROP\s+INDEX\s+CONCURRENTLY\b/i,
    /\bREINDEX\b.*\bCONCURRENTLY\b/i,
    /^\s*VACUUM\b/i,
  ];

  for (const stmt of statements) {
    const clean = stripSqlComments(stmt);
    for (const pattern of forbiddenPatterns) {
      if (pattern.test(clean)) {
        throw new Error(
          `[Aura Migrator] A migration "${file}" contém comando incompatível com execução transacional: "${clean.slice(0, 80)}".`
        );
      }
    }
  }
}

async function ensureMigrationTable(client: MigrationClientLike): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS _schema_migrations (
      id VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      checksum VARCHAR(64) NOT NULL
    );
  `);
}

async function migrationTableExists(client: MigrationClientLike): Promise<boolean> {
  const res = await client.query<{ regclass_name: string | null }>(
    "SELECT to_regclass('_schema_migrations')::text AS regclass_name"
  );
  return Boolean(res.rows[0]?.regclass_name);
}

/**
 * Runs all pending migrations from server/db/migrations in sequential alphanumeric order.
 * Protected by session-level pg_advisory_lock on a single dedicated physical client,
 * strict SHA-256 checksum validation, and atomic per-migration transactions.
 */
export async function runMigrations(options: MigratorOptions = {}): Promise<RunMigrationsResult> {
  const migrationsDir =
    options.migrationsDir || path.join(process.cwd(), "server", "db", "migrations");
  const advisoryLockKey = options.advisoryLockKey || MIGRATION_ADVISORY_LOCK_KEY;
  const dryRun = Boolean(options.dryRun);
  const logger = options.logger || console;

  if (!fs.existsSync(migrationsDir)) {
    throw new Error(`[Migration Error] Migrations directory not found at: ${migrationsDir}`);
  }

  const pool = options.pool || getPostgresPool();
  const client = await pool.connect();

  let lockAcquired = false;
  let shouldDestroyClient = false;
  let activeError: unknown = null;

  const applied: string[] = [];
  const skipped: string[] = [];
  const pending: string[] = [];

  try {
    // 1. Acquire exclusive advisory lock BEFORE reading or applying any migration
    await client.query("SELECT pg_advisory_lock($1::bigint)", [advisoryLockKey]);
    lockAcquired = true;

    // 2. In dry-run mode, inspect table existence read-only without DDL; otherwise ensure table exists
    const hasMigrationTable = dryRun
      ? await migrationTableExists(client)
      : (await ensureMigrationTable(client), true);

    // 3. Load recorded migrations (including checksums) on the same locked connection
    const appliedMap = new Map<string, MigrationRecord>();
    if (hasMigrationTable) {
      const existingResult = await client.query<MigrationRecord>(
        "SELECT id, checksum, applied_at FROM _schema_migrations ORDER BY id ASC"
      );
      for (const row of existingResult.rows) {
        appliedMap.set(row.id, row);
      }
    }

    // 4. Read only top-level .sql files in alphanumeric order (ignore /archive)
    const files = fs
      .readdirSync(migrationsDir)
      .filter((file) => file.endsWith(".sql") && fs.statSync(path.join(migrationsDir, file)).isFile())
      .sort();

    logger.log(`\n📦 [Aura Migrator] Verificando ${files.length} migrações oficiais...`);

    const pendingMigrations: Array<{ file: string; statements: string[]; checksum: string }> = [];

    // 5. Validate checksums for ALL already-applied migrations before executing anything
    for (const file of files) {
      const filePath = path.join(migrationsDir, file);
      const sqlContent = fs.readFileSync(filePath, "utf-8");
      const currentChecksum = computeMigrationChecksum(sqlContent);

      const recorded = appliedMap.get(file);
      if (recorded) {
        if (recorded.checksum !== currentChecksum) {
          throw new MigrationChecksumError(file, recorded.checksum, currentChecksum);
        }
        skipped.push(file);
        continue;
      }

      const statements = splitSqlStatements(sqlContent);
      assertTransactionalCompatibility(file, statements);
      pending.push(file);
      pendingMigrations.push({ file, statements, checksum: currentChecksum });
    }

    if (dryRun) {
      logger.log(
        `🔎 [Aura Migrator] Modo dry-run: ${pending.length} pendente(s), ${skipped.length} validada(s). Nenhuma alteração aplicada.`
      );
      return { applied, skipped, pending };
    }

    // 6. Execute each pending migration inside its own atomic transaction on the SAME locked client
    for (const migration of pendingMigrations) {
      logger.log(
        `🚀 [Aura Migrator] Aplicando: ${migration.file} (${migration.statements.length} instruções)...`
      );

      let inTransaction = false;
      try {
        await client.query("BEGIN");
        inTransaction = true;

        for (const stmt of migration.statements) {
          await client.query(stmt);
        }

        await client.query(
          "INSERT INTO _schema_migrations (id, checksum, applied_at) VALUES ($1, $2, CURRENT_TIMESTAMP)",
          [migration.file, migration.checksum]
        );

        await client.query("COMMIT");
        inTransaction = false;

        applied.push(migration.file);
        logger.log(`✅ [Aura Migrator] ${migration.file} aplicado com sucesso.`);
      } catch (err: any) {
        if (inTransaction) {
          try {
            await client.query("ROLLBACK");
          } catch (rollbackErr: any) {
            // Preserve original migration failure; destroy connection since transaction state is compromised
            shouldDestroyClient = true;
            logger.error(
              `❌ [Aura Migrator] Falha no ROLLBACK de ${migration.file} (erro original preservado):`,
              rollbackErr?.message || rollbackErr
            );
          }
        }
        logger.error(`❌ [Aura Migrator] Falha ao aplicar ${migration.file}:`, err?.message || err);
        throw err;
      }
    }

    if (applied.length === 0) {
      logger.log(
        `✨ [Aura Migrator] Banco de dados já está 100% atualizado (${skipped.length} migrações validadas).\n`
      );
    } else {
      logger.log(
        `✨ [Aura Migrator] Concluído: ${applied.length} migrações aplicadas com sucesso.\n`
      );
    }

    return { applied, skipped, pending };
  } catch (err) {
    activeError = err;
    throw err;
  } finally {
    if (lockAcquired) {
      if (shouldDestroyClient) {
        // Connection state is broken; do not risk returning a locked client to the pool
        logger.warn(
          "[Aura Migrator] Conexão com estado transacional comprometido será destruída para liberar o advisory lock com segurança."
        );
      } else {
        try {
          const unlockRes = await client.query<{ unlocked: boolean }>(
            "SELECT pg_advisory_unlock($1::bigint) AS unlocked",
            [advisoryLockKey]
          );
          const unlocked = unlockRes?.rows?.[0]?.unlocked;
          if (unlocked !== true) {
            shouldDestroyClient = true;
          } else {
            lockAcquired = false;
          }
        } catch (unlockErr: any) {
          shouldDestroyClient = true;
          logger.error(
            "[Aura Migrator] Falha ao liberar pg_advisory_lock; conexão será destruída:",
            unlockErr?.message || unlockErr
          );
          if (!activeError) {
            // If everything else succeeded but unlock failed, destroy connection and fail explicitly
            client.release(true);
            throw unlockErr;
          }
        }
      }
    }

    if (shouldDestroyClient) {
      client.release(true);
    } else {
      client.release();
    }
  }
}

// CLI execution handler
if (
  process.argv[1] &&
  (process.argv[1].endsWith("migrator.ts") || process.argv[1].endsWith("migrator.js"))
) {
  runMigrations()
    .then(() => {
      console.log("[Aura Migrator] Processo finalizado com sucesso.");
      process.exit(0);
    })
    .catch((err) => {
      console.error("[Aura Migrator Fatal]", err);
      process.exit(1);
    });
}

