import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "os";
import path from "path";
import type pg from "pg";
import {
  MIGRATION_ADVISORY_LOCK_KEY,
  MigrationChecksumError,
  MigrationClientLike,
  MigrationPoolLike,
  MigrationRecord,
  computeMigrationChecksum,
  runMigrations,
} from "./migrator";

const SILENT_LOGGER = {
  log: () => {},
  warn: () => {},
  error: () => {},
};

interface QueryCall {
  text: string;
  params?: any[];
  category: "readOnly" | "sessionControl" | "transactionControl" | "mutation";
}

class MockPgEnvironment implements MigrationPoolLike {
  public readonly appliedRows = new Map<string, MigrationRecord>();
  public readonly queryHistory: QueryCall[] = [];
  public readonly readOnlyQueries: string[] = [];
  public readonly sessionControlCommands: string[] = [];
  public readonly transactionControlCommands: string[] = [];
  public readonly mutationOperations: string[] = [];
  public readonly executedDdl: string[] = [];
  public readonly releaseCalls: Array<{ clientId: number; destroyed: boolean }> = [];
  public migrationTableExists = true;
  public activeLockHolder: number | null = null;
  public lockOverlapDetected = false;
  public activeTransaction = false;

  private nextClientId = 1;
  private lockWaiters: Array<() => void> = [];
  private currentTxPendingRows: MigrationRecord[] = [];
  private currentTxPendingDdl: string[] = [];

  public failOnStatement?: (
    sql: string,
    clientId: number
  ) => (Error & { code?: string }) | null;
  public failOnRollback?: Error | null = null;
  public failOnUnlock?: Error | null = null;
  public unlockReturnsFalse = false;
  public ddlDelayMs = 0;

  async connect(): Promise<MigrationClientLike> {
    const clientId = this.nextClientId++;
    const env = this;
    let released = false;

    return {
      async query<T extends pg.QueryResultRow = any>(
        text: string,
        params?: any[]
      ): Promise<pg.QueryResult<T>> {
        const normalized = text.trim();

        if (normalized.startsWith("SELECT pg_advisory_lock")) {
          env.queryHistory.push({ text, params, category: "sessionControl" });
          env.sessionControlCommands.push(normalized);
          if (env.activeLockHolder !== null) {
            await new Promise<void>((resolve) => {
              env.lockWaiters.push(resolve);
            });
          }
          if (env.activeLockHolder !== null) {
            env.lockOverlapDetected = true;
          }
          env.activeLockHolder = clientId;
          return { rows: [{ pg_advisory_lock: "" }] } as any;
        }

        if (normalized.startsWith("SELECT pg_advisory_unlock")) {
          env.queryHistory.push({ text, params, category: "sessionControl" });
          env.sessionControlCommands.push(normalized);
          if (env.failOnUnlock) {
            throw env.failOnUnlock;
          }
          if (env.unlockReturnsFalse) {
            return { rows: [{ unlocked: false }] } as any;
          }
          if (env.activeLockHolder === clientId) {
            env.activeLockHolder = null;
            const next = env.lockWaiters.shift();
            if (next) next();
          }
          return { rows: [{ unlocked: true }] } as any;
        }

        if (normalized.startsWith("SELECT to_regclass('_schema_migrations')")) {
          env.queryHistory.push({ text, params, category: "readOnly" });
          env.readOnlyQueries.push(normalized);
          return {
            rows: [{ regclass_name: env.migrationTableExists ? "_schema_migrations" : null }],
          } as any;
        }

        if (normalized.startsWith("CREATE TABLE IF NOT EXISTS _schema_migrations")) {
          env.queryHistory.push({ text, params, category: "mutation" });
          env.mutationOperations.push(normalized);
          env.migrationTableExists = true;
          return { rows: [] } as any;
        }

        if (normalized.startsWith("SELECT id, checksum, applied_at FROM _schema_migrations")) {
          env.queryHistory.push({ text, params, category: "readOnly" });
          env.readOnlyQueries.push(normalized);
          if (!env.migrationTableExists) {
            throw makePgError('relation "_schema_migrations" does not exist', "42P01");
          }
          const rows = Array.from(env.appliedRows.values()).sort((a, b) =>
            a.id.localeCompare(b.id)
          );
          return { rows } as any;
        }

        if (normalized === "BEGIN") {
          env.queryHistory.push({ text, params, category: "transactionControl" });
          env.transactionControlCommands.push(normalized);
          env.activeTransaction = true;
          env.currentTxPendingRows = [];
          env.currentTxPendingDdl = [];
          return { rows: [] } as any;
        }

        if (normalized === "COMMIT") {
          env.queryHistory.push({ text, params, category: "transactionControl" });
          env.transactionControlCommands.push(normalized);
          for (const row of env.currentTxPendingRows) {
            env.appliedRows.set(row.id, row);
          }
          env.executedDdl.push(...env.currentTxPendingDdl);
          env.currentTxPendingRows = [];
          env.currentTxPendingDdl = [];
          env.activeTransaction = false;
          return { rows: [] } as any;
        }

        if (normalized === "ROLLBACK") {
          env.queryHistory.push({ text, params, category: "transactionControl" });
          env.transactionControlCommands.push(normalized);
          if (env.failOnRollback) {
            throw env.failOnRollback;
          }
          env.currentTxPendingRows = [];
          env.currentTxPendingDdl = [];
          env.activeTransaction = false;
          return { rows: [] } as any;
        }

        if (normalized.startsWith("INSERT INTO _schema_migrations")) {
          env.queryHistory.push({ text, params, category: "mutation" });
          env.mutationOperations.push(normalized);
          const [id, checksum] = params || [];
          env.currentTxPendingRows.push({
            id,
            checksum,
            applied_at: new Date().toISOString(),
          });
          return { rows: [] } as any;
        }

        env.queryHistory.push({ text, params, category: "mutation" });
        env.mutationOperations.push(normalized);

        if (env.ddlDelayMs > 0) {
          await new Promise((r) => setTimeout(r, env.ddlDelayMs));
        }

        if (env.failOnStatement) {
          const err = env.failOnStatement(normalized, clientId);
          if (err) {
            throw err;
          }
        }

        env.currentTxPendingDdl.push(normalized);
        return { rows: [] } as any;
      },

      release(destroy?: boolean | Error) {
        if (released) return;
        released = true;
        const destroyed = Boolean(destroy);
        env.releaseCalls.push({ clientId, destroyed });
        if (destroyed && env.activeLockHolder === clientId) {
          // Physical connection destruction releases PostgreSQL session advisory locks
          env.activeLockHolder = null;
          const next = env.lockWaiters.shift();
          if (next) next();
        }
      },
    };
  }
}

function createTempMigrationsDir(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aura-migrator-test-"));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content, "utf-8");
  }
  return dir;
}

function makePgError(message: string, code: string): Error & { code: string } {
  const err = new Error(message) as Error & { code: string };
  err.code = code;
  return err;
}

test("1. Migration executada com sucesso é registrada em _schema_migrations dentro da mesma transação", async () => {
  const sql = "CREATE TABLE IF NOT EXISTS test_items (id VARCHAR(64) PRIMARY KEY);";
  const dir = createTempMigrationsDir({ "001_test.sql": sql });
  const mockPool = new MockPgEnvironment();

  try {
    const result = await runMigrations({
      pool: mockPool,
      migrationsDir: dir,
      logger: SILENT_LOGGER,
    });

    assert.deepEqual(result.applied, ["001_test.sql"]);
    assert.deepEqual(result.skipped, []);
    assert.deepEqual(result.pending, ["001_test.sql"]);

    const recorded = mockPool.appliedRows.get("001_test.sql");
    assert.ok(recorded);
    assert.equal(recorded.checksum, computeMigrationChecksum(sql));

    const queries = mockPool.queryHistory.map((q) => q.text.trim());
    const beginIdx = queries.indexOf("BEGIN");
    const ddlIdx = queries.findIndex((q) => q.includes("CREATE TABLE IF NOT EXISTS test_items"));
    const insertIdx = queries.findIndex((q) => q.startsWith("INSERT INTO _schema_migrations"));
    const commitIdx = queries.indexOf("COMMIT");
    assert.ok(beginIdx < ddlIdx && ddlIdx < insertIdx && insertIdx < commitIdx);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("2. Migration com erro genérico não é registrada e interrompe execução", async () => {
  const dir = createTempMigrationsDir({
    "001_fail.sql": "CREATE TABLE test_bad (id INT);",
    "002_next.sql": "CREATE TABLE test_after (id INT);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.failOnStatement = (sql) =>
    sql.includes("test_bad") ? makePgError("syntax error near bad", "42601") : null;

  try {
    await assert.rejects(
      () => runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      /syntax error near bad/
    );

    assert.equal(mockPool.appliedRows.size, 0);
    assert.equal(mockPool.executedDdl.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("3. Erro 42501 (must be owner of / permission denied) interrompe o processo e não registra migration", async () => {
  const dir = createTempMigrationsDir({
    "007_strict_rls_test.sql":
      "ALTER TABLE products ENABLE ROW LEVEL SECURITY; CREATE POLICY p ON products FOR ALL USING (true);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.failOnStatement = () =>
    makePgError("must be owner of table products", "42501");

  try {
    await assert.rejects(
      () => runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      (err: any) => err.code === "42501" && err.message.includes("must be owner of")
    );

    assert.equal(mockPool.appliedRows.has("007_strict_rls_test.sql"), false);
    assert.ok(!mockPool.queryHistory.some((q) => q.text.trim() === "COMMIT"));
    assert.ok(mockPool.queryHistory.some((q) => q.text.trim() === "ROLLBACK"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("4. Erro 42710 (objeto duplicado) não é ignorado automaticamente", async () => {
  const dir = createTempMigrationsDir({
    "001_dup_policy.sql": "CREATE POLICY tenant_isolation_policy ON orders FOR ALL USING (true);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.failOnStatement = () =>
    makePgError('policy "tenant_isolation_policy" for table "orders" already exists', "42710");

  try {
    await assert.rejects(
      () => runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      (err: any) => err.code === "42710"
    );

    assert.equal(mockPool.appliedRows.size, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("5. Erro 42P07 (tabela/relação já existente) não é ignorado automaticamente", async () => {
  const dir = createTempMigrationsDir({
    "001_dup_table.sql": "CREATE TABLE orders (id VARCHAR(64) PRIMARY KEY);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.failOnStatement = () =>
    makePgError('relation "orders" already exists', "42P07");

  try {
    await assert.rejects(
      () => runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      (err: any) => err.code === "42P07"
    );

    assert.equal(mockPool.appliedRows.size, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("6. Checksum divergente interrompe o processo, informa nome/checksums e não modifica histórico (008 e 009)", async () => {
  const realMigrationsDir = path.join(process.cwd(), "server", "db", "migrations");
  const files = fs
    .readdirSync(realMigrationsDir)
    .filter((f) => f.endsWith(".sql") && fs.statSync(path.join(realMigrationsDir, f)).isFile())
    .sort();

  for (const divergentFile of ["008_billing_invoices.sql", "009_consignments.sql"]) {
    const mockPool = new MockPgEnvironment();

    for (const file of files) {
      if (file === "011_billing_idempotency_unique.sql") continue;
      const content = fs.readFileSync(path.join(realMigrationsDir, file), "utf-8");
      const checksum =
        file === divergentFile
          ? "0".repeat(64)
          : computeMigrationChecksum(content);
      mockPool.appliedRows.set(file, {
        id: file,
        checksum,
        applied_at: "2026-01-01T00:00:00Z",
      });
    }

    const realChecksum = computeMigrationChecksum(
      fs.readFileSync(path.join(realMigrationsDir, divergentFile), "utf-8")
    );

    await assert.rejects(
      () =>
        runMigrations({
          pool: mockPool,
          migrationsDir: realMigrationsDir,
          logger: SILENT_LOGGER,
        }),
      (err: any) => {
        assert.ok(err instanceof MigrationChecksumError);
        assert.equal(err.migrationId, divergentFile);
        assert.equal(err.recordedChecksum, "0".repeat(64));
        assert.equal(err.currentChecksum, realChecksum);
        assert.ok(err.message.includes(divergentFile));
        assert.ok(err.message.includes("0".repeat(64)));
        assert.ok(err.message.includes(realChecksum));
        return true;
      }
    );

    // Histórico preservado sem alterações e 011 não aplicada
    assert.equal(mockPool.appliedRows.get(divergentFile)?.checksum, "0".repeat(64));
    assert.equal(mockPool.appliedRows.has("011_billing_idempotency_unique.sql"), false);
    assert.equal(mockPool.executedDdl.length, 0);
  }
});

test("7. Duas execuções concorrentes são serializadas pelo pg_advisory_lock e não executam simultaneamente", async () => {
  const dir = createTempMigrationsDir({
    "001_concurrent.sql": "CREATE TABLE concurrent_check (id VARCHAR(64) PRIMARY KEY);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.ddlDelayMs = 40;

  try {
    const [res1, res2] = await Promise.all([
      runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
    ]);

    assert.equal(mockPool.lockOverlapDetected, false);
    assert.equal(mockPool.activeLockHolder, null);
    assert.deepEqual(res1.applied, ["001_concurrent.sql"]);
    assert.deepEqual(res2.applied, []);
    assert.deepEqual(res2.skipped, ["001_concurrent.sql"]);
    assert.equal(mockPool.executedDdl.length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("8. Erro durante execução provoca ROLLBACK e não confirma alterações nem grava histórico", async () => {
  const dir = createTempMigrationsDir({
    "001_atomic.sql":
      "CREATE TABLE t1 (id INT); CREATE TABLE t2 (id INT);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.failOnStatement = (sql) =>
    sql.includes("t2") ? makePgError("second statement failed", "42000") : null;

  try {
    await assert.rejects(
      () => runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      /second statement failed/
    );

    const queries = mockPool.queryHistory.map((q) => q.text.trim());
    assert.ok(queries.includes("BEGIN"));
    assert.ok(queries.includes("ROLLBACK"));
    assert.ok(!queries.includes("COMMIT"));
    assert.equal(mockPool.activeTransaction, false);
    assert.equal(mockPool.executedDdl.length, 0);
    assert.equal(mockPool.appliedRows.size, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("9. Erro durante ROLLBACK não oculta a falha original e destrói a conexão sem retornar com lock ativo ao Pool", async () => {
  const dir = createTempMigrationsDir({
    "001_rollback_fail.sql": "CREATE TABLE broken_tx (id INT);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.failOnStatement = () => makePgError("ORIGINAL_MIGRATION_FAILURE", "42601");
  mockPool.failOnRollback = new Error("ROLLBACK_NETWORK_FAILURE");

  try {
    await assert.rejects(
      () => runMigrations({ pool: mockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      (err: any) => err.message === "ORIGINAL_MIGRATION_FAILURE"
    );

    assert.equal(mockPool.releaseCalls.length, 1);
    assert.equal(mockPool.releaseCalls[0].destroyed, true);
    assert.equal(mockPool.activeLockHolder, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("10. Conexão e advisory lock são liberados corretamente (e destruídos se unlock falhar)", async () => {
  const dir = createTempMigrationsDir({
    "001_lock_life.sql": "CREATE TABLE lock_test (id INT);",
  });

  try {
    // Caso A: Sucesso — lock adquirido, mesma conexão usada até o fim, unlock e release normal
    const okPool = new MockPgEnvironment();
    await runMigrations({ pool: okPool, migrationsDir: dir, logger: SILENT_LOGGER });

    const lockCalls = okPool.queryHistory.filter((q) =>
      q.text.includes("pg_advisory_lock")
    );
    const unlockCalls = okPool.queryHistory.filter((q) =>
      q.text.includes("pg_advisory_unlock")
    );
    assert.equal(lockCalls.length, 1);
    assert.deepEqual(lockCalls[0].params, [MIGRATION_ADVISORY_LOCK_KEY]);
    assert.equal(unlockCalls.length, 1);
    assert.deepEqual(unlockCalls[0].params, [MIGRATION_ADVISORY_LOCK_KEY]);
    assert.equal(okPool.activeLockHolder, null);
    assert.deepEqual(okPool.releaseCalls, [{ clientId: 1, destroyed: false }]);

    // Caso B: Falha ao liberar lock — conexão destruída (release(true)), nunca retorna ao Pool com lock ativo
    const failUnlockPool = new MockPgEnvironment();
    failUnlockPool.failOnUnlock = new Error("UNLOCK_FAILED");
    await assert.rejects(
      () => runMigrations({ pool: failUnlockPool, migrationsDir: dir, logger: SILENT_LOGGER }),
      /UNLOCK_FAILED/
    );
    assert.deepEqual(failUnlockPool.releaseCalls, [{ clientId: 1, destroyed: true }]);
    assert.equal(failUnlockPool.activeLockHolder, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("11. Migration 011 é identificada como pendente sem ser executada no dry-run isolado", async () => {
  const realMigrationsDir = path.join(process.cwd(), "server", "db", "migrations");
  const mockPool = new MockPgEnvironment();

  const files = fs
    .readdirSync(realMigrationsDir)
    .filter((f) => f.endsWith(".sql") && fs.statSync(path.join(realMigrationsDir, f)).isFile())
    .sort();

  for (const file of files) {
    if (file === "011_billing_idempotency_unique.sql") continue;
    const content = fs.readFileSync(path.join(realMigrationsDir, file), "utf-8");
    mockPool.appliedRows.set(file, {
      id: file,
      checksum: computeMigrationChecksum(content),
      applied_at: "2026-01-01T00:00:00Z",
    });
  }

  const result = await runMigrations({
    pool: mockPool,
    migrationsDir: realMigrationsDir,
    dryRun: true,
    logger: SILENT_LOGGER,
  });

  assert.deepEqual(result.pending, ["011_billing_idempotency_unique.sql"]);
  assert.deepEqual(result.applied, []);
  assert.equal(result.skipped.length, 10);
  assert.equal(mockPool.executedDdl.length, 0);
  assert.equal(mockPool.mutationOperations.length, 0);
  assert.equal(mockPool.transactionControlCommands.length, 0);
  assert.equal(mockPool.appliedRows.has("011_billing_idempotency_unique.sql"), false);
  assert.equal(mockPool.activeLockHolder, null);
  assert.deepEqual(mockPool.releaseCalls, [{ clientId: 1, destroyed: false }]);
});

test("12. dryRun com _schema_migrations existente: nenhuma operação DDL ou DML (apenas leitura e controle de sessão)", async () => {
  const sql001 = "CREATE TABLE IF NOT EXISTS items_a (id VARCHAR(64) PRIMARY KEY);";
  const dir = createTempMigrationsDir({ "001_items_a.sql": sql001 });
  const mockPool = new MockPgEnvironment();
  mockPool.migrationTableExists = true;
  mockPool.appliedRows.set("001_items_a.sql", {
    id: "001_items_a.sql",
    checksum: computeMigrationChecksum(sql001),
    applied_at: "2026-01-01T00:00:00Z",
  });

  try {
    const result = await runMigrations({
      pool: mockPool,
      migrationsDir: dir,
      dryRun: true,
      logger: SILENT_LOGGER,
    });

    assert.deepEqual(result, {
      applied: [],
      skipped: ["001_items_a.sql"],
      pending: [],
    });

    // Classificação separada das operações:
    assert.equal(mockPool.mutationOperations.length, 0);
    assert.equal(mockPool.transactionControlCommands.length, 0);
    assert.equal(mockPool.sessionControlCommands.length, 2); // pg_advisory_lock + pg_advisory_unlock
    assert.equal(mockPool.readOnlyQueries.length, 2); // to_regclass + SELECT _schema_migrations
    assert.ok(mockPool.readOnlyQueries[0].includes("to_regclass"));
    assert.ok(mockPool.readOnlyQueries[1].includes("FROM _schema_migrations"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("13. dryRun com _schema_migrations inexistente: consulta to_regclass, não cria tabela e lista todas como pendentes", async () => {
  const dir = createTempMigrationsDir({
    "001_init.sql": "CREATE TABLE IF NOT EXISTS alpha (id INT);",
    "002_next.sql": "CREATE TABLE IF NOT EXISTS beta (id INT);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.migrationTableExists = false;

  try {
    const result = await runMigrations({
      pool: mockPool,
      migrationsDir: dir,
      dryRun: true,
      logger: SILENT_LOGGER,
    });

    assert.deepEqual(result.applied, []);
    assert.deepEqual(result.skipped, []);
    assert.deepEqual(result.pending, ["001_init.sql", "002_next.sql"]);

    // Garantias estritas de não modificação:
    assert.equal(mockPool.migrationTableExists, false);
    assert.equal(mockPool.mutationOperations.length, 0);
    assert.equal(mockPool.transactionControlCommands.length, 0);
    assert.equal(mockPool.sessionControlCommands.length, 2);
    assert.deepEqual(mockPool.readOnlyQueries, [
      "SELECT to_regclass('_schema_migrations')::text AS regclass_name",
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("14. dryRun com migrations pendentes (misto de aplicadas e pendentes): identifica apenas os arquivos pendentes sem mutação", async () => {
  const sql001 = "CREATE TABLE IF NOT EXISTS m1 (id INT);";
  const sql002 = "CREATE TABLE IF NOT EXISTS m2 (id INT);";
  const sql003 = "CREATE UNIQUE INDEX IF NOT EXISTS idx_m2 ON m2 (id);";
  const dir = createTempMigrationsDir({
    "001_m1.sql": sql001,
    "002_m2.sql": sql002,
    "003_idx.sql": sql003,
  });
  const mockPool = new MockPgEnvironment();
  mockPool.migrationTableExists = true;
  mockPool.appliedRows.set("001_m1.sql", {
    id: "001_m1.sql",
    checksum: computeMigrationChecksum(sql001),
    applied_at: "2026-01-01T00:00:00Z",
  });

  try {
    const result = await runMigrations({
      pool: mockPool,
      migrationsDir: dir,
      dryRun: true,
      logger: SILENT_LOGGER,
    });

    assert.deepEqual(result.applied, []);
    assert.deepEqual(result.skipped, ["001_m1.sql"]);
    assert.deepEqual(result.pending, ["002_m2.sql", "003_idx.sql"]);
    assert.equal(mockPool.mutationOperations.length, 0);
    assert.equal(mockPool.transactionControlCommands.length, 0);
    assert.equal(mockPool.appliedRows.size, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("15. dryRun com checksum divergente: interrompe a simulação sem alterar histórico ou executar DDL/DML", async () => {
  const dir = createTempMigrationsDir({
    "001_modified.sql": "CREATE TABLE modified_tbl (id INT);",
    "002_pending.sql": "CREATE TABLE pending_tbl (id INT);",
  });
  const mockPool = new MockPgEnvironment();
  mockPool.migrationTableExists = true;
  mockPool.appliedRows.set("001_modified.sql", {
    id: "001_modified.sql",
    checksum: "f".repeat(64),
    applied_at: "2026-01-01T00:00:00Z",
  });

  try {
    await assert.rejects(
      () =>
        runMigrations({
          pool: mockPool,
          migrationsDir: dir,
          dryRun: true,
          logger: SILENT_LOGGER,
        }),
      (err: any) =>
        err instanceof MigrationChecksumError &&
        err.migrationId === "001_modified.sql" &&
        err.recordedChecksum === "f".repeat(64)
    );

    assert.equal(mockPool.mutationOperations.length, 0);
    assert.equal(mockPool.transactionControlCommands.length, 0);
    assert.equal(mockPool.sessionControlCommands.length, 2); // lock adquirido e liberado no finally
    assert.equal(mockPool.activeLockHolder, null);
    assert.deepEqual(mockPool.releaseCalls, [{ clientId: 1, destroyed: false }]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("16. Execução normal com _schema_migrations inexistente: cria tabela de histórico e aplica migrations transacionalmente", async () => {
  const sql = "CREATE TABLE IF NOT EXISTS fresh_tbl (id VARCHAR(64) PRIMARY KEY);";
  const dir = createTempMigrationsDir({ "001_fresh.sql": sql });
  const mockPool = new MockPgEnvironment();
  mockPool.migrationTableExists = false;

  try {
    const result = await runMigrations({
      pool: mockPool,
      migrationsDir: dir,
      logger: SILENT_LOGGER,
    });

    assert.equal(mockPool.migrationTableExists, true);
    assert.deepEqual(result.applied, ["001_fresh.sql"]);
    assert.deepEqual(result.pending, ["001_fresh.sql"]);
    assert.equal(mockPool.appliedRows.size, 1);

    // Verifica separação clara das categorias na execução normal:
    assert.equal(mockPool.sessionControlCommands.length, 2); // lock + unlock
    assert.equal(mockPool.readOnlyQueries.length, 1); // SELECT _schema_migrations (após CREATE TABLE)
    assert.deepEqual(mockPool.transactionControlCommands, ["BEGIN", "COMMIT"]);
    assert.equal(mockPool.mutationOperations.length, 3); // CREATE TABLE _schema_migrations + DDL + INSERT _schema_migrations
    assert.ok(mockPool.mutationOperations[0].startsWith("CREATE TABLE IF NOT EXISTS _schema_migrations"));
    assert.ok(mockPool.mutationOperations[1].includes("CREATE TABLE IF NOT EXISTS fresh_tbl"));
    assert.ok(mockPool.mutationOperations[2].startsWith("INSERT INTO _schema_migrations"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

