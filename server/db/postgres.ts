import dotenv from "dotenv";
dotenv.config();

import pg from "pg";
import { TenantContext, TenantSessionContext } from "./tenantContext";
const { Pool } = pg;

// Singleton connection pool adhering to lazy connection pattern
declare global {
  var _auraPgPool: pg.Pool | undefined;
}

export interface PgPoolClientLike {
  query: <T extends pg.QueryResultRow = any>(
    text: string | pg.QueryConfig<any[]>,
    values?: any[]
  ) => Promise<pg.QueryResult<T>>;
  release: (destroy?: boolean | Error) => void;
}

export interface PgPoolLike {
  connect: () => Promise<PgPoolClientLike>;
  query?: <T extends pg.QueryResultRow = any>(
    text: string | pg.QueryConfig<any[]>,
    values?: any[]
  ) => Promise<pg.QueryResult<T>>;
}

export interface RlsContextInput {
  tenantId?: string;
  isSuperAdmin?: boolean;
}

export interface PostgresExecutionOptions {
  pool?: PgPoolLike;
  context?: RlsContextInput;
}

export class RlsContextError extends Error {
  readonly code: string;

  constructor(message: string, code = "RLS_CONTEXT_ERROR") {
    super(message);
    this.name = "RlsContextError";
    this.code = code;
  }
}

interface InterceptedClientState {
  inTransaction: boolean;
  contextAppliedInTx: boolean;
  contaminated: boolean;
}

const RLS_INTERCEPTED_MARKER = Symbol("aura_rls_intercepted");
const RLS_CLIENT_STATE = Symbol("aura_rls_client_state");

const TENANT_ID_PATTERN = /^[a-zA-Z0-9_-]+$/;

/**
 * Strictly validates a tenant/organization identifier without silently mutating
 * arbitrary invalid characters into another identifier.
 */
export function sanitizeTenantId(
  tenantId: string | undefined | null,
  options: { allowEmpty?: boolean } = {}
): string {
  const { allowEmpty = false } = options;

  if (tenantId === undefined || tenantId === null) {
    if (allowEmpty) return "";
    throw new RlsContextError(
      "tenantId obrigatório para estabelecer contexto RLS transacional.",
      "RLS_TENANT_REQUIRED"
    );
  }

  if (typeof tenantId !== "string") {
    throw new RlsContextError(
      "tenantId deve ser uma string válida para contexto RLS.",
      "RLS_INVALID_TENANT_ID"
    );
  }

  if (tenantId === "") {
    if (allowEmpty) return "";
    throw new RlsContextError(
      "tenantId não pode ser vazio para estabelecer contexto RLS de organização.",
      "RLS_TENANT_REQUIRED"
    );
  }

  if (!TENANT_ID_PATTERN.test(tenantId)) {
    throw new RlsContextError(
      "tenantId contém caracteres inválidos para contexto RLS.",
      "RLS_INVALID_TENANT_ID"
    );
  }

  return tenantId;
}

function extractSqlText(queryArg: unknown): string {
  if (typeof queryArg === "string") return queryArg;
  if (queryArg && typeof queryArg === "object" && "text" in queryArg) {
    const text = (queryArg as { text?: unknown }).text;
    return typeof text === "string" ? text : "";
  }
  return "";
}

function stripLeadingSqlComments(sql: string): string {
  let remaining = sql.trimStart();
  while (remaining.length > 0) {
    if (remaining.startsWith("--")) {
      const nl = remaining.indexOf("\n");
      remaining = nl === -1 ? "" : remaining.slice(nl + 1).trimStart();
    } else if (remaining.startsWith("/*")) {
      const end = remaining.indexOf("*/");
      remaining = end === -1 ? "" : remaining.slice(end + 2).trimStart();
    } else {
      break;
    }
  }
  return remaining;
}

function classifySqlControl(sql: string): "begin" | "commit" | "rollback" | "other" {
  const normalized = stripLeadingSqlComments(sql);
  if (/^(BEGIN|START\s+TRANSACTION)\b/i.test(normalized)) {
    return "begin";
  }
  if (/^COMMIT(?:\s+TRANSACTION)?(?:\s*;|\s*$)/i.test(normalized)) {
    return "commit";
  }
  if (/^ROLLBACK(?:\s+TRANSACTION)?(?:\s*;|\s*$)/i.test(normalized)) {
    return "rollback";
  }
  return "other";
}

function getClientState(client: any): InterceptedClientState | undefined {
  return client ? (client[RLS_CLIENT_STATE] as InterceptedClientState | undefined) : undefined;
}

function isPoolObject(candidate: unknown): boolean {
  return (
    Boolean(candidate) &&
    typeof (candidate as any).connect === "function" &&
    typeof (candidate as any).release !== "function"
  );
}

function resolveEffectiveRlsParams(explicitContext?: RlsContextInput): {
  tenantId: string;
  isSuperAdmin: "true" | "false";
  hasActiveContext: boolean;
} {
  const context: RlsContextInput | TenantSessionContext | undefined =
    explicitContext ?? TenantContext.get();

  const isSuperAdminFlag = Boolean(context?.isSuperAdmin);
  const rawTenantId = context?.tenantId;

  if (rawTenantId !== undefined && rawTenantId !== null && rawTenantId !== "") {
    const validatedTenantId = sanitizeTenantId(rawTenantId, { allowEmpty: false });
    return {
      tenantId: validatedTenantId,
      isSuperAdmin: isSuperAdminFlag ? "true" : "false",
      hasActiveContext: true,
    };
  }

  return {
    tenantId: "",
    isSuperAdmin: isSuperAdminFlag ? "true" : "false",
    hasActiveContext: isSuperAdminFlag,
  };
}

/**
 * Returns or initializes the PostgreSQL connection pool lazily.
 * Prioritizes standard DATABASE_URL, followed by individual SQL_* / DB_* env variables.
 * Never hardcodes fallback passwords, hosts, or usernames in code.
 */
export function getPostgresPool(): pg.Pool {
  if (!global._auraPgPool) {
    const connectionString = process.env.DATABASE_URL;
    const host = process.env.SQL_HOST || process.env.DB_HOST;
    const user = process.env.SQL_USER || process.env.DB_USER;
    const password = process.env.SQL_PASSWORD || process.env.DB_PASSWORD;
    const database = process.env.SQL_DB_NAME || process.env.DB_NAME;
    const portEnv = process.env.SQL_PORT || process.env.DB_PORT;

    if (!connectionString && !host) {
      throw new Error(
        "[PostgreSQL Error] Nenhuma configuração de banco de dados encontrada. " +
          "Defina DATABASE_URL ou SQL_HOST / SQL_USER / SQL_PASSWORD no arquivo .env."
      );
    }

    const poolConfig: pg.PoolConfig = connectionString
      ? {
          connectionString,
          ssl:
            process.env.DATABASE_SSL === "true" || process.env.DB_SSL === "true"
              ? { rejectUnauthorized: false }
              : undefined,
          max: parseInt(process.env.DB_POOL_MAX || "10", 10),
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 15000,
        }
      : {
          host,
          user,
          password,
          database,
          // If host is a Unix socket path (e.g. /app/cloudsql/...), omit port
          port: host && host.startsWith("/") ? undefined : parseInt(portEnv || "5432", 10),
          ssl:
            process.env.DATABASE_SSL === "true" || process.env.DB_SSL === "true"
              ? { rejectUnauthorized: false }
              : undefined,
          max: parseInt(process.env.DB_POOL_MAX || "10", 10),
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 15000,
        };

    global._auraPgPool = new Pool(poolConfig);

    global._auraPgPool.on("error", (err) => {
      console.error("[PostgreSQL Pool Error]", err);
    });

    // Intercept client checkouts to track transaction boundaries and enforce fail-safe release
    const originalConnect = global._auraPgPool.connect.bind(global._auraPgPool);
    global._auraPgPool.connect = function (...args: any[]) {
      if (typeof args[0] === "function") {
        const cb = args[0];
        return originalConnect((err: any, client: any, release: any) => {
          if (err) return cb(err, client, release);
          const wrappedClient = interceptClientWithRls(client);
          const safeRelease = (destroy?: boolean | Error) => wrappedClient.release(destroy);
          return cb(null, wrappedClient, safeRelease);
        });
      }
      return originalConnect().then((client: any) => interceptClientWithRls(client));
    } as any;
  }

  return global._auraPgPool;
}

/**
 * Wraps a pg.PoolClient to enforce strict transaction-scoped RLS guarantees:
 * 1. Never uses session-scoped set_config(..., false) — eliminates pool cross-contamination.
 * 2. Never performs un-awaited async queries inside synchronous client.release().
 * 3. Automatically binds transaction-local RLS context inside active transactions when missing.
 * 4. Fails closed if a tenant-scoped query is attempted directly on a client outside a transaction.
 * 5. Destroys the physical connection (release(true)) if released while inTransaction or contaminated.
 */
export function interceptClientWithRls<TClient extends PgPoolClientLike>(client: TClient): TClient {
  if (!client || typeof client.query !== "function") {
    return client;
  }

  if ((client as any)[RLS_INTERCEPTED_MARKER]) {
    return client;
  }

  const originalQuery: any = client.query.bind(client);
  const originalRelease =
    typeof client.release === "function" ? client.release.bind(client) : undefined;

  const state: InterceptedClientState = {
    inTransaction: false,
    contextAppliedInTx: false,
    contaminated: false,
  };

  Object.defineProperty(client, RLS_INTERCEPTED_MARKER, {
    value: true,
    enumerable: false,
    configurable: false,
  });

  Object.defineProperty(client, RLS_CLIENT_STATE, {
    value: state,
    enumerable: false,
    configurable: false,
  });

  (client as any).query = async function (this: any, ...args: any[]) {
    const sql = extractSqlText(args[0]);
    const controlKind = classifySqlControl(sql);

    if (controlKind === "begin") {
      const result = await originalQuery.apply(this, args);
      state.inTransaction = true;
      state.contextAppliedInTx = false;
      return result;
    }

    if (controlKind === "commit") {
      try {
        const result = await originalQuery.apply(this, args);
        state.inTransaction = false;
        state.contextAppliedInTx = false;
        return result;
      } catch (err) {
        // Commit failed; transaction state must be rolled back or connection destroyed
        state.contaminated = true;
        throw err;
      }
    }

    if (controlKind === "rollback") {
      try {
        const result = await originalQuery.apply(this, args);
        state.inTransaction = false;
        state.contextAppliedInTx = false;
        return result;
      } catch (err) {
        state.contaminated = true;
        throw err;
      }
    }

    // Never allow queries with active TenantContext outside a transaction on a raw checked-out client,
    // because set_config(..., true) only persists within BEGIN..COMMIT/ROLLBACK.
    const activeContext = TenantContext.get();
    const hasTenantOrAdminContext = Boolean(activeContext?.tenantId || activeContext?.isSuperAdmin);

    if (!state.inTransaction && hasTenantOrAdminContext) {
      throw new RlsContextError(
        "Operação com TenantContext em PoolClient direto requer transação ativa (BEGIN) para isolamento RLS transacional. Utilize query() ou withTransaction().",
        "RLS_TRANSACTION_REQUIRED"
      );
    }

    if (state.inTransaction && !state.contextAppliedInTx && hasTenantOrAdminContext) {
      const { tenantId, isSuperAdmin } = resolveEffectiveRlsParams(activeContext);
      try {
        await originalQuery.call(
          this,
          "SELECT set_config('app.current_tenant_id', $1, true), set_config('app.is_super_admin', $2, true)",
          [tenantId, isSuperAdmin]
        );
        state.contextAppliedInTx = true;
      } catch (err) {
        state.contaminated = true;
        throw err;
      }
    }

    return originalQuery.apply(this, args);
  };

  if (originalRelease) {
    (client as any).release = function (destroy?: boolean | Error) {
      const mustDestroy = Boolean(destroy) || state.contaminated || state.inTransaction;
      state.inTransaction = false;
      state.contextAppliedInTx = false;
      state.contaminated = false;

      if (destroy) {
        return originalRelease(destroy);
      }
      return mustDestroy ? originalRelease(true) : originalRelease();
    };
  }

  return client;
}

/**
 * Backwards-compatible alias for getPostgresPool.
 */
export function createPostgresPool(): pg.Pool {
  return getPostgresPool();
}

/**
 * Transparent proxy for pg.Pool so that importing `pool` does NOT
 * instantiate the connection on module load time. The pool is created
 * strictly on the first call to a method (e.g. query, connect).
 */
export const pool = new Proxy({} as pg.Pool, {
  get(_target, prop) {
    const actualPool = getPostgresPool();
    const value = (actualPool as any)[prop];
    if (typeof value === "function") {
      return value.bind(actualPool);
    }
    return value;
  },
});

/**
 * Applies transaction-local RLS context parameters (`set_config(..., true)`)
 * onto a dedicated `pg.PoolClient` inside an active transaction.
 * Always explicitly sets both `app.current_tenant_id` and `app.is_super_admin`
 * (using `''` and `'false'` when no tenant context is active) so no residual
 * values can ever remain active.
 */
export async function applyRlsContext(
  client: PgPoolClientLike | pg.Pool,
  explicitContext?: RlsContextInput
): Promise<void> {
  if (!client || typeof client.query !== "function" || isPoolObject(client)) {
    throw new RlsContextError(
      "applyRlsContext requer um PoolClient dedicado dentro de uma transação ativa.",
      "RLS_DEDICATED_CLIENT_REQUIRED"
    );
  }

  const state = getClientState(client);
  if (state && !state.inTransaction) {
    throw new RlsContextError(
      "applyRlsContext só pode ser executado dentro de uma transação ativa (após BEGIN).",
      "RLS_TRANSACTION_REQUIRED"
    );
  }

  const { tenantId, isSuperAdmin } = resolveEffectiveRlsParams(explicitContext);

  const targetClient = client as PgPoolClientLike;

  try {
    await targetClient.query(
      "SELECT set_config('app.current_tenant_id', $1, true), set_config('app.is_super_admin', $2, true)",
      [tenantId, isSuperAdmin]
    );
    if (state) {
      state.contextAppliedInTx = true;
    }
  } catch (err) {
    if (state) {
      state.contaminated = true;
    }
    throw err;
  }
}

/**
 * Explicit helper to set transaction-local tenant context on a PostgreSQL client
 * using parameterized `set_config(..., true)` (strictly scoped to the current transaction).
 */
export async function setLocalTenantId(
  client: PgPoolClientLike,
  tenantId: string,
  isSuperAdmin: boolean = false
): Promise<void> {
  if (!client || typeof client.query !== "function" || isPoolObject(client)) {
    throw new RlsContextError(
      "setLocalTenantId requer um PoolClient dedicado dentro de uma transação ativa.",
      "RLS_DEDICATED_CLIENT_REQUIRED"
    );
  }

  const state = getClientState(client);
  if (state && !state.inTransaction) {
    throw new RlsContextError(
      "setLocalTenantId só pode ser executado dentro de uma transação ativa (após BEGIN).",
      "RLS_TRANSACTION_REQUIRED"
    );
  }

  const sanitizedTenantId = sanitizeTenantId(tenantId, { allowEmpty: isSuperAdmin });
  const isSuperFlag = isSuperAdmin ? "true" : "false";

  try {
    await client.query(
      "SELECT set_config('app.current_tenant_id', $1, true), set_config('app.is_super_admin', $2, true)",
      [sanitizedTenantId, isSuperFlag]
    );
    if (state) {
      state.contextAppliedInTx = true;
    }
  } catch (err) {
    if (state) {
      state.contaminated = true;
    }
    throw err;
  }
}

/**
 * Executes a callback inside an isolated single-connection PostgreSQL transaction
 * with strictly transaction-local RLS context (`set_config(..., true)`).
 * Preserves the original error if ROLLBACK also fails, and destroys compromised
 * connections instead of returning them to the pool.
 */
export async function withTransaction<T>(
  callback: (client: pg.PoolClient) => Promise<T>,
  options: PostgresExecutionOptions = {}
): Promise<T> {
  const targetPool: PgPoolLike = options.pool ?? getPostgresPool();
  const rawClient = await targetPool.connect();
  const client = interceptClientWithRls(rawClient);

  let inTransaction = false;
  let shouldDestroyClient = false;
  let contextEstablishFailed = false;

  try {
    await client.query("BEGIN");
    inTransaction = true;

    try {
      await applyRlsContext(client, options.context);
    } catch (contextError) {
      contextEstablishFailed = true;
      shouldDestroyClient = true;
      throw contextError;
    }

    const result = await callback(client as pg.PoolClient);

    try {
      await client.query("COMMIT");
      inTransaction = false;
    } catch (commitError) {
      shouldDestroyClient = true;
      throw commitError;
    }

    return result;
  } catch (originalError) {
    if (inTransaction) {
      try {
        await client.query("ROLLBACK");
        inTransaction = false;
        if (!contextEstablishFailed && !shouldDestroyClient) {
          shouldDestroyClient = false;
        }
      } catch (rollbackError) {
        shouldDestroyClient = true;
        console.error(
          "[PostgreSQL Transaction Error] Falha ao executar ROLLBACK; conexão será descartada:",
          rollbackError
        );
      }
    } else {
      shouldDestroyClient = true;
    }
    throw originalError;
  } finally {
    if (inTransaction || contextEstablishFailed) {
      shouldDestroyClient = true;
    }
    if (shouldDestroyClient) {
      client.release(true);
    } else {
      client.release();
    }
  }
}

/**
 * High-level helper to execute any database query block with guaranteed
 * transaction-local RLS isolation (`set_config(..., true)`) on a single physical client.
 */
export async function executeWithTenantRlsContext<T>(
  tenantId: string,
  callback: (client: pg.PoolClient) => Promise<T>,
  isSuperAdmin: boolean = false,
  options: PostgresExecutionOptions = {}
): Promise<T> {
  const validatedTenantId = sanitizeTenantId(tenantId, { allowEmpty: isSuperAdmin });
  const parentContext = TenantContext.get();
  const scopedContext: TenantSessionContext = {
    ...(parentContext ?? {}),
    tenantId: validatedTenantId,
    isSuperAdmin: Boolean(isSuperAdmin),
  };

  return await TenantContext.run(scopedContext, async () => {
    return await withTransaction(callback, {
      ...options,
      context: {
        tenantId: validatedTenantId,
        isSuperAdmin: Boolean(isSuperAdmin),
      },
    });
  });
}

/**
 * Executes a single parameterized SQL query on a dedicated client inside an atomic
 * transaction with explicit transaction-local RLS parameters (`set_config(..., true)`).
 * Guarantees that no session-scoped context ever leaks across pooled connections.
 */
export async function query<T extends pg.QueryResultRow = any>(
  text: string,
  params?: any[],
  options: PostgresExecutionOptions = {}
): Promise<pg.QueryResult<T>> {
  return await withTransaction(
    async (client) => {
      return await client.query<T>(text, params);
    },
    options
  );
}
