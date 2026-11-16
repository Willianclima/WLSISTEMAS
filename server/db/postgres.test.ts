import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {
  applyRlsContext,
  createPostgresPool,
  executeWithTenantRlsContext,
  getPostgresPool,
  interceptClientWithRls,
  PgPoolClientLike,
  PgPoolLike,
  pool,
  query,
  RlsContextError,
  sanitizeTenantId,
  setLocalTenantId,
  withTransaction,
} from "./postgres";
import { TenantContext } from "./tenantContext";

interface RecordedSqlExecution {
  connectionId: string;
  sql: string;
  params: any[];
  inTransactionAtExecution: boolean;
  effectiveTenantBefore: string | null;
  effectiveTenantAfter: string | null;
  effectiveSuperAdminAfter: string | null;
}

interface MockConnectionFaults {
  failBegin?: boolean;
  failSetConfig?: boolean;
  failCommit?: boolean;
  failRollback?: boolean;
}

class InMemoryRlsClient implements PgPoolClientLike {
  readonly connectionId: string;
  inTransaction = false;
  sessionGucs = new Map<string, string>();
  localGucs = new Map<string, string>();
  destroyed = false;
  releaseCalls: Array<boolean | Error | undefined> = [];

  private readonly onReleaseCallback: (client: InMemoryRlsClient, destroy?: boolean | Error) => void;
  private readonly history: RecordedSqlExecution[];
  private readonly customFaults: MockConnectionFaults;
  private readonly queryInterceptor?: (sql: string, params: any[], client: InMemoryRlsClient) => any;

  constructor(
    connectionId: string,
    history: RecordedSqlExecution[],
    onReleaseCallback: (client: InMemoryRlsClient, destroy?: boolean | Error) => void,
    faults: MockConnectionFaults = {},
    queryInterceptor?: (sql: string, params: any[], client: InMemoryRlsClient) => any
  ) {
    this.connectionId = connectionId;
    this.history = history;
    this.onReleaseCallback = onReleaseCallback;
    this.customFaults = faults;
    this.queryInterceptor = queryInterceptor;
  }

  getEffectiveSetting(key: string): string | null {
    if (this.localGucs.has(key)) return this.localGucs.get(key)!;
    if (this.sessionGucs.has(key)) return this.sessionGucs.get(key)!;
    return null;
  }

  async query<T extends pg.QueryResultRow = any>(
    text: string | pg.QueryConfig<any[]>,
    values: any[] = []
  ): Promise<pg.QueryResult<T>> {
    const sql = typeof text === "string" ? text : text.text;
    const params = typeof text === "string" ? values : text.values || [];
    const normalized = sql.trim();

    const effectiveBefore = this.getEffectiveSetting("app.current_tenant_id");
    const inTxBefore = this.inTransaction;

    const record = (resultRows: any[] = []): pg.QueryResult<T> => {
      this.history.push({
        connectionId: this.connectionId,
        sql: normalized,
        params,
        inTransactionAtExecution: inTxBefore,
        effectiveTenantBefore: effectiveBefore,
        effectiveTenantAfter: this.getEffectiveSetting("app.current_tenant_id"),
        effectiveSuperAdminAfter: this.getEffectiveSetting("app.is_super_admin"),
      });
      return {
        command: "SELECT",
        rowCount: resultRows.length,
        oid: 0,
        fields: [],
        rows: resultRows as T[],
      };
    };

    if (/^BEGIN\b/i.test(normalized)) {
      if (this.customFaults.failBegin) {
        throw new Error("Simulated BEGIN failure");
      }
      this.inTransaction = true;
      this.localGucs.clear();
      return record();
    }

    if (/^COMMIT\b/i.test(normalized)) {
      if (this.customFaults.failCommit) {
        throw new Error("Simulated COMMIT failure");
      }
      this.inTransaction = false;
      this.localGucs.clear();
      return record();
    }

    if (/^ROLLBACK\b/i.test(normalized)) {
      if (this.customFaults.failRollback) {
        throw new Error("Simulated ROLLBACK failure");
      }
      this.inTransaction = false;
      this.localGucs.clear();
      return record();
    }

    if (/set_config\(/i.test(normalized)) {
      if (this.customFaults.failSetConfig) {
        throw new Error("Simulated set_config failure");
      }

      // Parse SELECT set_config('app.current_tenant_id', $1, true), set_config('app.is_super_admin', $2, true)
      const isLocalTenant = /set_config\(\s*'app\.current_tenant_id'\s*,\s*\$1\s*,\s*true\s*\)/i.test(normalized);
      const isSessionTenant = /set_config\(\s*'app\.current_tenant_id'\s*,\s*\$1\s*,\s*false\s*\)/i.test(normalized);

      if (isSessionTenant) {
        this.sessionGucs.set("app.current_tenant_id", String(params[0] ?? ""));
        if (params.length > 1) {
          this.sessionGucs.set("app.is_super_admin", String(params[1] ?? "false"));
        }
      } else if (isLocalTenant) {
        if (this.inTransaction) {
          this.localGucs.set("app.current_tenant_id", String(params[0] ?? ""));
          if (params.length > 1) {
            this.localGucs.set("app.is_super_admin", String(params[1] ?? "false"));
          }
        }
        // Outside transaction, is_local = true expires immediately after statement (PG semantics)
      }
      return record();
    }

    if (/current_setting\(\s*'app\.current_tenant_id'/i.test(normalized)) {
      return record([
        {
          connection_id: this.connectionId,
          tenant_id: this.getEffectiveSetting("app.current_tenant_id"),
          is_super_admin: this.getEffectiveSetting("app.is_super_admin"),
        },
      ]);
    }

    if (this.queryInterceptor) {
      const interceptedRows = await this.queryInterceptor(normalized, params, this);
      if (Array.isArray(interceptedRows)) {
        return record(interceptedRows);
      }
    }

    return record([
      {
        connection_id: this.connectionId,
        tenant_id: this.getEffectiveSetting("app.current_tenant_id"),
        is_super_admin: this.getEffectiveSetting("app.is_super_admin"),
      },
    ]);
  }

  release(destroy?: boolean | Error): void {
    this.releaseCalls.push(destroy);
    if (destroy) {
      this.destroyed = true;
    }
    this.onReleaseCallback(this, destroy);
  }
}

class InMemoryRlsPgPool implements PgPoolLike {
  readonly maxConnections: number;
  readonly history: RecordedSqlExecution[] = [];
  readonly idlePool: InMemoryRlsClient[] = [];
  readonly allCreatedClients: InMemoryRlsClient[] = [];
  private activeCount = 0;
  private waitQueue: Array<(client: InMemoryRlsClient) => void> = [];
  private nextFaults: MockConnectionFaults = {};
  private queryInterceptor?: (sql: string, params: any[], client: InMemoryRlsClient) => any;
  private seq = 0;

  constructor(
    options: {
      maxConnections?: number;
      faults?: MockConnectionFaults;
      queryInterceptor?: (sql: string, params: any[], client: InMemoryRlsClient) => any;
    } = {}
  ) {
    this.maxConnections = options.maxConnections ?? 1;
    this.nextFaults = options.faults ?? {};
    this.queryInterceptor = options.queryInterceptor;
  }

  setNextFaults(faults: MockConnectionFaults): void {
    this.nextFaults = faults;
  }

  get destroyedCount(): number {
    return this.allCreatedClients.filter((c) => c.destroyed).length;
  }

  get idleCount(): number {
    return this.idlePool.length;
  }

  async connect(): Promise<InMemoryRlsClient> {
    if (this.idlePool.length > 0) {
      this.activeCount += 1;
      return this.idlePool.pop()!;
    }

    if (this.activeCount < this.maxConnections) {
      this.activeCount += 1;
      this.seq += 1;
      const client = new InMemoryRlsClient(
        `conn-${this.seq}`,
        this.history,
        (releasedClient, destroy) => this.handleRelease(releasedClient, destroy),
        this.nextFaults,
        this.queryInterceptor
      );
      this.allCreatedClients.push(client);
      return client;
    }

    return await new Promise<InMemoryRlsClient>((resolve) => {
      this.waitQueue.push((client) => {
        this.activeCount += 1;
        resolve(client);
      });
    });
  }

  private handleRelease(client: InMemoryRlsClient, destroy?: boolean | Error): void {
    this.activeCount = Math.max(0, this.activeCount - 1);

    if (destroy) {
      client.destroyed = true;
      if (this.waitQueue.length > 0) {
        const nextWaiter = this.waitQueue.shift()!;
        this.seq += 1;
        const freshClient = new InMemoryRlsClient(
          `conn-${this.seq}`,
          this.history,
          (c, d) => this.handleRelease(c, d),
          this.nextFaults,
          this.queryInterceptor
        );
        this.allCreatedClients.push(freshClient);
        nextWaiter(freshClient);
      }
      return;
    }

    if (this.waitQueue.length > 0) {
      const nextWaiter = this.waitQueue.shift()!;
      nextWaiter(client);
      return;
    }

    this.idlePool.push(client);
  }
}

test("1. Reutiliza exatamente a mesma conexão física durante toda a transação", async () => {
  const mockPool = new InMemoryRlsPgPool({ maxConnections: 2 });

  const observedConnections = await TenantContext.run({ tenantId: "org-alpha" }, async () => {
    return await withTransaction(
      async (client) => {
        const r1 = await client.query("SELECT * FROM products WHERE sku = $1", ["SKU-1"]);
        const r2 = await client.query("UPDATE inventory_balances SET on_hand_quantity = 5");
        const r3 = await client.query("SELECT current_setting('app.current_tenant_id', true) AS tenant_id");
        return {
          c1: r1.rows[0].connection_id,
          c2: r2.rows[0].connection_id,
          c3: r3.rows[0],
        };
      },
      { pool: mockPool }
    );
  });

  assert.equal(observedConnections.c1, "conn-1");
  assert.equal(observedConnections.c2, "conn-1");
  assert.equal(observedConnections.c3.tenant_id, "org-alpha");

  const connIds = new Set(mockPool.history.map((h) => h.connectionId));
  assert.deepEqual([...connIds], ["conn-1"]);
  assert.equal(mockPool.history[0].sql, "BEGIN");
  assert.match(mockPool.history[1].sql, /set_config\('app\.current_tenant_id', \$1, true\)/);
  assert.equal(mockPool.history[mockPool.history.length - 1].sql, "COMMIT");
  assert.equal(mockPool.allCreatedClients[0].sessionGucs.size, 0);
});

test("2. Isolamento entre duas organizações consecutivas reutilizando a mesma conexão do pool (max=1)", async () => {
  const mockPool = new InMemoryRlsPgPool({ maxConnections: 1 });

  const resOrgA = await executeWithTenantRlsContext(
    "org-loja-a",
    async (client) => {
      const row = await client.query("SELECT current_setting('app.current_tenant_id', true) AS tenant_id");
      return {
        tenant: row.rows[0].tenant_id,
        isSuper: row.rows[0].is_super_admin,
      };
    },
    false,
    { pool: mockPool }
  );

  const resOrgB = await executeWithTenantRlsContext(
    "org-loja-b",
    async (client) => {
      const row = await client.query("SELECT current_setting('app.current_tenant_id', true) AS tenant_id");
      return {
        tenant: row.rows[0].tenant_id,
        isSuper: row.rows[0].is_super_admin,
      };
    },
    false,
    { pool: mockPool }
  );

  // Sem contexto algum após Org A e Org B
  const resNoTenant = await query(
    "SELECT current_setting('app.current_tenant_id', true) AS tenant_id",
    [],
    { pool: mockPool }
  );

  assert.equal(mockPool.allCreatedClients.length, 1, "Deve reutilizar a mesma conexão física conn-1");
  assert.equal(resOrgA.tenant, "org-loja-a");
  assert.equal(resOrgB.tenant, "org-loja-b");
  assert.equal(resNoTenant.rows[0].tenant_id, "");
  assert.equal(resNoTenant.rows[0].is_super_admin, "false");

  // Garante que nenhuma GUC de sessão (is_local=false) foi gravada
  assert.equal(mockPool.allCreatedClients[0].sessionGucs.size, 0);
  assert.ok(
    mockPool.history.every((h) => !/set_config\([^)]*,\s*false\s*\)/i.test(h.sql)),
    "Nunca deve executar set_config(..., false)"
  );
});

test("3. Ausência total de contexto RLS após COMMIT na conexão devolvida ao pool", async () => {
  const mockPool = new InMemoryRlsPgPool({ maxConnections: 1 });

  await TenantContext.run({ tenantId: "org-commit-check", isSuperAdmin: true }, async () => {
    await withTransaction(
      async (client) => {
        const res = await client.query("SELECT current_setting('app.current_tenant_id', true)");
        assert.equal(res.rows[0].tenant_id, "org-commit-check");
        assert.equal(res.rows[0].is_super_admin, "true");
      },
      { pool: mockPool }
    );
  });

  const physicalClient = mockPool.allCreatedClients[0];
  assert.equal(physicalClient.inTransaction, false);
  assert.equal(physicalClient.localGucs.size, 0);
  assert.equal(physicalClient.sessionGucs.size, 0);
  assert.equal(physicalClient.getEffectiveSetting("app.current_tenant_id"), null);
  assert.equal(physicalClient.getEffectiveSetting("app.is_super_admin"), null);
});

test("4. Ausência total de contexto RLS após ROLLBACK e 5. Rollback em caso de exceção", async () => {
  const mockPool = new InMemoryRlsPgPool({ maxConnections: 1 });

  await assert.rejects(
    async () => {
      await TenantContext.run({ tenantId: "org-rollback-check", isSuperAdmin: true }, async () => {
        await withTransaction(
          async (client) => {
            const inside = await client.query("SELECT current_setting('app.current_tenant_id', true)");
            assert.equal(inside.rows[0].tenant_id, "org-rollback-check");
            throw new Error("Erro de negócio simulado");
          },
          { pool: mockPool }
        );
      });
    },
    (err: Error) => err.message === "Erro de negócio simulado"
  );

  const physicalClient = mockPool.allCreatedClients[0];
  assert.equal(physicalClient.inTransaction, false);
  assert.equal(physicalClient.localGucs.size, 0);
  assert.equal(physicalClient.sessionGucs.size, 0);
  assert.equal(physicalClient.getEffectiveSetting("app.current_tenant_id"), null);
  assert.equal(physicalClient.getEffectiveSetting("app.is_super_admin"), null);
  assert.equal(physicalClient.destroyed, false, "Rollback limpo pode devolver a conexão sem contexto residual ao pool");
  assert.equal(mockPool.history[mockPool.history.length - 1].sql, "ROLLBACK");

  // Próxima requisição sem tenant não herda absolutamente nada
  const nextRes = await query(
    "SELECT current_setting('app.current_tenant_id', true)",
    [],
    { pool: mockPool }
  );
  assert.equal(nextRes.rows[0].tenant_id, "");
  assert.equal(nextRes.rows[0].is_super_admin, "false");
});

test("6. Preservação do erro original quando o ROLLBACK também falhar e destruição da conexão", async () => {
  const mockPool = new InMemoryRlsPgPool({
    maxConnections: 1,
    faults: { failRollback: true },
  });

  await assert.rejects(
    async () => {
      await TenantContext.run({ tenantId: "org-fail-rb" }, async () => {
        await withTransaction(
          async () => {
            throw new Error("ERRO_ORIGINAL_NEGOCIO");
          },
          { pool: mockPool }
        );
      });
    },
    (err: Error) => err.message === "ERRO_ORIGINAL_NEGOCIO"
  );

  assert.equal(mockPool.destroyedCount, 1, "Conexão com ROLLBACK falho deve ser destruída e não devolvida ao pool");
  assert.equal(mockPool.idleCount, 0);
  assert.deepEqual(mockPool.allCreatedClients[0].releaseCalls, [true]);
});

test("7. Falha segura: destrói conexão ao falhar ao estabelecer contexto, ao falhar COMMIT ou ao liberar com transação aberta", async () => {
  // 7a. Falha ao estabelecer set_config
  const failContextPool = new InMemoryRlsPgPool({
    maxConnections: 1,
    faults: { failSetConfig: true },
  });

  await assert.rejects(
    () =>
      TenantContext.run({ tenantId: "org-fail-ctx" }, () =>
        withTransaction(async () => "never", { pool: failContextPool })
      ),
    /Simulated set_config failure/
  );
  assert.equal(failContextPool.destroyedCount, 1);
  assert.equal(failContextPool.idleCount, 0);

  // 7b. Falha no COMMIT
  const failCommitPool = new InMemoryRlsPgPool({
    maxConnections: 1,
    faults: { failCommit: true },
  });

  await assert.rejects(
    () =>
      TenantContext.run({ tenantId: "org-fail-commit" }, () =>
        withTransaction(async () => "ok", { pool: failCommitPool })
      ),
    /Simulated COMMIT failure/
  );
  assert.equal(failCommitPool.destroyedCount, 1);
  assert.equal(failCommitPool.idleCount, 0);

  // 7c. Cliente interceptado liberado sem COMMIT/ROLLBACK (transação abandonada) deve ser destruído
  const leakPool = new InMemoryRlsPgPool({ maxConnections: 1 });
  const raw = await leakPool.connect();
  const intercepted = interceptClientWithRls(raw);
  await TenantContext.run({ tenantId: "org-abandoned" }, async () => {
    await intercepted.query("BEGIN");
    await intercepted.query("SELECT 1");
    // Esquece COMMIT/ROLLBACK e chama release()
    intercepted.release();
  });
  assert.equal(leakPool.destroyedCount, 1);
  assert.equal(leakPool.idleCount, 0);
});

test("8. Validações fail-closed, interceptação direta e compatibilidade com API pública do pool", async () => {
  const mockPool = new InMemoryRlsPgPool({ maxConnections: 1 });

  // Rejeita tenantId malicioso / inválido sem mutação silenciosa
  assert.throws(
    () => sanitizeTenantId("org-a'; DROP TABLE orders; --"),
    (err: unknown) => err instanceof RlsContextError
  );
  assert.throws(
    () => sanitizeTenantId(""),
    (err: unknown) => err instanceof RlsContextError
  );

  // Rejeita aplicação de RLS em objeto Pool (exige PoolClient)
  await assert.rejects(
    () => applyRlsContext(mockPool as unknown as pg.Pool),
    (err: unknown) => err instanceof RlsContextError && err.code === "RLS_DEDICATED_CLIENT_REQUIRED"
  );

  // Rejeita query direta em PoolClient interceptado fora de transação quando TenantContext está ativo
  const client = interceptClientWithRls(await mockPool.connect());
  await assert.rejects(
    () =>
      TenantContext.run({ tenantId: "org-direct" }, async () => {
        await client.query("SELECT * FROM orders");
      }),
    (err: unknown) => err instanceof RlsContextError && err.code === "RLS_TRANSACTION_REQUIRED"
  );

  // Dentro de transação no cliente interceptado, set_config(..., true) é aplicado automaticamente
  await TenantContext.run({ tenantId: "org-direct" }, async () => {
    await client.query("BEGIN");
    const res = await client.query("SELECT current_setting('app.current_tenant_id', true)");
    assert.equal(res.rows[0].tenant_id, "org-direct");
    await client.query("COMMIT");
  });
  client.release();
  assert.equal(mockPool.destroyedCount, 0);
  assert.equal(mockPool.idleCount, 1);

  // Verifica que setLocalTenantId exige transação ativa no cliente interceptado
  const client2 = interceptClientWithRls(await mockPool.connect());
  await assert.rejects(
    () => setLocalTenantId(client2, "org-x"),
    (err: unknown) => err instanceof RlsContextError && err.code === "RLS_TRANSACTION_REQUIRED"
  );
  client2.release();

  // Verifica assinaturas exportadas compatíveis sem abrir conexão com PostgreSQL real
  assert.equal(typeof getPostgresPool, "function");
  assert.equal(typeof createPostgresPool, "function");
  assert.equal(typeof pool, "object");
});

test("9. Concorrência multi-tenant com pool limitado (max=2) nunca mistura contexto RLS entre organizações", async () => {
  const mockPool = new InMemoryRlsPgPool({ maxConnections: 2 });
  const tenants = ["org-01", "org-02", "org-03", "org-04", "org-05", "org-06"];

  const results = await Promise.all(
    tenants.map((tenantId, idx) =>
      TenantContext.run({ tenantId }, async () => {
        return await withTransaction(
          async (client) => {
            const q1 = await client.query("SELECT current_setting('app.current_tenant_id', true)");
            // Simula latência assíncrona variável para provocar disputa de pool e intercalamento
            await new Promise((resolve) => setTimeout(resolve, (tenants.length - idx) * 5));
            const q2 = await client.query("SELECT current_setting('app.current_tenant_id', true)");
            const q3 = await client.query("SELECT * FROM orders");

            return {
              expected: tenantId,
              t1: q1.rows[0].tenant_id,
              t2: q2.rows[0].tenant_id,
              c1: q1.rows[0].connection_id,
              c3: q3.rows[0].connection_id,
              t3: q3.rows[0].tenant_id,
            };
          },
          { pool: mockPool }
        );
      })
    )
  );

  for (const r of results) {
    assert.equal(r.t1, r.expected);
    assert.equal(r.t2, r.expected);
    assert.equal(r.t3, r.expected);
    assert.equal(r.c1, r.c3, "Todas as queries da transação devem permanecer na mesma conexão física");
  }

  for (const c of mockPool.allCreatedClients) {
    assert.equal(c.inTransaction, false);
    assert.equal(c.sessionGucs.size, 0);
    assert.equal(c.localGucs.size, 0);
  }
});
