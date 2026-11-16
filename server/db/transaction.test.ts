import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { PgPoolClientLike, PgPoolLike, RlsContextError } from "./postgres";
import { UnitOfWork } from "./transaction";
import { TenantContext } from "./tenantContext";

interface TxRecordedOp {
  connectionId: string;
  sql: string;
  params: any[];
  tenantAtExecution: string | null;
}

class MockTxClient implements PgPoolClientLike {
  readonly connectionId: string;
  inTransaction = false;
  sessionGucs = new Map<string, string>();
  localGucs = new Map<string, string>();
  destroyed = false;

  private readonly ops: TxRecordedOp[];
  private readonly onRelease: (client: MockTxClient, destroy?: boolean | Error) => void;
  private readonly failRollback: boolean;
  private readonly failCommit: boolean;

  constructor(
    connectionId: string,
    ops: TxRecordedOp[],
    onRelease: (client: MockTxClient, destroy?: boolean | Error) => void,
    options: { failRollback?: boolean; failCommit?: boolean } = {}
  ) {
    this.connectionId = connectionId;
    this.ops = ops;
    this.onRelease = onRelease;
    this.failRollback = Boolean(options.failRollback);
    this.failCommit = Boolean(options.failCommit);
  }

  async query<T extends pg.QueryResultRow = any>(
    text: string | pg.QueryConfig<any[]>,
    values: any[] = []
  ): Promise<pg.QueryResult<T>> {
    const sql = (typeof text === "string" ? text : text.text).trim();
    const params = typeof text === "string" ? values : text.values || [];

    if (/^BEGIN\b/i.test(sql)) {
      this.inTransaction = true;
      this.localGucs.clear();
    } else if (/^COMMIT\b/i.test(sql)) {
      if (this.failCommit) throw new Error("Simulated UnitOfWork COMMIT error");
      this.inTransaction = false;
      this.localGucs.clear();
    } else if (/^ROLLBACK\b/i.test(sql)) {
      if (this.failRollback) throw new Error("Simulated UnitOfWork ROLLBACK error");
      this.inTransaction = false;
      this.localGucs.clear();
    } else if (/set_config\(\s*'app\.current_tenant_id'\s*,\s*\$1\s*,\s*true\s*\)/i.test(sql)) {
      if (this.inTransaction) {
        this.localGucs.set("app.current_tenant_id", String(params[0] ?? ""));
        if (params.length > 1) {
          this.localGucs.set("app.is_super_admin", String(params[1] ?? "false"));
        }
      }
    } else if (/set_config\([^)]*,\s*false\s*\)/i.test(sql)) {
      this.sessionGucs.set("app.current_tenant_id", String(params[0] ?? ""));
    }

    const activeTenant =
      this.localGucs.get("app.current_tenant_id") ??
      this.sessionGucs.get("app.current_tenant_id") ??
      null;

    this.ops.push({
      connectionId: this.connectionId,
      sql,
      params,
      tenantAtExecution: activeTenant,
    });

    return {
      command: "SELECT",
      rowCount: 1,
      oid: 0,
      fields: [],
      rows: [{ connection_id: this.connectionId, tenant_id: activeTenant }] as unknown as T[],
    };
  }

  release(destroy?: boolean | Error): void {
    if (destroy) {
      this.destroyed = true;
    }
    this.onRelease(this, destroy);
  }
}

class MockTxPool implements PgPoolLike {
  readonly maxConnections: number;
  readonly ops: TxRecordedOp[] = [];
  readonly clients: MockTxClient[] = [];
  private readonly idle: MockTxClient[] = [];
  private readonly waiters: Array<(c: MockTxClient) => void> = [];
  private active = 0;
  private seq = 0;
  private readonly failRollback: boolean;
  private readonly failCommit: boolean;

  constructor(options: { maxConnections?: number; failRollback?: boolean; failCommit?: boolean } = {}) {
    this.maxConnections = options.maxConnections ?? 1;
    this.failRollback = Boolean(options.failRollback);
    this.failCommit = Boolean(options.failCommit);
  }

  async connect(): Promise<MockTxClient> {
    if (this.idle.length > 0) {
      this.active += 1;
      return this.idle.pop()!;
    }
    if (this.active < this.maxConnections) {
      this.active += 1;
      this.seq += 1;
      const client = new MockTxClient(
        `tx-conn-${this.seq}`,
        this.ops,
        (c, d) => this.releaseClient(c, d),
        { failRollback: this.failRollback, failCommit: this.failCommit }
      );
      this.clients.push(client);
      return client;
    }
    return await new Promise<MockTxClient>((resolve) => {
      this.waiters.push((c) => {
        this.active += 1;
        resolve(c);
      });
    });
  }

  private releaseClient(client: MockTxClient, destroy?: boolean | Error): void {
    this.active = Math.max(0, this.active - 1);
    if (destroy) {
      client.destroyed = true;
      if (this.waiters.length > 0) {
        const w = this.waiters.shift()!;
        this.seq += 1;
        const fresh = new MockTxClient(
          `tx-conn-${this.seq}`,
          this.ops,
          (c, d) => this.releaseClient(c, d),
          { failRollback: this.failRollback, failCommit: this.failCommit }
        );
        this.clients.push(fresh);
        w(fresh);
      }
      return;
    }
    if (this.waiters.length > 0) {
      const w = this.waiters.shift()!;
      w(client);
      return;
    }
    this.idle.push(client);
  }
}

test("UnitOfWork.transaction executa callback e flush de entidades staged na mesma conexão física com set_config local", async () => {
  const mockPool = new MockTxPool({ maxConnections: 1 });
  let capturedTx: any;

  const result = await TenantContext.run(
    {
      tenantId: "org-uow-a",
      userId: "user-1",
      userEmail: "operador@aura.com",
      userRole: "ADMIN",
    },
    async () => {
      return await UnitOfWork.transaction(
        "org-uow-a",
        async (tx) => {
          capturedTx = tx;
          assert.ok(tx.pgClient, "tx.pgClient deve estar disponível durante a transação");
          assert.equal(TenantContext.getUserId(), "user-1", "Deve preservar metadados do usuário");

          await tx.pgClient.query("SELECT * FROM inventory_balances WHERE organization_id = $1 FOR UPDATE", [
            "org-uow-a",
          ]);

          tx.stagedOrders.set("ord-1", {
            id: "ord-1",
            organizationId: "org-uow-a",
            orderNumber: "PED-001",
            customerId: "cust-1",
            customerSnapshot: { name: "Cliente" },
            status: "PAID",
            shippingAddress: {},
            subtotalAmount: 100,
            discountAmount: 0,
            shippingAmount: 0,
            totalAmount: 100,
          });
          tx.stagedInventoryMovements.set("mov-1", {
            id: "mov-1",
            organizationId: "org-uow-a",
            productId: "prod-1",
            type: "SALE",
            quantityChange: -1,
            physicalBalanceAfter: 9,
            consignedBalanceAfter: 0,
            operatorName: "Operador",
          });

          return "order-created";
        },
        { pool: mockPool }
      );
    }
  );

  assert.equal(result, "order-created");
  assert.equal(capturedTx.isCommitted, true);
  assert.equal(capturedTx.isRolledBack, false);
  assert.equal(capturedTx.pgClient, undefined, "tx.pgClient deve ser desanexado após término da transação");

  const connIds = new Set(mockPool.ops.map((o) => o.connectionId));
  assert.deepEqual([...connIds], ["tx-conn-1"]);
  assert.equal(mockPool.ops[0].sql, "BEGIN");
  assert.match(mockPool.ops[1].sql, /set_config\('app\.current_tenant_id', \$1, true\)/);
  assert.equal(mockPool.ops[mockPool.ops.length - 1].sql, "COMMIT");
  assert.ok(mockPool.ops.some((o) => /INSERT INTO orders/i.test(o.sql) && o.tenantAtExecution === "org-uow-a"));
  assert.ok(
    mockPool.ops.some(
      (o) => /INSERT INTO inventory_movements/i.test(o.sql) && o.tenantAtExecution === "org-uow-a"
    )
  );
  assert.equal(mockPool.clients[0].sessionGucs.size, 0);
  assert.equal(mockPool.clients[0].localGucs.size, 0);
});

test("UnitOfWork.transaction isola organizações consecutivas e concorrentes sem vazamento RLS", async () => {
  const mockPool = new MockTxPool({ maxConnections: 1 });

  const tenants = ["org-a", "org-b", "org-c", "org-d"];
  const outcomes = await Promise.all(
    tenants.map((orgId, index) =>
      UnitOfWork.transaction(
        orgId,
        async (tx) => {
          const r1 = await tx.pgClient!.query("SELECT current_setting('app.current_tenant_id', true)");
          await new Promise((r) => setTimeout(r, (tenants.length - index) * 4));
          const r2 = await tx.pgClient!.query("SELECT current_setting('app.current_tenant_id', true)");
          return {
            orgId,
            firstTenant: r1.rows[0].tenant_id,
            secondTenant: r2.rows[0].tenant_id,
            c1: r1.rows[0].connection_id,
            c2: r2.rows[0].connection_id,
          };
        },
        { pool: mockPool }
      )
    )
  );

  assert.equal(mockPool.clients.length, 1, "Pool max=1 deve reutilizar a mesma conexão sequencialmente");
  for (const out of outcomes) {
    assert.equal(out.firstTenant, out.orgId);
    assert.equal(out.secondTenant, out.orgId);
    assert.equal(out.c1, out.c2);
  }
  assert.equal(mockPool.clients[0].inTransaction, false);
  assert.equal(mockPool.clients[0].sessionGucs.size, 0);
  assert.equal(mockPool.clients[0].localGucs.size, 0);
});

test("UnitOfWork.transaction bloqueia divergência cross-tenant e executa rollback mantendo erro original", async () => {
  // Bloqueio quando contexto ativo pertence a outra organização (não super-admin)
  const mockPool = new MockTxPool({ maxConnections: 1 });
  await assert.rejects(
    () =>
      TenantContext.run({ tenantId: "org-x", isSuperAdmin: false }, () =>
        UnitOfWork.transaction("org-y", async () => "blocked", { pool: mockPool })
      ),
    (err: unknown) => err instanceof RlsContextError && err.code === "RLS_TENANT_MISMATCH"
  );
  assert.equal(mockPool.clients.length, 0, "Não deve nem abrir conexão do pool quando tenant diverge");

  // Bloqueio se registro staged pertencer a outra organização
  await assert.rejects(
    () =>
      UnitOfWork.transaction(
        "org-a",
        async (tx) => {
          tx.stagedOrders.set("ord-cross", {
            id: "ord-cross",
            organizationId: "org-b",
            orderNumber: "PED-CROSS",
            customerId: "c1",
            customerSnapshot: {},
            status: "PAID",
            shippingAddress: {},
            subtotalAmount: 10,
            discountAmount: 0,
            shippingAmount: 0,
            totalAmount: 10,
          });
        },
        { pool: mockPool }
      ),
    (err: unknown) => err instanceof RlsContextError && err.code === "RLS_TENANT_MISMATCH"
  );
  assert.equal(mockPool.ops[mockPool.ops.length - 1].sql, "ROLLBACK");
  assert.equal(mockPool.clients[0].localGucs.size, 0);

  // Preserva erro original mesmo se ROLLBACK falhar e destrói conexão
  const failRollbackPool = new MockTxPool({ maxConnections: 1, failRollback: true });
  await assert.rejects(
    () =>
      UnitOfWork.transaction(
        "org-err",
        async () => {
          throw new Error("FALHA_APLICACAO_UOW");
        },
        { pool: failRollbackPool }
      ),
    (err: Error) => err.message === "FALHA_APLICACAO_UOW"
  );
  assert.equal(failRollbackPool.clients[0].destroyed, true);
});
