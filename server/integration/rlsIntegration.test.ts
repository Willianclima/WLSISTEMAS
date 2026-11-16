import test, { after, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { interceptClientWithRls, PgPoolClientLike, PgPoolLike } from "../db/postgres";
import { TenantContext } from "../db/tenantContext";
import { JwtService } from "../services/jwtService";
import { authMiddleware, AuthenticatedRequest } from "../middlewares/authMiddleware";
import { jwtTenantRlsMiddleware } from "../middlewares/jwtTenantRlsMiddleware";
import { tenantRlsMiddleware } from "../middlewares/tenantRlsMiddleware";
import { dbRlsInterceptorMiddleware } from "../middlewares/dbRlsInterceptorMiddleware";
import { AuthService } from "../services/authService";
import { ProductService } from "../modules/products/product.service";
import { productRepo } from "../modules/products/product.repository";
import { ConsignmentController } from "../modules/consignments/consignment.controller";
import { OrderService } from "../modules/orders/order.service";
import { InventoryConcurrencyService } from "../modules/inventory/inventoryConcurrency.service";
import { ReservationExpiryWorker } from "../modules/inventory/reservationExpiryWorker";
import { IdempotencyService } from "../services/idempotency.service";

interface RecordedSqlOp {
  connectionId: string;
  sql: string;
  params: any[];
  inTransaction: boolean;
  tenantAtExecution: string | null;
  isSuperAdminAtExecution: string | null;
}

type QueryResolver = (
  sql: string,
  params: any[],
  state: {
    connectionId: string;
    inTransaction: boolean;
    localGucs: Map<string, string>;
  }
) => { rows: any[]; rowCount?: number } | undefined;

class IntegrationMockClient implements PgPoolClientLike {
  readonly connectionId: string;
  inTransaction = false;
  localGucs = new Map<string, string>();
  sessionGucs = new Map<string, string>();
  destroyed = false;

  constructor(
    connectionId: string,
    private readonly ops: RecordedSqlOp[],
    private readonly resolverRef: () => QueryResolver | undefined,
    private readonly onRelease: (client: IntegrationMockClient, destroy?: boolean | Error) => void
  ) {
    this.connectionId = connectionId;
  }

  async query<T extends pg.QueryResultRow = any>(
    text: string | pg.QueryConfig<any[]>,
    values: any[] = []
  ): Promise<pg.QueryResult<T>> {
    const sql = (typeof text === "string" ? text : text.text).trim();
    const params = typeof text === "string" ? values : text.values || [];

    // Hard fail-fast assertions against dangerous session-wide or interpolated GUC statements
    assert.equal(
      /set_config\([^)]*,\s*false\s*\)/i.test(sql),
      false,
      `Proibido usar set_config(..., false): ${sql}`
    );
    assert.equal(
      /\bSET\s+LOCAL\s+app\./i.test(sql),
      false,
      `Proibido usar SET LOCAL interpolado: ${sql}`
    );

    if (/^BEGIN\b/i.test(sql)) {
      this.inTransaction = true;
      this.localGucs.clear();
    } else if (/^COMMIT\b/i.test(sql)) {
      this.inTransaction = false;
      this.localGucs.clear();
    } else if (/^ROLLBACK\b/i.test(sql)) {
      this.inTransaction = false;
      this.localGucs.clear();
    } else if (/set_config\(\s*'app\.current_tenant_id'/i.test(sql)) {
      assert.equal(this.inTransaction, true, `set_config deve executar dentro de transação: ${sql}`);
      this.localGucs.set("app.current_tenant_id", String(params[0] ?? ""));
      if (params.length > 1) {
        this.localGucs.set("app.is_super_admin", String(params[1] ?? "false"));
      }
    }

    const activeTenant = this.localGucs.get("app.current_tenant_id") ?? null;
    const activeAdmin = this.localGucs.get("app.is_super_admin") ?? null;

    this.ops.push({
      connectionId: this.connectionId,
      sql,
      params: [...params],
      inTransaction: this.inTransaction,
      tenantAtExecution: activeTenant,
      isSuperAdminAtExecution: activeAdmin,
    });

    const resolver = this.resolverRef();
    const custom = resolver
      ? resolver(sql, params, {
          connectionId: this.connectionId,
          inTransaction: this.inTransaction,
          localGucs: this.localGucs,
        })
      : undefined;

    if (custom) {
      return {
        command: "SELECT",
        rowCount: custom.rowCount ?? custom.rows.length,
        oid: 0,
        fields: [],
        rows: custom.rows as T[],
      };
    }

    return {
      command: "SELECT",
      rowCount: 0,
      oid: 0,
      fields: [],
      rows: [] as T[],
    };
  }

  release(destroy?: boolean | Error): void {
    if (destroy) {
      this.destroyed = true;
    }
    this.onRelease(this, destroy);
  }
}

class IntegrationMockPool implements PgPoolLike {
  readonly ops: RecordedSqlOp[] = [];
  readonly clients: IntegrationMockClient[] = [];
  private readonly idle: IntegrationMockClient[] = [];
  private seq = 0;
  private resolver?: QueryResolver;

  setResolver(resolver: QueryResolver | undefined) {
    this.resolver = resolver;
  }

  resetOps() {
    this.ops.length = 0;
  }

  async connect(): Promise<PgPoolClientLike> {
    if (this.idle.length > 0) {
      const reused = this.idle.pop()!;
      return interceptClientWithRls(reused);
    }
    this.seq += 1;
    const raw = new IntegrationMockClient(
      `int-conn-${this.seq}`,
      this.ops,
      () => this.resolver,
      (c, destroy) => {
        if (destroy || c.destroyed) return;
        this.idle.push(c);
      }
    );
    this.clients.push(raw);
    return interceptClientWithRls(raw);
  }
}

function createMockRes() {
  const res: any = {
    statusCode: 200,
    body: undefined as any,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: any) {
      this.body = payload;
      return this;
    },
  };
  return res;
}

function extractTxGroups(ops: RecordedSqlOp[]): Array<{
  connectionId: string;
  ops: RecordedSqlOp[];
  committed: boolean;
  rolledBack: boolean;
}> {
  const groups: Array<{
    connectionId: string;
    ops: RecordedSqlOp[];
    committed: boolean;
    rolledBack: boolean;
  }> = [];
  const openByConn = new Map<string, RecordedSqlOp[]>();

  for (const op of ops) {
    if (/^BEGIN\b/i.test(op.sql)) {
      openByConn.set(op.connectionId, [op]);
      continue;
    }
    const current = openByConn.get(op.connectionId);
    if (current) {
      current.push(op);
      if (/^COMMIT\b/i.test(op.sql)) {
        groups.push({
          connectionId: op.connectionId,
          ops: current,
          committed: true,
          rolledBack: false,
        });
        openByConn.delete(op.connectionId);
      } else if (/^ROLLBACK\b/i.test(op.sql)) {
        groups.push({
          connectionId: op.connectionId,
          ops: current,
          committed: false,
          rolledBack: true,
        });
        openByConn.delete(op.connectionId);
      }
    }
  }
  return groups;
}

let originalPool: pg.Pool | undefined;
let mockPool: IntegrationMockPool;

const TENANT_A = "org-tenant-a";
const TENANT_B = "org-tenant-b";
const USER_A = "usr-owner-a";
const USER_SUPER = "usr-super-admin";

const ORG_A_ROW = {
  id: TENANT_A,
  name: "Joalheria Tenant A",
  slug: "tenant-a",
  document: "11.111.111/0001-11",
  segment: "SEMIJOIAS",
  city: "Limeira",
  state: "SP",
  contact_email: "dona@tenanta.com",
  contact_whatsapp: "19999990001",
  custom_domain: null,
  custom_domain_status: "NOT_CONFIGURED",
  status: "ACTIVE",
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
};

const ORG_B_ROW = {
  id: TENANT_B,
  name: "Joalheria Tenant B",
  slug: "tenant-b",
  document: "22.222.222/0001-22",
  segment: "SEMIJOIAS",
  city: "Campinas",
  state: "SP",
  contact_email: "dona@tenantb.com",
  contact_whatsapp: "19999990002",
  custom_domain: null,
  custom_domain_status: "NOT_CONFIGURED",
  status: "ACTIVE",
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
};

const USER_A_ROW = {
  id: USER_A,
  name: "Maria Tenant A",
  email: "maria@tenanta.com",
  password_hash: "$2a$12$dummy",
  is_platform_super_admin: false,
  status: "ACTIVE",
  created_at: "2026-01-01T00:00:00.000Z",
};

const USER_SUPER_ROW = {
  id: USER_SUPER,
  name: "Super Admin",
  email: "admin@aura.com",
  password_hash: "$2a$12$dummy",
  is_platform_super_admin: true,
  status: "ACTIVE",
  created_at: "2026-01-01T00:00:00.000Z",
};

before(() => {
  originalPool = global._auraPgPool;
  mockPool = new IntegrationMockPool();
  global._auraPgPool = mockPool as unknown as pg.Pool;
});

after(() => {
  global._auraPgPool = originalPool;
});

beforeEach(() => {
  mockPool.resetOps();
  mockPool.setResolver(undefined);
});

test("1. Middlewares RLS: authMiddleware, jwtTenantRlsMiddleware, tenantRlsMiddleware e dbRlsInterceptorMiddleware aplicam set_config(..., true) e bloqueiam spoofing", async () => {
  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");
    const isAdmin = state.localGucs.get("app.is_super_admin") === "true";

    if (/FROM users WHERE id = \$1/i.test(sql)) {
      if (params[0] === USER_A) return { rows: [USER_A_ROW] };
      if (params[0] === USER_SUPER) return { rows: [USER_SUPER_ROW] };
    }
    if (/FROM organization_members WHERE user_id = \$1/i.test(sql)) {
      if (params[0] === USER_A) {
        return {
          rows: [
            {
              id: "mem-a",
              organization_id: TENANT_A,
              user_id: USER_A,
              role: "OWNER",
              custom_permissions: ["*"],
              status: "ACTIVE",
              created_at: "2026-01-01T00:00:00.000Z",
            },
          ],
        };
      }
      return { rows: [] };
    }
    if (/FROM organization_members WHERE organization_id = \$1 AND user_id = \$2/i.test(sql)) {
      if (params[0] === TENANT_A && params[1] === USER_A) {
        return {
          rows: [
            {
              id: "mem-a",
              organization_id: TENANT_A,
              user_id: USER_A,
              role: "OWNER",
              custom_permissions: ["*"],
              status: "ACTIVE",
              created_at: "2026-01-01T00:00:00.000Z",
            },
          ],
        };
      }
      return { rows: [] };
    }
    if (/FROM organizations WHERE id = \$1/i.test(sql)) {
      if (params[0] === TENANT_A) return { rows: [ORG_A_ROW] };
      if (params[0] === TENANT_B) return { rows: [ORG_B_ROW] };
    }
    if (/FROM products WHERE organization_id = \$1/i.test(sql)) {
      // Simulate strict 007 RLS enforcement
      if (activeTenant === TENANT_A || (isAdmin && activeTenant === TENANT_A)) {
        return { rows: [{ id: "prod-a-1", organization_id: TENANT_A }] };
      }
      return { rows: [] };
    }
    if (/INSERT INTO audit_logs/i.test(sql)) {
      assert.ok(activeTenant || isAdmin, "audit_logs deve ter contexto RLS válido");
      return { rows: [{ id: params[0] }], rowCount: 1 };
    }
    return { rows: [] };
  });

  const userAToken = JwtService.sign({
    sub: USER_A,
    userId: USER_A,
    email: USER_A_ROW.email,
    organizationId: TENANT_A,
    tenantId: TENANT_A,
    role: "OWNER",
  });

  // 1a. authMiddleware happy path + req.scopedQuery / req.withTenantDb inside AsyncLocalStorage
  const req1: any = {
    headers: { authorization: `Bearer ${userAToken}` },
    query: {},
    ip: "127.0.0.1",
    method: "GET",
  };
  const res1 = createMockRes();
  let next1Called = false;
  let scopedRows: any[] = [];

  await authMiddleware(req1 as AuthenticatedRequest, res1, () => {
    next1Called = true;
    // Executes inside TenantContext.run established by authMiddleware
  });
  assert.equal(next1Called, true);
  assert.equal(req1.organizationId, TENANT_A);

  const queryRes = await req1.scopedQuery("SELECT id FROM products WHERE organization_id = $1", [TENANT_A]);
  scopedRows = queryRes.rows;
  assert.equal(scopedRows.length, 1);

  const productOps = mockPool.ops.filter((op) => /FROM products/i.test(op.sql));
  assert.equal(productOps.length, 1);
  assert.equal(productOps[0].tenantAtExecution, TENANT_A);
  assert.equal(productOps[0].isSuperAdminAtExecution, "false");
  assert.equal(productOps[0].inTransaction, true);

  // 1b. Cross-tenant spoofing blocked (403) on authMiddleware
  const spoofReq: any = {
    headers: { authorization: `Bearer ${userAToken}`, "x-tenant-id": TENANT_B },
    query: {},
    ip: "127.0.0.1",
    method: "GET",
  };
  const spoofRes = createMockRes();
  let spoofNextCalled = false;
  await authMiddleware(spoofReq as AuthenticatedRequest, spoofRes, () => {
    spoofNextCalled = true;
  });
  assert.equal(spoofNextCalled, false);
  assert.equal(spoofRes.statusCode, 403);
  assert.equal(spoofRes.body.code, "UNAUTHORIZED_TENANT_ACCESS");

  // 1c. jwtTenantRlsMiddleware blocks cross-tenant spoofing (403) and handles valid support session
  const jwtSpoofReq: any = {
    headers: { authorization: `Bearer ${userAToken}`, "x-tenant-id": TENANT_B },
    query: {},
    ip: "127.0.0.1",
    method: "GET",
  };
  const jwtSpoofRes = createMockRes();
  await jwtTenantRlsMiddleware(jwtSpoofReq as AuthenticatedRequest, jwtSpoofRes, () => {});
  assert.equal(jwtSpoofRes.statusCode, 403);
  assert.equal(jwtSpoofRes.body.code, "UNAUTHORIZED_TENANT_ACCESS");

  const supportToken = JwtService.sign({
    sub: USER_SUPER,
    userId: USER_SUPER,
    email: USER_SUPER_ROW.email,
    organizationId: TENANT_B,
    tenantId: TENANT_B,
    role: "OWNER",
    isPlatformSuperAdmin: true,
    isSupportSession: true,
    supportReason: "Auditoria técnica controlada",
    supportScope: "READ_ONLY",
  });
  const jwtSupportReq: any = {
    headers: { authorization: `Bearer ${supportToken}` },
    query: {},
    ip: "127.0.0.1",
    method: "POST",
  };
  const jwtSupportRes = createMockRes();
  await jwtTenantRlsMiddleware(jwtSupportReq as AuthenticatedRequest, jwtSupportRes, () => {});
  assert.equal(jwtSupportRes.statusCode, 403);
  assert.equal(jwtSupportRes.body.code, "SUPPORT_READ_ONLY_VIOLATION");

  // 1d. tenantRlsMiddleware attaches scoped helpers & enforces membership
  const trlsReq: any = {
    user: USER_A_ROW,
    userRole: "OWNER",
    organizationId: TENANT_A,
    headers: {},
    query: {},
    ip: "127.0.0.1",
  };
  const trlsRes = createMockRes();
  let trlsNextCalled = false;
  await tenantRlsMiddleware(trlsReq as AuthenticatedRequest, trlsRes, () => {
    trlsNextCalled = true;
  });
  assert.equal(trlsNextCalled, true);
  assert.equal(trlsReq.organizationId, TENANT_A);

  // 1e. dbRlsInterceptorMiddleware fails closed when no context exists and uses late-bound context when present
  const bareReq: any = { headers: {}, query: {} };
  await dbRlsInterceptorMiddleware(bareReq as AuthenticatedRequest, createMockRes(), () => {});
  await assert.rejects(
    () => bareReq.scopedQuery("SELECT 1"),
    (err: any) => err?.code === "RLS_TENANT_REQUIRED"
  );
  await TenantContext.run({ tenantId: TENANT_A, isSuperAdmin: false }, async () => {
    const okRes = await bareReq.scopedQuery("SELECT id FROM products WHERE organization_id = $1", [TENANT_A]);
    assert.equal(okRes.rows.length, 1);
  });
});

test("2. ProductService & ProductRepository: listPublicProducts falha em slug desconhecido e addMedia/deleteMedia executam em conexão física única", async () => {
  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");

    if (/FROM organizations WHERE id = \$1/i.test(sql) || /FROM organizations WHERE slug = \$1/i.test(sql)) {
      return { rows: [] };
    }
    if (/FROM product_media WHERE organization_id = \$1 AND id = \$2/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: params[1],
            organization_id: TENANT_A,
            product_id: "prod-1",
            storage_key: "k1",
            url: "https://cdn.example.com/1.webp",
            cdn_url: "https://cdn.example.com/1.webp",
            media_type: "IMAGE",
            mime_type: "image/webp",
            file_size_bytes: 0,
            etag: null,
            is_primary: true,
            sort_order: 0,
            title: null,
            alt_text: null,
            created_at: new Date(),
            updated_at: new Date(),
          },
        ],
      };
    }
    if (/FROM product_media WHERE organization_id = \$1 AND product_id = \$2/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [] };
    }
    if (/DELETE FROM product_media WHERE organization_id = \$1 AND id = \$2/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [], rowCount: 1 };
    }
    if (/INSERT INTO product_media/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: params[0],
            organization_id: params[1],
            product_id: params[2],
            storage_key: params[3],
            url: params[4],
            cdn_url: params[5],
            media_type: params[6],
            mime_type: params[7],
            file_size_bytes: params[8],
            etag: params[9],
            is_primary: params[10],
            sort_order: params[11],
            title: params[12],
            alt_text: params[13],
            created_at: new Date(),
            updated_at: new Date(),
          },
        ],
        rowCount: 1,
      };
    }
    if (/UPDATE products SET image_url/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      assert.match(sql, /organization_id = \$2/i);
      return { rows: [], rowCount: 1 };
    }
    if (/DELETE FROM product_media WHERE organization_id = \$1 AND product_id = \$2 AND id = \$3/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [], rowCount: 1 };
    }
    return { rows: [] };
  });

  await assert.rejects(
    () => ProductService.listPublicProducts("loja-inexistente"),
    /não encontrado/i
  );

  mockPool.resetOps();
  const added = await productRepo.addMedia(TENANT_A, "prod-1", {
    storageKey: "k1",
    url: "https://cdn.example.com/1.webp",
    isPrimary: true,
  });
  assert.equal(added.organizationId, TENANT_A);

  const txGroups = extractTxGroups(mockPool.ops);
  assert.equal(txGroups.length, 1);
  assert.equal(txGroups[0].committed, true);
  const distinctConns = new Set(txGroups[0].ops.map((o) => o.connectionId));
  assert.equal(distinctConns.size, 1);
  assert.equal(
    txGroups[0].ops.some((o) => /INSERT INTO product_media/i.test(o.sql)),
    true
  );
  assert.equal(
    txGroups[0].ops.some((o) => /UPDATE products SET image_url/i.test(o.sql)),
    true
  );

  mockPool.resetOps();
  const deleted = await productRepo.deleteMedia(TENANT_A, "prod-1", added.id);
  assert.equal(deleted, true);
  const delGroups = extractTxGroups(mockPool.ops);
  assert.equal(delGroups.length, 1);
  assert.equal(delGroups[0].committed, true);
  assert.equal(new Set(delGroups[0].ops.map((o) => o.connectionId)).size, 1);
});

test("3. ConsignmentController & ConsignmentRepository: isolamento por organization_id bloqueia acesso cross-tenant (404)", async () => {
  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");
    if (/FROM consignments WHERE organization_id = \$1 AND id = \$2/i.test(sql)) {
      // Consignment belongs to TENANT_A only; TENANT_B sees nothing
      if (params[0] === TENANT_A && params[1] === "csg-tenant-a" && activeTenant === TENANT_A) {
        return {
          rows: [
            {
              id: "csg-tenant-a",
              organization_id: TENANT_A,
              code: "CSG-0001",
              reseller_name: "Ana",
              status: "OPEN",
              commission_rate: 30,
              total_pieces: 5,
              total_value: 500,
              sold_value: 0,
              reseller_commission: 0,
              net_store_amount: 0,
              items: [],
              dispatched_at: new Date(),
              settlement_due_at: new Date(),
              created_at: new Date(),
              updated_at: new Date(),
            },
          ],
        };
      }
      return { rows: [] };
    }
    return { rows: [] };
  });

  // Cross-tenant attempt from TENANT_B for TENANT_A's consignment
  const crossReq: any = {
    organizationId: TENANT_B,
    params: { id: "csg-tenant-a" },
  };
  const crossRes = createMockRes();
  await TenantContext.run({ tenantId: TENANT_B }, async () => {
    await ConsignmentController.getById(crossReq as AuthenticatedRequest, crossRes);
  });
  assert.equal(crossRes.statusCode, 404);
  assert.equal(
    mockPool.ops.some((op) => /FROM consignments WHERE organization_id = \$1 AND id = \$2/i.test(op.sql)),
    true
  );

  // Legitimate attempt from TENANT_A succeeds
  const ownReq: any = {
    organizationId: TENANT_A,
    params: { id: "csg-tenant-a" },
  };
  const ownRes = createMockRes();
  await TenantContext.run({ tenantId: TENANT_A }, async () => {
    await ConsignmentController.getById(ownReq as AuthenticatedRequest, ownRes);
  });
  assert.equal(ownRes.statusCode, 200);
  assert.equal(ownRes.body.consignment.organizationId, TENANT_A);
});

test("4. AuthService: registerTrial e setupFirstAdmin vinculam set_config(..., true) antes de tabelas tenant e usam conexão única", async () => {
  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");
    const isAdmin = state.localGucs.get("app.is_super_admin");

    if (/FROM users WHERE email = \$1/i.test(sql)) return { rows: [] };
    if (/SELECT count\(\*\) as count FROM users/i.test(sql)) return { rows: [{ count: "0" }] };
    if (/SELECT id FROM users WHERE is_platform_super_admin = true/i.test(sql)) return { rows: [] };
    if (/SELECT \* FROM organizations LIMIT 1/i.test(sql)) return { rows: [] };
    if (/FROM plans WHERE id = \$1/i.test(sql)) {
      return {
        rows: [
          {
            id: params[0],
            name: params[0],
            price_monthly_brl: 0,
            trial_days: 30,
            max_users: 5,
            max_products: 100,
            max_resellers: 10,
            allowed_modules: ["CATALOG", "INVENTORY", "ORDERS"],
            description: "Plan",
          },
        ],
      };
    }
    if (/INSERT INTO organizations/i.test(sql)) {
      return {
        rows: [
          {
            id: params[0],
            name: params[1],
            slug: params[2],
            document: params[3],
            segment: params[4],
            city: params[5],
            state: params[6],
            contact_email: params[7],
            contact_whatsapp: params[8],
            status: "ACTIVE",
            created_at: new Date(),
            updated_at: new Date(),
          },
        ],
        rowCount: 1,
      };
    }
    if (/INSERT INTO users/i.test(sql)) {
      return {
        rows: [
          {
            id: params[0],
            name: params[1],
            email: params[2],
            password_hash: params[3],
            phone: params[4],
            is_platform_super_admin: true,
            status: "ACTIVE",
            created_at: new Date(),
            last_login_at: new Date(),
          },
        ],
        rowCount: 1,
      };
    }
    if (/INSERT INTO (organization_members|subscriptions|organization_modules|inventory_locations)/i.test(sql)) {
      assert.ok(activeTenant && activeTenant.length > 0, `Contexto tenant obrigatório antes de ${sql}`);
      if (/INSERT INTO organization_members/i.test(sql)) {
        return {
          rows: [
            {
              id: params[0],
              organization_id: params[1],
              user_id: params[2],
              role: "OWNER",
              custom_permissions: ["*"],
              status: "ACTIVE",
              created_at: new Date(),
            },
          ],
          rowCount: 1,
        };
      }
      if (/INSERT INTO subscriptions/i.test(sql)) {
        return {
          rows: [
            {
              id: params[0],
              organization_id: params[1],
              plan_id: "ENTERPRISE",
              status: "ACTIVE",
              trial_started_at: new Date(),
              trial_ends_at: new Date(),
              current_period_start: new Date(),
              current_period_end: new Date(),
              payment_method: "MANUAL_TRIAL",
              auto_renew: true,
              created_at: new Date(),
              updated_at: new Date(),
            },
          ],
          rowCount: 1,
        };
      }
      return { rows: [], rowCount: 1 };
    }
    if (/SELECT \* FROM subscriptions WHERE organization_id = \$1/i.test(sql)) {
      assert.ok(activeTenant && isAdmin === "true");
      return { rows: [] };
    }
    if (/FROM organization_members WHERE user_id = \$1/i.test(sql)) {
      return { rows: [] };
    }
    return { rows: [] };
  });

  // 4a. registerTrial
  const trialSession = await AuthService.registerTrial({
    userName: "Carla Teste",
    email: "carla.trial@example.com",
    password: "StrongPassword123!",
    organizationName: "Atelier Carla",
  });
  assert.ok(trialSession.organization.id);

  const trialTxGroups = extractTxGroups(mockPool.ops);
  const mainTrialTx = trialTxGroups.find((g) => g.ops.some((o) => /INSERT INTO subscriptions/i.test(o.sql)));
  assert.ok(mainTrialTx, "Transação principal de registerTrial deve existir");
  assert.equal(mainTrialTx.committed, true);
  assert.equal(new Set(mainTrialTx.ops.map((o) => o.connectionId)).size, 1);
  const setIdx = mainTrialTx.ops.findIndex(
    (o) => /set_config/i.test(o.sql) && o.params[0] === trialSession.organization.id
  );
  const memberIdx = mainTrialTx.ops.findIndex((o) => /INSERT INTO organization_members/i.test(o.sql));
  assert.ok(setIdx >= 0 && memberIdx > setIdx, "set_config deve ocorrer antes de gravar organization_members");

  // 4b. setupFirstAdmin
  mockPool.resetOps();
  const adminSession = await AuthService.setupFirstAdmin({
    name: "Root Master",
    email: "root@aura.com",
    password: "RootStrongPassword!2026",
  });
  assert.equal(adminSession.user.isPlatformSuperAdmin, true);

  const setupTxGroups = extractTxGroups(mockPool.ops);
  const mainSetupTx = setupTxGroups.find((g) => g.ops.some((o) => /pg_advisory_xact_lock/i.test(o.sql)));
  assert.ok(mainSetupTx, "Transação de bootstrap setupFirstAdmin deve existir");
  assert.equal(mainSetupTx.committed, true);
  assert.equal(new Set(mainSetupTx.ops.map((o) => o.connectionId)).size, 1);
  const adminSetIdx = mainSetupTx.ops.findIndex(
    (o) => /set_config/i.test(o.sql) && o.params[0] === adminSession.organization.id && o.params[1] === "true"
  );
  const adminSubIdx = mainSetupTx.ops.findIndex((o) => /INSERT INTO subscriptions/i.test(o.sql));
  assert.ok(adminSetIdx >= 0 && adminSubIdx > adminSetIdx);
});

test("5. OrderService.createOrder: executa pedido, itens, estoque e audit_logs em conexão física única e executa ROLLBACK em erro", async () => {
  let forceOrderInsertFailure = false;

  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");

    if (/FROM organizations WHERE id = \$1/i.test(sql)) {
      return { rows: [ORG_A_ROW] };
    }
    if (/SELECT \* FROM customers/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [] };
    }
    if (/INSERT INTO customers/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [{ id: params[0] }], rowCount: 1 };
    }
    if (/SELECT COUNT\(\*\) as total FROM orders/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [{ total: "0" }] };
    }
    if (/FROM inventory_locations WHERE organization_id = \$1/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: "loc-matriz-a",
            organization_id: TENANT_A,
            name: "Matriz",
            type: "HEADQUARTERS",
            code: "MATRIZ",
            is_active: true,
            created_at: new Date(),
          },
        ],
      };
    }
    if (/FROM products WHERE organization_id = \$1 AND id = \$2/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: "prod-a-1",
            organization_id: TENANT_A,
            sku: "SKU-A-1",
            name: "Anel Ouro 18k",
            category: "ANEIS",
            collection: "Classica",
            material: "Ouro 18k",
            bath: "OURO_18K",
            stones: [],
            price: 350,
            cost_price: 100,
            warranty_months: 12,
            is_customizable: false,
            image_url: "https://example.com/anel.jpg",
            description: "Anel",
            status: "ATIVO",
            created_at: new Date(),
            updated_at: new Date(),
          },
        ],
      };
    }
    if (/FROM inventory_balances/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: "bal-a-1",
            organization_id: TENANT_A,
            product_id: "prod-a-1",
            location_id: "loc-matriz-a",
            on_hand_quantity: 10,
            reserved_quantity: 0,
            available_quantity: 10,
            created_at: new Date(),
            updated_at: new Date(),
          },
        ],
      };
    }
    if (/INSERT INTO orders\b/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      if (forceOrderInsertFailure) {
        throw new Error("Simulated order insert DB failure");
      }
      return { rows: [{ id: params[0] }], rowCount: 1 };
    }
    if (/INSERT INTO audit_logs/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [{ id: params[0] }], rowCount: 1 };
    }
    return { rows: [{ id: params[0] ?? "ok" }], rowCount: 1 };
  });

  // 5a. Success path: single physical connection for UnitOfWork
  const order = await TenantContext.run({ tenantId: TENANT_A, userId: USER_A }, async () => {
    return await OrderService.createOrder(
      TENANT_A,
      {
        channel: "ECOMMERCE",
        customer: { name: "Juliana Cliente", email: "ju@example.com", phone: "11999998888" },
        items: [{ productId: "prod-a-1", locationId: "loc-matriz-a", quantity: 2, unitPrice: 350 }],
        initialStatus: "INVENTORY_RESERVED",
      } as any,
      "Operador Teste",
      USER_A
    );
  });
  assert.equal(order.organizationId, TENANT_A);

  const txGroups = extractTxGroups(mockPool.ops);
  const orderTx = txGroups.find((g) => g.ops.some((o) => /INSERT INTO orders/i.test(o.sql)));
  assert.ok(orderTx, "Transação UnitOfWork de createOrder deve existir");
  assert.equal(orderTx.committed, true);
  assert.equal(new Set(orderTx.ops.map((o) => o.connectionId)).size, 1);
  assert.equal(
    orderTx.ops.some((o) => /INSERT INTO order_items/i.test(o.sql)),
    true
  );
  assert.equal(
    orderTx.ops.some((o) => /INSERT INTO inventory_reservations/i.test(o.sql)),
    true
  );
  assert.equal(
    orderTx.ops.some((o) => /INSERT INTO audit_logs/i.test(o.sql)),
    true
  );

  // 5b. Rollback path when a write inside UnitOfWork fails
  mockPool.resetOps();
  forceOrderInsertFailure = true;
  await assert.rejects(
    () =>
      TenantContext.run({ tenantId: TENANT_A, userId: USER_A }, () =>
        OrderService.createOrder(
          TENANT_A,
          {
            channel: "ECOMMERCE",
            customer: { name: "Juliana Rollback", email: "rb@example.com", phone: "11999997777" },
            items: [{ productId: "prod-a-1", locationId: "loc-matriz-a", quantity: 1, unitPrice: 350 }],
          } as any,
          "Operador Teste",
          USER_A
        )
      )
  );
  const failedTxGroups = extractTxGroups(mockPool.ops);
  const rolledBackTx = failedTxGroups.find((g) => g.rolledBack);
  assert.ok(rolledBackTx, "Transação com erro deve executar ROLLBACK limpo na mesma conexão");
  assert.equal(new Set(rolledBackTx.ops.map((o) => o.connectionId)).size, 1);
});

test("6. InventoryConcurrencyService & ReservationExpiryWorker: FOR UPDATE, saldo, reserva e auditoria na mesma conexão física", async () => {
  const resId = "res-exp-1";
  const balRow = {
    id: "bal-a-1",
    organization_id: TENANT_A,
    product_id: "prod-a-1",
    location_id: "loc-matriz-a",
    on_hand_quantity: 5,
    reserved_quantity: 2,
    available_quantity: 3,
    created_at: new Date(),
    updated_at: new Date(),
  };

  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");
    const isAdmin = state.localGucs.get("app.is_super_admin");

    if (/FROM organizations/i.test(sql) && !/WHERE/i.test(sql)) {
      assert.equal(isAdmin, "true");
      return { rows: [ORG_A_ROW] };
    }
    if (/FROM inventory_balances/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return { rows: [balRow] };
    }
    if (/FROM inventory_reservations WHERE organization_id = \$1 AND id = \$2/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: resId,
            organization_id: TENANT_A,
            product_id: "prod-a-1",
            location_id: "loc-matriz-a",
            quantity: 2,
            reference_type: "ORDER",
            reference_id: "ord-1",
            status: "ACTIVE",
            expires_at: new Date(Date.now() - 60_000).toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ],
      };
    }
    if (/FROM inventory_reservations WHERE organization_id = \$1/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: resId,
            organization_id: TENANT_A,
            product_id: "prod-a-1",
            location_id: "loc-matriz-a",
            quantity: 2,
            reference_type: "ORDER",
            reference_id: "ord-1",
            status: "ACTIVE",
            expires_at: new Date(Date.now() - 60_000).toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ],
      };
    }
    if (/UPDATE inventory_reservations SET/i.test(sql)) {
      assert.equal(activeTenant, TENANT_A);
      return {
        rows: [
          {
            id: resId,
            organization_id: TENANT_A,
            product_id: "prod-a-1",
            location_id: "loc-matriz-a",
            quantity: 2,
            reference_type: "ORDER",
            reference_id: "ord-1",
            status: params[2] || "CONFIRMED",
            expires_at: new Date(Date.now() - 60_000).toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ],
        rowCount: 1,
      };
    }
    return { rows: [{ ...balRow, id: params[0] ?? "ok" }], rowCount: 1 };
  });

  // 6a. InventoryConcurrencyService.createReservation
  const createdRes = await InventoryConcurrencyService.createReservation(TENANT_A, {
    productId: "prod-a-1",
    locationId: "loc-matriz-a",
    quantity: 1,
    referenceType: "ORDER",
    referenceId: "ord-new-1",
    operatorName: "Teste",
  });
  assert.equal(createdRes.organizationId, TENANT_A);

  const resTx = extractTxGroups(mockPool.ops).find((g) =>
    g.ops.some((o) => /INSERT INTO inventory_reservations/i.test(o.sql))
  );
  assert.ok(resTx);
  assert.equal(resTx.committed, true);
  assert.equal(new Set(resTx.ops.map((o) => o.connectionId)).size, 1);
  assert.equal(
    resTx.ops.some((o) => /FOR UPDATE/i.test(o.sql)),
    true
  );
  assert.equal(
    resTx.ops.some((o) => /INSERT INTO audit_logs/i.test(o.sql)),
    true
  );

  // 6b. InventoryConcurrencyService.confirmReservation
  mockPool.resetOps();
  const confirmed = await InventoryConcurrencyService.confirmReservation(TENANT_A, resId, "PagSeguro");
  assert.equal(confirmed.status, "CONFIRMED");
  const confirmTx = extractTxGroups(mockPool.ops).find((g) =>
    g.ops.some((o) => /INSERT INTO inventory_movements/i.test(o.sql))
  );
  assert.ok(confirmTx);
  assert.equal(confirmTx.committed, true);
  assert.equal(new Set(confirmTx.ops.map((o) => o.connectionId)).size, 1);
  assert.equal(
    confirmTx.ops.some((o) => /FOR UPDATE/i.test(o.sql)),
    true
  );

  // 6c. ReservationExpiryWorker.runSweepCycle
  mockPool.resetOps();
  const worker = ReservationExpiryWorker.getInstance();
  const cycle = await worker.runSweepCycle();
  assert.equal(cycle.organizationsChecked, 1);
  assert.equal(cycle.totalExpired, 1);

  const workerTxGroups = extractTxGroups(mockPool.ops);
  const expireTx = workerTxGroups.find(
    (g) =>
      g.ops.some((o) => /INSERT INTO inventory_reservations/i.test(o.sql)) &&
      g.ops.some((o) => /INSERT INTO audit_logs/i.test(o.sql) && o.params.includes("RESERVATION_TTL_EXPIRED"))
  );
  assert.ok(expireTx);
  assert.equal(expireTx.committed, true);
  assert.equal(new Set(expireTx.ops.map((o) => o.connectionId)).size, 1);
  assert.equal(
    expireTx.ops.some((o) => /FOR UPDATE/i.test(o.sql)),
    true
  );
});

test("7. IdempotencyService.sweepExpired: varredura multi-tenant respeita TenantContext por organização", async () => {
  mockPool.setResolver((sql, params, state) => {
    const activeTenant = state.localGucs.get("app.current_tenant_id");
    const isAdmin = state.localGucs.get("app.is_super_admin");

    if (/SELECT id FROM organizations/i.test(sql)) {
      assert.equal(isAdmin, "true");
      return { rows: [{ id: TENANT_A }, { id: TENANT_B }] };
    }
    if (/DELETE FROM idempotency_keys WHERE organization_id = \$1/i.test(sql)) {
      assert.equal(activeTenant, params[0]);
      return { rows: [], rowCount: 2 };
    }
    return { rows: [] };
  });

  const deletedCount = await IdempotencyService.sweepExpired();
  assert.equal(deletedCount, 4);

  const delOps = mockPool.ops.filter((o) => /DELETE FROM idempotency_keys/i.test(o.sql));
  assert.equal(delOps.length, 2);
  assert.deepEqual(
    delOps.map((o) => o.tenantAtExecution),
    [TENANT_A, TENANT_B]
  );
});
