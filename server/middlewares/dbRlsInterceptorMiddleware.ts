import { Response, NextFunction } from "express";
import pg from "pg";
import { AuthenticatedRequest } from "./authMiddleware";
import { TenantContext } from "../db/tenantContext";
import { executeWithTenantRlsContext, query, RlsContextError } from "../db/postgres";

/**
 * Middleware e Interceptor de Banco de Dados para RLS (Row Level Security).
 *
 * Anexa helpers transacionais com resolução tardia do contexto ativo (AsyncLocalStorage / req)
 * delegando exclusivamente para executeWithTenantRlsContext e query() (set_config(..., true)),
 * falhando de forma fechada quando nenhum contexto de tenant ou super admin estiver ativo.
 */
export async function dbRlsInterceptorMiddleware(
  req: AuthenticatedRequest,
  _res: Response,
  next: NextFunction
) {
  const resolveRlsScope = () => {
    const context = TenantContext.get();
    const tenantId = context?.tenantId ?? req.organizationId ?? "";
    const isSuperAdmin = Boolean(context?.isSuperAdmin || req.user?.isPlatformSuperAdmin);
    if (!tenantId && !isSuperAdmin) {
      throw new RlsContextError(
        "Nenhum contexto de tenant ou super admin disponível para execução RLS.",
        "RLS_TENANT_REQUIRED"
      );
    }
    return { tenantId, isSuperAdmin };
  };

  if (!req.withTenantDb) {
    req.withTenantDb = async <T>(
      callback: (client: pg.PoolClient) => Promise<T>
    ): Promise<T> => {
      const { tenantId, isSuperAdmin } = resolveRlsScope();
      return await executeWithTenantRlsContext(tenantId, callback, isSuperAdmin);
    };
  }

  if (!req.executeWithRls) {
    req.executeWithRls = req.withTenantDb;
  }

  if (!req.scopedQuery) {
    req.scopedQuery = async <T extends pg.QueryResultRow = any>(
      sql: string,
      params?: any[]
    ): Promise<pg.QueryResult<T>> => {
      const { tenantId, isSuperAdmin } = resolveRlsScope();
      return await query<T>(sql, params, {
        context: { tenantId, isSuperAdmin },
      });
    };
  }

  if (!req.db) {
    req.db = {
      query: <T extends pg.QueryResultRow = any>(sql: string, params?: any[]) =>
        req.scopedQuery!<T>(sql, params),
      withTransaction: <T>(callback: (client: pg.PoolClient) => Promise<T>) =>
        req.withTenantDb!<T>(callback),
    };
  }

  next();
}

export { tenantRlsMiddleware } from "./tenantRlsMiddleware";

