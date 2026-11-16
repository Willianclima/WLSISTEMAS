import { Response, NextFunction } from "express";
import pg from "pg";
import { AuthenticatedRequest } from "./authMiddleware";
import { JwtService, TenantJwtPayload } from "../services/jwtService";
import { userRepo, orgRepo, memberRepo } from "../repositories";
import { TenantContext } from "../db/tenantContext";
import { executeWithTenantRlsContext, query, RlsContextError, sanitizeTenantId } from "../db/postgres";
import { auditService } from "../services/auditService";
import { UserEntity, OrganizationRole } from "../types/saas";
import { isProduction } from "../config/environment";

/**
 * Middleware Express que:
 * 1. Intercepta todas as requisições autenticadas.
 * 2. Valida o tenant_id proveniente do contexto de identidade do usuário no JWT (Membership).
 * 3. Garante que qualquer tentativa de spoofing via headers ou query seja rejeitada (HTTP 403).
 * 4. Executa o comando SQL 'SET LOCAL app.current_tenant_id = ?' antes da execução de qualquer query,
 *    garantindo o isolamento estrito do Row Level Security (RLS) no kernel do PostgreSQL.
 */
export async function jwtTenantRlsMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const isProd = isProduction();

    // -------------------------------------------------------------------------
    // 1. EXTRAÇÃO DO TOKEN (JWT ou Sessão Assinada)
    // -------------------------------------------------------------------------
    const authHeader = req.headers.authorization || (req.headers["x-session-token"] as string) || (req.query.token as string);
    const tenantHeader = (req.headers["x-tenant-id"] as string) || (req.query.tenantId as string);

    if (!authHeader && !req.user) {
      return res.status(401).json({
        success: false,
        code: "AUTH_TOKEN_REQUIRED",
        error: "Acesso não autorizado: token de autenticação JWT é obrigatório.",
      });
    }

    let tokenPayload: TenantJwtPayload | null = null;
    let userId: string | null = null;
    let tokenTenantId: string | null = null;

    if (authHeader) {
      const rawToken = authHeader.replace(/^Bearer\s+/i, "").trim();

      // Token no formato JWT padrão RFC 7519 (header.payload.signature)
      if (JwtService.isJwt(rawToken)) {
        try {
          tokenPayload = JwtService.verify(rawToken);
          userId = tokenPayload.userId || tokenPayload.sub;
          tokenTenantId = tokenPayload.tenantId || tokenPayload.organizationId;
        } catch (jwtErr: any) {
          return res.status(401).json({
            success: false,
            code: "INVALID_JWT_TOKEN",
            error: `Token JWT inválido ou expirado: ${jwtErr.message}`,
          });
        }
      } else {
        return res.status(401).json({
          success: false,
          code: "JWT_TOKEN_REQUIRED",
          error: "Formato de token não reconhecido ou legado rejeitado. Um token JWT RFC 7519 válido é estritamente obrigatório.",
        });
      }
    }

    // -------------------------------------------------------------------------
    // 2. VALIDAÇÃO DE IDENTIDADE DO USUÁRIO
    // -------------------------------------------------------------------------
    let user: UserEntity | null = null;

    if (userId) {
      user = await userRepo.findById(userId);
    } else if (req.user) {
      user = req.user;
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        code: "AUTH_TOKEN_REQUIRED",
        error: "Acesso não autorizado: token JWT com identidade válida é obrigatório.",
      });
    }

    if (user.status !== "ACTIVE") {
      return res.status(401).json({
        success: false,
        code: "USER_INACTIVE",
        error: "Conta de usuário inativa ou suspensa.",
      });
    }

    req.user = user;
    const isSuperAdmin = Boolean(user.isPlatformSuperAdmin);
    const isSupportSession = Boolean(tokenPayload?.isSupportSession);
    const supportReason = tokenPayload?.supportReason;
    const supportScope = tokenPayload?.supportScope || "FULL_SUPPORT";

    // -------------------------------------------------------------------------
    // 3. VALIDAÇÃO E ENFORCEMENT DO TENANT_ID A PARTIR DO MEMBERSHIP NO JWT
    // -------------------------------------------------------------------------
    // O tenant_id primário é obtido estritamente do contexto de identidade no JWT
    let targetTenantId = tokenTenantId || (req.jwtPayload?.tenantId || req.jwtPayload?.organizationId);

    // Se a requisição contiver cabeçalho 'x-tenant-id' ou 'tenantId', validamos contra tentativa de spoofing
    if (tenantHeader && tenantHeader.trim()) {
      let sanitizedHeaderTenant: string;
      try {
        sanitizedHeaderTenant = sanitizeTenantId(tenantHeader.trim());
      } catch {
        return res.status(400).json({
          success: false,
          code: "INVALID_TENANT_ID",
          error: "Identificador de organização inválido no cabeçalho da requisição.",
        });
      }

      // Se o cabeçalho tentar sobrescrever o tenant do JWT:
      if (targetTenantId && sanitizedHeaderTenant !== targetTenantId) {
        // 1. Verifica se a identidade autenticada possui membership legítimo no tenant solicitado
        const memberships = await memberRepo.listByUser(user.id);
        const hasMembership = memberships.some(
          (m) => m.organizationId === sanitizedHeaderTenant && m.status === "ACTIVE"
        );

        if (hasMembership) {
          targetTenantId = sanitizedHeaderTenant;
        } else if (isSupportSession && tokenPayload?.tenantId === sanitizedHeaderTenant) {
          // Sessão de suporte controlada especificamente autorizada para este tenant
          targetTenantId = sanitizedHeaderTenant;
        } else if (isSuperAdmin) {
          // P0 CONTROLLED SUPPORT: Super Admin NÃO tem passe livre automático.
          // Deve obrigatoriamente iniciar sessão de suporte escopada com motivo e auditoria.
          await TenantContext.run(
            {
              tenantId: sanitizedHeaderTenant,
              userId: user.id,
              userEmail: user.email,
              ipAddress: req.ip || (req.headers["x-forwarded-for"] as string) || "127.0.0.1",
              userAgent: (req.headers["user-agent"] as string) || "Aura Web Client",
              isSuperAdmin: true,
            },
            async () => {
              await auditService.logAction(
                sanitizedHeaderTenant,
                user!.id,
                "SUPER_ADMIN_UNAUTHORIZED_DIRECT_TENANT_ACCESS_BLOCKED",
                "ORGANIZATION",
                sanitizedHeaderTenant,
                req.ip,
                req.headers["user-agent"] as string,
                `Super Admin (${user!.email}) tentou acessar tenant '${sanitizedHeaderTenant}' via cabeçalho direto sem sessão de suporte auditada. Bloqueado.`
              );
            }
          );

          return res.status(403).json({
            success: false,
            code: "CONTROLLED_SUPPORT_SESSION_REQUIRED",
            error: `Acesso negado: Administradores da plataforma devem iniciar uma sessão de suporte técnico controlada com motivo obrigatório e auditoria em PostgreSQL para acessar os dados da organização '${sanitizedHeaderTenant}'.`,
          });
        } else {
          await TenantContext.run(
            {
              tenantId: sanitizedHeaderTenant,
              userId: user.id,
              userEmail: user.email,
              ipAddress: req.ip || (req.headers["x-forwarded-for"] as string) || "127.0.0.1",
              userAgent: (req.headers["user-agent"] as string) || "Aura Web Client",
              isSuperAdmin: false,
            },
            async () => {
              await auditService.logAction(
                sanitizedHeaderTenant,
                user!.id,
                "SECURITY_UNAUTHORIZED_TENANT_ACCESS",
                "RLS_BARRIER",
                targetTenantId || "unknown",
                req.ip,
                req.headers["user-agent"] as string,
                JSON.stringify({
                  jwtTenantId: targetTenantId,
                  attemptedTenantId: sanitizedHeaderTenant,
                  reason: "Spoofing attempt blocked: user has no active membership in target organization",
                })
              );
            }
          );

          return res.status(403).json({
            success: false,
            code: "UNAUTHORIZED_TENANT_ACCESS",
            error: `Acesso não autorizado: a identidade autenticada (${user.email}) não possui membership ativo na organização '${sanitizedHeaderTenant}'. Bloqueado na barreira de Membership.`,
          });
        }
      } else if (!targetTenantId) {
        targetTenantId = sanitizedHeaderTenant;
      }
    }

    // Se ainda não tiver tenant definido, busca o membership ativo padrão do usuário
    if (!targetTenantId) {
      const memberships = await memberRepo.listByUser(user.id);
      const activeMembership = memberships.find((m) => m.status === "ACTIVE");
      if (!activeMembership && !isSupportSession) {
        return res.status(403).json({
          success: false,
          code: "MEMBERSHIP_REQUIRED",
          error: "O usuário não possui membership ativo em nenhuma organização.",
        });
      }
      targetTenantId = activeMembership?.organizationId;
    }

    if (!targetTenantId) {
      return res.status(400).json({
        success: false,
        code: "TENANT_ID_REQUIRED",
        error: "Não foi possível resolver o tenant_id a partir do contexto de Membership do usuário.",
      });
    }

    let validatedTenantId: string;
    try {
      validatedTenantId = sanitizeTenantId(targetTenantId);
    } catch (err) {
      if (err instanceof RlsContextError) {
        return res.status(400).json({
          success: false,
          code: "INVALID_TENANT_ID",
          error: err.message,
        });
      }
      throw err;
    }

    // Validação estrita do Membership da identidade no banco de dados
    const membership = await memberRepo.findByOrgAndUser(validatedTenantId, user.id);
    if (!membership && !isSupportSession) {
      if (isSuperAdmin) {
        return res.status(403).json({
          success: false,
          code: "CONTROLLED_SUPPORT_SESSION_REQUIRED",
          error: `Acesso negado: Administradores da plataforma devem iniciar uma sessão de suporte técnico controlada com motivo obrigatório para acessar o tenant '${validatedTenantId}'.`,
        });
      }
      return res.status(403).json({
        success: false,
        code: "MEMBERSHIP_NOT_FOUND",
        error: `Acesso negado: membership não encontrado para o usuário na organização '${validatedTenantId}'.`,
      });
    }

    if (membership && membership.status !== "ACTIVE" && !isSupportSession) {
      return res.status(403).json({
        success: false,
        code: "MEMBERSHIP_SUSPENDED",
        error: "O seu acesso a esta organização está inativo ou suspenso.",
      });
    }

    // Se for sessão de suporte em modo SOMENTE LEITURA, bloquear operações de escrita
    if (isSupportSession && supportScope === "READ_ONLY") {
      const mutationMethods = ["POST", "PUT", "PATCH", "DELETE"];
      if (mutationMethods.includes(req.method.toUpperCase())) {
        return res.status(403).json({
          success: false,
          code: "SUPPORT_READ_ONLY_VIOLATION",
          error: "Sessão de suporte técnico sob escopo SOMENTE LEITURA. Operações de modificação de dados não são permitidas.",
        });
      }
    }

    const organization = await orgRepo.findById(validatedTenantId);
    if (!organization || (isProd && organization.status !== "ACTIVE")) {
      return res.status(403).json({
        success: false,
        code: "ORGANIZATION_INACTIVE",
        error: "Organização vinculada não encontrada ou inativa.",
      });
    }

    const effectiveRole: OrganizationRole = isSupportSession
      ? (supportScope === "READ_ONLY" ? "VENDEDOR" : "OWNER")
      : (membership?.role || "VENDEDOR");

    // -------------------------------------------------------------------------
    // 4. ATRIBUIÇÃO AO OBJETO REQUEST
    // -------------------------------------------------------------------------
    req.user = user;
    req.tenant = organization;
    req.organizationId = validatedTenantId;
    req.userRole = effectiveRole;
    req.jwtPayload = tokenPayload || {
      sub: user.id,
      userId: user.id,
      email: user.email,
      tenantId: validatedTenantId,
      organizationId: validatedTenantId,
      role: effectiveRole,
      isPlatformSuperAdmin: isSuperAdmin,
    };

    // -------------------------------------------------------------------------
    // 5. INJEÇÃO DE CLIENT HELPERS TRANSACIONAIS COM 'set_config(..., true)'
    // -------------------------------------------------------------------------
    req.withTenantDb = async <T>(
      callback: (client: pg.PoolClient) => Promise<T>
    ): Promise<T> => {
      return await executeWithTenantRlsContext(validatedTenantId, callback, isSuperAdmin);
    };
    req.executeWithRls = req.withTenantDb;

    req.scopedQuery = async <T extends pg.QueryResultRow = any>(
      text: string,
      params?: any[]
    ): Promise<pg.QueryResult<T>> => {
      return await query<T>(text, params, {
        context: {
          tenantId: validatedTenantId,
          isSuperAdmin,
        },
      });
    };

    req.db = {
      query: <T extends pg.QueryResultRow = any>(sql: string, params?: any[]) => req.scopedQuery!<T>(sql, params),
      withTransaction: <T>(callback: (client: pg.PoolClient) => Promise<T>) => req.withTenantDb!<T>(callback),
    };

    // -------------------------------------------------------------------------
    // 6. EXECUÇÃO NO CONTEXTO TENANT (AsyncLocalStorage)
    // Garante que todas as queries executadas no escopo desta requisição (mesmo via query(...) do pool)
    // executem 'SET LOCAL app.current_tenant_id = ?' antes de tocar nas tabelas do PostgreSQL.
    // -------------------------------------------------------------------------
    TenantContext.run(
      {
        tenantId: validatedTenantId,
        userId: user.id,
        userEmail: user.email,
        userRole: effectiveRole,
        ipAddress: req.ip || (req.headers["x-forwarded-for"] as string) || "127.0.0.1",
        userAgent: (req.headers["user-agent"] as string) || "Aura Web Client",
        isSuperAdmin,
        isSupportSession,
        supportReason,
        supportScope,
        supportAdminEmail: tokenPayload?.supportAdminEmail,
      },
      () => {
        next();
      }
    );
  } catch (error: any) {
    console.error("[JwtTenantRlsMiddleware] Erro crítico no pipeline de segurança RLS:", error);
    return res.status(500).json({
      success: false,
      code: "RLS_MIDDLEWARE_ERROR",
      error: `Erro ao aplicar barreira de isolamento RLS: ${error.message}`,
    });
  }
}
