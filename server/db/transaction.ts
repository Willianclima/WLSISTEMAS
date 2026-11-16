import pg from "pg";
import {
  withTransaction,
  sanitizeTenantId,
  RlsContextError,
  PostgresExecutionOptions,
} from "./postgres";
import { TenantContext, TenantSessionContext } from "./tenantContext";

/**
 * Transaction Context and Unit-of-Work for Atomic Operations across Modules
 * 
 * Supports nested operations and atomic rollbacks across:
 * - Orders & Order Items & Snapshots
 * - Inventory Balances, Ledger Movements & Reservations
 * - Payments & Gateways
 * - Order State Transitions & Audit Logs
 */
export interface TransactionContext {
  id: string;
  organizationId: string;
  startedAt: string;
  isCommitted: boolean;
  isRolledBack: boolean;
  pgClient?: pg.PoolClient;

  // Staged records for transactional commit or rollback
  stagedOrders: Map<string, any>;
  stagedOrderItems: Map<string, any>;
  stagedOrderPayments: Map<string, any>;
  stagedOrderTransitions: Map<string, any>;
  stagedInventoryMovements: Map<string, any>;
  stagedInventoryBalances: Map<string, any>;
  stagedInventoryReservations: Map<string, any>;
  stagedAuditLogs: Array<any>;

  // Rollback compensations for existing modified records
  originalInventoryBalances: Map<string, any>;
  originalOrders: Map<string, any>;
}

function assertStagedOrganization(recordOrgId: unknown, expectedOrgId: string, entityLabel: string): void {
  if (recordOrgId !== undefined && recordOrgId !== null && recordOrgId !== expectedOrgId) {
    throw new RlsContextError(
      `Violação de isolamento em ${entityLabel}: organizationId '${String(recordOrgId)}' diverge do tenant da transação '${expectedOrgId}'.`,
      "RLS_TENANT_MISMATCH"
    );
  }
}

export class UnitOfWork {
  /**
   * Executes a callback within an atomic transaction context directly on PostgreSQL.
   * Begins a transaction on a dedicated physical client, enforces transaction-local
   * RLS parameters (set_config(..., true)), provides tx.pgClient for real row locks
   * (SELECT ... FOR UPDATE), and atomically commits or rolls back on the same connection.
   */
  static async transaction<T>(
    organizationId: string,
    callback: (tx: TransactionContext) => Promise<T>,
    options: PostgresExecutionOptions = {}
  ): Promise<T> {
    const sanitizedOrgId = sanitizeTenantId(organizationId, { allowEmpty: false });
    const parentContext = TenantContext.get();

    if (
      parentContext?.tenantId &&
      parentContext.tenantId !== sanitizedOrgId &&
      !parentContext.isSuperAdmin
    ) {
      throw new RlsContextError(
        `Violação de isolamento: contexto ativo '${parentContext.tenantId}' não pode abrir transação para '${sanitizedOrgId}'.`,
        "RLS_TENANT_MISMATCH"
      );
    }

    const txId = `tx-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
    const txSessionContext: TenantSessionContext = {
      ...(parentContext ?? {}),
      tenantId: sanitizedOrgId,
      isSuperAdmin: Boolean(parentContext?.isSuperAdmin),
    };

    const tx: TransactionContext = {
      id: txId,
      organizationId: sanitizedOrgId,
      startedAt: new Date().toISOString(),
      isCommitted: false,
      isRolledBack: false,
      pgClient: undefined,
      stagedOrders: new Map(),
      stagedOrderItems: new Map(),
      stagedOrderPayments: new Map(),
      stagedOrderTransitions: new Map(),
      stagedInventoryMovements: new Map(),
      stagedInventoryBalances: new Map(),
      stagedInventoryReservations: new Map(),
      stagedAuditLogs: [],
      originalInventoryBalances: new Map(),
      originalOrders: new Map(),
    };

    return await TenantContext.run(txSessionContext, async () => {
      try {
        const result = await withTransaction(
          async (client) => {
            tx.pgClient = client;

            // 1. Execute business transaction logic inside the active PostgreSQL transaction
            const callbackResult = await callback(tx);

            // 2. Flush all staged records to PostgreSQL using the SAME physical connection
            // 2.1 Orders
            for (const order of tx.stagedOrders.values()) {
              assertStagedOrganization(order.organizationId, sanitizedOrgId, "order");
              await client.query(
                `INSERT INTO orders (
                  id, organization_id, order_number, customer_id, customer_snapshot, channel,
                  status, shipping_address, currency, subtotal_amount, discount_amount,
                  shipping_amount, total_amount, reseller_id, reseller_name,
                  reseller_commission_rate, reseller_commission_amount, warranty_code, idempotency_key, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                  status = EXCLUDED.status,
                  subtotal_amount = EXCLUDED.subtotal_amount,
                  discount_amount = EXCLUDED.discount_amount,
                  shipping_amount = EXCLUDED.shipping_amount,
                  total_amount = EXCLUDED.total_amount,
                  updated_at = NOW()`,
                [
                  order.id,
                  order.organizationId || sanitizedOrgId,
                  order.orderNumber,
                  order.customerId,
                  JSON.stringify(order.customerSnapshot),
                  order.channel || "PRESENTIAL_POS",
                  order.status,
                  JSON.stringify(order.shippingAddress),
                  order.currency || "BRL",
                  order.subtotalAmount,
                  order.discountAmount,
                  order.shippingAmount,
                  order.totalAmount,
                  order.resellerId || null,
                  order.resellerName || null,
                  order.resellerCommissionRate || 0,
                  order.resellerCommissionAmount || 0,
                  order.warrantyCode || null,
                  order.idempotencyKey || null,
                ]
              );
            }

            // 2.2 Order Items
            for (const item of tx.stagedOrderItems.values()) {
              assertStagedOrganization(item.organizationId, sanitizedOrgId, "order_item");
              await client.query(
                `INSERT INTO order_items (
                  id, organization_id, order_id, product_id, location_id,
                  product_snapshot, quantity, unit_price, cost_price_snapshot,
                  discount_amount, total_amount, customization_spec, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
                ON CONFLICT (id) DO NOTHING`,
                [
                  item.id,
                  item.organizationId || sanitizedOrgId,
                  item.orderId,
                  item.productId,
                  item.locationId,
                  JSON.stringify(item.productSnapshot),
                  item.quantity,
                  item.unitPrice,
                  item.costPriceSnapshot,
                  item.discountAmount,
                  item.totalAmount,
                  JSON.stringify(item.customizationSpec || null),
                ]
              );
            }

            // 2.3 Order Payments
            for (const pay of tx.stagedOrderPayments.values()) {
              assertStagedOrganization(pay.organizationId, sanitizedOrgId, "order_payment");
              await client.query(
                `INSERT INTO order_payments (
                  id, organization_id, order_id, payment_method, gateway, gateway_transaction_id,
                  status, amount, installments, pix_qr_code, pix_qr_code_url, pix_copy_paste,
                  pix_expiration, boleto_barcode, boleto_url, paid_at, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                  status = EXCLUDED.status,
                  paid_at = EXCLUDED.paid_at,
                  updated_at = NOW()`,
                [
                  pay.id,
                  pay.organizationId || sanitizedOrgId,
                  pay.orderId,
                  pay.paymentMethod,
                  pay.gateway || "MANUAL",
                  pay.gatewayTransactionId || null,
                  pay.status,
                  pay.amount,
                  pay.installments || 1,
                  pay.pixQrCode || null,
                  pay.pixQrCodeUrl || null,
                  pay.pixCopyPaste || null,
                  pay.pixExpiration || null,
                  pay.boletoBarcode || null,
                  pay.boletoUrl || null,
                  pay.paidAt || null,
                ]
              );
            }

            // 2.4 Order State Transitions
            for (const trans of tx.stagedOrderTransitions.values()) {
              assertStagedOrganization(trans.organizationId, sanitizedOrgId, "order_state_transition");
              await client.query(
                `INSERT INTO order_state_transitions (
                  id, organization_id, order_id, from_status, to_status, event, operator_id, operator_name, reason, metadata, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                ON CONFLICT (id) DO NOTHING`,
                [
                  trans.id,
                  trans.organizationId || sanitizedOrgId,
                  trans.orderId,
                  trans.fromStatus,
                  trans.toStatus,
                  trans.event,
                  trans.operatorId || null,
                  trans.operatorName || null,
                  trans.reason || null,
                  JSON.stringify(trans.metadata || {}),
                ]
              );
            }

            // 2.5 Inventory Balances
            for (const bal of tx.stagedInventoryBalances.values()) {
              assertStagedOrganization(bal.organizationId, sanitizedOrgId, "inventory_balance");
              await client.query(
                `INSERT INTO inventory_balances (
                  id, organization_id, product_id, location_id, on_hand_quantity, reserved_quantity, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
                ON CONFLICT (organization_id, product_id, location_id) DO UPDATE SET
                  on_hand_quantity = EXCLUDED.on_hand_quantity,
                  reserved_quantity = EXCLUDED.reserved_quantity,
                  updated_at = NOW()`,
                [
                  bal.id,
                  bal.organizationId || sanitizedOrgId,
                  bal.productId,
                  bal.locationId,
                  bal.onHandQuantity,
                  bal.reservedQuantity,
                ]
              );
            }

            // 2.6 Inventory Movements
            for (const mov of tx.stagedInventoryMovements.values()) {
              assertStagedOrganization(mov.organizationId, sanitizedOrgId, "inventory_movement");
              await client.query(
                `INSERT INTO inventory_movements (
                  id, organization_id, product_id, type, quantity_change,
                  physical_balance_after, consigned_balance_after, location_id,
                  reference_type, reference_id, operator_name, notes, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
                ON CONFLICT (id) DO NOTHING`,
                [
                  mov.id,
                  mov.organizationId || sanitizedOrgId,
                  mov.productId,
                  mov.type,
                  mov.quantityChange,
                  mov.physicalBalanceAfter,
                  mov.consignedBalanceAfter,
                  mov.locationId || null,
                  mov.referenceType || null,
                  mov.referenceId || null,
                  mov.operatorName,
                  mov.notes || null,
                ]
              );
            }

            // 2.7 Inventory Reservations
            for (const res of tx.stagedInventoryReservations.values()) {
              assertStagedOrganization(res.organizationId, sanitizedOrgId, "inventory_reservation");
              await client.query(
                `INSERT INTO inventory_reservations (
                  id, organization_id, product_id, location_id, quantity,
                  status, reference_type, reference_id, idempotency_key, expires_at,
                  confirmed_at, released_at, operator_name, notes, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                  status = EXCLUDED.status,
                  confirmed_at = COALESCE(EXCLUDED.confirmed_at, inventory_reservations.confirmed_at),
                  released_at = COALESCE(EXCLUDED.released_at, inventory_reservations.released_at),
                  notes = COALESCE(EXCLUDED.notes, inventory_reservations.notes),
                  updated_at = NOW()`,
                [
                  res.id,
                  res.organizationId || sanitizedOrgId,
                  res.productId,
                  res.locationId,
                  res.quantity,
                  res.status || "ACTIVE",
                  res.referenceType || "ORDER",
                  res.referenceId || res.orderId || "N/A",
                  res.idempotencyKey || null,
                  res.expiresAt || new Date(Date.now() + 3600000).toISOString(),
                  res.confirmedAt || null,
                  res.releasedAt || null,
                  res.operatorName || null,
                  res.notes || null,
                ]
              );
            }

            return callbackResult;
          },
          {
            ...options,
            context: {
              tenantId: sanitizedOrgId,
              isSuperAdmin: Boolean(txSessionContext.isSuperAdmin),
            },
          }
        );

        tx.isCommitted = true;
        return result;
      } catch (error) {
        tx.isCommitted = false;
        tx.isRolledBack = true;
        throw error;
      } finally {
        // Prevent any post-transaction reuse of a released PoolClient reference
        tx.pgClient = undefined;
      }
    });
  }
}
