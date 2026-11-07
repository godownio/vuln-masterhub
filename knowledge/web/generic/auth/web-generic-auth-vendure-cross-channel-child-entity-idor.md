---
id: web-generic-auth-vendure-cross-channel-child-entity-idor
title: Vendure 跨渠道子实体 IDOR（GHSA-7qvr-c5vf-xxfh）：裸 ID 全局加载 + 父订单渠道断言缺失
type: scenario
domain: web
path: web/generic/auth
technique: channel-child-entity-idor-parent-order-boundary
aliases:
- GHSA-7qvr-c5vf-xxfh
- Vendure 跨渠道 IDOR
- Vendure payment refund IDOR
- 多渠道租户越权
- 子实体父订单渠道边界
- 空 lines 跨渠道退款
tags:
- web
- idor
- multi-tenant
- authorization
- vendure
- ecommerce
- payment
- refund
- channel
- graphql
cve: []
severity: critical
confidence: high
status: verified
affected_versions: '@vendure/core < 3.7.3（修复版本 3.7.3）'
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:02:05+08:00'
  notes: 已对照原文与 10 张图片核对：子实体现金流路径（settlePayment/cancelPayment/transitionPaymentToState/refundOrder 空 lines/settleRefund）、两层真空授权（getOrdersFromLines 循环体内渠道检查 + orders.length 短路）、remarks/history 全局加载、v3.7.3 assertOrderIsInChannel、EXISTS 半连接与反枚举错误命名、版本区间均与原文及图 1-10 一致。未验证点：原文实验仓库尚未公开，读者无法独立复现；本地 fake gateway 不代表真实资金变动；履约/库存副作用为阴性结果。卡内已保留这些边界。
---

## 一句话结论

Vendure < 3.7.3 的多渠道部署中，`Payment`/`Refund`/`Fulfillment`/`OrderHistoryEntry` 等订单子实体不实现 `ChannelAware`，渠道归属只存在于父 `Order.channels`；多个 Admin mutation 按客户端提交的裸 ID 全局加载子实体，却从不校验父订单是否属于当前渠道。持有渠道 B `UpdateOrder` 的受限管理员因此可对渠道 A 的 `paymentId`/`refundId`/`noteId` 发起支付状态迁移、退款（尤其 `lines: []` 时两层检查同时失效）、备注增删，退款命令还会携带受害渠道的交易标识发往支付网关。

## 原理

- **数据层：渠道过滤是显式选择加入，不是默认**。`TransactionalConnection.getEntityOrThrow(ctx, Entity, id)` 只有调用方显式传 `channelId` 才走 `findOneInChannel`（join `channels` 表）；不传就是按主键全局 `findOne`，对 `ChannelAware` 实体也不自动加渠道条件。`ChannelAware` 只是一个标记接口，`getRepository()` 返回普通仓库，没有隐式租户过滤。
- **授权层只回答“会话在活跃渠道有没有这个权限”**。Admin GraphQL 的 `@Allow(Permission.UpdateOrder)` 最终落到 `RequestContext.userHasPermissions()`：只查 `user.channelPermissions` 中活跃渠道的权限集合，不接收任何目标实体参数。它是正确的授权层语义，但不覆盖“目标对象是否属于该渠道”。
- **资源层：子实体的渠道归属住在父订单里**。`Payment`、`Refund`、`Fulfillment`、`OrderHistoryEntry` 都直接继承 `VendureEntity`，没有 `channels` 关系；只有父 `Order implements ChannelAware`，且 `Order.channels` 是多对多。因此任何按子实体 ID 操作的服务方法都必须自己断言 `payment.order.channels ∋ ctx.channelId`，而 v3.7.2 的多数方法没有做。
- **退款路径的两层真空授权**：`refundOrder` 首先允许 `lines: []` + `shipping`/`amount`（退运费/任意金额是合法业务）；`getOrdersFromLines` 把渠道检查写在 `for (const line of lines)` 循环体内，空数组时循环零次执行，检查从未运行并返回 `[]`；随后 `if (orders.length && !idsAreEqual(payment.order.id, orders[0].id))` 的 `orders.length` 短路，使 `PaymentOrderMismatchError` 也未执行；`Payment` 仍被全局加载，最终 `createRefund` 进入 `PaymentMethodHandler.createRefund()` 产生网关命令。
- **支付/退款结算路径连“寄生检查”都没有**：`settlePayment`、`cancelPayment`、`transitionToState`、`settleRefund` 都是全局加载后直接走 handler/状态机；`relations: ['order']` 加载了父订单却从不比较渠道。状态机只校验业务状态迁移是否合法（`Authorized → Cancelled`、`Pending → Settled` 都合法），无法区分“谁”触发。
- **ID 可枚举**：默认 `AutoIncrementIdStrategy` 下 Payment/Refund 的 API ID 是十进制主键，自增计数跨渠道连续；渠道 B 管理员从自己的合法数据即可观察全局 ID 序列形态。攻击是“盲写”：目标订单在自身会话不可见，但按 ID 写可达。
- **修复（3.7.3）**：新增 `assertOrderIsInChannel(ctx, connection, orderId, childEntityName, childEntityId)`，用 `EXISTS` 半连接检查父订单渠道，失败抛点名子实体的 `EntityNotFoundError`（不泄露订单存在性）；断言必须放在状态变更/网关调用之前。支付三条链收敛为 `getPaymentInChannelOrThrow`；退款在 `createRefund` 前断言；`settleRefund` 在事务内断言；history 四个入口断言父对象并补类型过滤。

## 触发条件

- `@vendure/core < 3.7.3`，且部署至少两个渠道（多渠道/多租户/多供应商）。
- 攻击者持有受限管理员会话，其角色在自身渠道拥有 `UpdateOrder`（不需要超级管理员）。
- 知道或可枚举目标渠道的子实体 ID（`paymentId`/`refundId`/`fulfillmentId`/`noteId`/`orderLineId`）。
- 目标子实体处于业务合法状态（如 `Authorized` payment、`Pending` refund），否则状态机会拒绝——这是业务前置，不是安全防线。
- 退款路径给 `lines: []` 并设置 `shipping` 或 `amount`（绕过 `NothingToRefund`）；跨渠道请求携带自己的渠道令牌（`vendure-token`）决定 `ctx.channelId`。

## 利用步骤

1. 以渠道 B 受限管理员登录 Admin API，确认自身角色只在渠道 B 有 `UpdateOrder`。
2. 从自身合法订单观察 Payment/Refund ID 形态（默认十进制、全局连续），推测/枚举渠道 A 的目标 ID。
3. 跨渠道支付状态改写：`transitionPaymentToState(id: <渠道A paymentId>, state: "Cancelled")`（或 `settlePayment`/`cancelPayment`），请求头使用渠道 B 的 `vendure-token`。
4. 跨渠道退款：`refundOrder(input: { lines: [], shipping: 100, paymentId: "<渠道A paymentId>" })`；空 `lines` 跳过渠道检查与 mismatch，退款命令携带渠道 A 的交易标识出站。
5. 跨渠道退款结算：`settleRefund(input: { id: "<渠道A refundId>", transactionId: "..." })`，目标 refund 从 `Pending` 落库为 `Settled`，受害订单 history 新增归因给渠道 B 调用者的 `ORDER_REFUND_TRANSITION`。
6. 备注面：`updateOrderNote` / `deleteOrderNote` 以 `noteId` 跨渠道修改/删除；v3.7.2 的删除还缺类型过滤，可删任意类型历史记录。
7. 验证：用超级管理员读回渠道 A 目标状态；检查独立 fake gateway 是否收到退款命令（本地测试环境）；检查受害订单审计记录。

## PoC

```http
POST /admin-api HTTP/1.1
Host: target
vendure-token: second_channel_token
Authorization: Bearer <渠道B管理员令牌>
Content-Type: application/json
```

```graphql
# 操作 1：资金出口——空 lines 跨渠道退款
mutation {
  refundOrder(input: { lines: [], shipping: 100, paymentId: "<渠道A paymentId>" }) {
    ... on Refund { id state }
    ... on ErrorResult { errorCode message }
  }
}

# 操作 2：状态改写——跨渠道支付取消
mutation {
  transitionPaymentToState(id: "<渠道A paymentId>", state: "Cancelled") {
    ... on Payment { id state }
    ... on ErrorResult { errorCode message }
  }
}
```

```text
# v3.7.2（受影响）：
#   操作 1 -> 成功创建 Refund；fake gateway 收到
#     {"action":"refund","transactionId":"<渠道A合成交易标识>","amount":100}
#   操作 2 -> state "Cancelled"，SuperAdmin 读回渠道 A payment 为 Cancelled
# v3.7.3（修复）：
#   两者均返回 ENTITY_NOT_FOUND（点名 Payment 与其 ID，不泄露订单存在性）
#   跨渠道 gateway 命令 0 条；目标状态保持 Authorized/Pending
```

```text
# 本地实验边界：fake gateway 仅接收无害 JSON，不代表真实资金变动；
# 履约状态持久化与库存副作用在所测默认路径未复现（阴性结果）。
```

## 变体与关联

- 变体：`settlePayment`、`cancelPayment`、`transitionPaymentToState` 的其他目标状态；`addFulfillmentToOrder`/`transitionFulfillmentToState`（入口可达，所测默认路径未复现持久化副作用）。
- 变体：`updateOrderNote`/`deleteOrderNote`；v3.7.2 无类型过滤的 history 删除可删状态迁移等任意类型记录。
- 变体：其他“子实体非租户感知、父对象携带租户、按裸 ID 全局加载”的实体组合（多租户 SaaS、多店铺电商、多品牌 CMS）。
- 关联：[[code-analysis-vuln-discovery-vacuous-authorization-empty-collection]]（本案提炼的空集合真空授权审计模式）、[[web-generic-auth-authenticated-change-password-idor]]（按 ID/用户名改他人资源的同类授权缺失）、[[web-generic-auth-multitenant-tenant-header-missing-superadmin]]（多租户 fail-open 的另一形态）。
- 边界：单渠道部署无“另一个渠道”；升级到 3.7.3 后断言生效；若服务层显式在 `WHERE` 带渠道条件或对子实体做父订单校验，则不成立。

## 检测与防御

- 检测：审计 `ORDER_REFUND_TRANSITION` 等 history 条目中“订单所属渠道”与“事件发生时活跃渠道”不一致的记录（活跃渠道需从访问日志/渠道令牌取得，再按 `administrator.id → User.roles → Role.channels` 映射）；同一管理员跨多个渠道 ID 的支付/退款/备注操作；跨渠道退款命令的 `transactionId` 与调用者渠道不匹配；GraphQL 请求中 `lines: []` 且带 `paymentId` 的退款。
- 修复：升级 `@vendure/core` 到 3.7.3+，各 `@vendure/*` 包版本对齐；升级后先在预发布验证合法跨渠道运维流程不会被误拒。
- 加固：任何按子实体 ID 的加载都必须在状态变更/网关调用前断言父订单渠道；优先使用 `findOneInChannel` 或 `EXISTS` 半连接；报错点名子实体而非父订单以防枚举；敏感 mutation 增加渠道与操作者归属审计。
- 回归测试：把“网关处理器未被调用”作为一等断言（`expect(spy).not.toHaveBeenCalled()`），并同时保留同渠道正对照、跨渠道负对照、超级管理员合法跨渠道正对照。
