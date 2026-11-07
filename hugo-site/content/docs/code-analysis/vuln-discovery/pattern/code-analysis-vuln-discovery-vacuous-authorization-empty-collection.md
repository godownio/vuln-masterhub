---
id: code-analysis-vuln-discovery-vacuous-authorization-empty-collection
title: 空集合上的真空授权：循环体检查、短路与 every 恒真的审计模式
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: vacuous-authorization-empty-collection
tags:
- code-analysis
- authorization
- idor
- vulnerability-discovery
- pattern
- empty-collection
- fail-open
- static-analysis
- multi-tenant
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:02:07+08:00'
  notes: 已对照原文 §6.1/§6.2/§8.2/§8.3/§14.2-14.3 核对：循环体检查空集合未执行、length && 短路、Array.every 空数组恒真、检查对象≠使用对象四种形态与 Vendure 实例一致；正例（0 < length && 守卫、独立 assertOrderIsInChannel）与原文修复代码一致。属从本案提炼的可复用审计模式卡，非独立漏洞；未验证点：模式在其他代码库的泛化适用性、静态检索召回应由实际项目复核。
url: /docs/code-analysis/vuln-discovery/pattern/code-analysis-vuln-discovery-vacuous-authorization-empty-collection/
draft: false
kb_aliases:
- 真空授权
- vacuous authorization
- 空集合授权绕过
- 循环体里的权限检查
- every 空数组恒真
- 检查对象不等于使用对象
- 空数组 fail-open
---

## 一句话结论

当授权谓词被写在“用户可控集合的循环体”里、依赖 `collection.length && ...` 短路、或使用 `Array.every()` 判断归属时，空集合会让检查**从未执行**或**恒为真**，从而形成“真空授权”：攻击者用空数组/空列表通过所有检查，后续按裸 ID 寻址的敏感操作照常执行。本案（Vendure 跨渠道 IDOR）中，空 `lines` 同时让循环体内的渠道检查和 `orders.length` 短路的 mismatch 检查失效，两层叠加直达退款网关。

## 原理

- **循环体检查的真空执行**：`for (const x of userProvidedCollection) { assertAuthorized(x); }` 的语义是“对集合中每个元素校验”。集合为空时循环体执行零次，谓词不是“返回真”，而是“从未运行”；函数随后返回一个看似合法的空结果，调用方无法区分“校验通过”与“没有可校验对象”。
- **短路表达式的真空执行**：`if (orders.length && !idsAreEqual(payment.order.id, orders[0].id)) throw ...` 在 `orders = []` 时因 `orders.length` 为 0 直接跳过整个条件，业务一致性/授权检查未执行。
- **`Array.every` 的真空真**：`collection.every(pred)` 对空数组返回 `true`。用 `orders.every(o => channelOk(o))` 判断“归属”时，一个没有任何拥有订单的对象会自动通过渠道测试。修复者自己的首版补丁就踩了这个坑，后续才用 `0 < orders.length && ...` 加显式非空守卫 fail closed。
- **检查对象 ≠ 使用对象**：授权层常见语义是“会话在活跃租户/渠道是否持有某权限”，它只接收会话与租户，不接收目标实体；资源层却按客户端提交的裸 ID 全局加载目标对象。若中间没有“目标对象的父对象属于该租户”的断言，检查通过的是“你的权限”，实际使用的是“别人的对象”。
- **为何危险**：空数组/空列表往往是合法业务输入（例如“退运费/任意金额退款”就允许 `lines: []`），攻击者不需要构造畸形数据；状态机、业务校验都会“正确地”放行，因为它们回答的是业务问题，不是授权问题。

## 触发条件

- 代码中存在“用户可控集合 + 集合内元素的授权/归属检查”组合（循环体、`some`/`every`/`filter` 回调）。
- 或存在 `collection.length && sensitiveCheck` 之类短路，且集合可为空。
- 资源按客户端提供的裸 ID 全局加载，且实体本身不携带租户/渠道字段（归属只在父对象）。
- 加载后进入状态变更、文件/网络副作用或敏感读取。
- 业务上允许空集合输入（空行退款、空成员列表、空标签集合等）。

## 利用步骤

1. **找实体**：列出“非租户感知 + 按裸 ID 寻址 + 父对象携带归属”的实体（子订单、支付、退款、附件、备注、成员关系等）。
2. **找加载点**：搜索服务层对这类实体的 `findById`/`getEntityOrThrow`/`findOne({id})`，确认没有 `tenantId`/`channelId` 条件。
3. **找检查**：在同一调用链上搜索授权谓词；标记三类形态——循环体内的检查、`length &&` 短路、`every()` 归属判断。
4. **构造空输入**：把集合参数置空（`lines: []`、`ids: []`、`members: []`），保留定位敏感对象的裸 ID 与触发副作用的字段（金额、状态、内容）。
5. **动态验证**：在隔离环境用两个租户/渠道的夹具，正对照（同租户必须成功）、负对照（跨租户必须拒绝且副作用未发生）、超级管理员合法跨租户正对照三者齐备；把“处理器未被调用”作为一等断言。
6. **静态检索**：用 CodeQL/Semgrep 枚举 `for-of` 循环体内引用 `channelId/tenantId` 的候选、`.every(` 回调含归属谓词的候选、`getEntityOrThrow` 无 channel 选项的候选；候选只作人工复核入口，不直接当结论。

## PoC

```typescript
// 反例 1：授权检查寄生在循环体内，空集合时未执行
for (const line of userProvidedLines) {
  const order = line.order;
  if (!order.channels.some(c => c.id === ctx.channelId)) {
    throw new EntityNotFoundError('Order', order.id);
  }
}
// lines: [] -> 循环零次 -> 返回 []，调用方认为“没有订单需要校验”

// 反例 2：短路使业务/授权检查未执行
if (orders.length && !idsAreEqual(payment.order.id, orders[0].id)) {
  return new PaymentOrderMismatchError();
}
// orders: [] -> 条件整体跳过

// 反例 3：every() 空数组恒真（修复者首版补丁踩过的坑）
const ownedByActiveChannel = orders.every(o =>
  o.channels.some(c => idsAreEqual(c.id, txCtx.channelId)));
// orders: [] -> true -> 未拥有任何订单的对象也通过渠道测试
```

```typescript
// 正例：独立断言 + 显式非空守卫，fail closed
const ownedByActiveChannel =
  0 < orders.length &&                       // 空集合必须拒绝
  orders.every(o => o.channels.some(c => idsAreEqual(c.id, txCtx.channelId)));
if (!ownedByActiveChannel) {
  throw new EntityNotFoundError('Fulfillment', fulfillmentId); // 点名子实体，防枚举
}

// 更彻底的修复：断言输入不依赖用户集合，而是已加载子实体的父对象 ID
await assertOrderIsInChannel(ctx, connection, payment.order.id, 'Payment', paymentId);
```

```graphql
# 触发空集合的最小业务输入（Vendure 案例）
mutation {
  refundOrder(input: { lines: [], shipping: 100, paymentId: "<他人渠道 paymentId>" }) {
    ... on Refund { id state }
    ... on ErrorResult { errorCode message }
  }
}
```

## 变体与关联

- 变体：`collection.some(...)` 空数组恒假，用于“存在即拒绝”的黑名单式检查时会 fail-open；`filter(...).length === 0` 同理。
- 变体：`Promise.all([])`、批量接口的 `ids: []`、`IN ()` 空条件、`UNION` 空集合，都可能导致“批量校验”整体不执行。
- 变体：检查对象 ≠ 使用对象（授权层校验会话×租户，资源层按裸 ID 全局加载）；与空集合叠加时形成两层真空。
- 变体：修复时把 `every()` 换成 `some()` 而不加非空守卫，只是把恒真换成恒假/恒真，仍然 fail-open 或误杀。
- 关联：[[web-generic-auth-vendure-cross-channel-child-entity-idor]]（本案完整漏洞）、[[web-generic-auth-multitenant-tenant-header-missing-superadmin]]（租户缺失 fail-open 的另一形态）、[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（静态候选筛选思路）。
- 边界：只适用于“集合为空是合法输入”的路径；若上游强制非空，漏洞不可触发；静态候选需人工确认数据流与可达性。

## 检测与防御

- 检测（代码审计）：`for (… of userInput)` 循环体内出现 `tenantId/channelId/ownerId` 判断；`every(` 回调内出现归属谓词且无 `0 < length` 前置；`length && sensitiveCheck` 短路；`getEntityOrThrow`/`findOne` 无租户条件且实体非租户感知。
- 检测（运行时）：跨租户 ID 的写操作；同一会话访问自身不可见的父对象 ID；敏感处理器被调用但归属校验事件缺失（插桩事件序列 `load → handler`，没有 `assert` 事件）。
- 修复：授权断言必须独立于用户集合内容（用已加载子实体的父 ID 做 `EXISTS` 检查）；空集合一律 fail closed；`every` 前显式要求非空；断言放在状态变更/网关调用之前。
- 测试：空数组、空 ID 列表、`IN ()` 作为必测用例；把“副作用未发生”作为一等断言；正/负/超管对照成对出现。
