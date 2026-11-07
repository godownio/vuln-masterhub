---
id: web-generic-payment-amount-tamper-no-order-binding
title: 支付金额篡改：支付接口信任客户端 totalAmount 且未绑定已创建订单
type: scenario
domain: web
path: web/generic
technique: payment-amount-tamper-no-order-binding
tags:
- payment
- business-logic
- amount-tamper
- order-binding
- integrity
- api
- miniprogram
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V62
  verified_at: '2026-11-05T12:50:49+08:00'
  notes: 已对照原文与图01/05/06核对：先创建真实 32 元洗车订单，原请求 totalAmount=3200 且响应 3200；改用重签脚本把 totalAmount 改为 10 后，服务端 respCode=0000、respDesc=成功的响应、totalAmount=10、返回新的 miniPayRequest；收银台显示 ¥0.10，与卡一致。未验证点：原文未完成实际支付与业务履约，资金损失为条件性结论（卡中已分步说明）；mchntOrderId 可独立新建支付会话为原文描述、未给出完整对照请求；PoC 未复跑；原文未标注产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/web-generic-payment-amount-tamper-no-order-binding/
draft: false
kb_aliases:
- 支付金额篡改
- totalAmount 客户端直传
- 支付订单绑定缺失
- 改价 0.1 元
- 支付完整性缺陷
- mchntOrderId 未校验
---

## 一句话结论

支付拉起接口 `get-wx-payurl` 直接接受客户端提交的 `totalAmount`，且 `mchntOrderId` 不要求绑定一个已创建、已校验的业务订单；攻击者在付款阶段把 3200 分改成 10 分，服务端仍返回成功并生成 ¥0.10 的支付请求，形成完整的支付金额篡改。

## 原理

- 支付链路通常分两步：业务下单（生成订单号、金额、回调地址）→ 支付拉起（用订单号换支付参数）。安全设计应保证第二步的金额来自服务端订单，而不是客户端再次提交。
- 该接口的请求体同时包含 `totalAmount`、`mchntOrderId`、`notifyUrl`、`subOpenId` 等字段；服务端只校验签名（或签名本身可伪造），没有把 `totalAmount` 与订单服务中的应付金额做比对。
- 同时，`mchntOrderId` 没有被强制绑定到“当前用户已创建且待支付”的订单：攻击者可以继续用原订单号，也可以生成新的订单号，支付接口都会为其创建支付会话。
- 三点叠加：签名边界失效（可本地重签）、订单绑定失效、金额绑定失效。即使订单是真实存在的 32 元洗车订单，付款阶段仍可改成 1 角。
- 结果：微信支付侧看到的是服务端下发的 `totalAmount=10`，用户实际支付 0.10 元，而业务侧订单仍是 32 元，形成资金损失/对账差异。

## 触发条件

- 支付拉起接口接受客户端提交的金额字段（`totalAmount`/`amount`/`payAmount` 等），且服务端不按订单重新计算。
- `mchntOrderId`/`orderNo` 未校验归属、状态（待支付）、金额，或允许客户端新建订单号。
- 签名可伪造（客户端密钥泄露/弱签名）或接口未做签名校验。
- 支付渠道按服务端提交的金额生成支付单，业务侧未在回调中复核金额。

## 利用步骤

1. 正常创建一笔真实业务订单，记录 `outer_order_number`、应付金额（如 32 元 = 3200 分）、回调地址。
2. 抓取支付拉起接口 `POST /xxx/get-wx-payurl`，确认请求体包含 `totalAmount` 与 `mchntOrderId`。
3. 修改 `totalAmount` 为攻击者指定值（如 10 分），保留或替换 `mchntOrderId`，按签名算法重算 `Authorization`（若签名可伪造）。
4. 重放请求，观察响应：
   ```json
   {"respCode":"0000","totalAmount":10,"miniPayRequest":"..."}
   ```
5. 用返回的 `miniPayRequest` 拉起支付，确认收银台显示 ¥0.10，完成支付并观察业务侧是否按原订单金额发货。
6. 若业务侧仍按 32 元订单履约，则资金损失成立；若回调校验金额，则漏洞影响降级为支付会话异常。

## PoC

```http
POST /xxx/get-wx-payurl HTTP/1.1
Host: target
Content-Type: application/json
Authorization: appId="...",Timestamp="...",Nonce="...",Signature="..."

{"vaMchntNo":"...","vaTermNo":"...","totalAmount":10,
 "notifyUrl":"https://.../callback","mchntOrderId":"<真实订单号>",
 "subOpenId":"...","subAppId":"...","instMid":"...","tradeType":"...",
 "msgType":"wx.unifiedOrder","loginToken":"..."}
```

```json
// 服务端响应（示例）
{"respCode":"0000","respDesc":"成功的响应","totalAmount":10,
 "miniPayRequest":"..."}
```

## 变体与关联

- 变体：负数金额、0 元、极小金额（0.01）、货币单位混淆（元/分）、数量/单价拆分、优惠券/积分抵扣参数篡改。
- 变体：篡改 `notifyUrl` 把回调指向攻击者；复用他人 `mchntOrderId`；用未支付/已退款订单号重新拉起支付。
- 变体：签名只覆盖部分字段时，金额字段可能不在签名范围内，无需恢复密钥即可改价。
- 关联：[[web-generic-auth-miniprogram-local-config-signature-forgery]]（签名伪造前置）、[[web-generic-payment-negative-quantity-offset]]（负数/数量类支付逻辑缺陷）、[[web-generic-client-side-score-trust]]（客户端信任类业务逻辑）。
- 边界：服务端按订单 ID 查询应付金额并比对、支付回调复核金额、订单与用户/状态强绑定、签名覆盖金额字段时，单纯改 `totalAmount` 无效。

## 检测与防御

- 检测：支付拉起请求中的 `totalAmount` 与订单服务应付金额不一致；同一订单多次拉起且金额变化；`mchntOrderId` 不存在/不属于当前用户/状态异常；回调金额与订单金额不一致。
- 修复：支付金额只能由服务端根据订单计算，客户端提交的金额仅作展示/忽略；`mchntOrderId` 必须绑定当前用户、待支付状态与应付金额；支付回调必须复核金额与订单状态。
- 加固：签名覆盖全部关键字段（金额、订单号、回调地址）；服务端生成一次性支付 token；对账与异常金额告警；禁止客户端新建/复用订单号。
