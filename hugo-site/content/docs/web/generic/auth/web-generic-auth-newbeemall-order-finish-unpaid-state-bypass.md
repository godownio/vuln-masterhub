---
id: web-generic-auth-newbeemall-order-finish-unpaid-state-bypass
title: NewBeeMall /orders/{orderNo}/finish 未校验支付与出库状态：未支付订单可直接完成交易
type: scenario
domain: web
path: web/generic/auth
technique: newbeemall-order-finish-missing-state-validation
tags:
- business-logic
- order
- state-machine
- payment
- java
- spring
- newbee-mall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:04:35+08:00'
  notes: 对照原文 img58-61 与正文：@PutMapping /orders/{orderNo}/finish 取 session 用户后调用 finishOrder(orderNo,user.getUserId())，原文明确称服务实现未校验是否支付/出库等前置状态，且 @PutMapping 决定必须用 PUT；img58 PayStatusEnum 佐证支付状态字段存在。原文复现截图在 xzfile.aliyuncs.com 外部图床、本地未保存，状态变化部分无法本地核实，卡内已标 confidence medium 并注明未复跑，合理。与 paysuccess 卡（GET /paySuccess 直写支付状态）端点、方法、状态跃迁均不同，非同一条链，保留。
url: /docs/web/generic/auth/web-generic-auth-newbeemall-order-finish-unpaid-state-bypass/
draft: false
kb_aliases:
- NewBeeMall 未支付订单完成
- finishOrder 状态机绕过
- 订单状态直接完成
- 白嫖订单
- PutMapping finish 未校验支付
---

## 一句话结论

NewBeeMall 的 `PUT /orders/{orderNo}/finish` 只按 orderNo 与 session userId 调用 `finishOrder`，服务实现没有校验订单是否已支付、是否已出库/收货，也没有状态机前置条件；用户对刚下单、尚未支付的订单直接发 PUT 请求即可把订单推进到完成（原文称“成功支付商品”），绕过支付流程完成交易。

## 原理

- **入口**：订单控制器 `@PutMapping("/orders/{orderNo}/finish") @ResponseBody public Result finishOrder(@PathVariable("orderNo") String orderNo, HttpSession httpSession)`，取 session 中的用户后调用 `newBeeMallOrderService.finishOrder(orderNo, user.getUserId())`，按返回结果给成功/失败。
- **服务层缺陷**：`finishOrder` 只按 orderNo 查订单并校验归属，然后直接推进订单状态；没有检查 `payStatus == PAY_SUCCESS`、没有检查订单是否已出库/已发货/已收货，也没有限制合法的状态跃迁（原文：“对于该订单是否支付，是否出库等过程都没有校验”）。
- **为什么成立**：订单完成本应发生在“已支付 → 已发货 → 已收货”之后，由服务端状态机驱动；这里把状态推进能力直接开放给任意已登录用户的 PUT 请求，前置状态校验缺失，等价于让用户自行确认“交易已完成”。
- **请求方法约束**：接口是 `@PutMapping`，只有 PUT 方法会进入该处理逻辑；GET/POST 不会触发（原文专门验证了这一点），因此利用时需用 PUT。
- **危害**：未支付订单被标记为完成/已支付（原文后台订单列表可见状态变化），商家按订单发货或结算即产生资金损失；也可用于绕过下单支付流程、刷销量/积分/优惠等衍生逻辑。
- **边界**：原文的复现截图在外部图床、本地未保存，卡片依据正文描述与代码截图；具体状态字段（完成/已支付）以版本实现为准。若服务端在 finish 前有其他校验（如必须已收货），该利用不成立。

## 触发条件

- 目标为 NewBeeMall（或同款订单实现），`/orders/{orderNo}/finish` 可达。
- 攻击者拥有任意注册账号并已登录，且有一个自己的待支付订单（orderNo 可从订单列表/确认页取得）。
- 服务端 `finishOrder` 未校验支付/出库/状态机前置条件。

## 利用步骤

1. 以攻击者账号添加商品到购物车并提交订单，保持“待支付”状态，记录 orderNo。
2. 用同一会话发送 `PUT /orders/<orderNo>/finish`（注意必须是 PUT）。
3. 响应 `{"resultCode":200,"message":"SUCCESS"}`；到后台订单管理/订单列表确认状态已变为完成/已支付。
4. 记录请求、响应与状态变化；验证后停止，不对生产订单批量操作。

## PoC

```http
PUT /orders/16885421543443721/finish HTTP/1.1
Host: target.example:28089
Cookie: JSESSIONID=<下单用户会话>
Content-Length: 0
```

```text
# 预期：HTTP/1.1 200 {"resultCode":200,"message":"SUCCESS","data":null}
# 后台订单管理该订单由“未支付”变为完成/已支付（原文表述：成功支付商品）。
# 原文复现截图位于外部图床未随文抓取，本卡未在真实目标复跑。
```

## 变体与关联

- 变体：同控制器的 `PUT /orders/{orderNo}/cancel` 同样只按 orderNo 操作，若缺少状态校验可取消他人/已支付订单（归属校验需实测）。
- 变体：`/paySuccess?orderNo=` 是另一条“仅凭 orderNo 改支付状态”的路径：[[web-generic-auth-newbeemall-paysuccess-payment-bypass]]。
- 关联：[[web-generic-auth-newbeemall-order-detail-orderno-idor]]（同一订单模块的归属校验缺失）、[[web-generic-payment-negative-quantity-offset]]（支付金额/数量逻辑缺陷）。
- 边界：客户端只应展示状态；任何状态推进都必须由服务端依据支付回调与业务规则完成。

## 检测与防御

- 检测：审计所有修改订单状态的接口，检查是否校验支付状态、出库/收货状态与合法状态跃迁；监控待支付订单短时间内被 finish/取消；对比支付流水与订单完成记录。
- 修复：在 `finishOrder` 内强制状态机校验（仅允许 `ORDER_RECEIVED → ORDER_FINISHED`），并要求存在有效支付流水；未支付订单调用 finish 直接拒绝；所有按 orderNo 操作的接口加用户归属校验。
- 加固：订单状态变更记录审计日志；支付与订单状态由对账系统校验；接口层限制批量/异常调用。
