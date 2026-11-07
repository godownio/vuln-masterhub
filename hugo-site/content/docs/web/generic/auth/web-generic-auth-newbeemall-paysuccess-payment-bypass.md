---
id: web-generic-auth-newbeemall-paysuccess-payment-bypass
title: NewBeeMall /paySuccess 未校验支付真实性：仅凭 orderNo 把待支付订单改为已支付
type: scenario
domain: web
path: web/generic/auth
technique: order-pay-success-no-payment-verification
tags:
- business-logic
- payment
- order
- idor
- java
- spring
- newbee-mall
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:08:36+08:00'
  notes: 已对照原文与图11-14核对：paySuccess 控制器 GET /paySuccess?orderNo=&payType=，service 按 orderNo 查订单后无条件 setOrderStatus(ORDER_PAID)/setPayStatus(PAY_SUCCESS)/setPayTime，TODO 未实现；订单 15698039249771093 由待支付变已支付。卡与原文一致。未验证点：截图请求未带 Cookie，文章未展示无会话的完整请求头；未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-newbeemall-paysuccess-payment-bypass/
draft: false
kb_aliases:
- NewBeeMall 支付漏洞
- paySuccess 支付状态篡改
- 0 元购
- orderNo 直接标记已支付
- 支付回调无签名校验
- 订单状态越权修改
---

## 一句话结论

NewBeeMall 的 `GET /paySuccess?orderNo=<订单号>&payType=1` 只按 orderNo 查询订单，查到后直接把 `orderStatus=ORDER_PAID`、`payStatus=PAY_SUCCESS`、`payTime=now` 写回数据库，没有校验支付流水、回调签名、订单归属或支付金额；攻击者传入任意待支付订单号即可把订单改为已支付，实现 0 元购。

## 原理

- 控制器：`@GetMapping("/paySuccess") @ResponseBody public Result paySuccess(@RequestParam("orderNo") String orderNo, @RequestParam("payType") int payType)`，直接调用 `newBeeMallOrderService.paySuccess(orderNo, payType)`。
- 服务实现：`NewBeeMallOrder newBeeMallOrder = newBeeMallOrderMapper.selectByOrderNo(orderNo); if (newBeeMallOrder != null) { newBeeMallOrder.setOrderStatus(ORDER_PAID); newBeeMallOrder.setPayType(payType); newBeeMallOrder.setPayStatus(PAY_SUCCESS); newBeeMallOrder.setPayTime(new Date()); newBeeMallOrder.setUpdateTime(new Date()); if (updateByPrimaryKeySelective(...) > 0) return SUCCESS; ... }`。
- 缺陷：`orderNo` 与 `payType` 完全由客户端控制；没有校验订单是否属于当前用户（该接口本身也未要求登录）、没有校验订单金额与支付渠道回调、没有验证支付平台签名/流水号。代码中的 TODO 注释“订单状态判断 非支付状态下不进行修改”并未实现，实际是无条件置为已支付。
- 为什么成立：支付状态是交易的核心信任字段，必须由可信支付渠道的服务端回调（带签名、金额、商户号校验）来推进；此处把该字段的写入权交给了任意 HTTP 请求。
- 危害：任意待支付订单被标记为已支付，商家发货/出库后造成资金损失；也可用于绕过下单支付流程、刷积分/优惠券等衍生逻辑。

## 触发条件

- 目标为 NewBeeMall（或同款商城代码），`/paySuccess` 接口可达且无需登录。
- 攻击者知道一个待支付订单号（可通过订单列表、ID 枚举或泄露获得）。
- 服务端未对支付回调做签名/流水校验（文章环境满足）。

## 利用步骤

1. 在后台/订单列表确认目标订单状态为“待支付”（文章订单号 15698039249771093，金额 3199）。
2. 直接请求 `/paySuccess?orderNo=15698039249771093&payType=1`，无需登录或携带任意会话。
3. 响应 `{"resultCode":200,"message":"SUCCESS","data":null}`。
4. 回到订单列表确认该订单状态变为“已支付”，支付方式变为“支付宝支付”。
5. 将 orderNo 换成其他待支付订单批量操作，或结合下单接口实现 0 元购。

## PoC

```http
GET /paySuccess?orderNo=15698039249771093&payType=1 HTTP/1.1
Host: target.example:28089
```

```text
# 预期：HTTP/1.1 200
# {"resultCode":200,"message":"SUCCESS","data":null}
# 订单列表中该订单由“待支付/无”变为“已支付/支付宝支付”（文章截图）。
```

## 变体与关联

- 变体：`payType` 可伪造为微信/支付宝等任意值；若存在金额字段，也可尝试篡改金额或数量（需另测）。
- 变体：其他商城系统的 `paySuccess`、`payNotify`、`callback` 等接口若只按订单号改状态，同样可利用。
- 关联：[[web-generic-auth-mall-pay-success-idor-zero-cost-order]]（mall APP 端同类 paySuccess 支付状态篡改）；[[web-generic-payment-negative-quantity-offset]]（支付金额/数量逻辑缺陷）；[[web-generic-auth-mall-cancel-user-order-idor]]（订单接口缺少归属校验的同类模式）。
- 边界：文章在本地 NewBeeMall 环境实测订单状态从待支付变为已支付；未给出 NewBeeMall 版本号。

## 检测与防御

- 检测：审计所有修改订单支付状态的接口，确认是否校验支付渠道回调签名、商户号、金额与流水号；监控无支付流水却出现 `PAY_SUCCESS` 的订单；关注同一 IP 批量调用 `/paySuccess` 的行为。
- 修复：支付状态只能由支付渠道服务端回调推进，回调必须验签、校验金额与订单归属；前端不得直接调用改状态接口；订单状态机限制非法跃迁。
- 加固：支付回调幂等处理与重放防护；订单操作记录审计日志；对账系统定期核对支付流水与订单状态。
