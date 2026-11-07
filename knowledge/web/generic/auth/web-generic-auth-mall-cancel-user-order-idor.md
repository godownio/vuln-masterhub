---
id: web-generic-auth-mall-cancel-user-order-idor
title: mall APP 端 /order/cancelUserOrder 水平越权：orderId 未校验归属可取消他人未付款订单
type: scenario
domain: web
path: web/generic/auth
technique: order-cancel-idor-missing-ownership
aliases:
- mall 取消订单越权
- cancelUserOrder IDOR
- 任意取消他人订单
- 订单接口缺少 memberId 校验
- 水平越权 订单取消
tags:
- web
- idor
- horizontal-privilege-escalation
- business-logic
- order
- java
- spring
- mall
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:56:45+08:00'
  notes: 已对照原文与7张图片核对：cancelOrder 查询条件仅 id+status=0+deleteStatus=0，无 memberId；图02新账号订单列表为空，图04用该 token 取消 orderId=73 返回操作成功，图05 status 变为4。原文为本地环境复现，未给 mall 版本；未在本地执行请求；frontmatter无sources/source_url。
---

## 一句话结论

mall 商城 APP 端的 `POST /order/cancelUserOrder` 只按客户端传入的 `orderId` 查询并取消“未付款”订单，没有校验订单的 `memberId` 是否等于当前登录用户，任意已登录用户都能取消他人的待付款订单，并连带释放库存锁定、修改优惠券状态和返还积分。

## 原理

- Controller 直接把客户端 `orderId` 传给 Service：
  ```java
  @RequestMapping(value = "/cancelUserOrder", method = RequestMethod.POST)
  public CommonResult cancelUserOrder(Long orderId) {
      portalOrderService.cancelOrder(orderId);
      return CommonResult.success(null);
  }
  ```
- `cancelOrder(orderId)` 的查询条件只有 `id = orderId`、`status = 0`（待付款）、`deleteStatus = 0`，没有当前登录用户的 `memberId` 条件：
  ```java
  example.createCriteria().andIdEqualTo(orderId)
         .andStatusEqualTo(0).andDeleteStatusEqualTo(0);
  ```
- 因此只要知道或枚举到一个待付款订单 ID，任何持有普通用户 token 的请求都会命中该订单并把 `status` 改为 4（已关闭）；Service 随后用订单自身的 `memberId` 执行 `updateCouponStatus`、返还 `useIntegration` 积分，并调用 `releaseSkuStockLock` 释放商品库存锁定。
- 项目的垂直权限由 `DynamicSecurityFilter` + `ums_resource` URL 规则统一控制，普通用户本来就有权访问该用户端接口；漏洞出在“同一角色内不同用户之间的资源归属”校验，URL 级权限无法覆盖。

## 触发条件

- 攻击者拥有一个可正常登录的普通会员账号（APP 端 JWT/Bearer token）。
- 目标订单处于待付款状态（`status = 0`）且未被删除。
- 攻击者知道或能枚举目标 `orderId`（订单 ID 常为自增/可预测）。
- 接口未额外校验订单归属、未要求二次确认或验证码。

## 利用步骤

1. 注册/登录一个普通会员账号，抓取带 `Authorization: Bearer <token>` 的请求。
2. 通过订单列表、下单接口或 ID 遍历获取目标待付款订单 ID。
3. 向 `/order/cancelUserOrder` 提交目标 `orderId`。
4. 响应固定为成功（服务在查不到订单时也静默返回），需通过订单详情或数据库确认目标订单 `status` 变为 4、库存锁定与优惠券/积分状态被改动。
5. 用另一个账号复测同一订单，确认越权成立。

## PoC

```http
POST /order/cancelUserOrder?orderId=73 HTTP/1.1
Host: target:8085
Authorization: Bearer <普通用户 token>
Content-Type: application/json

```

```text
响应：{"code":200,"message":"操作成功"}
数据库核对：oms_order.id=73 的 status 由 0（待付款）变为 4（已关闭），
对应订单商品的库存锁定被释放，优惠券状态与积分按订单 memberId 被回滚。
```

## 变体与关联

- 变体：同类订单/资源接口（订单详情、取消、退款申请、收货地址、优惠券领取记录）只要按客户端 ID 查询而不附加 `memberId` 条件，都可用相同思路测试。
- 关联卡片：[[web-generic-auth-mall-pay-success-idor-zero-cost-order]]（同一商城的支付状态接口，可直接把他人订单改为已支付，危害更高）。
- 边界：若订单 ID 使用不可预测的 UUID 且无法从其他接口泄露，利用门槛会提高，但仍不构成授权校验；若接口额外校验 `memberId`，则本越权不成立。

## 检测与防御

- 修复：所有用户侧订单操作都在 SQL/Service 层追加 `member_id = 当前登录用户` 条件，例如 `andMemberIdEqualTo(currentMemberId)`；取消操作先按“订单 ID + 当前用户”查询，查不到直接返回 404/403。
- 加固：统一封装资源归属校验切面/注解，避免每个接口各写一套；对订单状态变更做状态机校验与操作审计；不要把“URL 级权限”当作水平权限校验。
- 检测：审计订单状态变更日志中“操作者 memberId 与订单 memberId 不一致”的记录；多账号矩阵测试同一 `orderId` 的跨用户访问；监控短时间内大量取消请求与订单 ID 递增枚举。
