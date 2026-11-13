---
id: web-generic-auth-newbeemall-order-detail-orderno-idor
title: NewBeeMall 订单详情按 orderNo 查询未校验归属：任意登录用户查看他人订单与收货信息
type: scenario
domain: web
path: web/generic/auth
technique: newbeemall-order-detail-orderno-idor
tags:
- idor
- horizontal-privilege-escalation
- order
- java
- spring
- newbee-mall
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:04:19+08:00'
  notes: 对照原文与61张本地截图（img48-51）：控制器 GET /orders/{orderNo} 调用 getOrderDetailByOrderNo(orderNo,user.getUserId())，服务实现仅 selectByOrderNo(orderNo) 并保留 //todo 验证是否是当前userId下的订单；img50/51 两个不同用户会话访问同一 orderNo 均返回含收货信息的订单详情，归属校验缺失成立。已把控制器表述改为原文的 controller/mall/OrderController。原文未标受影响版本，affected_versions 保持为空。与 paysuccess/cart-delete/updateinfo 卡端点与方法不同，非同一条链。
url: /docs/web/generic/auth/web-generic-auth-newbeemall-order-detail-orderno-idor/
draft: false
kb_aliases:
- NewBeeMall 订单越权
- orderNo 越权查看订单
- getOrderDetailByOrderNo IDOR
- 订单详情缺少归属校验
- newbee-mall 水平越权
---

## 一句话结论

NewBeeMall 的订单详情页 `GET /orders/{orderNo}` 把 orderNo 交给 `getOrderDetailByOrderNo(orderNo, user.getUserId())`，但服务实现只用 orderNo 查订单、完全忽略 userId，代码里的 TODO“验证是否是当前 userId 下的订单”并未实现；任意登录用户只要拿到他人订单号，就能查看对方订单的商品、金额、收货人姓名/电话/地址与支付方式。

## 原理

- **控制器**：`ltd.newbee.mall.controller.mall.OrderController`（原文 controller/mall/OrderController.java:36）的 `orderDetailPage(HttpServletRequest, @PathVariable("orderNo") String orderNo, HttpSession)` 从 session 取当前用户 `user`，然后调用 `newBeeMallOrderService.getOrderDetailByOrderNo(orderNo, user.getUserId())`。
- **服务层**：`getOrderDetailByOrderNo(String orderNo, Long userId)` 的实现是 `newBeeMallOrderMapper.selectByOrderNo(orderNo)`——按订单号唯一查询，`userId` 参数在方法体内没有被使用；服务层还保留着 `//todo 验证是否是当前userId下的订单，否则报错` 的注释，说明归属校验本应存在但缺失。
- **为什么成立**：订单号是全局唯一的业务主键，服务端把“能否访问”完全建立在“知道 orderNo”上，没有把订单对象与 session 用户做比对；而订单详情渲染时会带出收货信息、订单项、支付方式等敏感数据。
- **orderNo 获取面**：本人订单列表/确认页/支付跳转链接、短信/邮件通知、Referer、日志、分享链接等都可能泄露；订单号形如 `16885421543443721`（时间戳+随机位），并不具备抗枚举能力，且不在授权判断中使用。
- **边界**：只能读不能改；若部署层对 `/orders/**` 额外做了登录校验，也仅要求任意账号登录，不影响越权本身。

## 触发条件

- 目标为 NewBeeMall（或同款订单详情实现），`/orders/{orderNo}` 可达。
- 攻击者拥有任意注册账号并已登录。
- 知道或获得他人 orderNo（订单列表泄露、链接分享、日志等）。

## 利用步骤

1. 用账号 A 下单（或从订单列表/链接）取得一个 orderNo。
2. 登录账号 B（不同用户），携带 B 的会话请求 `GET /orders/<A 的 orderNo>`。
3. 页面返回 A 的订单详情：商品、金额、收货人姓名/电话/地址、支付方式等；原文用两个不同用户的 Cookie 对照验证。
4. 记录请求与响应作为证据；批量遍历需谨慎，避免影响业务。

## PoC

```http
GET /orders/16885421543443721 HTTP/1.1
Host: target.example:28089
Cookie: JSESSIONID=<B 用户会话>
```

```text
# 预期：返回订单详情页 HTML，包含 A 用户的收货信息（姓名/电话/地址）与订单项；
# 服务层代码只有 //todo 归属校验注释，userId 参数未参与查询条件。
（原文用两个用户会话对照，改 Cookie 后仍能看到同一订单；本卡未在真实目标复跑。）
```

## 变体与关联

- 变体：订单列表 `/orders` 正常按 session userId 过滤，但详情、取消（`PUT /orders/{orderNo}/cancel`）、完成（`PUT /orders/{orderNo}/finish`）等按 orderNo 操作的接口都要逐一确认是否校验归属。
- 关联：[[web-generic-auth-newbeemall-updateinfo-userid-idor]]（同系统资料更新越权）、[[web-generic-auth-newbeemall-cart-delete-idor]]（购物车删除越权）、[[web-generic-auth-newbeemall-paysuccess-payment-bypass]]（订单状态接口缺校验）。
- 边界：仅信息泄露；若订单详情页含“再次购买/取消”等按钮，需确认后端是否另有校验。

## 检测与防御

- 检测：服务层查询条件是否包含 `userId`/`order.getUserId()` 与 session 用户比对；监控同一账号访问多个不属于自己的 orderNo；订单详情接口返回的 userId 与会话用户不一致。
- 修复：`selectByOrderNoAndUserId(orderNo, userId)` 或查询后显式比对 `order.getUserId().equals(userId)`，不匹配返回 404/403；所有按 orderNo 操作的接口统一加对象级授权。
- 加固：订单号使用不可枚举的高熵值（但不能替代授权）；敏感字段（完整收货信息）按需脱敏展示；审计异常订单访问。
