---
id: web-generic-auth-newbeemall-cart-delete-idor
title: NewBeeMall DELETE /shop-cart/{id} 未校验购物车项归属：可删除任意用户购物车条目
type: scenario
domain: web
path: web/generic/auth
technique: cart-item-delete-missing-ownership
tags:
- idor
- horizontal-privilege-escalation
- java
- spring
- newbee-mall
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:08:37+08:00'
  notes: 已对照原文与图17/18核对：@DeleteMapping(/shop-cart/{newBeeMallShoppingCartItemId}) 从 session 取 user 但未使用，直接 deleteById(id)；截图给出 DELETE 请求但未展示响应。卡已标 confidence medium。未验证点：未证明他人条目实际被删，未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-newbeemall-cart-delete-idor/
draft: false
kb_aliases:
- NewBeeMall 购物车越权
- 删除任意购物车
- shop-cart IDOR
- newBeeMallShoppingCartItemId 越权
- 水平越权删除
---

## 一句话结论

NewBeeMall 的 `DELETE /shop-cart/{newBeeMallShoppingCartItemId}` 虽然从 session 取到了当前用户对象，却只调用 `deleteById(id)` 删除购物车项，没有校验该 id 是否属于当前用户；任意已登录用户只要知道（或枚举）购物车项 ID，就能删除他人的购物车条目。

## 原理

- 控制器：`@DeleteMapping("/shop-cart/{newBeeMallShoppingCartItemId}") @ResponseBody public Result updateNewBeeMallShoppingCartItem(@PathVariable("newBeeMallShoppingCartItemId") Long id, HttpSession session)`。
- 代码：`NewBeeMallUserVO user = (NewBeeMallUserVO) session.getAttribute(Constants.MALL_USER_SESSION_KEY); Boolean deleteResult = newBeeMallShoppingCartService.deleteById(id);`——`user` 取出后未被使用，`deleteById` 只按主键删除。
- 缺陷：购物车项是用户私有对象，删除前必须校验 `item.userId == session.user.userId`；这里缺少对象级授权（IDOR），ID 通常为自增数字，易于枚举。
- 为什么成立：接口只要求登录（session 存在），不要求对象归属；服务层 `deleteById` 按主键直删，没有附带 userId 条件。
- 危害：删除他人购物车商品，破坏用户数据完整性；若结合其他接口（如结算、优惠券）可能影响下单流程。

## 触发条件

- 目标为 NewBeeMall，用户已登录（可自行注册）。
- `DELETE /shop-cart/{id}` 可达。
- 攻击者知道或能枚举目标购物车项 ID（自增 ID 易枚举）。

## 利用步骤

1. 注册/登录一个普通账号，获取会话 Cookie。
2. 构造 `DELETE /shop-cart/<目标ID>`，携带自己的会话。
3. 服务端按 ID 删除购物车项，不校验归属，返回成功。
4. 遍历 ID 可批量删除他人购物车条目；结合商品/订单接口评估进一步影响。

## PoC

```http
DELETE /shop-cart/15692218454123239 HTTP/1.1
Host: target.example:28089
Cookie: JSESSIONID=<自己的会话>
```

```text
# 预期：HTTP/1.1 200，返回删除成功；该购物车项不属于当前登录用户也会被删除。
# 文章截图给出该 DELETE 请求，未展示响应体。
```

## 变体与关联

- 变体：同类 `deleteById`/`selectById`/`updateById` 接口若只按主键操作，均可能存在 IDOR。
- 变体：购物车项 ID 自增，可编写脚本遍历批量删除。
- 关联：[[web-generic-auth-mall-cancel-user-order-idor]]（订单取消缺少 memberId 校验的同类水平越权）；[[web-generic-auth-xxl-job-jobinfo-remove-idor]]（按 ID 删除缺少归属校验）；[[web-generic-auth-newbeemall-updateuserinfo-userid-session-idor]]（同系统资料更新越权）。
- 边界：文章只展示请求，未展示响应或他人购物车被删除的前后对比；代码逻辑明确缺少归属校验，confidence 定为 medium。

## 检测与防御

- 检测：审计所有按主键删除/修改的接口是否附带当前用户 ID 条件；监控同一会话对大量递增 ID 的删除请求。
- 修复：删除前校验对象归属（`WHERE item_id=? AND user_id=?`），或先查对象再比对 userId；服务层方法增加 userId 参数。
- 加固：对象 ID 使用不可预测的 UUID；对批量/高频删除做限流与审计；统一在数据访问层强制租户/用户隔离。
