---
id: web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure
title: 小智 ESP32 管理平台：拦截器 PUBLIC_PATHS 前缀 /api/user/ 放行导致用户信息未授权泄露
type: scenario
domain: web
path: web/generic/auth
technique: spring-interceptor-public-path-prefix-data-exposure
tags:
- access-control
- unauth
- java
- spring
- interceptor
- data-exposure
- user-enumeration
- xiaozhi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:10:31+08:00'
  notes: 已对照原文与图06/09/10/11核对：WebMvcConfig 注册 AuthenticationInterceptor，PUBLIC_PATHS 含 /api/user/ 等，isPublicPath 为 startsWith；实测 /api/user/query?username=admin 与 /api/user/queryUsers 未登录 200 返回用户数据（admin userId=1、isAdmin=1 等）。卡内字段与截图一致。未验证点：queryUsers 截图未显示 password 字段（卡已注明）；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure/
draft: false
kb_aliases:
- 小智 ESP32 未授权信息泄露
- PUBLIC_PATHS /api/user/
- AuthenticationInterceptor 白名单前缀
- queryUsers 未授权
- 用户列表泄露
- 用户名枚举
---

## 一句话结论

小智 ESP32 管理平台的 `AuthenticationInterceptor` 把 `/api/user/` 整体加入 `PUBLIC_PATHS`，并用 `path.startsWith()` 判断放行；结果该前缀下的 `GET /api/user/query?username=admin` 与 `GET /api/user/queryUsers` 均可未登录访问，直接返回用户 ID、用户名、姓名、邮箱、角色、isAdmin 等字段，形成未授权用户信息泄露与用户名枚举。

## 原理

- 白名单：`private static final List<String> PUBLIC_PATHS = Arrays.asList("/api/user/", "/api/device/ota", "/audio/", "/uploads/", "/ws/");`，`isPublicPath(path)` 为 `PUBLIC_PATHS.stream().anyMatch(path::startsWith)`。
- 缺陷：`/api/user/` 本意可能只想放行登录/注册，但前缀匹配把整个用户控制器都放行了，包括查询、列表、更新等敏感接口；`startsWith` 也不区分具体路由与 HTTP 方法。
- `UserController#query`：`@GetMapping("/query")`，参数 `username` 直接传给 `userService.query(username)`，返回 `SysUser` 全字段。
- `UserController#queryUsers`：`@GetMapping("/queryUsers")`，接收 `SysUser` 查询条件与分页，未传条件时 SQL 为 `SELECT ... FROM sys_user WHERE 1 = 1 ORDER BY createTime DESC`，返回大部分 `sys_user` 字段（含 email、tel、roleId、isAdmin、wxOpenId 等）。
- 危害：未登录即可枚举管理员与全部用户、拿到邮箱/手机号/角色/微信 openid 等，为 Cookie 冒充、密码重置、钓鱼等后续攻击提供输入；文章实测两个接口均返回 200 与用户数据。

## 触发条件

- 目标为小智 ESP32 Server Java 管理平台，`WebMvcConfig` 按默认注册 `AuthenticationInterceptor` 且 `PUBLIC_PATHS` 含 `/api/user/`。
- `/api/user/query`、`/api/user/queryUsers` 路由可达，无需登录。
- 数据库中存在目标用户（默认 admin）。

## 利用步骤

1. 直接请求 `GET /api/user/query?username=admin`，不带任何 Cookie/Token。
2. 观察 200 响应中的 `data`，获取 userId、username、name、isAdmin、roleId、email 等。
3. 请求 `GET /api/user/queryUsers`（可带分页/条件参数），获取用户列表与更多字段。
4. 用枚举出的 username 进行 Cookie 冒充或对 `/api/user/update` 发起未授权密码重置（见关联卡）。

## PoC

```http
GET /api/user/query?username=admin HTTP/1.1
Host: target.example:10808
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0
```

```text
# 预期：HTTP/1.1 200
# {"code":200,"data":{"userId":1,"username":"admin","name":"小智","isAdmin":"1","roleId":"1","email":...,"wxOpenId":null,...},"message":"操作成功"}
```

```http
GET /api/user/queryUsers HTTP/1.1
Host: target.example:10808
Accept: application/json, text/plain, */*
```

```text
# 预期：HTTP/1.1 200，data.list 返回 sys_user 记录（userId、username、name、isAdmin、roleId、email、tel、wxOpenId 等），
# 文章实测返回 admin 记录，total=1。
```

## 变体与关联

- 变体：`/api/user/` 前缀下其他接口（如 `/api/user/update`）同样被放行，可进一步做未授权写操作。
- 变体：`queryUsers` 的条件参数（email/tel/name/isAdmin）可用于精确检索与批量枚举。
- 关联：[[web-generic-auth-xiaozhi-cookie-username-impersonation]]（用泄露的 username 直接建会话）；[[web-generic-auth-xiaozhi-unauth-user-update-password-reset]]（用泄露的 username 重置任意用户密码）；[[web-generic-auth-type-dispatch-unauth-data-exposure]]（未授权用户数据接口的同类模式）；[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]（拦截器白名单匹配缺陷）。
- 边界：文章实测 `/api/user/query` 与 `/api/user/queryUsers` 均未登录返回用户数据；未验证 `queryUsers` 是否返回密码哈希（截图未显示 password 字段）。

## 检测与防御

- 检测：审计拦截器白名单是否使用宽泛前缀；逐个核对白名单前缀下的所有路由与 HTTP 方法；监控未登录访问 `/api/user/query`、`/api/user/queryUsers` 的请求与批量枚举行为。
- 修复：白名单改为精确路由（如 `/api/user/login`、`/api/user/register`），不要用 `/api/user/` 前缀；对查询/列表/更新接口强制认证与角色校验。
- 加固：响应中最小化用户字段（不返回 email/tel/wxOpenId 等敏感信息）；对用户查询做限流与审计；管理端接口与前台接口分域部署。
