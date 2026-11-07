---
id: web-generic-auth-unsigned-cookie-admin-keys
title: 无签名 Cookie 作为身份凭证导致后台登录伪造（admin_keys=2）
type: scenario
domain: web
path: web/generic/auth
technique: unsigned-cookie-auth-bypass
aliases:
- Cookie 伪造登录
- admin_keys=2
- 无 Session 认证
- Cookie 认证绕过
- 用户后台身份伪造
- 客户端信任绕过
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- auth-bypass
- cookie
- session
- privilege-escalation
- client-side-trust
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:34:20+08:00'
  notes: 已对照原文与图 22-25 核对：login.php 账号密码校验后 setcookie('admin_keys','2') 且无 session_start，后台直接信任 Cookie；设置 admin_keys=2 可进管理后台；用户侧 setcookie user_key/user_key2/username/bdmail 同样可伪造；均与原文一致。
---

## 一句话结论

登录成功后服务端只用 `setcookie('admin_keys','2',...)` 下发一个固定值 Cookie 表示管理员身份，后台页面直接信任该 Cookie、没有 `session_start`、没有签名/HMAC、没有服务端会话校验；攻击者手动设置 `admin_keys=2` 即可未授权访问管理后台，用户侧同理可伪造 `user_key` 等 Cookie 进入用户后台。

## 原理

- 正常认证应把身份状态保存在服务端（Session）或使用带签名/加密的令牌（如 JWT），客户端只持有不可伪造的句柄。该程序在账号密码校验通过后直接：
  ```php
  setcookie('admin_keys', '2', time() + 1800, '/');
  header('Location: index.php');
  ```
  没有 `session_start()`，也没有把用户 ID/角色绑定到服务端状态。
- 后台页面判断管理员身份时读取 `$_COOKIE['admin_keys']`（或等价逻辑），只要值等于预期（如 `2`）就放行。Cookie 完全由客户端控制，浏览器开发者工具或代理都能任意修改，因此该判断等价于“用户自称是管理员”。
- 管理员的 Cookie 值是常量 `2`，不随用户/会话变化，也不含随机数或签名；攻击者无需知道任何密码即可复制该值。
- 用户侧同样把 `user_key`、`user_key2`、`username`、`bdmail` 等身份信息写在 Cookie 中并直接信任，攻击者修改这些值即可冒充其他用户或访问用户后台。
- 根本问题是**把客户端可修改的数据当作可信身份凭证**，缺少服务端状态与完整性保护；Cookie 的 `HttpOnly` 只能降低 XSS 窃取风险，不能阻止用户自己伪造。

## 触发条件

1. 目标使用 Cookie 作为登录态，且 Cookie 值可预测/固定（如 `admin_keys=2`）。
2. 服务端没有对 Cookie 做签名、加密或服务端会话映射。
3. 后台/用户中心仅依据该 Cookie 判断身份，未再次校验服务端会话。
4. 攻击者能访问登录页/后台入口（无需有效账号）。

## 利用步骤

1. 访问目标后台登录页，确认认证方式（观察响应 `Set-Cookie`、是否存在 `PHPSESSID`）。
2. 在浏览器控制台或代理中设置 `admin_keys=2`（或登录响应中观察到的管理员 Cookie 值）。
3. 直接访问 `/admin/index.php` 等后台页面，确认无需登录即可进入。
4. 同理枚举/修改用户侧 Cookie（`user_key`、`user_key2`、`username`、`bdmail`），访问用户中心。
5. 在后台执行管理员操作、读取敏感数据，或结合其他漏洞进一步利用。

## PoC

浏览器控制台：

```javascript
document.cookie = "admin_keys=2";
```

随后访问：

```text
http://target/admin/index.php
```

原文实测可直接进入管理后台（无需输入账号密码）。

用户侧伪造示例：

```http
GET /index.php HTTP/1.1
Host: target
Cookie: user_key_u_cWHbEF=aaa; user_key=aaa; user_key2=aaa; username=aaa
```

服务端据此把请求识别为用户 `aaa`，返回该用户的个人中心内容。

## 变体与关联

- 同类问题包括：Cookie 中直接存 `role=admin`、`isAdmin=true`、`uid=1`，或 Base64 编码但未签名的 JSON 身份对象。
- 与 JWT 仅校验签名/不校验角色、Session 固定、记住我令牌可预测等问题同属认证与会话缺陷。
- 若 Cookie 同时被 XSS 读取（未设 HttpOnly），可与存储型 XSS 组合劫持管理员身份。
- 该程序的管理员与用户两套登录都使用 Cookie 认证，说明缺陷是系统性的，审计时应检查所有身份判断点。

## 检测与防御

- 使用服务端 Session 保存登录态，登录成功后 `session_regenerate_id(true)`，身份与角色只从服务端会话读取。
- 若必须使用 Cookie 令牌，使用 HMAC/加密签名并绑定用户、过期时间、随机 nonce；服务端验签失败即拒绝。
- 不要把角色、用户 ID 等身份信息明文放在客户端 Cookie 中；Cookie 设置 `HttpOnly`、`Secure`、`SameSite`。
- 后台所有入口统一做服务端鉴权中间件，禁止各页面自行判断 Cookie 值。
- 代码审计搜索 `setcookie(` 后接身份字段、`$_COOKIE[...]` 直接用于权限判断、缺少 `session_start` 的登录逻辑。
