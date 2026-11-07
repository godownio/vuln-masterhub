---
id: web-generic-auth-gettokenbyid-userid-token-issuance
title: 未授权 getTokenById 接口按 userId 签发 token 导致管理员账户接管
type: scenario
domain: web
path: web/generic/auth
technique: unauth-userid-token-issuance
tags:
- auth
- token
- idor
- unauthorized
- account-takeover
- java
- spring
- api
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:04:20+08:00'
  notes: '已对照全文与图01/02/03核对：GET /zhq/system/user/getTokenById?userId=1 以空 Authorization: Bearer 请求返回 200；随后 /zhq/getInfo 返回 roles=["admin"]、userId=1、nickName=超级管理员（图01）；/system/user/list?pageNum=11&pageSize=10000 拉取约302KB用户列表（图02），后台/移动端可查校友 PII（图03）。卡内步骤与 PoC 与原文一致。未验证点：原文响应为打码后的 {"code":200,"msg":"已打码","data":null}，token 字段/值未展示，具体 token 位置为据叙述推断；PoC 未在本机执行。frontmatter 无 sources/source_url（全库惯例）。'
url: /docs/web/generic/auth/web-generic-auth-gettokenbyid-userid-token-issuance/
draft: false
kb_aliases:
- getTokenById 未授权
- userId 换 token
- 任意用户 token 签发
- 管理员 token 接管
- 接口越权签发 token
---

## 一句话结论

当系统提供 `getTokenById?userId=<id>` 这类“按用户 ID 签发 token”的接口且未校验调用者身份时，攻击者无需登录即可传入管理员 `userId`，取得管理员 token，接管后台并访问用户列表、系统配置等敏感接口。

## 原理

- 正常登录流程应先验证账号口令或已有会话，再把 token 绑定到“当前认证主体”。`getTokenById` 把签发对象完全交给请求参数 `userId`，等于把“我是谁”的决定权交给调用者。
- 接口没有认证中间件（或认证中间件对该路径放行），且签发逻辑没有校验“调用者是否有权代表该 userId”，因此任意人传 `userId=1` 就能拿到 1 号用户的 token。
- 服务端后续只校验 token 的签名/有效性，不再区分 token 是登录签发还是该接口签发；拿到管理员 token 后，`/getInfo` 会返回 `roles: ["admin"]`、`userId: 1` 等身份信息，所有管理员接口随之开放。
- 这类漏洞常见于“SSO/单点登录回调”“内部用户切换”“移动端免密登录”等辅助接口：开发为了方便按 userId 查 token，却忘了加调用者鉴权。
- 危害是垂直越权到管理员：可读取全量用户信息（含手机号、邮箱、身份证等 PII）、系统配置（可能含数据库口令、管理员账号口令）、后台功能，并进一步利用后台的报表/文件接口。

## 触发条件

- 目标存在按 userId 签发/查询 token 的接口（如 `/system/user/getTokenById`，前缀随部署不同）。
- 该接口不需要有效认证，或认证可被空 Bearer/伪造头绕过。
- 攻击者知道或能枚举管理员 userId（常见为 1；也可从用户列表、注册接口、错误信息推断）。
- 签发的 token 被后续接口接受，且管理员账号未被额外风控（IP 白名单、二次验证）限制。

## 利用步骤

1. 探测接口：对 `/system/user/getTokenById?userId=1` 发 GET，观察是否返回 200 与 token 字段；可尝试空 `Authorization: Bearer` 或直接不带认证头。
2. 枚举 userId：从 1 开始递增，或先从公开接口/注册流程获取自己的 userId，再推测管理员。
3. 提取响应中的 token（可能在 `data`、`data.token`、`access_token` 或响应头）。
4. 用该 token 请求 `/getInfo` 或等价“当前用户信息”接口，确认 `roles` 含 `admin`、`userId` 为目标管理员。
5. 用管理员 token 访问 `/system/user/list`、`/system/config/list` 等接口，收集用户 PII 与配置凭据；必要时登录后台继续利用报表/文件接口。

## PoC

```http
### 1) 未授权按 userId 取 token（无需有效登录态）
GET /zhq/system/user/getTokenById?userId=1 HTTP/1.1
Host: target
Authorization: Bearer

### 响应（原文打码）：{"code":200,"msg":"...","data":"<token>"}

### 2) 用 token 查当前身份
GET /zhq/getInfo HTTP/1.1
Host: target
Authorization: Bearer <token>

### 响应关键字段：
# "roles": ["admin"]
# "user": {"userId": 1, "userName": "...", "nickName": "超级管理员", ...}
```

```http
### 3) 管理员接口读取全量用户
GET /zhq/system/user/list?pageNum=11&pageSize=10000 HTTP/1.1
Host: target
Authorization: Bearer <token>
```

## 变体与关联

- 变体：接口名可能为 `getToken`、`getTokenByUserId`、`tokenById`、`switchUser`、`loginById` 等；参数可能为 `userId`、`id`、`username`。
- 变体：token 可能在响应体、`Set-Cookie`、响应头或重定向 URL 中返回。
- 变体：若接口要求“已登录”，但仍不校验目标 userId 与当前用户是否一致，则低权限用户可越权拿到管理员 token（水平→垂直）。
- 关联：[[web-generic-auth-login-header-userid-token-binding-takeover]]（登录头 userId 绑定缺陷）、[[web-generic-auth-jwt-signature-only-role-bypass]]（token 只验签名不验角色）、[[web-generic-auth-azuriom-servers-route-missing-gate-token-account-takeover]]（路由缺权限中间件签发 token）。
- 边界：接口已下线、加了调用者鉴权、管理员 userId 非 1 且不可枚举、token 绑定 IP/设备指纹时，利用难度上升或失效。

## 检测与防御

- 检测：审计对 `getTokenById`/`tokenById` 等签发接口的未认证请求；同一 IP 对 userId 的递增枚举；管理员 token 在异常 IP/设备上被使用；`/getInfo` 返回 admin 角色但无对应登录记录。
- 修复：删除按 userId 签发 token 的接口；如业务确需，必须要求调用者已认证，并校验“当前用户 == 目标 userId”或具备管理员授权；token 签发绑定认证主体、短有效期与来源。
- 加固：所有 token 签发接口纳入统一鉴权；管理员账号启用 2FA 与登录告警；对 userId 枚举做速率限制；定期审计敏感接口的未授权访问。
