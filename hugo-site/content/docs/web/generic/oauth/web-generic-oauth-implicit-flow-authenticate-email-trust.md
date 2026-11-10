---
id: web-generic-oauth-implicit-flow-authenticate-email-trust
title: OAuth 隐式流程客户端 /authenticate 信任请求体 email：用自己的 token 改 email 即可登录他人账户
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-implicit-flow-client-email-trust-auth-bypass
tags:
- web
- oauth
- implicit-flow
- auth-bypass
- account-takeover
- openid
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:07:14+08:00'
  notes: '已对照原文 Lab: Authentication bypass via OAuth implicit flow 与图01-10核对：/oauth-callback 前端 JS 从 location.hash 取 access_token，调 /me 后 POST /authenticate 提交 email/username/token（图08/09），把 email 改为 carlos@carlos-montoya.net 后 302 建会话并显示 carlos（图10）。卡内原理、触发条件与 PoC 与原文一致；无版本信息，未设 affected_versions。未执行靶场。'
url: /docs/web/generic/oauth/web-generic-oauth-implicit-flow-authenticate-email-trust/
draft: false
kb_aliases:
- OAuth implicit flow 认证绕过
- 修改 email 登录他人账户
- /authenticate email 篡改
- 隐式流程 token 冒用
- implicit flow account takeover
---

## 一句话结论

OAuth 隐式流程下，客户端回调页会用 `access_token` 调 `/me` 取资料，再把 `email`/`username`/`token` 提交给 `/authenticate` 建立会话；如果 `/authenticate` 用请求体里的 `email`（而不是 token 的 `sub`）决定登录哪个账户，攻击者拿自己的合法 token、只把 `email` 改成受害者邮箱，就能登录受害者账户。

## 原理

- 隐式流程把 `access_token` 放在回调 URL 的 fragment 里返回；客户端 JS 从 `location.hash` 解析 token，调用 `/me`（`Authorization: Bearer <token>`）取得 `sub`、`name`、`email`、`email_verified` 等资料，再 `POST /authenticate` 用这些资料换取本站会话。
- 问题在于身份映射：`/authenticate` 收到 `{email, username, token}` 后，如果以 `email` 作为本站账户的唯一查找键，只把 `token` 当作"已登录 OAuth"的形式凭证，而不校验 `email` 是否等于 token 对应 `sub` 的资料，攻击者就能在请求体里写任意受害者的 `email`。
- 本例 `/me` 返回的 `email_verified: true` 只说明 OAuth 提供方验证过该邮箱；它不能证明请求体里的 `email` 属于当前 token。服务端必须用 token introspection/userinfo 重新取 `email`，或直接用 `sub` 做账户映射。
- 该缺陷位于客户端应用，而不是 OAuth 提供方：提供方按规范返回了正确 token 与资料，客户端却在"token → 用户"的映射上信任了客户端提交的参数。

## 触发条件

- 目标使用 OAuth/OIDC 隐式流程（`response_type=token`）登录，回调页是客户端 JS。
- 客户端有一个类似 `/authenticate` 的接口，接收前端提交的 `email`/`username` 与 `token` 并创建会话。
- 服务端不校验提交的 email/username 与 token 的 `sub`/userinfo 是否一致，或校验可被绕过。
- 攻击者拥有一个自己的合法 OAuth 账号（能拿到有效 token 与 /me 资料）。

## 利用步骤

1. 用自己的 OAuth 账号（如 `wiener:peter`）完成隐式流程登录，用代理抓取回调页的 JS 与后续请求。
2. 记录 `/me` 的 Bearer 请求与响应（包含 `sub`、`email`），以及 `POST /authenticate` 的请求体。
3. 在 Burp Repeater 中重放 `/authenticate`，保持 `token` 与 `username` 不变，把 `email` 改为受害者的邮箱（如 `carlos@carlos-montoya.net`）。
4. 发送后若返回 302 与新的 `session` Cookie，说明服务端按邮箱切换了账户。
5. 用该会话访问 `/my-account`，确认已是受害者账户；随后按目标业务继续操作（本例删除 carlos 完成靶场）。

## PoC

正常回调页的核心逻辑（简化）：

```javascript
const params = new URLSearchParams(window.location.hash.substr(1));
const token = params.get('access_token');
fetch('/me', { headers: { 'Authorization': 'Bearer ' + token } })
  .then(r => r.json())
  .then(user => fetch('/authenticate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: user.email, username: user.sub, token })
  }))
  .then(() => { location = '/'; });
```

篡改请求：

```http
POST /authenticate HTTP/1.1
Host: target
Cookie: session=<自己的会话>
Content-Type: application/json

{"email":"victim@example.com","username":"wiener","token":"<自己的 access_token>"}
```

响应：

```http
HTTP/1.1 302 Found
Location: /
Set-Cookie: session=<受害者的新会话>; HttpOnly; SameSite=None
```

## 变体与关联

- 变体：改 `username` 而不是 `email`；或两者同时改，取决于服务端以哪个字段查账户。
- 变体：若 `/authenticate` 会先验证 token 再取 email，可尝试 token 与 body 的解析差异（重复字段、大小写、Unicode、邮箱别名）制造不一致。
- 变体：OIDC 场景可尝试 `id_token` 的 `email` 声明与 `sub` 不一致，或把 `email_verified` 当授权依据。
- 关联：[[web-generic-oauth-missing-state-account-link-csrf-takeover]]（OAuth 身份绑定缺少会话校验的另一条账户接管路径）。
- 关联：[[web-generic-oauth-postmessage-code-theft-sso-bind-xxe]]（授权码窃取 + SSO 绑定提权）。
- 边界：服务端若始终以 token 的 `sub` 映射账户、或对 token 做 introspection 后取 email，则本手法不成立。

## 检测与防御

- 修复：服务端收到 `/authenticate` 时必须用 `token` 重新调用 OAuth 提供方的 userinfo/introspection 取得 `sub` 与 `email`，以 `sub`（issuer+sub）映射本站账户；绝不能用前端提交的 email/username 作为身份键。
- 修复：校验 token 的 `aud`（必须等于本客户端）、`iss`、`exp`；隐式流程优先迁移到授权码 + PKCE。
- 检测：同一 token 在短时间内为多个不同 email 创建会话；`/authenticate` 请求体中 email 与 token 的 userinfo 不一致；新会话的 IP/设备与 OAuth 授权时的会话不符。
- 检测：审计前端回调 JS 与后端认证接口，确认身份字段只来自 token 解析结果；对会话创建接口做参数与 token 一致性校验。
