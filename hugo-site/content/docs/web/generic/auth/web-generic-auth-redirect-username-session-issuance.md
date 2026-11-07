---
id: web-generic-auth-redirect-username-session-issuance
title: 登录重定向接口按 username 签发会话：改 username=admin 获取管理员 Session
type: scenario
domain: web
path: web/generic/auth
technique: redirect-username-session-issuance
tags:
- web
- auth
- session
- auth-bypass
- redirect
- idor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:48:09+08:00'
  notes: '已对照原文与图22-25核对：/auth/redirect?username=testuser 响应含 X-Session-Key: youfindme 与 Set-Cookie SESSION，改 username=admin 取得新 SESSION 后访问 /admin 得到 flag；PoC 未在本机复现'
url: /docs/web/generic/auth/web-generic-auth-redirect-username-session-issuance/
draft: false
kb_aliases:
- 登录跳转接口会话泄露
- X-Session-Key
- username 参数签发 Session
- 任意用户会话获取
- auth/redirect 越权
---

## 一句话结论

登录跳转接口 `/auth/redirect?next=/dashboard&username=testuser` 不校验身份，直接按 `username` 参数签发会话（响应带 `X-Session-Key` 和 `Set-Cookie: SESSION=...`）；把 `username` 改成 `admin` 就能拿到管理员会话，再用该 Cookie 访问 `/admin` 即可越权。

## 原理

- 该接口把“身份认证”和“登录后跳转”混在同一个端点：它只读取 `next` 与 `username`，然后调用会话服务生成/返回该用户名的 Session，并 302 到 `next`。
- `username` 完全由客户端控制，接口没有先验证密码、验证码、SSO token 或当前会话；因此任何请求者都能为任意用户名申请会话。
- 响应中的 `X-Session-Key: youfindme` 与 `Set-Cookie: SESSION=...` 是会话材料：前者可能是会话签名/查询键或调试线索，后者是服务端签发的会话 Cookie。把 `username=testuser` 换成 `username=admin` 后，服务端按 admin 生成新的 `SESSION`。
- 访问控制只信任 `SESSION` Cookie 对应的用户，不重新核验认证来源；所以用 admin 的 `SESSION` 请求 `/admin` 就通过了管理员校验。
- 根因是“会话签发”没有绑定到已认证主体（authenticated subject），而是绑定到请求参数；`next` 参数只影响跳转地址，不是漏洞点。

## 触发条件

- 存在登录/SSO 回调或重定向端点，接受 `username`、`user`、`uid`、`account` 等参数并据此签发会话。
- 接口在签发会话前没有校验密码、token、当前会话或服务端保存的登录态。
- 会话 Cookie 可被客户端直接使用，且下游权限判断只看会话中的用户名/角色。
- 目标存在高权限账户（如 `admin`），且管理员路由只校验会话。

## 利用步骤

1. 以普通用户或未登录状态访问 `GET /auth/redirect?next=/dashboard&username=testuser`，观察 302 响应中的 `X-Session-Key` 与 `Set-Cookie: SESSION=...`。
2. 记录普通用户的 `SESSION` 值，请求 `/dashboard` 确认该 Cookie 可用。
3. 把 `username` 改为 `admin`，重新发送同一请求；服务端返回新的 `SESSION`（以及相同/不同的 `X-Session-Key`）。
4. 用 admin 的 `SESSION` 访问 `/admin`、`/admin/flag` 等管理路由；若返回 200 且包含 flag/管理数据，说明会话越权成立。
5. 若接口只返回 `X-Session-Key` 而不直接设置 Cookie，尝试把该值作为 `X-Session-Key` 请求头、查询参数或 Cookie 使用；按目标实现调整。
6. 若 `username` 不是明文（如 base64/hex），按目标编码后再提交；若接口还校验 `next` 白名单，把 `next` 设为合法站内路径。

## PoC

```bash
# 1) 普通用户会话
curl -i 'https://target/auth/redirect?next=/dashboard&username=testuser'

# 2) 改为 admin，获取管理员会话
curl -i 'https://target/auth/redirect?next=/dashboard&username=admin'

# 3) 用返回的 SESSION Cookie 访问管理路由
curl -i -b 'SESSION=<admin_session_value>' 'https://target/admin'
```

```http
GET /auth/redirect?next=/dashboard&username=admin HTTP/2
Host: target

HTTP/2 302 Found
Location: /dashboard
X-Session-Key: youfindme
Set-Cookie: SESSION=<admin_session>; HttpOnly; Path=/
```

## 变体与关联

- 变体：`username` 放在 POST body、JSON、`X-User` 头或 `next` 的嵌套参数中；只要会话签发逻辑读取它且不校验认证，效果相同。
- 变体：接口返回的是签名后的令牌（JWT/自定义 Cookie），但服务端为任意 username 签发，仍然等价于任意用户登录；需要检查签名密钥是否固定/可预测。
- 变体：`X-Session-Key` 可能是固定的全局密钥（示例 `youfindme`），可结合会话 Cookie 伪造/解密；若会话 Cookie 是 `username` 的可预测编码，可直接构造。
- 关联卡片：[[web-generic-auth-two-step-password-hidden-userid-header-trust]]（客户端 user_id/X-UserId 信任）、[[web-generic-auth-cookie-base64-identity-forgery]]（Cookie 身份伪造）、[[web-generic-auth-login-phone-any-password]]（登录校验缺失）。
- 边界：如果服务端在签发前要求有效登录态，或 `username` 与会话绑定到当前认证主体，则本场景不成立；`next` 开放重定向是另一个问题，不应与本节混淆。

## 检测与防御

- 检测：审计所有“重定向/回调/SSO”端点中对 `username`/`uid` 参数的使用；用普通账号重放并替换为 `admin`，观察是否返回不同用户的会话。
- 修复：会话只能由已认证主体签发；重定向端点只负责跳转，不负责登录；不要把用户名作为会话身份的唯一来源；对会话 Cookie 使用 HttpOnly/Secure/SameSite 并在服务端保存登录态。
- 加固：对管理路由做二次鉴权（角色 + 会话 + 来源校验）；限制 `next` 为站内白名单；监控同一 IP 短时间内为多个用户名签发会话的异常。
