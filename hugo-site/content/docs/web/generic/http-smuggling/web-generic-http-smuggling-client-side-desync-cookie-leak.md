---
id: web-generic-http-smuggling-client-side-desync-cookie-leak
title: 客户端去同步（CSD）：浏览器 fetch 走私前缀污染连接并泄露受害者 Cookie
type: scenario
domain: web
path: web/generic/http-smuggling
technique: client-side-desync-cookie-leak
tags:
- http-smuggling
- desync
- csrf
- browser
- fetch
- cookie-leak
- cors
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V605
  verified_at: '2026-11-12T18:34:17+08:00'
  notes: '已对照原文与图09-27核对：CSD 原理图（图09）、POST / 改 CL110 无 body 立即 302 确认忽略 CL（图12）、单连接序列确认 desync（图13-14）、CL631 嵌套评论请求与 /capture-me 拼接后 302 到评论确认页（图15-16）、评论区回显 GET /capture（图17）；浏览器 fetch+CORS 错误+catch 续发 /capture-me，Network 两请求（图18-19），回显 HeadlessChrome 受害者完整请求与 Cookie: victim-fingerprint/secret/session（图24-25），盗用 Cookie 访问 /my-account 并 Solved（图26-27）。卡片机制、fetch PoC（CL300、credentials include、CORS 错误后 no-cors）与原文一致。已修正一处笔误：利用步骤6 的 PHPSESSID 改为原文实际的 session Cookie（库内卡片与 staging 草稿同步修正）。原文未给受影响版本，affected_versions 保持 null；未在本机复现。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-client-side-desync-cookie-leak/
draft: false
kb_aliases:
- Client-side desync
- CSD
- 浏览器去同步
- browser-powered desync
- fetch 走私
- 客户端去同步攻击
---

## 一句话结论

客户端去同步（CSD）不需要前后端解析差异：只要服务器在某些端点忽略 Content-Length 并保持连接复用，攻击者页面用 JavaScript `fetch` 发送一个 body 内含完整 HTTP 请求前缀的 POST，服务器响应后把该前缀留在浏览器-服务器连接上，浏览器复用连接发出的下一个请求就会拼接到前缀之后；若走私前缀是一个会把请求（含 Cookie 头）写入评论/日志的接口，攻击者即可读取受害者 Cookie 并接管会话。

## 原理

- **去同步发生在浏览器与网站之间**：CSD 与服务器间请求走私类似，但不同步的是“受害者浏览器 ↔ 易受攻击网站”的 TCP/TLS 连接，不依赖两台服务器解析差异，单服务器站点也可能中招。
- **连接复用是放大器**：浏览器对同一 origin 复用 keep-alive 连接；攻击者先让浏览器发送一个 POST，body 中包含 `POST /comment HTTP/1.1 ... Content-Length: <较短>` 的走私前缀；服务器按自己的 CL 读取/忽略 body 并响应，但连接上残留了前缀之后的字节。
- **下一个请求被拼接**：随后 `fetch('.../capture-me')` 复用同一连接，浏览器把 `GET /capture-me HTTP/1.1...Cookie: ...` 追加到残留前缀之后；服务器把整段当作“前缀请求的 body”，若前缀是评论提交接口，这段内容（含受害者 Cookie 头）就被存进评论并在页面回显。
- **为什么要制造 CORS 错误**：攻击者用 `fetch(..., {mode:'cors', credentials:'include'})` 触发请求；由于目标不返回 ACAO，浏览器抛出 CORS 错误并不跟随重定向；在 `.catch()` 里再发第二个 `no-cors` fetch，确保连接被复用并附加到中毒前缀。
- **利用条件**：目标存在忽略 CL 的端点；服务器在响应后保持连接；攻击者能让受害者访问恶意页面并执行 JS；目标接口会把请求头/请求行回显到攻击者可读位置（评论、日志、错误页）。
- **危害**：泄露受害者 Session Cookie/CSRF Token，进而以受害者身份操作；配合存储型回显还可持久化窃取。

## 触发条件

- 服务器对某些端点忽略 Content-Length 并复用连接（与 CL.0 相同的前置条件）。
- 受害者浏览器允许攻击者页面发起跨站 fetch（`credentials: 'include'` 需目标未设置严格 SameSite/跨域限制，或攻击者页面与目标同站）。
- 存在把请求内容/头写入可读位置的接口（评论、反馈、日志预览等）。
- 受害者会访问攻击者控制的页面。

## 利用步骤

1. 寻找忽略 CL 的端点：在 Burp 中把 `GET /` 改成 `POST`，设置一个较大 `Content-Length` 但不发 body；若服务器立即响应而不等待，说明忽略 CL。
2. 用 Repeater tab group（single connection）确认：POST + 走私前缀 + 后续正常请求，第二个响应返回前缀路径（如 404 /hopefully404）即确认可去同步。
3. 在浏览器复现：用 `fetch` 把完整走私请求放进 body，制造 CORS 错误，再在 catch 中 fetch 目标“capture”路径；Network 面板应看到两个请求（主请求 CORS error、capture 请求 404）。
4. 构造泄露：走私前缀改为评论/留言接口（Content-Length 截断在 body 前），让下一个请求（含 Cookie）成为评论内容；刷新页面确认评论里出现自己的请求头。
5. 在漏洞利用服务器托管该 JS，诱导受害者访问；刷新评论区读取受害者 Cookie。
6. 用窃取的 `session` Cookie 访问 `/my-account` 验证会话接管。

## PoC

```html
<script>
fetch('https://<target>', {
  method: 'POST',
  body: 'POST /en/post/comment HTTP/1.1\r\nHost: <target>\r\nCookie: session=<victim-session>\r\nContent-Length: 300\r\nContent-Type: x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\ncsrf=<token>&postId=2&name=QWQQ&email=a@b.c&website=http://x&comment=',
  mode: 'cors',
  credentials: 'include',
}).catch(() => {
  fetch('https://<target>/capture-me', {
    mode: 'no-cors',
    credentials: 'include'
  })
})
</script>
```

若评论中出现 `GET /capture-me HTTP/1.1 ... Cookie: ...`，即说明受害者请求被拼接到走私前缀并泄露。

## 变体与关联

- **变体（暂停型 CSD）**：利用后端读取超时在浏览器连接上注入前缀。
- **变体（单服务器）**：不需要代理/后端解析差异，单台 Apache/Nginx 也可能因忽略 CL 触发。
- **变体（泄露目标）**：Session Cookie、CSRF Token、Authorization 头、内网页面内容。
- **关联**：[[web-generic-http-smuggling-cl0-backend-ignores-content-length]]（CL.0 条件与服务端版本）、[[web-generic-http-smuggling-pause-based-desync-timeout]]（超时注入）、[[web-generic-csrf-samesite-strict-bypass-client-side-redirect]]（浏览器侧跳转与 SameSite 背景）。
- **边界**：服务器严格按 CL 读取 body、响应后关闭连接、浏览器不复用连接、目标 Cookie 为 SameSite=Strict/跨站 fetch 被阻止、或没有可回显请求内容的接口时，CSD 不成立。

## 检测与防御

- **修复**：服务端一致地校验/消费 Content-Length，对不读取 body 的端点显式拒绝带 body 的请求；不要让连接在“未消费 body”的状态下复用。
- **缓解**：在敏感/静态端点强制 `Connection: close`；对请求体中出现 `GET /`/`POST /` 请求行特征的请求做拦截；Cookie 设置 `SameSite=Lax/Strict`、`Secure`、`HttpOnly`。
- **检测**：浏览器请求 body 中出现完整 HTTP 请求行；同一连接上出现被拼接的请求；评论/日志中出现 `GET /... HTTP/1.1` 与 Cookie 头；异常 CORS 错误后紧跟 no-cors 请求。
