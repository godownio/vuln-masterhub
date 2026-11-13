---
id: web-generic-http-smuggling-reflected-xss-delivery
title: 请求走私投递反射型 XSS：把恶意 User-Agent 藏进走私请求，让下一受害者的响应执行脚本
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-reflected-xss-delivery
tags:
- http-smuggling
- xss
- reflected-xss
- user-agent
- response-queue-poisoning
- cl-te
- http1
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:50+08:00'
  notes: '已对照原文『XSS反射』节及图58-60核对：外层 CL 150 + 0 块后 GET /post?postId=5，User-Agent: a\"/><script>alert(1)</script>，内层 CL 5 + x=1；图58请求一致，图59触发 alert(1)，图60 Solved。原理（无需交互、可污染请求头）与原文一致。未验证点：未本机复跑；无 sources；无版本/CVE。dedup：与 h2-response-queue-poisoning-session-capture（目标劫持会话）、xss-request-header-html-attribute-breakout（单纯头反射）不同链，保留。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-reflected-xss-delivery/
draft: false
kb_aliases:
- 走私投递反射 XSS
- deliver reflected XSS
- User-Agent 反射 XSS
- 响应队列投毒 XSS
- 无交互 XSS
---

## 一句话结论

当应用在 `User-Agent` 等请求头中反射 XSS 时，普通反射 XSS 无法让受害者发送自定义头；利用请求走私把带 `<script>` 的请求头塞进后端连接，下一个受害者的请求被拼接后收到该响应，脚本便在其浏览器中执行，无需诱导点击链接。

## 原理

- 反射型 XSS 的常规利用依赖受害者访问带 payload 的 URL；若反射点位于 `User-Agent`、`Referer` 等请求头，攻击者无法让受害者浏览器发送自定义头，漏洞难以实际利用。
- 请求走私可以控制"受害者收到的响应属于哪个请求"：攻击者先把一条带恶意 `User-Agent` 的请求走私到后端连接，后端处理它并生成含 payload 的响应；前端按请求顺序把该响应交给同一连接上的下一个请求者。
- 受害者随后通过同一前端连接发请求，收到的却是攻击者走私请求的响应（其中反射了恶意 User-Agent），浏览器执行 `<script>alert(1)</script>`。
- 为什么优于普通反射 XSS：无需给受害者发链接、无需交互；还能利用普通 XSS 无法控制的部分（如请求头）作为注入点。
- 该手法本质是响应队列错位/响应投毒；成立依赖前后端连接复用与响应顺序绑定。

## 触发条件

- 存在请求走私原语（CL.TE 等），前后端复用连接。
- 应用在某个请求头（`User-Agent`、`Referer`、`X-Forwarded-*` 等）中反射未编码输入，且反射出现在页面 HTML 中。
- 受害者会通过同一前端/后端连接发起后续请求（实验室为模拟用户，真实场景为高并发站点）。
- 反射的 payload 不需要额外的 CSP 绕过；若站点有严格 CSP，需配合其他绕过。

## 利用步骤

1. 确认反射点：抓包修改 `User-Agent` 为 `<script>alert(1)</script>`，观察响应页面是否原样反射。
2. 确认走私原语：用时间延迟或差分响应确认 CL.TE/TE.CL。
3. 构造走私请求：外层 `POST /` 带 `Transfer-Encoding: chunked` 与覆盖整包的 `Content-Length`，正文 `0` 块后写 `GET /post?postId=5 HTTP/1.1`、`User-Agent: a"/><script>alert(1)</script>`、`Content-Type`、`Content-Length: 5` 与 `x=1`。
4. 发送后等待下一受害者请求；受害者浏览器收到含 payload 的响应并执行。
5. 可把 payload 换成更完整的利用代码（窃取 Cookie、发起操作），但需注意响应归属与长度匹配。

## PoC

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

说明：`0` 块后为带恶意 User-Agent 的走私请求；后端生成含反射 payload 的响应，前端把它交给下一请求的受害者。payload 中的 `a"/>` 用于闭合原页面属性。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：反射点可换成 `Referer`、`Origin`、`X-Forwarded-Host` 等请求头；payload 可为 `<script>fetch('/account')</script>` 等。
- 变体：与缓存投毒结合，把恶意响应缓存到公共 URL，扩大影响面。
- 关联：[[web-generic-http-smuggling-capture-victim-requests-oversized-cl]]（同类的"污染下一用户请求"手法，目标是窃取 Cookie）、[[web-generic-http-smuggling-h2-response-queue-poisoning-session-capture]]（响应队列投毒劫持会话）、[[web-generic-cache-poisoning-smuggling-redirect-static-asset]]（把走私响应写入缓存）。
- 边界：前后端不复用连接、响应严格按请求一一对应、或反射输出被编码/CSP 拦截时，本链不成立。

## 检测与防御

- 检测：同一连接上响应内容与请求不匹配；用户收到含攻击者 User-Agent 的页面；请求体 `0` 块后出现完整请求行；同一前端连接出现多个后端请求。
- 防御：对请求头输出做 HTML 编码；拒绝 CL+TE 并存；前端重新序列化请求；禁用后端连接复用；部署响应队列一致性检测。
- 加固：CSP 作为纵深防御；WAF 检测头中的 `<script` 与走私特征；会话 Cookie 使用 `HttpOnly` 降低 XSS 窃取影响。
