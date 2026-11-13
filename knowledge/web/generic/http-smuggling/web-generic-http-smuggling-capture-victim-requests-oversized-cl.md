---
id: web-generic-http-smuggling-capture-victim-requests-oversized-cl
title: 捕获其他用户请求：走私一个 Content-Length 大于实际 body 的存储型 POST，让下一受害请求被拼进评论字段并回显其 Cookie
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-capture-victim-requests
aliases:
- capture other users' requests
- 捕获他人请求
- 超长 Content-Length 走私
- 评论字段窃取 Cookie
- 存储型请求拼接
tags:
- http-smuggling
- session-hijacking
- cookie-theft
- stored-xss
- content-length
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
  verified_at: '2026-11-12T20:50:48+08:00'
  notes: 已对照原文『越权操作』节及图49-57核对：外层 CL 330 + 0 块后走私 POST /post/comment（内层 CL 400、comment= 结尾），受害者请求被拼入评论并带出 session；原文随后按 600/800/808 试错并在图54/55得到 Cookie，替换 SESSION 登录 carlos（图56/57）。卡片参数与原文一致；已把步骤2外层方法注明为原文概念示例 GET /、靶场截图 POST /。未验证点：未本机复跑；无 sources；无版本/CVE。dedup：client-side-desync 是浏览器侧 CSD、H2 response queue 是响应队列，机制不同，保留。
---

## 一句话结论

利用请求走私把一个"存储文本"的 POST 请求送进后端连接，并把该请求的 `Content-Length` 声明得远大于实际发送的 body；后端会等待剩余字节，此时下一个受害者的请求（含 Cookie、认证头）被拼接到请求体末尾并作为评论/资料内容存储，攻击者随后读取该内容即可拿到受害者会话。

## 原理

- 应用存在存储文本的功能（评论、个人简介、昵称、邮件等），提交的参数会被持久化并在页面展示。
- 攻击者走私一个 `POST /post/comment` 请求到后端连接，把要存储的参数（如 `comment=`）放在 body 最后，并把该请求的 `Content-Length` 设为大于实际发送长度（例如声明 400，只发 144 字节）。
- 后端按 CL 认为 body 还缺 256 字节，保持连接等待；前端认为外层请求已结束，把下一个用户的请求（同一后端连接）继续转发。
- 受害者请求的前 256 字节被后端当作走私 POST 的 body 续写，正好接在 `comment=` 之后，于是受害者的请求行、Host、Cookie、User-Agent 等全部成为评论内容的一部分。
- 为什么成立：请求边界由 CL 决定而后端信任未完成的 body；受害者请求在传输层是合法的下一个请求，但在后端解析层被并入上一个请求的参数值。
- 长度需要试错：声明太小会立即结束、太大则等待超时；典型做法是从 600 起逐步调整（如 600/800/808），直到 Cookie 完整出现在存储内容中。

## 触发条件

- 存在 CL.TE（或等价）走私原语：前端按非 chunked/CL 转发，后端按 TE 在 `0` 块结束并把后续作为新请求。
- 后端与前端之间复用连接，受害者请求会落在同一后端连接上。
- 应用有存储并展示文本的功能，且参数可放在请求体末尾。
- 攻击者能观察存储内容（公开评论页、个人资料等）。
- 目标有持续访问的受害者（实验室中为模拟用户），且 CL 可调整到覆盖其请求前缀。

## 利用步骤

1. 找到存储型文本功能（评论/资料），确认提交后内容会在页面展示。
2. 构造外层请求（原文概念示例用 `GET /`，靶场截图实际为 `POST /`）：带 `Transfer-Encoding: chunked` 与覆盖 `0` 块前缀的 `Content-Length`，正文 `0` 块后写完整的 `POST /post/comment` 请求。
3. 在走私 POST 中把 `comment=` 放在 body 最后，`Content-Length` 设为大于实际 body 的较大值（如 400/600），只发送到 `comment=` 为止。
4. 等待下一个用户请求到达并被拼接；刷新评论页，若评论中出现 `GET / HTTP/1.1`、`Cookie: session=...` 等，说明捕获成功。
5. 若内容不完整或超时，调整 CL（如 600→800→808）重新尝试；拿到受害者 session 后替换自己的 Cookie 登录受害者账户。
6. 若受害者 Cookie 未出现，可增大 CL 覆盖更多请求头，或换用其他存储点。

## PoC

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 330
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&name=Carlos+Montoya&email=carlos%40normal-user.net&website=https%3A%2F%2Fnormal-user.net&comment=
```

说明：走私 POST 声明 400 字节但实际只发送到 `comment=`，后端等待剩余字节；下一受害请求被拼入 comment 参数并存储。原文通过多次调整 CL（600/800/808）取得完整 session。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：存储点可换成昵称、个人简介、反馈、邮件模板；只要能持久化并回显即可。
- 变体：若受害者请求带 CSRF Token 或其他敏感头，也可一并捕获；捕获到的 Cookie 可直接用于会话劫持。
- 关联：[[web-generic-http-smuggling-cl-te-basic-chunk-prefix]]（外层走私原语）、[[web-generic-http-smuggling-reflected-xss-delivery]]（同类的"污染下一用户请求"手法）、[[web-generic-http-smuggling-h2-response-queue-poisoning-session-capture]]（另一种捕获会话的响应队列攻击）。
- 边界：前端按 chunked 解析且后端不等待额外字节、前后端不复用连接、或存储内容不对外展示时，本链不成立。

## 检测与防御

- 检测：评论/资料中出现 HTTP 请求行、`Cookie:`、`User-Agent:` 等异常内容；后端收到 CL 大于实际 body 的请求并长时间等待；同连接请求数异常；存储内容长度远超用户输入。
- 防御：前端与后端统一解析并拒绝 CL+TE 并存/超长 CL；代理到后端禁用连接复用；存储功能对输入做长度与内容校验；会话 Cookie 使用 `HttpOnly`/`SameSite` 降低被拼接后的可利用性（但不能阻止泄露）。
- 加固：后端设置短读取超时并关闭不完整请求连接；对存储内容做敏感模式检测（HTTP 请求行、Cookie 头）；部署 desync 检测。
