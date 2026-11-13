---
id: web-generic-http-smuggling-cl0-backend-ignores-content-length
title: CL.0 请求走私：后端忽略 Content-Length 时前端/后端请求边界不一致
type: scenario
domain: web
path: web/generic/http-smuggling
technique: cl0-request-smuggling
aliases:
- CL.0
- Content-Length 0 走私
- 后端忽略 Content-Length
- CL.0 request smuggling
- 前端按CL后端忽略
tags:
- http-smuggling
- cl0
- content-length
- desync
- apache
- portswigger
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V605
  verified_at: '2026-11-12T18:34:15+08:00'
  notes: '已对照原文与图01-08逐项核对：POST /resources/images/blog.svg + Connection: keep-alive + CL34 + body GET /hopefully404，第二个响应 404（图03）确认后端忽略 CL；CL27 走私 GET /admin 拿到管理面板（图04，含 wiener/carlos 删除链接），CL50 走私 GET /admin/delete?username=carlos 返回 302 Location:/admin（图05-07），靶场 Solved（图08）。卡片原理（后端按0处理 body、前端按 CL 定界、单连接序列）、三个 PoC 的 CL 数值（34/27/50 均按正文逐字节核算正确）与原文一致；H2.0 已作变体说明。原文未给产品受影响版本，affected_versions 保持 null；未在本机复现。'
---

## 一句话结论

当链式系统中的后端服务器在某些端点上忽略 `Content-Length`（等价于把请求体长度当作 0），而前端仍按 `Content-Length` 决定请求结束位置时，攻击者发送一个正文里包含走私请求前缀的 POST 并保持连接，前端会把整个 CL 长度的字节转发给后端，后端响应第一个请求后把剩余字节当成新请求；后续复用该连接的请求会被拼接/污染，可用于访问前端 ACL 保护的管理面板。

## 原理

- **CL.0 不依赖 CL/TE 解析差异**：传统请求走私利用前端与后端对 `Content-Length`/`Transfer-Encoding` 的解析不一致；CL.0 的前提是后端“直接忽略 Content-Length”，把请求体视为空，而前端仍以 CL 为准。
- **哪些端点会忽略**：静态资源、重定向、某些框架的 GET-only 路由、错误页等，后端可能不读取 body；前端代理则严格按 CL 转发/等待。攻击者先用 `POST <endpoint>` + `Content-Length: 34` + body `GET /hopefully404 HTTP/1.1\r\nFoo: x`，再在同一连接发一个正常请求，若第二个响应变成 404，说明后端把 body 当成了新请求，CL.0 成立。
- **为什么需要单连接序列**：Burp Repeater 要把两个请求放入同一 tab group，用“Send group in sequence (single connection)”发送；否则不同连接无法复现连接级污染。
- **利用方式**：把走私前缀改成 `GET /admin HTTP/1.1` 或 `GET /admin/delete?username=carlos HTTP/1.1`，后端会在下一个请求处理它，绕过前端路由 ACL，直接访问管理功能。
- **H2.0**：HTTP/2 前端把请求降级为 HTTP/1 发给后端时，若后端忽略降级请求的 CL，同样形成与 CL.0 等价的走私（H2.0），检测/利用思路相同。
- **为什么危险**：前端基于路径的鉴权、WAF 规则、缓存键都可能被绕开；攻击者可读管理面板、执行敏感操作、投毒缓存。

## 触发条件

- 前端代理按 CL 确定请求边界，且保持后端连接复用（keep-alive）。
- 后端对部分端点忽略/不读取 Content-Length 指定的 body。
- 攻击者能与前端建立 keep-alive 连接并按顺序发送多个请求（或通过单连接组发送）。
- 目标存在值得绕过的前端 ACL/管理端点。

## 利用步骤

1. 在 Burp 中选定一个候选端点（静态资源、重定向端点等），发 `POST`，设置 `Connection: keep-alive`，body 放入 `GET /hopefully404 HTTP/1.1\r\nFoo: x`，CL 设置为该 body 长度。
2. 将“正常后续请求”与走私请求放入同一 Repeater tab group，使用“Send group in sequence (single connection)”发送。
3. 观察第二个请求的响应：若为 404（hopefully404），而非正常页面，说明前端把 body 当作后续请求、后端忽略了 CL，CL.0 成立。
4. 保持同一向量，把 body 中的路径改为 `GET /admin HTTP/1.1`，重发确认能拿到管理面板。
5. 按管理面板表单构造删除/操作请求（如 `/admin/delete?username=carlos`），完成敏感操作。
6. 换其他端点/路径 fuzz，确认影响面；注意请求顺序与连接复用。

## PoC

检测：

```http
POST /resources/images/blog.svg HTTP/1.1
Host: <target>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

随后在同一连接发送正常请求，若返回 `404 Not Found: /hopefully404`，说明 CL.0 成立。

利用：

```http
POST /resources/images/blog.svg HTTP/1.1
Host: <target>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

GET /admin HTTP/1.1
Foo: x
```

```http
POST /resources/images/blog.svg HTTP/1.1
Host: <target>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

GET /admin/delete?username=carlos HTTP/1.1
Foo: x
```

## 变体与关联

- **变体（H2.0）**：HTTP/2 降级为 HTTP/1 时后端忽略 CL，形成 H2.0 走私。
- **变体（浏览器端）**：同一 CL.0 条件可被浏览器 fetch 利用，形成客户端去同步（CSD）。
- **变体（超时）**：后端读取超时后保持连接，可形成基于暂停的 desync。
- **关联**：[[web-generic-http-smuggling-client-side-desync-cookie-leak]]（浏览器端 CSD）、[[web-generic-http-smuggling-pause-based-desync-timeout]]（暂停型）、[[web-generic-http-smuggling-empty-cl-chunked-admin-bypass]]（空 CL + chunked 变体）、[[web-generic-http-smuggling-unknown-te-cl-differential]]（TE/CL 解析差异）。
- **边界**：后端严格按 CL 读取 body、前端不复用连接、前端/后端都拒绝模糊请求时，CL.0 不成立。

## 检测与防御

- **修复**：让后端对所有端点一致地读取/校验 Content-Length；前后端使用同一套请求边界解析；对未读取 body 的端点也显式消费或拒绝带 body 的请求。
- **代理层**：禁用不必要的连接复用、在可疑路径强制 `Connection: close`；对同时出现 body 与“请求行”特征的请求做拦截。
- **检测**：同一 TCP 连接上出现两个请求、第二个请求的起始字节位于前一个请求 body 中；`hopefully404` 式探测请求；前端日志与后端日志的请求数/路径不一致。
