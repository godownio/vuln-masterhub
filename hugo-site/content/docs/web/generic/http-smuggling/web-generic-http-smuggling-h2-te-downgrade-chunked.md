---
id: web-generic-http-smuggling-h2-te-downgrade-chunked
title: 'H2.TE 请求走私：HTTP/2 请求携带 transfer-encoding: chunked，前端未剥离即降级导致后端按分块解析错位'
type: scenario
domain: web
path: web/generic/http-smuggling
technique: http2-downgrade-h2-te-smuggling
tags:
- http2
- request-smuggling
- h2-te
- transfer-encoding
- chunked
- downgrade
- desync
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:38:44+08:00'
  notes: '已对照原文12691「H2.TE vulnerabilities」节与截图19-25核对：POST / HTTP/2 + Transfer-Encoding: chunked + body 0/SMUGGLED 首包200、后续请求404确认前缀生效；完整走私GET /x后捕获管理员302(Location:/my-account?id=administrator + Set-Cookie session)、用会话进入/admin并调用/admin/delete?username=carlos、靶场Solved，卡内参数/PoC与截图一致。dedup：除自身外最高相关为unknown-te-cl-differential(HTTP/1未知TE)、CL.0、空CL+TE、Varnish等，均非同一利用链；与同文H2.CL卡按注入头与后端解析路径区分，原子。原文未给产品受影响版本，保持省略；未在本机复现。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-h2-te-downgrade-chunked/
draft: false
kb_aliases:
- H2.TE
- HTTP/2 transfer-encoding chunked
- HTTP/2 降级 TE 走私
- h2 chunked desync
---

## 一句话结论

HTTP/2 本身不支持 `Transfer-Encoding: chunked`，规范要求前端在收到该头时剥离或拒绝请求；如果前端未做处理、降级成 HTTP/1.1 时把该头原样传给支持分块编码的后端，攻击者就能用 `0\r\n\r\n` 提前结束请求体，把后面的字节变成第二个请求，形成 H2.TE 请求走私。

## 原理

- HTTP/2 的分帧自带消息长度，不存在"分块传输"的需要；RFC 明确禁止在 HTTP/2 中使用 `Transfer-Encoding: chunked`，并要求中间件将其移除或直接拒绝请求。
- 如果前端只按 H2 语义读取消息、却在降级时保留 `transfer-encoding: chunked`，转发出的 HTTP/1.1 请求就同时带有前端补的 `Content-Length` 和攻击者注入的 `Transfer-Encoding: chunked`。HTTP/1 后端通常优先按 TE 解析：遇到 `0\r\n\r\n` 认为 body 结束，之后的字节成为下一个请求。
- 攻击者在 H2 请求体中写入 `0`、空行和 `SMUGGLED` 或完整 HTTP/1 请求。前端看到的是一个 H2 消息；后端看到的是"一个 chunked POST 结束 + 第二个请求"，边界再次错位。
- 与 H2.CL 的差别：H2.CL 利用前端复用错误 CL；H2.TE 利用前端未剥离 TE。后端只要支持 chunked 且前端未按规范处理 TE，即成立。
- 为什么成立：TE 是逐跳头，本应在协议转换时被中间件消费/剥离；把它透传到后端等于让攻击者直接控制后端的分帧语义。

## 触发条件

- 前端接受 HTTP/2 并降级为 HTTP/1.1 转发。
- 前端未剥离或拒绝 H2 请求中的 `transfer-encoding: chunked`（或大小写/空白变体绕过其检查）。
- 后端支持 chunked 请求体并按 TE 优先解析。
- 前后端连接被复用，能把走私的请求送到其他用户的连接上下文。
- 攻击者可用原始 H2 工具构造伪头部与 body。

## 利用步骤

1. 在 Burp 中把协议设为 HTTP/2，关闭 Update Content-Length，构造 `POST / HTTP/2`，加入头部 `Transfer-Encoding: chunked`。
2. Body 写入 `0`、空行、`SMUGGLED`。随后发一个正常请求；若它返回 404 或前缀异常，说明后端已把后续请求拼到走私前缀上。
3. 把 `SMUGGLED` 换成完整 HTTP/1 请求，例如 `GET /x HTTP/1.1` + `Host: TARGET`，走私一个后端会正常处理的请求；两个请求都指向不存在的路径，便于区分正常 404 与被捕获的他人响应。
4. 观察后续响应：可捕获管理员/其他用户的 302 与 `Set-Cookie`，或把受害者的下一个请求引导到攻击者资源。
5. 与响应队列中毒结合可长期窃取会话（原文用此变体拿到 administrator 会话并删除 carlos）。

## PoC

```http
POST / HTTP/2
Host: TARGET
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
POST / HTTP/2
Host: TARGET
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET
```

说明：PoC 为原文 H2.TE/响应队列中毒靶场流程的结构化复现，域名已泛化；请求须以原始 HTTP/2 发送（Burp 关闭 Update Content-Length），未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：`Transfer-Encoding: chunked` 的大小写、前后空白、重复头、`xchunked` 等混淆形式可能绕过前端的关键字剥离。
- 变体：TE 头通过 CRLF 注入隐藏在另一个头值中（见 CRLF 走私卡），绕过"正常头里禁止 TE"的检查。
- 关联：[[web-generic-http-smuggling-h2-cl-downgrade-injected-content-length]]（H2.CL）、[[web-generic-http-smuggling-h2-response-queue-poisoning-session-capture]]（本变体的典型危害）、[[web-generic-http-smuggling-empty-cl-chunked-admin-bypass]]（HTTP/1 的空 CL + TE 变体）。
- 边界：前端按规范剥离/拒绝 TE、后端不支持 chunked、或连接不复用时，本链不成立。

## 检测与防御

- 检测：HTTP/2 请求中出现 `transfer-encoding`（尤其 chunked）；前后端请求数/响应数不匹配；正常请求出现 404 或响应错配；同一连接上出现来源用户的异常响应。
- 防御：前端严格按 RFC 拒绝/剥离 HTTP/2 中的 `transfer-encoding`，并在降级后只使用自己重建的 CL；后端优先采用统一的分帧策略；不跨用户复用前后端连接。
- 加固：升级反代/CDN 到正确处理 H2 逐跳头的版本；端到端 HTTP/2；WAF 支持 H2 语义并检测异常伪头部组合。
