---
id: web-generic-http-smuggling-cl-te-basic-chunk-prefix
title: CL.TE 基础请求走私：前端按 Content-Length 放行整包、后端按 chunked 在 0 块终止，剩余字节成为下一请求前缀
type: scenario
domain: web
path: web/generic/http-smuggling
technique: cl-te-request-smuggling-chunk-prefix
tags:
- http-smuggling
- cl-te
- transfer-encoding
- content-length
- chunked
- http1
- reverse-proxy
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:34+08:00'
  notes: "已对照原文『CL.TE vulnerabilities』节及图04-07核对：PoC 为 POST / + Content-Length: 6 + Transfer-Encoding: chunked，正文 0\r\n\r\nG，第二次请求回显 Unrecognized method GPOST，随后 Solved；参数与原理一致。注：原文正文写 CL 6，图05截图实为 CL 10（第二个请求前 4 字节 POST 补足 CL 后仍得到 GPOST），以正文/官方 lab 的 6 为准。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url；原文无受影响版本与 CVE。dedup：库内 empty-cl-chunked-admin-bypass、unknown-te-cl-differential、CL.0、H2 等均为不同机制，非同链，保留。"
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-cl-te-basic-chunk-prefix/
draft: false
kb_aliases:
- CL.TE
- CL.TE request smuggling
- 请求走私基础
- GPOST
- chunk 前缀走私
---

## 一句话结论

当前端服务器以 `Content-Length` 决定请求体长度、后端以 `Transfer-Encoding: chunked` 解析请求体时，发送一个 `0` 块后紧跟任意字节的请求，前端会把整包转发，后端却在 `0` 块处结束当前请求，把剩余字节当作同一连接上下一个请求的开头，从而在受害者请求前注入任意方法/路径/头部。

## 原理

- HTTP/1.1 提供两种描述消息结束位置的方式：`Content-Length`（字节数）与 `Transfer-Encoding: chunked`（按块长度，`0` 块表示结束）。规范要求两者同时出现时 `Transfer-Encoding` 优先并忽略 `Content-Length`，但真实代理与后端框架未必一致。
- CL.TE 组合下，前端信任 `Content-Length: 6`，把正文 `0\r\n\r\nG` 全部转发；后端信任 `Transfer-Encoding: chunked`，读到 `0` 块即认为请求结束。
- 后端在同一个后端连接上紧接着解析后续字节，`G` 被拼到下一个请求行前，正常请求 `POST /...` 变成 `GPOST /...`，返回 `Unrecognized method GPOST`，证明走私成功。
- 为什么能造成危害：前端只对"它看到的那个请求"做鉴权、限流、WAF 与审计，后半段字节对前端不可见；后端却把它当成合法的下一条请求处理，攻击者可借此绕过前端控制、投毒响应队列或污染缓存。
- 成立核心是"链路中存在解析差异 + 前端到后端复用连接"，两者缺一不可。

## 触发条件

- 目标位于 HTTP/1.1 反向代理/负载均衡器之后，代理与后端对 `Content-Length`/`Transfer-Encoding` 的优先级处理不同。
- 前端按 `Content-Length` 读取并把原始字节转发，不在转发时重写头或按 chunked 重新序列化。
- 前端与后端之间复用长连接（keep-alive），使剩余字节能被后端当作新请求读取。
- 攻击者能以原始 HTTP 字节方式发包（Burp Repeater/raw socket），并可控制两个头的值与正文。

## 利用步骤

1. 确认链路存在差异：发送同时带 `Content-Length` 与 `Transfer-Encoding: chunked` 的探测包，正文写 `0\r\n\r\nG`，观察是否出现超时（后端等待下一块）或后续请求被拼接。
2. 构造最小 CL.TE 包：`Content-Length` 覆盖整个正文（含 `0` 块与尾部字节），尾部写一个会被拼到下一请求前的字符，如 `G`。
3. 同一条连接上再发一个正常请求，若响应出现 `Unrecognized method GPOST`、`G` 开头的方法或路径错乱，即确认 CL.TE。
4. 把尾部字节换成完整请求前缀（如 `GET /admin HTTP/1.1\r\nHost: localhost\r\n...`），在握手连接被复用前紧跟受害者/普通请求，使后端执行被注入的请求。
5. 结合时间延迟法或差分响应法辅助确认（见关联卡），避免把网络抖动误判为走私。

## PoC

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

说明：`Content-Length: 6` 恰好覆盖 `0\r\n\r\nG`；前端转发整包，后端在 `0` 块结束，`G` 成为下一请求的方法前缀。随后在同一连接发送正常 `POST /`，预期得到 `Unrecognized method GPOST`。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：尾部字节可以是被走私请求的任意前缀（方法、路径、头名），配合 GET/POST 决定后端行为。
- 变体：用时间延迟法确认（后端等待不存在的下一块导致延迟），或用差分响应法确认（让下一请求命中 404）。
- 关联：[[web-generic-http-smuggling-te-cl-basic-chunk-prefix]]（反方向的 TE.CL）、[[web-generic-http-smuggling-te-te-obfuscated-transfer-encoding]]（双端都支持 TE 时的混淆）、[[web-generic-http-smuggling-front-end-acl-bypass-smuggled-request]]（走私完整请求绕过前端 ACL）。
- 边界：前端也按 chunked 解析、转发前重新序列化、或前后端不复用连接时，本形态不成立。

## 检测与防御

- 检测：同一请求同时出现 `Content-Length` 与 `Transfer-Encoding`；chunked `0` 块后仍有可解析的请求行/方法；响应出现 `Unrecognized method` 类错误；同连接请求数与前端访问日志不一致；异常超时。
- 防御：前端与后端统一使用严格 HTTP 解析器，拒绝 CL+TE 并存（返回 400）或统一按 TE 处理并剥离 CL；转发前重新序列化请求；代理到后端禁用连接复用或每个请求独立连接；前端 ACL 与 WAF 下沉到后端复核。
- 加固：升级已知对请求边界处理不一致的代理/框架版本，部署能识别 desync 的 WAF/网关，监控同连接内出现多个未在上游日志中记录的请求。
