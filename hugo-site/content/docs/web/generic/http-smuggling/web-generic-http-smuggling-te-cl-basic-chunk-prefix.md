---
id: web-generic-http-smuggling-te-cl-basic-chunk-prefix
title: TE.CL 基础请求走私：前端按 chunked 在 0 块截断、后端按 Content-Length 继续读取，剩余体字节成为下一请求
type: scenario
domain: web
path: web/generic/http-smuggling
technique: te-cl-request-smuggling-content-length-prefix
tags:
- http-smuggling
- te-cl
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
  verified_at: '2026-11-12T20:50:36+08:00'
  notes: '已对照原文『TE.CL vulnerabilities』节及图08-11核对：Content-Length: 4、chunk 5c、GPOST / HTTP/1.1、尾部 0，第二次请求 403 Unrecognized method GPOST，随后 Solved；与图09/10一致。原文提示需关闭 Burp Update Content-Length 且 0 后保留 CRLF，卡片已吸收。未验证点：未本机复跑；无 sources；无版本/CVE。dedup：与 CL.TE 卡方向相反、PoC 与利用条件不同；库内空 CL/H2/CL.0 均不同链，保留。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-te-cl-basic-chunk-prefix/
draft: false
kb_aliases:
- TE.CL
- TE.CL request smuggling
- Transfer-Encoding Content-Length smuggling
- GPOST
- 分块截断走私
---

## 一句话结论

当前端服务器以 `Transfer-Encoding: chunked` 解析请求体、后端以 `Content-Length` 决定请求体长度时，把完整恶意请求塞进一个 chunk 内、并让 `Content-Length` 只覆盖开头几个字节，前端会在 `0` 块处结束请求，后端却按 `Content-Length` 继续读取，把 chunk 内的字节解释为下一条请求。

## 原理

- TE.CL 是 CL.TE 的反向组合：前端信任 `Transfer-Encoding: chunked`，按块读取到 `0` 块后认为请求结束；后端信任 `Content-Length`，只读取声明的固定字节数。
- 攻击者把 `Content-Length` 设得很小（如 4），刚好覆盖第一个 chunk 的长度行 `5c\r\n`；前端按 chunked 完整解析并转发，后端只消费 4 字节，剩下的 `GPOST / HTTP/1.1...` 被当作同一连接上的下一个请求。
- 前端看到的是一个合法 chunked 请求，因此其审计、限流、路径 ACL 都只作用于这个"外层"请求；后端看到的是另一个请求，形成越权执行的基础。
- 关键细节：chunk 长度使用十六进制；`0` 块后需要一个空行（`\r\n`）终止 chunked 体；Burp 需关闭"自动更新 Content-Length"，否则工具会按实际长度改写而破坏走私。
- 成立同样依赖前后端连接复用与解析器不一致。

## 触发条件

- HTTP/1.1 前端代理与后端对 `Transfer-Encoding`/`Content-Length` 优先级处理相反：前端按 TE、后端按 CL。
- 前端把原始 chunked 字节转发给后端，不重新序列化或重新计算长度。
- 前后端复用 keep-alive 连接。
- 后端支持固定长度请求且不会拒绝残留字节。
- 攻击者可控制原始字节与两个头的值。

## 利用步骤

1. 用时间延迟法初步判断：发送 `Content-Length: 6`、`Transfer-Encoding: chunked`、正文 `0\r\n\r\nX`，TE.CL 下后端等待剩余字节会出现明显延迟（见关联卡）。
2. 计算 `Content-Length`：设为刚好覆盖第一个 chunk 的长度行（含 `\r\n`），例如 chunk 长度为 `5c` 时 `Content-Length: 4`。
3. chunk 内容写完整恶意请求，如 `GPOST / HTTP/1.1\r\nHost: ...\r\nContent-Length: 15\r\n\r\nx=1`，最后追加 `0\r\n\r\n` 结束 chunked。
4. 同连接发送正常请求，若返回 `Unrecognized method GPOST` 或恶意路径的结果，确认 TE.CL。
5. 将恶意 chunk 内容换成完整的 `GET /admin...` 或 `POST /admin/delete...`，紧跟正常请求触发后端执行。

## PoC

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

说明：`Content-Length: 4` 只覆盖 `5c\r\n`；前端按 TE 读到 `0` 块结束并转发，后端按 CL 消费 4 字节后把 `GPOST...` 当作下一请求。Burp 中需关闭 Update Content-Length，并保证最后一个 `0` 后有 `\r\n`。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：chunk 大小可为任意十六进制值，`Content-Length` 相应调整为首行长度；可把多个请求塞进不同 chunk。
- 变体：若前端会合并/规范化 TE 头，可先用 TE.TE 混淆让前端忽略 chunked。
- 关联：[[web-generic-http-smuggling-cl-te-basic-chunk-prefix]]（反方向 CL.TE）、[[web-generic-http-smuggling-time-delay-detection]]（TE.CL 延迟确认）、[[web-generic-http-smuggling-front-end-acl-bypass-smuggled-request]]（走私 admin 请求绕过前端限制）。
- 边界：前端按 CL 解析、转发前重新计算长度、或后端拒绝 chunked 结束后的残留字节时，本形态不成立。

## 检测与防御

- 检测：CL 小于实际 chunked 体长度；`0` 块后仍有数据；后端日志出现前端未记录的方法/路径；同连接出现多个请求；异常响应延迟。
- 防御：统一前后端解析器与优先级策略；对 CL+TE 并存请求直接拒绝；前端按自己的解析结果重新序列化或按块重新编码后再转发；禁用后端连接复用。
- 加固：WAF 检查 chunked 体完整性、块大小与实际字节一致性；监控 `Content-Length` 与 chunk 首行不匹配的请求。
