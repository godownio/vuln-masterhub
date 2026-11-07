---
id: web-generic-http-smuggling-empty-cl-chunked-admin-bypass
title: 空 Content-Length + TE chunked 解析差异：前置代理拦截 /admin，走私第二个 GET 到后端渲染路由
type: scenario
domain: web
path: web/generic/http-smuggling
technique: empty-content-length-chunked-parser-differential-admin-bypass
tags:
- http-smuggling
- cl-te
- chunked
- content-length
- proxy
- acl-bypass
- http1
- reverse-proxy
- ctf
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:17+08:00'
  notes: "已对照原文与图01核对：Server: Northstar-Gateway、/admin返回forbidden by proxy、空Content-Length+正文0\r\n\r\nGET /admin…、后端返回no such admin route并扫出/admin/render，PoC与原文最终请求一致。未验证点：原文最终利用请求头中未见Transfer-Encoding: chunked（探测段有TE），实际更接近空CL自动填充/CL.0的请求边界差异，卡片按原文叙述保留TE chunked表述；PoC未本机复跑；frontmatter无sources/source_url。"
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-empty-cl-chunked-admin-bypass/
draft: false
kb_aliases:
- 空 CL 走私
- Content-Length 自动填充
- Northstar-Gateway
- forbidden by proxy
- CL.TE 访问控制绕过
- 前端代理 ACL 绕过
---

## 一句话结论

前置代理（`Server: Northstar-Gateway`）对 `/admin` 返回 `forbidden by proxy`，但代理与后端对请求体边界的解析不一致：发送 `POST /` 且把 `Content-Length:` 留空、正文写成 `0\r\n\r\nGET /admin HTTP/1.1...`，代理按自动填充的 CL 处理，后端按 chunked 的 `0` 结束当前请求，把后面的 `GET /admin` 当作同一连接上的第二个请求执行，从而绕过代理的路径 ACL 访问后端管理路由。

## 原理

- **CL/TE 解析差异**：HTTP/1.1 允许 `Content-Length`（固定长度）或 `Transfer-Encoding: chunked`（分块）描述消息边界；如果前置代理和后端分别采用不同的头/算法，同一个字节流在两端会被切成不同数量的请求。经典形式是 CL.TE（代理信 CL、后端信 TE）或 TE.CL（反过来）。
- **空 CL 的自动填充**：本题请求头中 `Content-Length:` 留空；代理可能按实际 body 长度自动填充 CL，或按自己的策略补 0。后端收到含 `Transfer-Encoding: chunked` 的请求时，把正文 `0\r\n\r\n` 视为 chunked 结束，剩余字节 `GET /admin HTTP/1.1...` 被当作下一个请求的开头，在同一后端连接上继续解析。
- **ACL 只在代理层**：`/admin` 的 `forbidden by proxy` 是前置代理返回的，后端并没有同样的路径拦截；走私出的第二个请求绕过代理直接到达后端，因此能访问 `/admin` 及其子路由。
- **探测**：先发送同时带 `Content-Length` 与 `Transfer-Encoding: chunked` 的探测请求（如正文 `0\r\n\r\nG`），观察代理/后端对剩余字节的处理（响应差异、后续请求是否被拼接、连接是否复用），确认存在解析差异。
- **利用**：把第二个请求写成完整的 `GET /admin/render?expr=...`，后端把它当新请求处理并返回渲染结果；后续可在 `/admin` 下继续扫目录/fuzz 参数。
- **边界**：真正可利用需要“代理与后端解析差异 + 连接复用 + 后端无同等 ACL”；如果代理拒绝空 CL、强制单请求、或后端也校验 `/admin`，则走私不成立。原文的请求/响应证据支持该链，但具体头处理依赖目标网关，卡片按 medium 置信度记录。

## 触发条件

- 目标位于 HTTP/1.1 前置代理/网关之后，代理与后端使用不同的请求边界解析（CL/TE 处理不一致）。
- 代理对 `/admin` 等路径做 ACL，但后端没有同等拦截；代理与后端之间复用长连接。
- 攻击者能控制原始 HTTP 字节流（Burp/raw socket），可以设置空 `Content-Length`、`Transfer-Encoding: chunked` 和自定义正文。
- 后端存在值得访问的管理/渲染路由（本题 `/admin/render?expr=`）。

## 利用步骤

1. 访问 `/admin`，确认返回 `forbidden by proxy`；从响应头 `Server: Northstar-Gateway` 判断存在前置代理。
2. 发送 CL/TE 探测请求（同时带 `Content-Length` 与 `Transfer-Encoding: chunked`，正文 `0\r\n\r\nG`），观察代理是否按 CL、后端是否按 chunked 结束，以及后续字节是否被当作新请求。
3. 构造走私请求：`POST /`，`Content-Length:` 留空，正文先写 `0\r\n\r\n`，紧跟完整的 `GET /admin HTTP/1.1` + Host + 其他头。
4. 观察响应：若返回 `no such admin route` 而不是 `forbidden by proxy`，说明第二个请求已绕过代理到达后端。
5. 在 `/admin` 下低并发扫目录，发现 `/admin/render`；fuzz `expr` 参数进入下一阶段（SSTI）。
6. 若代理拒绝空 CL，尝试 CL.TE/TE.CL 的其他变体（重复 CL、TE 大小写/空格混淆、HTTP/2 降级等）。

## PoC

```http
POST / HTTP/1.1
Host: <target>:<port>
Content-Length:

0

GET /admin HTTP/1.1
Host: <target>:<port>
User-Agent: Mozilla/5.0
Accept: */*
```

代理自动填充 CL；后端按 chunked 的 `0` 结束第一个请求，随后处理 `GET /admin`。原文实测返回 `no such admin route`（说明到达后端），再扫出 `/admin/render`。未在本库复跑。

## 变体与关联

- **CL.TE / TE.CL**：代理信 CL、后端信 TE，或反过来；用 `Content-Length` 与 `Transfer-Encoding: chunked` 同时出现、重复头、大小写/空格混淆制造差异。
- **空 CL 变体**：`Content-Length:` 空值、`Content-Length: 0`、`Content-Length: +0`、`0x0` 等，不同代理自动填充策略不同。
- **HTTP/2 降级**：前端 H2、后端 H1 时，H2 的 `content-length`/`transfer-encoding` 处理差异也可走私。
- **关联卡片**：[[web-generic-http-smuggling-varnish-pipeline-cl-residual]]（Varnish CL 管线残留）、[[web-generic-http-smuggling-content-encoding-request-body-waf-bypass]]（请求体编码差异）、[[web-python-ssti-getattr-chr-blacklist-bypass]]（走私到 `/admin/render` 后的 SSTI 利用）。

## 检测与防御

- **统一解析**：前端代理与后端使用同一套严格的 HTTP 解析器；拒绝同时出现 `Content-Length` 与 `Transfer-Encoding`、空 CL、重复 CL、非法 chunk。
- **连接管理**：代理到后端禁用连接复用，或每个请求使用独立连接；对异常剩余字节直接关闭连接。
- **ACL 下沉**：不要只在代理层做 `/admin` ACL；后端也必须鉴权/授权，避免走私绕过。
- **检测**：请求同时含 CL/TE、空 CL、chunked 结束符后仍有可解析请求行；后端日志出现代理未记录的第二个请求；同一连接上请求数/路径与代理日志不一致。
