---
id: web-generic-http-smuggling-client-cert-cn-header-spoof
title: 走私伪造 mTLS 客户端证书身份头：前端校验并注入 X-SSL-CLIENT-CN，走私请求绕过覆盖直接以 administrator 到达后端
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-mtls-client-cn-header-spoof
aliases:
- X-SSL-CLIENT-CN
- mTLS 身份头伪造
- 客户端证书 CN 走私
- X-SSL-CLIENT-CN administrator
- 双向认证绕过
tags:
- http-smuggling
- mtls
- client-certificate
- header-spoofing
- access-control-bypass
- http1
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:46+08:00'
  notes: '已对照原文『绕客户端』节核对：原文仅给出概念性示例（前端注入 X-SSL-CLIENT-CN，走私请求中写 administrator，PoC CL 64/正文 0 块后 GET /admin + X-SSL-CLIENT-CN + Foo: x），该节无靶场无截图；卡片已如实标注 confidence medium。原理、头名、CL 64 与原文一致。未验证点：无靶场/截图，最终危害未实测；无 sources；无版本/CVE。dedup：与 H2 request tunnelling access-control-bypass（H2 隧道伪造同头并读嵌套响应）为不同传输/步骤，与 1panel mTLS 证书伪造链不同，保留。'
---

## 一句话结论

前端用双向 TLS 校验客户端证书，并把证书 CN 通过 `X-SSL-CLIENT-CN` 之类非标准头传给后端做身份/权限判断；正常请求中该头会被前端覆盖，但走私请求对前端不可见，因此可以在其中直接写 `X-SSL-CLIENT-CN: administrator`，让后端把它当作已认证的客户端证书身份。

## 原理

- mTLS 的校验发生在前端/负载均衡器：客户端出示证书，前端验证后把 CN、序列号、校验结果等放入 HTTP 头（如 `X-SSL-CLIENT-CN`、`X-SSL-VERIFIED`）转发给后端。
- 这些头本应只由前端生成，对用户隐藏；后端通常隐式信任它们，作为访问控制或身份识别的依据。
- 普通请求中用户自己带同名头会被前端覆盖，因此无法伪造。但请求走私的第二个请求由后端直接从连接缓冲解析，前端既看不到也不会重写它，其中的头原样到达后端。
- 于是攻击者可以在走私请求中自带 `X-SSL-CLIENT-CN: administrator`（以及必要的 `X-SSL-VERIFIED: 1` 等），后端无法区分"前端认证后注入"与"攻击者走私注入"。
- 该原语不要求前端对合法用户开放管理端点；它攻击的是"信任边界在前端、后端无条件信任前端头"的架构假设。

## 触发条件

- 前端终止 mTLS 并通过 HTTP 头把客户端证书信息传给后端，后端以这些头做鉴权/授权。
- 存在可用的请求走私原语（CL.TE/TE.CL/TE.TE 或 H2 降级等），使攻击者能向后端连接注入完整请求。
- 后端不校验这些内部头的来源，也不拒绝客户端自带的同名头（或前端只覆盖普通请求而走私请求绕过覆盖）。
- 走私请求需要补齐后端必需的头（Host、Content-Type、Content-Length 等），否则可能被后端拒绝。

## 利用步骤

1. 确认目标使用 mTLS 或客户端证书：访问受保护端点观察是否要求证书，或从响应/文档判断前端会注入身份头。
2. 确认存在走私原语（时间延迟/差分响应法），并确保走私请求能被后端完整解析。
3. 构造走私请求：`GET /admin HTTP/1.1`，带 `X-SSL-CLIENT-CN: administrator`（如后端还校验 `X-SSL-VERIFIED`，一并写 `1`），补上 Host、Content-Length 等必要头。
4. 紧随一个正常请求，使走私请求在后端连接上执行；观察是否返回管理页面或管理员专属数据。
5. 若被拒绝，尝试组合其他内部头（租户 ID、角色头、`X-Forwarded-*`），或用请求重写探测法先泄漏前端实际注入的头名与格式。

## PoC

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-SSL-CLIENT-CN: administrator
Foo: x
```

说明：`0` 块后为被走私的完整请求；`Foo: x` 为占位头，用于吸收后续拼接内容。原文仅给出概念性示例，未提供可执行靶场；本卡 confidence 记为 medium，PoC 未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：伪造 `X-SSL-VERIFIED: 1`、`X-SSL-CLIENT-SERIAL`、`X-SSL-CLIENT-DN` 等配套头；不同前端命名不同，需先探测。
- 变体：与请求重写探测结合，先让后端回显前端注入的头，再复制其名称/格式。
- 关联：[[web-generic-http-smuggling-front-end-rewrite-probe-header-spoof]]（探测并伪造前端注入头）、[[web-generic-http-smuggling-front-end-acl-bypass-smuggled-request]]（走私绕过路径 ACL）、[[web-generic-http-smuggling-h2-request-tunnelling-access-control-bypass]]（H2 场景下伪造 `X-SSL-CLIENT-CN` 的实例）。
- 边界：后端自行重新校验客户端证书、使用签名令牌而非明文头、或前端拒绝走私报文时，本链不成立。

## 检测与防御

- 检测：后端收到带 `X-SSL-CLIENT-CN` 等内部头但无对应前端 mTLS 会话的请求；同一连接出现两个请求而前端只记录一个；头值与前端证书校验日志不一致。
- 防御：后端不要仅凭明文头信任客户端证书身份，应校验前端签名（如 mTLS 到后端、JWT/HMAC 签名头）；前端拒绝 CL+TE 并存并重新序列化请求；对内部头做端到端保护。
- 加固：将证书校验下沉到后端或使用可信代理协议；管理端点使用独立强认证；部署 desync 检测与头来源审计。
