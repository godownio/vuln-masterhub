---
id: web-generic-http-smuggling-front-end-rewrite-probe-header-spoof
title: 探测前端请求重写并伪造内部头：走私 POST 让后端把下一请求的已重写头回显为参数值，再带该 IP 头访问 /admin
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-front-end-rewrite-probe-header-spoof
tags:
- http-smuggling
- header-spoofing
- request-rewriting
- x-forwarded-for
- access-control-bypass
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
  verified_at: '2026-11-12T20:50:45+08:00'
  notes: '已对照原文『请求重写』节及图38-48核对：探测包 CL 124 + 0 块后 POST / + CL 200 + search=test，响应回显重写请求头 X-GoOvNz-Ip（图42，值打码）；随后 CL 143 + GET /admin + X-GoOvNz-Ip: 127.0.0.1 进入 Admin panel 并删除 carlos，图43-48一致。卡片以示例头名说明需按泄漏结果替换，正确。未验证点：头值在截图中被打码，127.0.0.1 取自原文文字；未本机复跑；无 sources；无版本/CVE。dedup：与 H2 request tunnelling（不同传输与读响应方式）、XFF 直伪造卡均不同链，保留。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-front-end-rewrite-probe-header-spoof/
draft: false
kb_aliases:
- reveal front-end request rewriting
- 前端请求重写探测
- X-Forwarded-For 走私
- 内部 IP 头伪造
- 走私回显重写头
---

## 一句话结论

前端转发请求时会追加 `X-Forwarded-For`、TLS 信息或自定义 `X-*-IP` 等内部头，后端常据此判断来源；利用请求走私让后端把"下一个正常请求（已被前端重写）的请求行与头"当作某个反射参数的值回显出来，即可获知重写头的名称与格式，再在走私请求中伪造同名头访问仅限本地/管理员的端点。

## 原理

- 很多前端会重写请求：追加客户端 IP 头（如 `X-Forwarded-For`）、协议/TLS 头、内部服务标识，甚至根据会话注入用户 ID。后端把这些头当作可信来源信息。
- 直接伪造这些头通常无效，因为前端会覆盖同名头；但走私请求由后端直接解析，前端完全看不到，其中的头不会被覆盖。
- 探测方法：找一个把 POST 参数值反射到响应中的端点（登录 email、搜索词等），构造走私请求把该参数名放在 body 末尾（如 `search=`），随后正常请求到达时，后端把"重写后的正常请求行 + 头"追加为参数值，响应中即可看到前端加了哪些头及具体值。
- 关键点：前缀必须放在请求体的最后，后续请求的头才会被当作该参数的值；响应通常是 `0 search results for '前缀 + 请求头...'` 之类的形式。
- 拿到头名（如 `X-GoOvNz-Ip`，常为随机化名称）后，在走私的 `GET /admin` 请求中带上 `X-GoOvNz-Ip: 127.0.0.1`，后端即认为请求来自本地。

## 触发条件

- 存在 CL.TE 或 TE.CL 走私原语。
- 站点有一个把 POST 参数回显到响应的端点，且参数值可放在请求体末尾。
- 前端在转发时追加/重写内部来源头，后端信任这些头做访问控制（例如仅允许 127.0.0.1 访问 /admin）。
- 前端追加的头名可能是随机化的，需要先泄漏再复用。

## 利用步骤

1. 找一个反射型 POST 端点（如搜索），确认参数值会出现在响应体中。
2. 构造 CL.TE 探测包：外层 `POST /` 带 `Transfer-Encoding: chunked` 与覆盖整包的 `Content-Length`，正文 `0` 块后写 `POST / HTTP/1.1`、`Content-Type`、一个较大的 `Content-Length`、`Connection: close` 和目标参数名 `search=test`。
3. 立即发送一个正常 POST 搜索请求；后端会把该正常请求（含前端追加的头）拼进走私请求的 body，并按 `search=test...` 回显到响应。
4. 在响应中记录前端追加的 IP/认证头名称与格式（如 `X-GoOvNz-Ip: 127.0.0.1`）。
5. 构造第二个走私请求：`GET /admin HTTP/1.1` 带上刚泄漏的头，值设为 `127.0.0.1`；若成功进入管理面板，再用 `/admin/delete?username=...` 完成操作。

## PoC

探测重写头：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```

伪造头访问管理面板：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-GoOvNz-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

说明：`X-GoOvNz-Ip` 为示例随机头名，需按泄漏结果替换；长度字段按实际报文计算。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：回显点可换成错误页、日志查看、JSON 回显接口；关键是能把下一请求的请求行/头纳入输出。
- 变体：泄漏的头可能是 `X-Forwarded-For`、`X-Forwarded-Proto`、`X-TLS-*`、`X-Real-IP`、租户 ID、签名密钥；不一定是 IP 头。
- 关联：[[web-generic-http-smuggling-front-end-acl-bypass-smuggled-request]]（不依赖重写头的通用 ACL 绕过）、[[web-generic-http-smuggling-client-cert-cn-header-spoof]]（伪造 mTLS 身份头）、[[web-generic-http-smuggling-differential-response-confirmation]]（先确认走私原语）。
- 边界：后端不信任前端头、前端拒绝 CL+TE、无反射点时，本链不成立。

## 检测与防御

- 检测：响应体中出现完整 HTTP 请求行/头（`GET /`、`X-Forwarded-For` 等）；请求体末尾带参数名后紧跟另一个请求；后端日志出现前端未记录的路径。
- 防御：后端对来源头做端到端签名/校验，不信任可被走私绕过的前端追加头；前端拒绝 CL+TE 并存；管理端点使用独立会话鉴权而非 IP 头；响应输出避免回显拼接后的原始请求内容。
- 加固：内部头使用不可预测且每请求变化的值；将"仅本地访问"改为 mTLS/跳板机校验；部署 desync 检测。
