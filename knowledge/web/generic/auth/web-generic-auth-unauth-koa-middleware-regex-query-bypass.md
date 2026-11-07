---
id: web-generic-auth-unauth-koa-middleware-regex-query-bypass
title: Koa 鉴权中间件未锚定正则匹配整条 URL：查询参数塞 webhooks/trigger 绕过全部鉴权（CVE-2026-31816）
type: scenario
domain: web
path: web/generic/auth
technique: koa-auth-middleware-unanchored-regex-query-bypass
aliases:
- CVE-2026-31816
- Budibase 未授权访问
- isWebhookEndpoint 绕过
- authorized 中间件正则绕过
- 未锚定正则鉴权绕过
- ctx.request.url 匹配查询串
tags:
- auth-bypass
- nodejs
- koa
- middleware
- regex
- budibase
- cve-2026-31816
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:04:16+08:00'
  notes: 已对照原文与2张截图核对：authorized 中间件 isWebhookEndpoint(ctx)||ctx.internal 时直接 next()，WEBHOOK_ENDPOINTS 为 4 个片段的 join("|") 生成未锚定正则并对 ctx.request.url test，截图与卡内描述一致；CVE-2026-31816 与源码/镜像 3.31.4 一致；原文未给受影响区间故未设 affected_versions（正确），也未附实际请求/响应，卡内 PoC 为按代码构造、confidence medium，已注明未执行；路径 web/generic/auth 合法，无 sources/source/source_url
---

## 一句话结论

Budibase 服务端 `authorized()` 中间件在判断 Webhook 路径时，用 `new RegExp(["webhooks/trigger","webhooks/schema","webhooks/discord","webhooks/ms-teams"].join("|"))` 对 `ctx.request.url` 做未锚定的 `test()`；`ctx.request.url` 包含查询串，因此攻击者给任意受保护 API 拼接 `?/webhooks/trigger`（或 `&/webhooks/trigger`）即可让 `isWebhookEndpoint()` 返回 true，`authorized()` 直接 `return next()`，跳过身份认证、角色鉴权和 CSRF 校验，未授权访问并操作所有 API 端点。

## 原理

- `authorized(permType, permLevel, opts, resourcePath)` 的放行条件是 `if (isWebhookEndpoint(ctx) || ctx.internal) { return next() }`；注释说明 Webhook 和内部服务间请求不需要鉴权。
- `isWebhookEndpoint(ctx)` 的实现为 `return WEBHOOK_ENDPOINTS.test(ctx.request.url)`，其中 `WEBHOOK_ENDPOINTS = new RegExp(["webhooks/trigger", "webhooks/schema", "webhooks/discord", "webhooks/ms-teams"].join("|"))`。
- 关键缺陷一：正则没有 `^`/`$` 锚定，`test()` 只要求 URL 任意位置出现该子串。正确做法应是匹配规范化后的 pathname，并锚定到固定前缀。
- 关键缺陷二：取的是 `ctx.request.url` 而不是 `ctx.request.path`。Koa 的 `request.url` 是原始请求行中的 path + query string（如 `/api/users?/webhooks/trigger`），而路由匹配只看 pathname `/api/users`。因此把 payload 放在查询串里既命中正则，又不影响目标路由。
- 关键缺陷三：`join("|")` 只做了字符串拼接，`/` 在正则中不具特殊含义，但列表元素未转义、未加边界，任何包含这些片段的 URL（包括查询参数值、甚至片段）都命中。
- 放行后 `authorized()` 不再执行后续权限检查，Webhook/内部请求的“免鉴权”信任被扩展到全部 API；攻击者可以读取、创建、修改数据，具体能做什么取决于暴露的 API（用户、配置、数据源、自动化等）。
- 根因是“用子串正则做安全边界判断”：安全决策依据的是整条原始 URL 是否包含某字符串，而该字符串可由攻击者在查询参数中自由构造，属于典型的信任边界混淆。

## 触发条件

- 目标为存在该 `authorized`/`isWebhookEndpoint` 实现的 Budibase 版本（文章对照 3.31.4 源码与镜像）。
- 目标 API 经过 `authorized()` 中间件保护，且攻击者能访问该端口（示例 10000）。
- 请求走 Koa 路由，payload 放在查询串中不会改变 `ctx.request.path` 与路由匹配。
- 无需账号、Cookie、CSRF token；`ctx.internal` 分支与攻击者无关，本卡利用的是 Webhook 分支。

## 利用步骤

1. 确认目标 Budibase 可访问（默认 10000 端口），随便请求一个受保护 API（如 `/api/global/configs` 或业务数据接口），未带凭据时预期 401/403。
2. 在同一路径后追加查询串 `?/webhooks/trigger`；若原 URL 已有查询参数则用 `&/webhooks/trigger`。
3. 不携带任何认证信息重放请求；`isWebhookEndpoint` 命中正则，`authorized` 直接放行，请求进入业务处理。
4. 对需要写操作的接口重复该方法，验证创建/修改能力（如用户、角色、数据源、Webhook 配置）。
5. 若目标对查询串做了规范化，可尝试列表中的其他片段 `webhooks/schema`、`webhooks/discord`、`webhooks/ms-teams`，或用 URL 编码/大小写变体观察是否仍命中。

## PoC

```http
### 未授权读取受保护 API（payload 放在查询串）
GET /api/global/configs?/webhooks/trigger HTTP/1.1
Host: target:10000

### 已有查询参数时用 & 追加
GET /api/global/configs?ts=1&/webhooks/trigger HTTP/1.1
Host: target:10000

### 其他可命中的片段
GET /api/users?/webhooks/schema HTTP/1.1
GET /api/users?/webhooks/ms-teams HTTP/1.1
```

```text
执行逻辑：
ctx.request.url = "/api/global/configs?/webhooks/trigger"
isWebhookEndpoint -> RegExp("webhooks/trigger|webhooks/schema|...").test(url) -> true
authorized() -> return next()  // 跳过认证、角色鉴权、CSRF
路由 pathname 仍为 /api/global/configs，业务接口正常处理
```

```text
说明：文章仅给出源码分析、Docker 启动命令与利用链，未附实际请求/响应截图；上述 PoC 按代码路径构造，未在本机复现，故 confidence 记 medium。
```

## 变体与关联

- 变体（匹配片段）：四个 Webhook 片段任意一个都能触发；`webhooks/trigger` 最直接，`webhooks/schema` 等可用于 WAF 只拦单一关键字时。
- 变体（放置位置）：查询串最稳（不改变路由）；也可放在路径参数、查询参数值中，只要 `ctx.request.url` 包含子串且路由仍匹配即可。
- 变体（其他框架）：任何用未锚定正则对 `request.url`/`originalUrl` 判断路径的鉴权中间件都可能被同样绕过；审计时应检查 `test()`/`match()` 的目标是 `url` 还是 `path`、正则是否锚定。
- 关联：同层其他“中间件/拦截器鉴权判断缺陷”的认证绕过卡；本卡特指 Koa 原始 URL 子串匹配导致的 Webhook 免鉴权扩散。
- 边界：若目标升级为按 pathname 锚定匹配、或在业务层再做一次权限校验，链路失效；若查询串被网关重写/拒绝，需要换放置位置；本卡只证明未授权访问，能造成的具体危害取决于目标 API 的写能力。

## 检测与防御

- 请求检测：任意 API 的查询串出现 `webhooks/trigger`、`webhooks/schema`、`webhooks/discord`、`webhooks/ms-teams`，尤其是 `?/`、`&/` 后紧跟这些片段；同一来源对多个不同 API 追加相同片段；无认证 Cookie 却访问受保护 API 且返回 200。
- 日志检测：`authorized` 放行日志中 `isWebhookEndpoint=true` 但请求路径不是 Webhook 路由；访问日志中出现查询串含 `webhooks/` 的非 Webhook 路径。
- 修复：改用 `ctx.request.path` 并锚定匹配（如 `^/api/webhooks/(trigger|schema|discord|ms-teams)$`）；或先由路由层把 Webhook 端点与普通 API 分离，再在各自路由上挂不同中间件。
- 修复：升级包含该修复的 Budibase 版本；若无法升级，在网关层拒绝查询串含 `webhooks/` 的请求，并对 `/api/*` 强制重新鉴权。
- 加固：鉴权判断依据规范化后的 pathname，禁止使用完整 URL/原始请求行；对 Webhook 免鉴权路径使用精确白名单并校验方法/签名；为 Webhook 请求增加独立密钥或 HMAC，而不是仅凭路径放行。
- 审计：搜索 `request.url`、`originalUrl`、`req.url` 与 `RegExp`/`test`/`match` 的组合；检查所有“路径包含某子串即放行”的中间件与拦截器。
