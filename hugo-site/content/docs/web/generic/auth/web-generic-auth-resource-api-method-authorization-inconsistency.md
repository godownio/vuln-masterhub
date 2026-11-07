---
id: web-generic-auth-resource-api-method-authorization-inconsistency
title: 同一资源接口不同 HTTP 方法鉴权不一致：未授权 DELETE/PUT 下架/上线资源
type: scenario
domain: web
path: web/generic/auth
technique: resource-api-method-authorization-inconsistency
tags:
- web
- auth
- http-method
- authorization
- idor
- rest-api
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:22:35+08:00'
  notes: 已对照原文与图25-28核对：同一资源接口 GET 正常返回 is_unpublished 等字段；DELETE 带 application/x-www-form-urlencoded 返回 INVALID_ARGUMENT，改 JSON {"reason":"1"} 返回 status OK，资源下架/上线成立。未复跑 PoC；文中 URL 已脱敏，卡内 PoC 为通用形式。
url: /docs/web/generic/auth/web-generic-auth-resource-api-method-authorization-inconsistency/
draft: false
kb_aliases:
- HTTP 方法鉴权不一致
- DELETE 未授权
- PUT 未授权
- 资源下架
- verb tampering
---

## 一句话结论

同一资源管理接口的 GET/POST 会做登录或权限校验，但 DELETE/PUT 等状态变更方法走的是另一套路由/处理器且没有鉴权；未登录攻击者直接发 `DELETE`（JSON body `{"reason":"1"}`）即可把资源下架，再用其它未鉴权方法把资源重新上线。

## 原理

- 许多框架按 HTTP 方法把请求分发到不同 handler（如 `Get`/`Post`/`Delete`/`Put` 方法或不同路由）；鉴权中间件/过滤器可能只挂在部分路由或只在 GET/POST 上生效。
- 本题资源接口：GET 返回资源详情（发布人、发布时间、`is_unpublished`、`open_scope` 等），正常的“下架/上线”在业务上需要权限；但直接构造 `DELETE` 请求并带 JSON `{"reason":"1"}`，服务端返回 `{"data":null,"error":{"code":0,...},"status":"OK"}`，资源被删除/下架。
- 用 `Content-Type: application/x-www-form-urlencoded` 发 DELETE 会得到 `INVALID_ARGUMENT`，说明后端按 JSON 解析 body；换成 JSON 即成功。这属于“方法/内容类型枚举”发现的鉴权缺口。
- 为什么危险：状态变更接口没有服务端授权，攻击者不需要账号即可影响业务数据（下架/上线/删除），并可结合 ID 遍历批量操作。
- 根因是授权按“路由/方法”零散配置，而不是在每个资源操作上统一做“当前用户是否有权修改该对象”的检查。

## 触发条件

- 资源管理 API 使用 REST 风格，不同 HTTP 方法对应不同 handler。
- 鉴权只覆盖部分方法（常见只保护 GET/POST，遗漏 DELETE/PUT/PATCH）。
- 资源 ID 可预测/可枚举，且状态变更不需要 CSRF token 或二次确认。
- 攻击者能直接访问接口（无需登录或仅有低权限账号）。

## 利用步骤

1. 枚举资源接口，记录 GET 返回的资源 ID 与状态字段（`is_unpublished`、`status` 等）。
2. 对同一 URL 依次尝试 `OPTIONS`、`GET`、`POST`、`PUT`、`PATCH`、`DELETE`，比较状态码与响应。
3. 对 DELETE/PUT 尝试不同 Content-Type（JSON、form、空 body），观察是否进入业务逻辑。
4. 用 `DELETE` + `{"reason":"1"}` 下架目标资源；用 `PUT`/其它接口重新上线，验证状态变化。
5. 批量遍历 ID，评估影响面；记录响应差异作为证据。

## PoC

```http
DELETE /api/resource/123 HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 14

{"reason":"1"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"data":null,"error":{"code":0,"details":{},"message":""},"status":"OK"}
```

说明：文章中的资源 URL 被脱敏，具体路径需按目标枚举；DELETE 后可用页面/GET 确认 `is_unpublished` 变化。

## 变体与关联

- **Verb tampering**：`X-HTTP-Method-Override: DELETE`、`_method=DELETE`、`X-Method-Override` 等让前置代理按 GET 放行、后端按 DELETE 处理。
- **签名只覆盖部分方法**：见 [[web-generic-auth-api-signature-method-scope-replay-bypass]]。
- **方法级 CSRF**：DELETE/PUT 若只靠 Cookie 鉴权且无 CSRF token，可被跨站触发（视浏览器/表单能力）。
- **对象级授权缺失**：即使方法鉴权存在，也要检查“当前用户是否拥有该资源 ID”。

## 检测与防御

- 统一在路由层做“认证 + 方法级权限”，默认拒绝未显式允许的方法；不要只保护 GET/POST。
- 每个资源操作做对象级授权（owner/tenant 校验），状态变更加 CSRF token/二次确认。
- 对 `OPTIONS` 返回真实的 Allow 列表，避免隐藏方法；网关层拒绝未使用的方法。
- 检测：同一 IP 对大量资源 ID 发 DELETE/PUT、非浏览器 Content-Type 的状态变更、`X-HTTP-Method-Override` 等头。
