---
id: web-generic-graphql-operation-name-authz-field-bypass
title: GraphQL 操作名授权绕过：允许未认证的 operationName=getPastes，却夹带未授权 systemHealth 字段直接读数据
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-operation-name-authz-field-bypass
aliases:
- GraphQL 操作名鉴权
- operationName 绕过
- 字段级授权缺失
- systemHealth 越权
- 白名单 operation 名
- GraphQL 授权缺陷
tags:
- graphql
- authorization
- authz-bypass
- operation-name
- field-level
- api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:52:57+08:00'
  notes: '已对照 content.md 与 img24-25 核对：直接 query systemHealth{systemHealth} 返回 400 Operation Name "systemHealth" is not allowed、query getPastes{systemHealth} 返回 System Load: 0.07 均与原文一致。未验证点：未实际复现；原文未展示授权中间件源码，字段级越权推断基于响应差异。'
---

## 一句话结论

应用用 operation 名称白名单做鉴权（未登录用户允许执行 `getPastes`），但只在入口检查 `operationName`，不检查本次文档实际请求的字段；攻击者发送 `query getPastes { systemHealth }`，操作名通过白名单，GraphQL 仍会执行未授权的 `systemHealth` resolver 并把系统负载等数据返回，形成字段级越权。

## 原理

- **GraphQL 文档结构**：一个 operation 由 `query/mutation 名称 { ... }` 组成，名称可被客户端任意指定；文档中的字段集合才是实际执行的内容。若鉴权只看 “operation 名是否在白名单”，而不检查字段/resolver 级权限，就出现“名称合法、内容越权”的缝隙。
- **文章复现**：直接查询 `query systemHealth{systemHealth}` 时，网关/应用返回 `400 Bad Request: Operation Name "systemHealth" is not allowed.`；改成 `query getPastes{systemHealth}` 后，因为 `getPastes` 是未认证用户允许的 operation 名，鉴权放行，响应 `{"data":{"systemHealth":"System Load: 0.07\n"}}`，说明授权检查只绑定 operation 名，而字段 `systemHealth` 本身没有独立鉴权。
- **为什么常见**：很多团队用 operation 名/查询白名单做“成本控制/权限控制”，或在网关按正则解析请求文本提取 operation 名；GraphQL 执行器 meanwhile 会执行整个字段集，包括别名、fragment 展开后的字段。operation 名不是安全边界。
- **影响**：可读取被设计为管理员/内部才能访问的字段（系统状态、用户列表、审计日志、配置等），若未授权 operation 还能调用 mutation，可能造成写操作越权；具体危害取决于 schema 暴露的字段。

## 触发条件

- GraphQL 端点对未认证/低权用户使用 operation 名白名单（如允许 `getPastes`、`login` 等公开操作）。
- 敏感字段（如 `systemHealth`、`users`、`systemDiagnostics`）的 resolver 没有独立的认证/角色检查，或检查只针对某些 operation。
- 攻击者能构造任意 GraphQL 文档，且可发送未在客户端出现的字段（introspection/字段建议可帮助发现）。
- 服务端没有对文档做“字段级 allowlist”或按用户裁剪 schema。

## 利用步骤

1. 通过 introspection/字段建议/前端 JS 找出公开 operation 名（如 `getPastes`）与敏感字段（如 `systemHealth`、`users`、`systemDebug`）。
2. 先验证直接访问敏感字段会被拒：发送 `{"query":"query systemHealth{systemHealth}"}`，观察 `Operation Name ... is not allowed` 或 401/403。
3. 构造“合法 operation 名 + 敏感字段”文档：`{"query":"query getPastes{systemHealth}"}`；若返回敏感数据，确认绕过。
4. 扩展字段：把多个敏感字段放进同一 operation（`query getPastes{systemHealth systemDiagnostics users{id username}}`），或用 fragment/别名隐藏字段名，观察哪些可读。
5. 若服务端按 operation 名白名单限制 mutation，尝试 `mutation login{ deleteAllPastes }` 等“公开 mutation 名 + 敏感字段”组合；确认是否有写操作越权。
6. 记录响应与 schema，评估数据敏感度与进一步利用（配置、凭据、用户枚举）。

## PoC

```json
// 被拒绝：operation 名本身不在白名单
{"query": "query systemHealth{ systemHealth }"}
// 响应：400 Bad Request: Operation Name "systemHealth" is not allowed.

// 绕过：operation 名用允许的 getPastes，字段仍请求 systemHealth
{"query": "query getPastes{ systemHealth }"}
// 响应：{"data":{"systemHealth":"System Load: 0.07\n"}}
```

```bash
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query getPastes{ systemHealth systemDiagnostics }"}'
```

## 变体与关联

- 变体：用 fragment 把敏感字段藏在 fragment 中，或把 operation 名写成允许值、用多个 operation + `operationName` 参数切换。
- 变体：批量/别名请求中混入敏感字段；或利用 GET 查询参数、持久化查询 hash 绕过 WAF 对 operation 名的正则解析。
- 变体：如果只校验“文档中是否出现敏感字段名”，可用别名（`x: systemHealth`）或 fragment 规避字符串匹配；如果按 operation 名校验，则本文手法直接适用。
- 关联：[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（发现 operation/字段）、[[web-generic-graphql-batch-alias-rate-limit-brute-force]]（别名/批量）、[[web-generic-graphql-upload-path-traversal-arbitrary-write]]、[[web-generic-graphql-importpaste-command-injection]]。

## 检测与防御

- 检测：审计 GraphQL 网关/中间件的授权逻辑，确认是否只看 operation 名；对“合法 operation 名 + 敏感字段”的组合做测试；监控返回敏感字段的未认证请求。
- 防御：在 resolver 层做字段级授权（每个字段检查当前用户角色/归属），不要用 operation 名白名单代替；按用户裁剪 schema/字段；对敏感字段单独限权；统一错误信息避免泄露 operation 是否存在；定期用 introspection/字段建议做自动化越权测试。
- 说明：本文是 GraphQL 授权缺陷（operation 名与字段级权限错配），severity 记为 medium；仅用于授权测试。
