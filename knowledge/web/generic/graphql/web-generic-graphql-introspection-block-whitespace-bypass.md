---
id: web-generic-graphql-introspection-block-whitespace-bypass
title: GraphQL 内省禁用绕过：拦截规则只匹配 `__schema{`，在字段名与花括号之间插入换行/空格/逗号即可取回完整 schema
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-introspection-disable-whitespace-bypass
aliases:
- GraphQL introspection 绕过
- __schema 换行绕过
- introspection is not allowed
- 内省禁用绕过
- GraphQL 方法/Content-Type 绕过
tags:
- graphql
- introspection
- bypass
- waf
- regex
- api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:09:52+08:00'
  notes: '已对照 content.md 与 img12-18 核对：POST /api 返回 405 Allow: GET、GET /api 报 Query not present、query{__typename} 探测成功；标准内省返回 ''GraphQL introspection is not allowed, but the query contained __schema or __type''，在 __schema 后插入 %0a 换行后 200 返回完整 schema（queryType/mutationType/types）。未验证点：未复现实例。'
---

## 一句话结论

不少 GraphQL 服务用正则/字符串匹配拦截 `__schema`（常见模式是匹配连续的 `__schema{`）来“禁用内省”，但 GraphQL 词法分析允许任意空白、换行和逗号出现在 token 之间；把查询写成 `__schema\n{...}`、`__schema {`、`__schema,{` 仍是合法内省查询却不命中该正则，从而取回完整 schema。若限制只做在 POST JSON 上，换用 GET 查询参数或 `application/x-www-form-urlencoded` 也常能绕过。

## 原理

- GraphQL 规范中的 “ignored tokens”：空白（空格、制表符）、行终结符（换行/回车）、逗号、注释在语法分析前被忽略，可出现在任意两个 token 之间。`__schema\n{ queryType { name } }` 与 `__schema{queryType{name}}` 语义完全等价。
- 开发者的“禁用内省”常实现为 WAF 规则或代码里的 `query.contains("__schema")` / 正则 `__schema\s*\{` 等粗糙匹配；如果规则只匹配 `__schema{` 这种紧凑写法，换行/空格/逗号即可绕过；如果是关键字黑名单，则需结合注释等其他 ignored token 或改用建议枚举（Clairvoyance）。
- 方法/内容类型维度：限制可能只挂在 POST JSON 的解析链路上；GraphQL 服务器往往同时支持 GET（`?query=`）与表单编码的 POST（`query=...&variables=...`），而这些入口不做同样的内省拦截。
- 之所以成立：过滤发生在字符串/HTTP 层，而语义解析发生在 GraphQL 层，两层对“同一个查询”的判定不一致。

## 触发条件

- 服务端禁用内省的方式是字符串/正则匹配，而不是 GraphQL 校验规则（如 NoIntrospection）。
- 拦截规则只匹配紧凑写法 `__schema{`，或只覆盖单一方法/Content-Type。
- GraphQL 端点接受 GET 查询参数或 `application/x-www-form-urlencoded` 的 POST。
- 正常内省请求返回 “introspection is not allowed” / “GraphQL introspection is not allowed, but the query contained __schema or __type” 类错误，说明限制存在但可尝试绕过。

## 利用步骤

1. 发送标准内省查询，确认被拦截（响应为 not allowed 类错误）。
2. 在 `__schema` 与 `{` 之间插入换行（`%0a`）、空格或逗号后重放；例如 `query{__schema\n{queryType{name}}}`。
3. 若仍被拦截，尝试切换方法：GET `/graphql?query=...`；或 POST `Content-Type: application/x-www-form-urlencoded`，body 为 URL 编码的 `query=...`。
4. 观察错误差异定位入口：例如 POST 返回 405 `Allow: GET`，GET 返回 `Query not present`，说明该路径存在一个只接受 GET 的 GraphQL 端点。
5. 绕过成功后保存完整内省 JSON，导入 InQL/Voyager 继续枚举查询与 mutation。

## PoC

```http
POST /api HTTP/1.1
Host: target
Content-Type: application/json

{"query":"query IntrospectionQuery { __schema\n { queryType { name } mutationType { name } types { name kind } } }"}
```

GET 形式（换行 URL 编码为 `%0a`）：

```http
GET /api?query=query%7B__schema%0a%7BqueryType%7Bname%7D%7D%7D HTTP/1.1
Host: target
```

原文环境结果：标准内省返回 `"GraphQL introspection is not allowed, but the query contained __schema or __type"`；在 `__schema` 后插入换行后返回完整 schema（queryType/mutationType/types 等），随后用 InQL 解析出 `getUser` 与 `deleteOrganizationUser`。

## 变体与关联

- 变体：逗号、空格、制表符、注释（`#` 到行尾）都属于 ignored token，可按拦截规则选择；注释后必须换行。
- 变体：若关键字黑名单同时匹配 `__schema` 与 `__type`，可改用字段建议（“Did you mean …?”）做 Clairvoyance 式重建，或从 GraphiQL/Playground、前端 JS、旧响应中获取 schema。
- 变体：只禁用 POST 的实现可换 GET；只禁止内省但允许 GraphiQL 的实现可直接从 IDE 获取 schema。
- 关联：[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（端点发现与正常内省/Clairvoyance 流程）；[[web-generic-graphql-introspection-private-field-exposure]]（拿到 schema 后的字段越权利用）。
- 边界：服务端在 GraphQL 校验层禁用内省（解析后拒绝 `__schema`/`__type`）时，该绕过无效；GET 与表单编码都被禁用时方法维度也不成立。

## 检测与防御

- 检测：请求体/查询参数中出现 `__schema` 后跟空白再跟 `{`、`%0a`、`%20`、逗号等变体；同一客户端先收到 introspection not allowed 后立刻发送变体查询；GET/表单形式的内省探测。
- 防御：不要用正则/字符串匹配禁用内省，改用 GraphQL 执行前的校验规则（如 graphql-java 的 NoIntrospection、Apollo 的 introspection: false），对解析后的 AST 做字段名校验。
- 防御：统一各方法/Content-Type 入口的安全策略；只允许 POST + `application/json`；对 introspection、字段建议与深层查询做速率限制和告警。
