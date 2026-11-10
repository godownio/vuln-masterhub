---
id: web-generic-graphql-endpoint-discovery-schema-enumeration
title: GraphQL 端点发现与 schema 枚举：__typename 探测 + introspection + Clairvoyance 建议重建 + graphw00f 引擎指纹
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-endpoint-discovery-schema-enumeration
aliases:
- GraphQL 端点发现
- query __typename
- GraphQL introspection
- Clairvoyance schema 重建
- graphw00f 指纹
- GraphQL Voyager
- InQL 扫描
- Field Suggestions 泄露
tags:
- graphql
- recon
- introspection
- schema-enumeration
- clairvoyance
- graphw00f
- api
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:53:00+08:00'
  notes: 已对照 content.md 与 img05-18 核对：query{__typename} 探测、introspection 完整查询、Clairvoyance Did you mean title、Voyager、Postman、InQL、graphql-cop 输出（Alias Overloading/Array-based Query Batching 等）、graphw00f 引擎指纹与实现矩阵、端点路径列表均与原文一致。未验证点：PoC 命令为工具通用用法整理，未逐一执行；graphql-cop 自 2022 年起未维护，卡片已注明。
---

## 一句话结论

GraphQL 测试从“找端点 + 拿 schema”开始：对常见路径（`/graphql`、`/graphiql`、`/v1/graphql`、`/api/graphql`、`/console`、`/playground` 等）发送 `{"query":"query{__typename}"}`，响应含 `{"data":{"__typename":"Query"}}` 即确认端点；随后优先执行 introspection 拉取完整类型/字段/参数，若 introspection 被禁用则用 Clairvoyance 借助 “Did you mean …?” 字段建议重建 schema，并用 graphw00f 根据错误/元数据指纹识别引擎（Graphene、Apollo、graphql-php 等）以对照已知安全缺陷。

## 原理

- **端点发现**：GraphQL 通常只有一个端点（常见 `/graphql`），但也可挂在 `/graphiql`、`/playground`、`/api/graphql`、`/v1/graphql`、`/console`、`/gql`、`/query` 等路径；用 Seclists 等单词表对该路径集合做 POST/GET 模糊测试，请求体 `query{__typename}`。`__typename` 是 GraphQL 内置元字段，任何合法 GraphQL 服务都会返回当前类型名（通常是 `Query`），比依赖错误信息更可靠。
- **introspection 枚举**：GraphQL 规范内置 `__schema`/`__type` 查询，可一次拿到 queryType/mutationType/types/fields/args/directives 等完整结构；文章给出的 introspection 查询用 `fragment FullType`/`InputValue`/`TypeRef` 递归展开 `ofType`，响应 JSON 即完整 schema。生产环境常禁用，但禁用不等于安全：字段建议、错误信息、GraphiQL/Playground 仍可能泄露结构。
- **Clairvoyance 重建**：introspection 关闭时，向服务发送带有近似字段名的查询，利用 GraphQL 的 “Cannot query field … Did you mean …?” 建议功能逐字符/逐词猜出字段名，再用单词表扩展，最终拼出部分 schema；若服务关闭字段建议或错误信息被统一化，该工具会失效。
- **graphw00f 指纹**：GraphQL 无官方实现，各引擎（Graphene、Apollo、graphql-php、graphql-yoga、graphql-ruby 等）在错误格式/元数据上有差异；graphw00f 发送特制请求，根据响应签名识别引擎，并给出该实现的攻击面矩阵（是否支持 introspection、字段建议、GET 查询、批量、持久化查询等），帮助选择后续测试项。
- **可视化与客户端**：GraphQL Voyager 把 schema 画成类型关系图；Postman/InQL 可自动发 introspection、生成查询/变更列表并发到 Repeater，便于快速定位敏感 mutation（上传、导入、管理操作）。

## 触发条件

- 目标暴露 GraphQL 端点（可能未公开/仅在特定功能或角色下使用）。
- 端点允许 `__typename`（几乎所有实现），introspection 可能开启或至少字段建议/错误信息可见。
- 可发送自定义 POST/GET 请求；有常见路径单词表或能从前端 JS/流量中发现端点。
- 仅用于授权测试；对生产环境应控制请求频率，避免 introspection/深层查询造成负担。

## 利用步骤

1. 从应用前端 JS、网络流量、公开文档或常见路径列表收集候选 GraphQL 路径。
2. 对每个候选 POST `{"query":"query{__typename}"}`；响应 `data.__typename == "Query"` 即确认端点；也观察 400/405 与 Content-Type。
3. 发送完整 introspection 查询（`{__schema{queryType{name}mutationType{name}types{...FullType}...}}` + fragments）；保存 JSON，导入 Voyager/Postman/InQL 可视化。
4. 若 introspection 返回 “introspection is not allowed”，改用 Clairvoyance：`clairvoyance http://target/graphql -w wordlist.txt -o schema.json`，根据 `Did you mean` 建议迭代重建。
5. 用 graphw00f 指纹：`graphw00f -t http://target/graphql`，记录引擎与攻击面矩阵；用 graphql-cop 快速跑常见项（introspection、字段建议、批量、别名、GET 支持）。
6. 在 schema 中标记高价值 query/mutation（用户列表、systemHealth、upload/import、admin 操作），进入授权/注入/文件/RCE 测试。

## PoC

```bash
# 1) 端点探测
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query{__typename}"}'
# 命中示例：{"data":{"__typename":"Query"}}

# 2) introspection（文章用的完整查询，可截断为最小版）
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name type{name kind ofType{name kind}}}}}}}"}'

# 3) introspection 关闭时用建议重建
clairvoyance http://target/graphql -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -o schema.json

# 4) 引擎指纹
graphw00f -t http://target/graphql

# 5) 常见漏洞快扫（工具较旧，结果仅作线索）
graphql-cop -t http://target/graphql -o json
```

## 变体与关联

- 变体：端点可能只接受 GET（query 参数）或需要特定 Content-Type/CSRF 头；可同时尝试 `application/json`、`application/graphql`、`application/x-www-form-urlencoded`。
- 变体：introspection 被禁用但 GraphiQL/Playground 仍开启，可直接从 IDE 的 schema 面板或自动补全获取字段；也可利用字段建议（`Did you mean`）做半自动枚举。
- 变体：使用持久化查询（persisted queries）时，端点只接受 hash，需要先从客户端/构建产物拿到查询文本。
- 关联：[[web-generic-graphql-batch-alias-rate-limit-brute-force]]（批量/别名放大）、[[web-generic-graphql-operation-name-authz-field-bypass]]（操作名授权绕过）、[[web-generic-graphql-upload-path-traversal-arbitrary-write]]、[[web-generic-graphql-importpaste-command-injection]]。

## 检测与防御

- 检测：监控对常见 GraphQL 路径的 `__typename`/introspection 请求、异常高的 “Did you mean” 建议请求、graphw00f/graphql-cop 特征 UA/请求模式；对 schema 枚举行为做速率限制与告警。
- 防御：生产环境禁用 introspection 与 GraphiQL/Playground；关闭字段建议或统一错误信息；对 GraphQL 端点做认证/授权与速率限制；schema 最小化，不暴露内部字段/mutation；不要把“隐藏端点”当作安全边界。
- 说明：本文是 GraphQL 侦察/枚举技术，severity 记为 low；仅用于授权评估。
