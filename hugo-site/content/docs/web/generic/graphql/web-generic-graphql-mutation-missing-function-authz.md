---
id: web-generic-graphql-mutation-missing-function-authz
title: GraphQL 管理 mutation 函数级鉴权缺失：内省发现 deleteOrganizationUser 后，普通用户直接调用删除任意用户
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-mutation-missing-function-level-authz
tags:
- graphql
- mutation
- authorization
- bfla
- privilege
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:09:50+08:00'
  notes: 已对照 content.md 与 img17-24 核对：__schema 换行绕过后 InQL 解析出 deleteOrganizationUser，会话经 GET /api?query= 执行 input:{id:3} 删除 carlos（响应 user.id=3），删除前 getUser(id:3)=carlos。未验证点：未复现实例；'普通用户'依据靶场流程与登录会话推断（图08 wiener 登录），原文未显式标注角色。
url: /docs/web/generic/graphql/web-generic-graphql-mutation-missing-function-authz/
draft: false
kb_aliases:
- GraphQL mutation 越权
- deleteOrganizationUser
- GraphQL BFLA
- GraphQL 函数级授权
- 管理 mutation 未鉴权
---

## 一句话结论

GraphQL 把所有 mutation 都作为可选字段暴露在同一个端点上，前端不展示管理功能并不等于服务端禁止调用；攻击者通过内省发现 `deleteOrganizationUser` 之类的管理 mutation 及其输入类型后，用普通账号直接发送该 mutation（如 `input:{id:3}`）即可删除任意用户，因为 resolver 只校验登录而未校验角色/权限。

## 原理

- GraphQL 执行引擎按查询文档执行字段；mutation 字段与 query 字段一样可由客户端自由选择，只要 schema 中存在且通过校验就会进入对应 resolver。UI 的菜单/按钮只是客户端行为，不构成安全边界。
- 内省会给出 mutation 名称、参数结构与输入类型（如 `deleteOrganizationUser(input: DeleteOrganizationUserInput!)`、`DeleteOrganizationUserInput { id: Int }`），InQL 等工具还能直接生成调用模板。
- 若 resolver 或统一鉴权只判断“已登录”，没有按角色/权限位校验该 mutation 是否允许当前用户执行，普通用户就能调用管理员操作（Broken Function Level Authorization）。
- 之所以成立：GraphQL 单端点 + schema 自描述使“隐藏功能”很容易被枚举，而授权若只做在路由/菜单层（而非字段/resolver 层）就会被绕过。

## 触发条件

- 目标暴露 GraphQL 端点并开启内省（或攻击者已获得 schema）。
- 存在敏感 mutation（删除/修改用户、改角色、发通知、改配置等），其 resolver 缺少角色/权限校验。
- 攻击者持有任意已登录账号（甚至未登录，若端点无认证）。
- 目标对象 ID 可枚举或已知。

## 利用步骤

1. 内省或 InQL 加载 schema，列出全部 mutations；重点看 `delete*`、`update*`、`create*`、`reset*`、`assign*` 等管理语义字段。
2. 找到目标 mutation 的入参结构，例如 `deleteOrganizationUser(input:{id:3})`。
3. 用普通账号会话直接发送该 mutation（POST JSON，或按目标支持的 GET/表单形式）。
4. 观察响应是否返回被操作用户对象（如 `{"data":{"deleteOrganizationUser":{"user":{"id":3}}}}`），再用查询确认该用户已消失。
5. 授权测试中只对自建测试对象操作，避免破坏真实数据。

## PoC

```http
POST /graphql HTTP/1.1
Host: target
Content-Type: application/json
Cookie: session=<普通用户会话>

{"query":"mutation { deleteOrganizationUser(input: {id: 3}) { user { id username } } }"}
```

响应确认删除成功：

```json
{"data":{"deleteOrganizationUser":{"user":{"id":3,"username":"carlos"}}}}
```

GET 形式（端点允许 GET 执行 mutation 时同样可用，也意味着可被 CSRF 利用）：

```http
GET /api?query=mutation%20%7B%20deleteOrganizationUser(input%3A%20%7Bid%3A3%7D)%20%7B%20user%20%7B%20id%20%7D%20%7D%20%7D HTTP/1.1
Host: target
```

## 变体与关联

- 变体：管理 mutation 不限于删除用户，还包括改角色/提权、重置密码、创建 API key、修改系统配置等；同一 schema 中的 query 也可能缺少对象级授权（见隐藏字段卡）。
- 变体：mutation 名可通过字段建议、前端 JS 或错误信息获得，不依赖内省。
- 关联：[[web-generic-graphql-introspection-private-field-exposure]]（同一内省流程下的字段/对象级越权）；[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（schema 枚举前置）；[[web-generic-graphql-operation-name-authz-field-bypass]]（操作名白名单被夹带字段绕过，机制不同）。
- 边界：resolver 或统一授权层按角色校验 mutation、生产环境关闭内省且无字段建议、管理 mutation 与普通端点分离时，该链路不成立。

## 检测与防御

- 检测：普通账号会话调用管理语义 mutation；mutation 调用与 UI 行为不一致；内省后短时间内出现敏感 mutation 请求；审计日志中出现非管理员执行的删除/提权操作。
- 防御：在 resolver/字段级实施授权（角色、权限、对象归属），不要只在路由或前端菜单做控制；管理 mutation 单独做权限校验与二次确认。
- 防御：生产环境关闭内省与字段建议；对 mutation 增加审计日志与告警；高风险管理操作要求 MFA/审批；GraphQL 端点统一认证并对未授权字段返回错误而非静默执行。
