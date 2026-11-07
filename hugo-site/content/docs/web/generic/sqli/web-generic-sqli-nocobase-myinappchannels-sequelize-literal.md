---
id: web-generic-sqli-nocobase-myinappchannels-sequelize-literal
title: NocoBase myInAppChannels 的 filter.$lt 拼接进 Sequelize.literal 导致认证后 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: nocobase-myinappchannels-sequelize-literal-sqli
tags:
- nodejs
- nocobase
- sequelize
- sql-injection
- orm
- literal
- authenticated
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:11:18+08:00'
  notes: 已通读原文（无图片）逐段核对：defineMyInAppChannels 的 handler 从 ctx.action.params 取 filter 零校验，filter.latestMsgReceiveTimestamp.$lt 原样拼入 Sequelize.literal；channelsRepo.find→Repository.find→buildQueryOptions 的 ...options 透传→model.findAll→QueryGenerator 落库；ACL registerSnippet 未指定 roles、member 默认可读，数据流与调用链均与原文一致。原文明确不提供 PoC、不做黑盒测试，卡内已注明未实测，confidence=medium 合理；原文未给版本，未设 affected_versions。PoC 请求结构按 NocoBase 资源路由推断，未在本机或目标验证。
url: /docs/web/generic/sqli/web-generic-sqli-nocobase-myinappchannels-sequelize-literal/
draft: false
kb_aliases:
- NocoBase SQL 注入
- myInAppChannels SQLi
- latestMsgReceiveTimestamp $lt 注入
- Sequelize.literal 注入
- NocoBase 站内消息注入
---

## 一句话结论

NocoBase 的 `myInAppChannels:list` 资源把请求参数 `filter[latestMsgReceiveTimestamp][$lt]` 直接拼进 `Sequelize.literal()` 的子查询比较表达式；该字段预期是数字时间戳却没有任何类型校验，任意已认证用户（包括默认开放自注册的普通 `member`）都能把 SQL 片段送进数据库执行。

## 原理

- **入口与数据流**：`plugin-notification-in-app-message/src/server/defineMyInAppChannels.ts` 用 `app.resourceManager.define({ name: 'myInAppChannels', actions: { list: { handler } } })` 注册资源。handler 第一行 `const { filter = {}, limit = 30 } = ctx.action?.params ?? {}` 直接取请求参数，`filter` 没有任何 schema/类型校验。
- **拼接点**：服务端先构造内部子查询 `latestMsgReceiveTimestampSQL`（表名/字段名来自 collection 元数据，本身不可控），随后：
  ```ts
  const latestMsgReceiveTSFilter = filter?.latestMsgReceiveTimestamp?.$lt
    ? Sequelize.literal(`${latestMsgReceiveTimestampSQL} < ${filter.latestMsgReceiveTimestamp.$lt}`)
    : null;
  ```
  右侧 `$lt` 完全来自 HTTP 查询串。Koa 会把 `?filter[latestMsgReceiveTimestamp][$lt]=...` 解析成嵌套对象，字符串原样进入模板字符串。
- **literal 为什么危险**：`Sequelize.literal()` 的语义是“这段内容已经是 SQL，不要转义/参数化”。Sequelize 的 QueryGenerator 会把它原样拼进最终 SQL，因此 `<` 右侧可以放 `1 OR 1=1`、子查询、`CASE WHEN`、时间盲注表达式等。
- **为什么能到达执行**：`latestMsgReceiveTSFilter` 被放进 `channelsRepo.find({ where: { [Op.and]: [userFilter, latestMsgReceiveTSFilter, ...] } })`。`Repository.find()` → `buildQueryOptions()` 中 `{ where: {}, ...options, ...params }`，这里的 `where` 是调用方已经构造好的对象，走 `...options` 展开，不经过 `OptionsParser` 的过滤；最终 `model.findAll(opts)` 进入 Sequelize `QueryGenerator.selectQuery()`，literal 原样落库。
- **权限面**：资源通过 `app.resourceManager.define()` 注册，默认经过 `auth`/`acl`；插件 `load()` 中 `this.app.acl.registerSnippet({ name: 'pm....myInAppChannels', actions: ['myInAppChannels:list'] })` 没有指定 `roles`，且 `member` 角色默认对站内消息资源有读取权限（业务需要每个用户看自己的消息）。因此任意已认证用户可达；NocoBase 默认开放自注册，攻击者可以先注册普通账号。
- **数据库无关性**：注入发生在 Sequelize 生成 SQL 的阶段，PostgreSQL/MySQL/SQLite 三种后端都会把用户片段拼入；具体可用的注入技巧（布尔、时间、UNION、堆叠）取决于后端和驱动。

## 触发条件

- 目标运行包含 `plugin-notification-in-app-message` 的 NocoBase（文章未给出具体受影响版本，需按代码是否含该 `Sequelize.literal` 写法确认）。
- 攻击者拥有任意已认证账号；若目标开放自注册，可直接注册 `member`。
- 目标资源路由 `myInAppChannels:list` 未额外收紧 ACL；`member` 角色可访问。
- 请求可携带嵌套 `filter` 参数（Koa query parser 默认支持 `filter[x][y]`）。

## 利用步骤

1. 注册/登录一个普通账号，获取会话 Cookie 或 Token。
2. 调用站内消息频道列表资源，例如 `GET /api/myInAppChannels:list`，确认返回正常数据。
3. 在 `filter[latestMsgReceiveTimestamp][$lt]` 中放入注入片段；先构造恒真条件验证，再用布尔/时间盲注或 UNION 提取数据。
4. 根据数据库类型选择载荷：PostgreSQL 可用 `CASE WHEN ... THEN ... ELSE ... END`、`pg_sleep`；MySQL 可用 `IF()`、`SLEEP()`；SQLite 可用 `CASE`/`randomblob` 等。
5. 用返回差异、时间延迟或报错信息判断注入结果；进一步可读取 `users`、`publicForms`、`workflows` 等表，为后续链提供数据。

## PoC

原文明确不提供 PoC、未做黑盒测试；以下仅为请求结构示意，未在目标上执行：

```http
GET /api/myInAppChannels:list?filter[latestMsgReceiveTimestamp][$lt]=1%20OR%201%3D1 HTTP/1.1
Host: target
Cookie: <authenticated session>
```

注入后服务端生成的 SQL 形态：

```sql
SELECT ...
FROM "notificationChannels" AS "notificationChannels"
WHERE (
  ...
  AND (
    (SELECT messages."receiveTimestamp"
     FROM "notificationInAppMessages" AS messages
     WHERE messages."channelName" = "notificationChannels"."name"
       AND messages."userId" = 1
     ORDER BY messages."receiveTimestamp" DESC
     LIMIT 1
    ) < 1 OR 1=1
  )
)
ORDER BY ...
```

## 变体与关联

- **同资源其他 filter 字段**：当前代码只对 `latestMsgReceiveTimestamp.$lt` 做 literal 拼接；其他比较操作符（`$gt`、`$between`）是否可达需按版本代码确认。
- **认证要求**：这是认证后注入；若目标关闭自注册且没有低权限账号，需要先通过其他入口获取会话。
- **与 NocoBase 未授权 RCE 链的关系**：SQL 注入可用于读取 `publicForms` 的 `formKey`、JWT 密钥相关表或业务数据，为 public-forms 链补足条件；两条链在原文中是独立发现，但可组合。
- 关联卡片：[[web-nodejs-nocobase-public-forms-path-traversal-jwt-workflow-rce]]。

## 检测与防御

- **代码修复**：不要用 `Sequelize.literal()` 拼接任何请求值；把 `$lt` 强制转为数字（`Number(...)`/`parseInt`）并用 `Op.lt`/`Sequelize.where(Sequelize.col(...), Op.lt, value)` 参数化；对 `filter` 做 schema 校验，只允许白名单字段与操作符。
- **权限**：确认 `myInAppChannels:list` 的 ACL 片段确实绑定到最小角色；关闭不必要的自注册；对站内消息资源做行级 `userId` 约束（代码已用 `ctx.state.currentUser.id`，但注入可绕过）。
- **检测**：`filter[...][$lt]` 中出现 SQL 关键字、引号、括号、`OR`、`SLEEP`、`CASE`、子查询；`myInAppChannels:list` 响应时间异常或返回行数异常；数据库日志出现由该资源产生的异常 SQL。
- **应急**：升级到修复版本/打补丁；审计 `myInAppChannels` 访问日志与数据库慢查询；轮换可能泄露的 JWT 密钥与数据库凭据。
