---
id: web-nodejs-ioredis-zadd-array-argument-injection
title: ioredis zadd 数组参数扁平化注入：一个 username 写入多个排行榜成员与任意分数
type: scenario
domain: web
path: web/nodejs
technique: ioredis-zadd-array-flattening-injection
tags:
- web
- nodejs
- redis
- ioredis
- zadd
- argument-injection
- type-confusion
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:10:28+08:00'
  notes: 已对照原文核对：源码 zadd('scoreboard', score, username)、/new 数组 username 请求与 /play 触发、Jay17=1337 排行榜及 /flag 截图均一致；ioredis 扁平化与 ZADD 多成员语义正确。未验证点：实际 Redis 命令文本未在原文抓包中直接给出，为按源码/客户端行为推定。
url: /docs/web/nodejs/web-nodejs-ioredis-zadd-array-argument-injection/
draft: false
kb_aliases:
- ioredis zadd 注入
- 数组参数扁平化
- Redis ZADD 多成员注入
- 用户名数组绕过排行榜
- corCTF 2024 rock-paper-scissors
---

## 一句话结论

Node.js 应用把用户可控的 `username` 直接传入 `redis.zadd('scoreboard', score, username)` 且没有类型校验时，由于 ioredis 会把数组参数扁平化，JSON 传入 `{"username":["J8",1337,"Jay17"]}` 会让实际命令变成 `ZADD scoreboard <score> J8 1337 Jay17`——J8 得到当前分数、攻击者控制的 Jay17 直接得到 1337 分，随后用 Jay17 身份访问 `/flag` 即可。

## 原理

- **ZADD 的多成员语义**：Redis `ZADD key score member [score member ...]` 支持一次设置多个成员；`zadd('scoreboard', 123, 'user1', 1337, 'user2')` 等价于两条 score/member 对。
- **ioredis 的数组扁平化**：ioredis 在构造命令时会扁平化数组参数，官方支持 `redis.zadd('key', [17, 'a'], [18, 'b'], [19, 'c'])` 这种写法。因此当应用传入 `zadd('scoreboard', score, ['J8', 1337, 'Jay17'])` 时，数组元素会被展开成额外的参数，而不是当成一个“用户名”整体。
- **类型校验缺失**：`username` 来自 JSON body，攻击者可以传字符串、数字、数组、对象。应用假设它是字符串，只做 JWT 签名/排行榜展示，没有 `typeof username === 'string'` 或长度/字符集校验；数组一路传到 ioredis。
- **排行榜覆盖语义**：代码用 `zadd` 而不是 `zadd(..., 'NX')`/`GT`，已有成员也会被覆盖；后台预先写入 `FizzBuzz101=1336`，攻击者用注入把任意成员写成高于阈值的分数。
- **为什么能拿 flag**：`/flag` 只校验 JWT 中的 `username` 对应排行榜分数 > 1336；JWT 由应用自己签发，攻击者先用注入成员名（如 `Jay17`）注册/开始游戏，再把它的分数写成 1337，即可通过校验。
- **本质**：这是“JSON 类型混淆 + 客户端库可变参数/数组扁平化”导致的参数注入，不是传统 SQL/NoSQL 注入；信任边界在应用层（一个用户名字段）与命令层（可变数量参数）之间。

## 触发条件

- Node.js + ioredis（或其他会扁平化数组参数的 Redis 客户端）应用。
- 用户可控字段（用户名、成员名、key 名等）被直接传入 `zadd`/`zincrby`/`mset` 等多参数命令，且没有强制转成字符串。
- 业务逻辑依赖排行榜/分数做权限或奖励判断（如分数 > 阈值给 flag）。
- 攻击者能发送 JSON 数组（`Content-Type: application/json`）并能以注入的成员名获得 JWT/会话。

## 利用步骤

1. 阅读源码，定位 `redis.zadd('scoreboard', score, username)` 等调用，确认 `username` 来自 `req.body` 且无类型校验。
2. 用数组作为 username 注册游戏：`POST /new`，body `{"username":["J8",1337,"Jay17"]}`，拿到签发给该“用户名”的 JWT Cookie。
3. 触发一次写入：`POST /play`（带 Cookie），故意输掉或正常结束，使代码执行 `zadd('scoreboard', score, username)`；数组被扁平化，`Jay17` 被写入 1337 分。
4. 查看 `/scores` 确认排行榜出现 `Jay17 1337`。
5. 以 `Jay17` 身份重新注册/登录（或直接构造 `{"username":"Jay17"}` 的 `/new` 请求拿 JWT），访问 `/flag`，分数 > 1336 即返回 flag。
6. 若目标用其他 Redis 命令，可类推：数组元素成为额外参数，注入多个成员/选项（如 `NX`、`XX`、`GT`、`CH`）。

## PoC

```http
POST /new HTTP/1.1
Host: target
Content-Type: application/json

{"username":["J8",1337,"Jay17"]}
```

```http
POST /play HTTP/1.1
Host: target
Cookie: session=<上一步返回的 JWT>
Content-Type: application/json

{"position":"..."}
```

```text
# Redis 实际执行（示意）：
ZADD scoreboard <当前分数> J8 1337 Jay17
# 排行榜：Jay17 = 1337，超过 FizzBuzz101 的 1336
```

```http
POST /new HTTP/1.1
Host: target
Content-Type: application/json

{"username":"Jay17"}
# 用返回的 session 访问：
GET /flag HTTP/1.1
Cookie: session=<Jay17 的 JWT>
```

## 变体与关联

- **命令变体**：`zadd` 之外，`mset`、`hmset`、`sadd`、`lpush` 等接受多参数/多字段的命令都可能被数组扁平化影响；带 `NX/XX/GT/CH` 选项的 `zadd` 还可注入选项改变语义。
- **客户端变体**：不同 Redis 客户端对数组/对象的处理不同；node-redis、go-redis、redis-py 的参数构造方式需按实现确认。ORM/查询构造器也可能存在类似的数组参数展开。
- **类型混淆变体**：除数组外，数字/布尔/对象可能被隐式转成字符串或触发不同分支；在 JWT、缓存 key、日志中也会产生不一致。
- **关联卡片**：[[web-nodejs-sequelize-findall-query-options-include-on-injection]]（同场比赛的 ORM 查询选项注入，同样是“用户输入直接进入库的选项”）、[[web-generic-sqli-nocobase-myinappchannels-sequelize-literal]]（Sequelize 原始 SQL 注入的另一类）。
- **边界**：应用对 username 做 `String()`/类型/长度校验、使用 `zadd` 时显式拆分参数、或排行榜使用服务端生成的不可控成员名时，本链不成立。

## 检测与防御

- **修复**：对进入 Redis 命令的用户字段做严格类型校验（必须是字符串）和长度/字符集限制；不要依赖客户端库的隐式转换；必要时显式 `String(username)` 并拒绝数组/对象。
- **命令层**：使用明确的单成员 API 或先校验参数个数；排行榜写入使用 `zadd(key, 'GT', score, member)` 等受控选项，避免覆盖已有分数。
- **业务层**：flag/奖励判断不要只看客户端可控的 username 与排行榜；用服务端会话绑定不可伪造的用户 ID，并对分数变更做审计。
- **检测**：请求体中出现 `username` 为数组/对象；同一 JWT 用户名与排行榜成员不一致；ZADD 命令参数数量异常（多出 score/member 对）；短时间大量 `/new` + `/play` 请求。
