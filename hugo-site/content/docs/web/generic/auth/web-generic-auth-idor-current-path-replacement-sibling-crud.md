---
id: web-generic-auth-idor-current-path-replacement-sibling-crud
title: IDOR 接口面扩展：current/me 替换为数字 ID、老版本接口与兄弟 CRUD 接口猜测
type: scenario
domain: web
path: web/generic/auth
technique: idor-current-path-replacement-sibling-crud
tags:
- idor
- bola
- auth
- access-control
- api
- rest
- enumeration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T18:40:30+08:00'
  notes: 已对照原文与图08核对：current→数字 ID 的 PUT /api/users/1235/profile/email 示例（200 返回 Id 1235）与原文一致；无身份参数补 id 示例、/v3→/v2 老接口、addeval→DeleteEval 兄弟接口（POST /ReportStudent/SLabSource/DeleteEval，EvalID=1069，图08）均与原文一致，原文称猜测删除接口后成功越权。dedup 候选 patient-infocode/face-photo/parameter-graph 等为不同手法（related/new）；dup-scan 与 openid 两段式卡 pair 判 related（不同攻击点，保留）。未执行写/删操作。
url: /docs/web/generic/auth/web-generic-auth-idor-current-path-replacement-sibling-crud/
draft: false
kb_aliases:
- current 替换 id
- me/my 路径越权
- 修改接口越权
- 兄弟接口猜测
- 老版本接口越权
- addeval 到 DeleteEval
- 隐藏 id 参数
---

## 一句话结论

对只操作自己数据的接口，把路径或参数中的 `current`/`me`/`my` 换成数字用户 ID（或在无身份参数的查询请求里补一个 `id` 参数），常能命中“只按 ID 定位对象、不校验归属”的实现；再结合老版本路由（`/v3/`→`/v2/`）和按命名规律猜测的兄弟 CRUD 接口（如只暴露 `addeval` 时猜 `DeleteEval`），可把只读越权扩展为改、删越权。

## 原理

- **current/me/my 只是别名**：框架/业务层通常把 `current`、`me`、`my` 解析为当前会话用户。若同一路由也接受数字 ID，替换后后端若没有额外校验该 ID 是否等于会话用户，就会按传入 ID 操作对象，形成水平越权。
- **隐式身份参数**：有些查询接口不带身份参数，直接按会话用户过滤；但后端可能同时接受可选的 `id`/`userId`/`accountId`，一旦客户端补上该参数，就可能覆盖会话过滤，返回/修改他人数据。
- **老版本接口**：`/v3/user/123` 与 `/v2/user/123` 这类并存路由中，旧版本可能缺少新版本加入的归属校验或鉴权中间件；同一 token 往往仍然可用。
- **兄弟接口**：前端只展示 `addeval`（添加评论），后端可能还有 `deleteEval`、`editEval`、`listEval` 等未在前端暴露的接口；按动作命名规律和常见动词（add/edit/update/delete/get/list/save）枚举，常能找到未做归属校验的写接口。
- **为什么成立**：鉴权只做到“登录/有 token”这一层，对象级授权（检查对象 owner/tenant）缺失；隐藏/旧版接口不在正常测试覆盖范围内，更容易遗漏。
- **利用面**：只读接口可泄露 PII/订单；写接口可改他人邮箱/密码/资料、删除他人评论/订单/招聘主题，危害显著高于单点只读越权。

## 触发条件

- 攻击者拥有一个低权限账号（或接口可未授权访问），能抓取自己的资料/订单/评论等自助接口。
- 接口路径或参数中出现 `current`/`me`/`my`，或查询接口不带身份参数但响应含对象 ID。
- 响应里能看到自己的数字用户 ID（或从 JWT/其他接口推导）。
- 同一应用存在老版本 API 路径或未在前端展示的兄弟接口，且接受同一套 token。
- 仅用于授权测试；写/删操作优先使用自己的测试对象或与厂商约定的测试数据。

## 利用步骤

1. 抓取个人中心/资料修改/订单/评论等自助接口，标记出 `current`/`me`/`my` 路径段、请求体中的 userId/accountId，以及响应中的数字 `Id`。
2. 把路径中的 `current` 替换成自己的数字 ID，发送同样的修改/查询请求；若返回 200 且数据一致，说明该路由接受数字 ID。
3. 换成另一个测试账号的数字 ID（或目标用户的 ID），重复请求；若返回/修改了对方数据，确认水平越权。
4. 对不带身份参数的查询接口，尝试在 query/body 中补 `id`、`userId`、`accountId`、`uid`，再替换为他人 ID；观察响应是否从“我的数据”变为“他人数据”。
5. 尝试老版本路由：把 `/v3/` 改成 `/v2/`、`/v1/`，或把 `/api/users/current` 改成 `/api/v2/users/123`；同时切换 GET/POST/PUT/PATCH/DELETE 方法。
6. 从已知动作名推断兄弟接口：如 `addeval` → `deleteEval`、`editEval`、`updateEval`、`getEval`、`listEval`；结合 JS 源码、Swagger/OpenAPI、OPTIONS 响应、错误信息中的路由提示。
7. 对猜到的写接口用测试对象验证（如删除自己的一条评论、修改自己的邮箱），再替换 ID 测试他人对象；记录请求、响应与影响。
8. 用第二个测试账号交叉确认；写操作完成后恢复测试数据，避免影响真实用户。

## PoC

current → 数字 ID 的修改越权（原文示例）：

```http
POST /api/users/current/profile/email HTTP/2
Host: api.example.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"email":"user@example.com"}
```

```http
PUT /api/users/1235/profile/email HTTP/2
Host: api.example.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"email":"changed@example.com"}
```

原文响应 `200 OK` 且返回 `{"Id":1235,"email":"changed@example.com"}`，说明把 `current` 换成他人数字 ID 后仍可修改，属于水平越权。

兄弟接口猜测（只有 addeval 时猜 DeleteEval）：

```http
POST /ReportStudent/SLabSource/DeleteEval HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: <低权限会话>
Authorization: <token>

EvalID=1069
```

原文中前端只暴露 `addeval`（添加评论），按命名规律猜出 `DeleteEval` 并传入 `EvalID=1069` 后成功删除他人评价，说明隐藏写接口同样缺少归属校验。

无身份参数补 id（思路）：

```http
GET /user/info HTTP/1.1
GET /user/info?id=123 HTTP/1.1
```

## 变体与关联

- **路径变体**：`/users/current`、`/users/me`、`/users/my`、`/profile/current`；替换为数字 ID、UUID、邮箱或用户名。
- **方法变体**：GET 只读越权 → PUT/PATCH/POST 写越权 → DELETE 删除越权；同一路由不同方法可能鉴权不一致。
- **版本变体**：`/v1/`、`/v2/`、`/v3/`、`/api/internal/`、`/api/admin/` 并存；旧版本/内部版本常缺校验。
- **隐藏接口变体**：`addeval`→`DeleteEval`；`getUserInfo`→`updateUserInfo`；`list`→`export`；结合 Swagger、JS chunk、错误堆栈、OPTIONS 枚举。
- **关联**：[[web-generic-auth-idor-openid-leak-enumerable-query-chain]]（不可遍历标识的泄露链）、[[web-generic-auth-idor-empty-wildcard-type-query-collapse]]（空值/通配符/类型导致全量返回）、[[web-generic-auth-authenticated-change-password-idor]]（登录后改密接口 username 可控）、[[web-generic-auth-multi-session-matrix-leakscore]]（多会话矩阵自动化验证）、[[web-generic-auth-face-photo-update-body-id-idor]]（请求体 id 写越权）。

## 检测与防御

- **检测**：同一会话对 `/users/<id>`、`/profile/<id>` 的 ID 与 token 中用户不一致；短时间内出现大量不同 ID 的 PUT/DELETE；访问未在前端出现的兄弟路由（404→200 变化、OPTIONS 暴露方法）；旧版本路径访问量异常。
- **防御**：对象级授权统一在服务端校验 `对象.owner == session.user`；不要仅凭路径中的数字 ID 定位对象；`current`/`me` 路由只允许操作会话用户；旧版本接口下线或补齐鉴权；隐藏/内部接口同样纳入鉴权与测试；对写操作增加二次确认、审计日志与频率限制。
- **测试注意**：写/删越权验证优先使用自己的测试对象，确认后再用测试账号交叉；不要删除真实用户数据；发现后可先只读验证影响，再按授权范围提交报告。
