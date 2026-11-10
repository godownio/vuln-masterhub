---
id: web-generic-auth-nuims-getuser-userid-idor-password-hash
title: NUIMS GetUser/LcpGetUser 显式 UserId 参数越权：读取任意用户资料与 bcrypt 密码哈希
type: scenario
domain: web
path: web/generic/auth
technique: nuims-getuser-userid-idor
aliases:
- NUIMS 越权
- GetUser UserId 越权
- LcpGetUser 越权
- communityUserId 收集
- 用户信息接口越权
- 密码哈希泄露
tags:
- web
- auth
- authz
- idor
- bola
- broken-access-control
- api
- pii
- password-hash
- enumeration
- src
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V412
  verified_at: '2026-11-09T14:56:00+08:00'
  notes: 已对照原文与图01-10核对：GetUser 追加 UserId 越权读取他人 bcrypt(P$2a$10$)哈希及 bandEmail/bandMobile/ssn/regIp/fullName；/gw/nuims/api/v1/nuims/LcpGetUser?UserId= 同源复现；/api/loadUserComment 的 communityUserId 与 GetUser 的 UserId 一致可用于收集 ID。未验证点：社区站点已脱敏，PoC 未复跑；社区接口/字段细节来自作者截图。
---

## 一句话结论

登录任意账号后，在统一身份服务（NUIMS）网关接口 `/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01` 上追加 `UserId` 参数，即可用自己的会话读取任意其他用户的资料，响应包含用户名、bcrypt 密码哈希、邮箱、手机号、注册 IP 与身份证号等敏感字段；另一网关前缀下的 `/gw/nuims/api/v1/nuims/LcpGetUser?UserId=...` 存在同样问题。

## 原理

- NUIMS 以 `UserId` 为主键存储用户实体。网关接口 `Action=GetUser` 的正常语义是“根据当前会话返回当前登录用户的信息”，但实现同时接受调用方传入的 `UserId` 并直接用它查询，请求参数覆盖了会话身份。
- 鉴权只做到功能级：检查请求是否携带有效登录态、接口是否可达；没有做对象级授权（BOLA），即没有比较 `UserId` 与会话身份是否一致，也没有限制调用方角色。服务端把“请求合法”误当成“访问对象合法”。
- 网关把身份服务的内部查询能力（按主键查用户）透传给浏览器端，导致“查询谁”完全由客户端决定；`Version` 参数只是 API 版本，不是授权凭据。
- 响应返回完整用户实体而非最小字段集：`Password` 为 bcrypt 哈希（`$2a$10$...`），`EnterpriseAuthInfo` 内含 `bandEmail`、`bandMobile`、`ssn`、`regIp`、`fullName` 等，使越权从“看昵称”升级为可直接用于撞库、钓鱼与账户恢复的 PII 与口令材料泄露。
- `LcpGetUser` 与 `GetUser` 查询同一后端实体、返回同构数据，说明缺陷位于身份服务本身而不是某一个网关路由；同一能力被多个网关前缀暴露，关闭一个入口不等于修复。

## 触发条件

- 攻击者拥有站点任意低权限登录账号，能正常拿到 Cookie 或 Authorization。
- 身份服务网关接口对已登录用户开放，并接受显式 `UserId` 参数。
- 服务端未做对象级授权：不校验 `UserId` 是否等于当前会话用户，也不限制调用方角色。
- 响应包含 Password（哈希）、邮箱、手机号、IP、ssn 等敏感字段。
- 目标 UserId 可获得：自增可遍历，或能从其他业务接口（评论、帖子、日志等）收集。

## 利用步骤

1. 登录后抓取自己的 `GetUser` 请求：`GET /gateway/nuims/nuims?Action=GetUser&Version=2020-06-01`，确认响应含 `UserId`、`Password`、`EnterpriseAuthInfo` 等字段。
2. 先追加 `UserId=<自己的 UserId>`，确认服务端采纳该参数；再替换为他人 UserId，若响应中的 `UserName`、`Password`、`bandEmail`、`bandMobile` 变为目标用户，则越权成立。
3. UserId 若是不可顺序遍历的长随机串，转去业务接口收集：论坛帖子/评论列表接口（如 `POST /api/loadUserComment`）的响应中每条评论都带作者对象，`communityUserId` 与 `communityUser.id` 中前者就是 NUIMS 的 `UserId`；打开任意帖子即可批量取得不同作者的 ID。
4. 用收集到的 ID 重放第 2 步请求批量读取资料；同时验证另一前缀 `/gw/nuims/api/v1/nuims/LcpGetUser?UserId=<id>`（可通过 JS 文件或接口发现插件找到），确认同源问题。
5. 抽样核对用户名/邮箱与目标账号的对应关系，评估规模后停止，避免全量拖库。
6. 后续利用：对 bcrypt 哈希做离线弱口令破解；用邮箱/手机号做密码找回或钓鱼；用泄露的身份信息社工客服。

## PoC

```http
GET /gateway/nuims/nuims?Action=GetUser&Version=2020-06-01&UserId=<victim-user-id> HTTP/1.1
Host: target
Cookie: <自己的登录会话>

HTTP/1.1 200 OK
Content-Type: application/json

{"Code":"Success","Data":{"UserId":"<victim-user-id>","UserName":"...","Password":"$2a$10$...","NickName":"...","EnterpriseAuthInfo":"{\"bandEmail\":\"...\",\"bandMobile\":\"...\",\"ssn\":\"...\",\"regIp\":\"...\"}"}}
```

```http
GET /gw/nuims/api/v1/nuims/LcpGetUser?UserId=<victim-user-id> HTTP/1.1
Host: target
Cookie: <自己的登录会话>
```

```text
# 从论坛评论响应收集作者 ID 后批量越权（伪代码）
ids = unique(comment.communityUserId for comment in POST /api/loadUserComment responses)
for uid in ids[:20]:
    GET /gateway/nuims/nuims?Action=GetUser&Version=2020-06-01&UserId=uid
```

## 变体与关联

- 变体：`UserId` 改放到 POST body、Header 或 Cookie 中传递；`Action` 换成同族的用户查询动作（QueryUser/GetUserInfo 等），通常复用同一授权缺陷。
- 变体：同一身份服务经不同网关前缀（`/gateway/nuims/...`、`/gw/nuims/api/v1/...`）暴露相同方法，在 JS 中检索 `nuims`、`GetUser` 可枚举全部入口。
- 变体：不可遍历 ID 的收集面还可来自帖子详情、消息/IM、登录日志、导出任务、组织架构等返回 `communityUserId` 或 `userId` 的接口。
- 关联：[[web-generic-auth-authlog-userid-enumeration-authz-bypass]]（同类“先收集合法 ID 再越权详情”，但那边是日志接口加自增用户详情，本条是身份服务网关参数越权）；[[web-generic-auth-mobile-person-permission-userid-idor-pii]]（userId 参数水平越权 PII）；[[web-generic-auth-imid-userinfo-mobile-pii-enumeration]]（imId 越权手机号）；[[web-generic-auth-related-object-pii-overreturn]]（响应过返 PII 的字段级问题）。
- 边界：服务端强制 UserId 取会话身份、按角色限制查询他人、响应脱敏且不返回密码哈希时，本路径失效；拿到哈希但用户密码强度高时，离线破解收益有限，危害仍以 PII 泄露为主。

## 检测与防御

- 检测：同一登录态短时间请求大量不同 UserId；`GetUser` 请求参数出现非当前用户 ID；身份服务响应包含 Password/ssn 等不应外发的字段；同一账号访问用户资料的数量异常。
- 修复：对象级授权——`GetUser` 忽略客户端传入的 UserId，一律取会话身份；如确需管理端查询，单独接口并按角色/租户校验，服务间调用走 mTLS 或内部鉴权。
- 修复：响应最小化，永不返回 Password（含哈希）、ssn、完整手机号/邮箱，按调用方角色脱敏。
- 加固：对身份查询接口做速率限制与审计告警；统一收敛 NUIMS 类网关的对外路由，下线冗余 `LcpGetUser` 暴露面。
