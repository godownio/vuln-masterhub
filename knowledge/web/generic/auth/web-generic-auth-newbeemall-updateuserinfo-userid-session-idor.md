---
id: web-generic-auth-newbeemall-updateuserinfo-userid-session-idor
title: newbee-mall updateUserInfo 用客户端 userId 重查用户并覆盖 session：两步越权修改他人资料
type: scenario
domain: web
path: web/generic/auth
technique: profile-update-client-userid-session-swap
aliases:
- newbee-mall 水平越权
- updateUserInfo 越权
- 个人资料越权修改
- session 用户覆盖
- userId 参数越权
tags:
- web
- idor
- horizontal-privilege-escalation
- session
- profile
- java
- spring
- newbee-mall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 2022-02 之前的 newbee-mall 版本（原文标记）
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T09:20:02+08:00'
  notes: 已对照原文与图05/06核对：updateInfo 接收 @RequestBody MallUser（userId 可控），NewBeeMallUserServiceImpl.updateUserInfo 先用 session userTemp.getUserId() 查库并更新自己，随后用 mallUser.getUserId() 重查并 BeanUtil.copyProperties + session.setAttribute 覆盖为受害者对象；原文明确指出 2022-02 前版本该行后续被删除修复，两步越权链成立。图05 仅证明 MallUser 有 userId 字段、图06 为 controller 入口，原文无完整两步请求截图，卡内 confidence medium 与“原文仅代码路径分析”备注准确。受影响版本按原文“2022年2月之前”已设置。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

newbee-mall 旧版 `updateUserInfo` 在更新完当前登录用户的资料后，又用请求体 `mallUser.userId` 重新查询用户并把结果覆盖进 session；攻击者先传他人 userId 把自己的 session 换成受害者身份，再提交一次改资料请求，即可越权修改受害者昵称、地址、个性签名等信息。

## 原理

- 入口 `POST /personal/updateInfo` 接收 `@RequestBody MallUser mallUser` 与 `HttpSession`，`mallUser` 的 `userId` 字段来自客户端，可任意指定。
- 服务端先用 session 中的当前用户 `userTemp.getUserId()` 查出 `userFromDB`，把请求里的昵称、地址、个性签名写入并更新——这一步只影响攻击者自己。
- 更新成功后，代码再次执行 `userFromDB = mallUserMapper.selectByPrimaryKey(mallUser.getUserId())`，即用客户端提交的 userId 查询任意用户；随后 `BeanUtil.copyProperties(userFromDB, newBeeMallUserVO)` 并 `httpSession.setAttribute(Constants.MALL_USER_SESSION_KEY, newBeeMallUserVO)`。
- 结果：攻击者的 session 里被写入了受害者的用户对象（含受害者 userId）。后续请求（包括再次调用 `/personal/updateInfo`）都会以受害者身份查库、更新，从而修改受害者的资料。
- 根因是“当前用户身份”在更新后被客户端参数重新决定：本应始终以 session 中的 userId 为准，却多了一次用 `mallUser.getUserId()` 的重查与 session 覆盖。作者后续修复正是删除这次重查，只保留基于 session 的查询。

## 触发条件

- 使用 2022-02 之前的 newbee-mall 版本（原文标记；该行代码后续被删除）。
- 攻击者拥有普通注册账号并已登录。
- `/personal/updateInfo` 接受 `mallUser.userId` 字段（JSON body 未做字段白名单/忽略）。
- 受害者 userId 可知或可枚举（自增 ID）。

## 利用步骤

1. 注册并登录攻击者账号，抓取 `/personal/updateInfo` 请求。
2. 第一次请求把 body 中的 `userId` 改为受害者 ID（昵称/地址等可留空或填任意值），触发重查并把 session 覆盖为受害者对象。
3. 确认响应返回的用户信息已变为受害者（或后续 `/personal` 页面显示受害者资料）。
4. 第二次请求把要篡改的昵称、地址、个性签名填入 body，服务端会以 session 中的受害者 userId 查库并更新，完成越权修改。
5. 记录两次请求与受害者资料变化作为证据；验证后停止，不批量修改。

## PoC

```http
POST /personal/updateInfo HTTP/1.1
Host: target
Cookie: JSESSIONID=<攻击者会话>
Content-Type: application/json

{"userId":<受害者ID>,"nickName":"x"}
```

第一次请求后 session 中的用户对象变为受害者；随后：

```http
POST /personal/updateInfo HTTP/1.1
Host: target
Cookie: JSESSIONID=<同一会话>
Content-Type: application/json

{"nickName":"hacked","address":"attacker-address","introduceSign":"pwned"}
```

第二次请求按 session 中的受害者 userId 更新其资料。原文仅给出代码路径与参数可控性分析，未提供完整两步请求截图。

## 变体与关联

- 变体：若框架支持 `@ModelAttribute`/表单绑定，可在 query 或 form 中直接传 `userId`；JSON 绑定同样有效。
- 变体：session 被覆盖后，攻击者还可读取受害者购物车、订单、收货地址等以 userId 为键的数据，形成横向信息泄露。
- 变体：同类代码若在“更新后重新查询”时使用客户端 id，均可造成 session 身份漂移，应重点审计 `session.setAttribute` 前的查询参数。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（登录后接口信任客户端 username 的同类越权）。
- 关联：[[web-generic-auth-vendure-cross-channel-child-entity-idor]]（父/子实体 ID 来自客户端导致的横向越权）。

## 检测与防御

- 防御：更新接口只从 session/令牌解析当前用户 ID，忽略请求体中的 `userId`；更新后重新查询也必须使用 session 中的 userId。
- 防御：对请求体做字段白名单（如只允许 nickName/address/introduceSign），禁止绑定 userId、角色、状态等敏感字段。
- 防御：修改资料等敏感操作要求重新认证或 CSRF token；session 中的用户对象变更后强制重新登录。
- 检测：同一 session 内 `updateUserInfo` 请求的 userId 与 session userId 不一致；资料更新后 session 用户对象 userId 发生变化；同一会话短时间内修改多个不同用户资料。
