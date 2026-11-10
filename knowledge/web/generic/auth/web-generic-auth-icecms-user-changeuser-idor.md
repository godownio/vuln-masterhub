---
id: web-generic-auth-icecms-user-changeuser-idor
title: IceCMS /User/ChangeUser 的 userId 越权（CVE-2023-6760/6761）：普通用户改他人资料并接管管理员账号
type: scenario
domain: web
path: web/generic/auth
technique: icecms-changeuser-userid-idor
aliases:
- IceCMS 水平越权
- IceCMS 垂直越权
- CVE-2023-6760
- CVE-2023-6761
- ChangeUser userId 篡改
- userinfo 越权改密
tags:
- authz
- idor
- horizontal-privilege-escalation
- vertical-privilege-escalation
- icecms
- account-takeover
- jwt
- java
cve:
- CVE-2023-6760
- CVE-2023-6761
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: Thecosy IceCMS 2.0.1
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T23:10:32+08:00'
  notes: 已对照原文与图21-32核对：普通用户对 POST /User/ChangeUser 将 userId 改为 334 修改他人 email/简介/密码；将 userId 改为 3（管理员）修改 name/password 后返回修改成功，数据库图30可见管理员被改，前端图31/32确认；图1 VulDB 中 CVE-2023-6761 为 User Data Handler improper access controls、6760 为 manage user sessions，与文章映射一致；卡片变体提到的 CVE-2023-36100（api/User/ChangeUser UserID）亦在图1出现，作为同端点旁证合理。未验证点：未复测管理员新口令登录（图34为另一轮登录）。
---

## 一句话结论

IceCMS 的用户资料更新接口 `POST /User/ChangeUser` 直接使用请求体里的 `userId` 作为要更新的目标用户，只校验 JWT 是否有效、不校验该 JWT 是否属于这个 userId，也不校验角色：普通用户把 `userId` 改成他人 ID 即可修改对方邮箱/性别/密码（水平越权，CVE-2023-6760），改成管理员 ID（如 3）即可改掉管理员口令并登录后台（垂直越权，CVE-2023-6761）。

## 原理

- **JWT 只证明"我是谁"，接口却按请求体决定"改谁"**：前端从 `/userinfo/index` 页面提交资料时会带上当前会话的 JWT 与一个包含 `userId` 的 JSON 对象；后端 `ChangeUser` 按 `userId` 主键执行 UPDATE，没有把目标 ID 与 token 中的用户 ID 绑定，也没有限制普通用户只能改自己。
- **水平越权**：攻击者注册普通账号 A，抓取自己更新资料的数据包，把 `userId` 换成同站另一普通用户 B 的 ID（示例 334），连同 `name`/`email`/`gender`/`password` 一起提交，返回 `{"code":200,"msg":"修改成功"}`，B 的资料与密码被改，前端页面刷新后显示新值。
- **垂直越权**：管理员 ID 在用户列表中可枚举（示例为 3），把 `userId` 改为 3 并提交新的 `username`/`password`/`name`，即可重置管理员账号；数据库确认管理员口令被改，随后用新口令登录后台，完成账号接管。
- **为什么能成功**：接口把编辑对象的 ID 交给客户端控制（IDOR），且缺少角色校验（任何登录用户都可更新任意用户）；前端隐藏字段/只读属性不构成安全边界。
- **影响**：从任意改资料到管理员账号接管，属于完整的高危越权链；即便不知道原密码，也能直接设置新密码。

## 触发条件

- 目标为 IceCMS 2.0.1（CVE-2023-6760/6761）。
- 攻击者拥有一个可登录的普通账号（可自行注册），并能抓包/重放 `POST /User/ChangeUser`。
- 目标用户 ID 可枚举（用户列表、注册返回、页面数据等均可获得）；管理员 ID 通常较小或可从公开信息推断。

## 利用步骤

1. 注册两个测试账号（测试1、测试2），分别登录并访问 `/userinfo/index` 更新资料，抓取 `POST /User/ChangeUser` 请求。
2. 观察请求体中的 `userId` 字段；用测试1 的 JWT 把 `userId` 改成测试2 的 ID（如 334），修改 `email`/`gender`/`password` 后发送。
3. 返回 `{"code":200,"msg":"修改成功"}`，登录测试2 或刷新其资料页确认被改（水平越权）。
4. 抓取管理员账号的 userId（示例为 3，可通过用户列表或注册信息推断），用普通用户 JWT 把 `userId` 改为 3，提交新的 `username`/`password`。
5. 用新口令登录管理员账号，确认数据库与后台均已变更（垂直越权）。

## PoC

```http
POST /User/ChangeUser HTTP/1.1
Host: target:8181
Authorization: Bearer <普通用户 JWT>
Content-Type: application/json

{"userId":3,"name":"pwned","username":"admin","password":"NewPass123","email":"a@b.c","gender":3,"intro":"x"}
```

返回 `{"code":200,"msg":"修改成功","data":null}` 即管理员账号口令被重置。把 `userId` 换成任意普通用户 ID 则为水平越权改资料/改密。

## 变体与关联

- 变体：只改 `email` 触发找回密码流程，绕过直接改密；或先改邮箱再走"忘记密码"接管账号。
- 变体：同产品 `api/User/ChangeUser` 的 `UserID` 参数有同类的权限提升问题（CVE-2023-36100），可按同一思路测试。
- 关联：[[web-generic-auth-icecms-square-comment-api-missing-jwt]]（先未授权拿到用户列表与口令）；[[web-generic-auth-icecms-delete-by-id-idor]]（同产品按 ID 越权删除）；[[web-generic-auth-form-field-id-idor-pii-enumeration]]（表单 userId 类 IDOR 通用模式）。

## 检测与防御

- 检测：更新接口请求体中的 userId 与会话身份不一致；同一 JWT 短时间内更新多个 userId；普通角色账号请求更新 admin 记录。
- 防御：自助资料更新一律忽略客户端 userId，使用 token 中的用户 ID；管理端修改他人资料必须独立接口并校验角色；对 userId 做服务端授权校验；敏感操作（改密/改邮箱）要求二次验证并通知原邮箱。
