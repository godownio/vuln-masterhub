---
id: web-generic-auth-spring-rbac-delete-user-idor
title: Spring Boot RBAC 删除用户接口只按 userId 删除：低权用户越权删除同级/任意用户
type: scenario
domain: web
path: web/generic/auth
technique: spring-rbac-delete-user-idor
tags:
- web
- auth
- idor
- vertical-privilege-escalation
- java
- spring-boot
- rbac
- user-management
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:31:42+08:00'
  notes: 已对照原文与全部61张图核对：Burp DELETE /api/user?userId=13（图33）、MySQL 通用日志 delete my_role_user/my_user_job/my_user where user_id=14（图34，user_id 与 userId 为不同测试轮次）、用户列表出现 test6（图35）、删除响应 {"success":true,"code":200,"msg":"成功"}（图40 userId=8）；原文称正常只能删下级、改 userId 后成功删除同级 test6，最新版因 JWT 校验无法越权。卡内原理/PoC/边界与原文一致。原子性：单一删除用户接口 IDOR，单卡单原子。未验证点：未复跑；无版本号，未设 affected_versions；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，xxl-job/NewBeeMall 等为不同资源接口；dup-scan 中本卡与同篇 XSS 卡 pair 判定 related，两张均保留。
url: /docs/web/generic/auth/web-generic-auth-spring-rbac-delete-user-idor/
draft: false
kb_aliases:
- 删除用户越权
- 垂直越权删除用户
- userId 越权
- my-springsecurity-plus 越权
- DELETE /api/user
- 同级用户删除
---

## 一句话结论

Spring Boot RBAC 后台的删除用户接口只根据请求参数 `userId` 定位并删除 `my_user`、`my_role_user`、`my_user_job` 中的记录，没有校验“当前登录用户是否有权删除该目标（是否为其下级）”；低权账号抓包修改 `userId` 就能删除同级用户甚至管理员，造成账号破坏/拒绝服务，最新版通过 JWT 权限校验后才修复。

## 原理

- 删除用户的正常业务逻辑应包含两层校验：当前用户是否拥有 `user:delete` 权限，以及目标用户是否在当前用户的可管理范围（如下级/同部门）。文章中的旧版本只做了前者（或仅有登录态），删除时直接使用客户端提交的 `userId`。
- 抓包可见请求为 `DELETE /api/user?userId=13`，服务端依次执行：
  ```sql
  delete from my_role_user where user_id = 14;
  delete from my_user_job where user_id = 14;
  delete from my_user where user_id = 14;
  ```
  （原文 SQL 日志中的 `user_id=14` 与实际请求的 `userId=13` 是不同测试轮次；关键是删除目标完全由请求参数决定。）
- 低权账号在用户管理页正常只能看到/操作下级用户，但接口没有对 `userId` 做归属校验；把它改成同级用户（如 `test6`）的 ID，服务端仍执行删除，原文实测成功删除同级用户。
- 最新版本在删除前增加 JWT 身份/权限校验，低权账号无法再越权删除；旧版本/未修复分支仍存在。
- 同类问题还可能出现在编辑用户、重置密码、修改角色等按 `userId` 操作的接口，需要一并审计。

## 触发条件

- 目标为 Spring Boot + SpringSecurity 的 RBAC 后台，删除用户接口接受客户端 `userId`（QueryString/表单/JSON 均可）。
- 攻击者拥有一个可登录的低权账号，并能访问用户管理/删除功能（或接口本身只校验登录态）。
- 服务端没有把 `userId` 与当前会话用户的可管理范围/组织层级做绑定校验。
- 目标用户存在且未被保护（如同一租户/系统内的同级用户、管理员账号）。

## 利用步骤

1. 用低权账号登录后台，进入用户管理，选择一个可删除的下级用户并抓取删除请求（如 `DELETE /api/user?userId=<id>`）。
2. 在响应/数据库日志中确认删除语句按 `user_id` 删除 `my_user`、`my_role_user`、`my_user_job` 等表。
3. 枚举/猜测其他用户的 `userId`（列表接口、返回包、自增 ID），把请求中的 `userId` 改成同级用户或管理员 ID。
4. 发送请求，观察是否返回成功、目标用户是否从列表/数据库消失。
5. 若删除接口有二次确认/验证码，尝试直接调用接口、重放、修改参数类型（数组/字符串）绕过前端校验。
6. 扩展到其他按 `userId` 操作的接口（编辑、重置密码、分配角色）测试同样的归属校验缺失。

## PoC

```http
DELETE /api/user?userId=13 HTTP/1.1
Host: target:8088
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Cookie: <低权账号会话>
Authorization: <低权账号 JWT>
```

服务端 SQL 日志（原文）：

```sql
delete from my_role_user where user_id = 14;
delete from my_user_job where user_id = 14;
delete from my_user where user_id = 14;
```

原文用低权账号成功删除了同级用户 `test6`；返回体示例：

```json
{"success": true, "code": 200, "msg": "成功", "count": null, "data": {}, "jwt": null}
```

## 变体与关联

- 变体：把 `userId` 改为管理员 ID 删除管理员（若管理员不在保护名单）；用数组/逗号分隔批量删除；通过编辑接口修改他人资料/角色；通过重置密码接口接管账号。同类按 ID 操作的接口都应检查归属。
- 关联：同项目的存储型 XSS 见 [[web-generic-xss-spring-rbac-user-dept-name-stored]]；通用 IDOR/越权卡见 [[web-generic-auth-idor-current-path-replacement-sibling-crud]]、[[web-generic-auth-mall-cancel-user-order-idor]]。
- 最新版通过 JWT 校验修复；若目标使用旧版本或自定义分支，仍需验证。

## 检测与防御

- 服务端校验：删除/编辑用户前，从会话/JWT 取当前用户身份，校验其角色/组织层级是否覆盖目标 `userId`；不要只信任客户端传入的 ID。
- 权限模型：把“可管理范围”（部门/角色/数据权限）落到查询条件中，而不是只在前端隐藏按钮；对管理员账号加保护（不可被低权删除/禁用）。
- 审计与日志：记录删除操作的操作者、目标、时间、来源 IP；对同一账号短时间大量删除、删除同级/上级用户的行为告警。
- 测试：用低权账号遍历 `userId` 做越权测试；检查所有按 `id` 操作的接口（删除、编辑、重置密码、分配角色）是否存在同样的归属校验缺失。
