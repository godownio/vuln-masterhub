---
id: web-generic-auth-unauth-user-create-admin-takeover
title: 未授权用户创建接口导致创建账号并登录后台
type: scenario
domain: web
path: web/generic/auth
technique: unauth-user-create-admin-takeover
tags:
- web
- auth-bypass
- unauthorized
- user-creation
- admin-panel
- privilege-escalation
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:32:58+08:00'
  notes: 已对照原文与图09/10/11核对：未登录进入用户管理点击“新增用户”，按用户名/密码/确认密码/邮箱/手机号创建成功，随后用新账号登录并显示“登录成功”，可操作服务管理/备份等。卡中同时说明用户列表接口仍要求登录，边界准确。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/auth/web-generic-auth-unauth-user-create-admin-takeover/
draft: false
kb_aliases:
- 未授权创建用户
- 后台账号接管
- 未授权新增用户接口
- 创建管理员账号
- 注册接口未鉴权
---

## 一句话结论

当后台的“新增用户”接口没有做服务端认证/角色校验时，未登录攻击者可以直接调用它创建一个账号，再用该账号登录后台，获得与新建用户角色对应的管理权限。

## 原理

- 管理后台的“新增用户”通常对应一个 `POST /user/create` 之类的接口。前端页面可能要求登录，但后端接口若没有独立的认证与授权中间件，就直接接受请求。
- 攻击者通过前端路由守卫绕过、JS 接口枚举或 Swagger 文档找到该接口后，直接发送符合字段规则的 JSON（用户名、密码、邮箱、手机号等）即可创建用户。
- 如果服务端在创建时把角色/权限字段交给客户端，或给新用户默认分配管理员/高权限角色，创建出的账号就具备后台操作能力；即使默认是普通角色，也可能通过后续越权接口提升。
- 创建成功后，用同一套登录接口输入刚创建的凭据即可登录；登录态由服务端正常签发，后续管理功能按该账号角色放行。
- 这类漏洞的核心是“把注册/创建用户能力暴露在未认证面上”，而不是前端页面是否可见。很多系统只保护了“用户列表”查询，却漏掉了“创建/修改/删除”写接口。

## 触发条件

- 存在用户创建接口（后台新增用户、注册、批量导入等），且未要求有效会话/管理员角色。
- 接口接受攻击者可控的用户名、密码及可选的角色/权限字段。
- 新建用户能够登录，且其默认角色足以访问至少部分后台功能；或可通过批量创建/角色字段直接获得管理员。
- 登录接口没有额外的强校验（验证码、邀请码、管理员审批等）阻断新账号。

## 利用步骤

1. 通过前端路由枚举、JS 文件、Swagger/OpenAPI 或抓包定位用户创建接口及其字段。
2. 去掉 Cookie/Token 重放创建请求，确认是否仍返回成功。
3. 按接口规则构造用户名、密码（必要时带 `role`/`isAdmin`/`status` 等字段）。
4. 用创建的凭据调用登录接口，保存返回的会话/Token。
5. 携带该会话访问后台管理接口，确认可执行用户管理、服务管理、备份恢复等操作。
6. 如接口支持批量创建或角色字段可控，进一步创建高权限账号或批量账号。

## PoC

```http
POST /api/user/create HTTP/1.1
Host: target.example
Content-Type: application/json

{
  "username": "audit_test_01",
  "password": "P@ssw0rd_2026",
  "email": "audit_test_01@example.com",
  "phone": "13800000000"
}
```

```bash
# 不带任何 Cookie/Token 发送
curl -i -X POST 'https://target.example/api/user/create' \
  -H 'Content-Type: application/json' \
  -d '{"username":"audit_test_01","password":"P@ssw0rd_2026","email":"audit_test_01@example.com"}'

# 用新账号登录
curl -i -X POST 'https://target.example/api/user/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"audit_test_01","password":"P@ssw0rd_2026"}'
```

```text
# 预期：
# 1) 创建接口返回 200/成功，未要求登录；
# 2) 登录接口返回有效会话或 Token；
# 3) 携带会话访问后台管理接口成功。
```

## 变体与关联

- 变体：批量创建接口（`createWithArray`/`createWithList`/导入）同样未鉴权，可一次创建大量账号。
- 变体：创建请求支持 `role`、`isAdmin`、`userStatus` 等字段且服务端未做白名单，直接创建管理员（mass assignment）。
- 变体：注册接口默认角色过高；或创建后通过未授权的“修改用户”接口改密码/角色。
- 关联：[[web-generic-auth-vue-router-frontend-guard-bypass]]（如何发现隐藏的后台新增用户页面/接口）；[[web-generic-auth-swagger-unauth-user-management]]（Swagger 暴露的同类增删接口）；[[web-generic-auth-jwt-signature-only-role-bypass]]（拿到会话后的垂直越权）。
- 边界：如果创建接口要求管理员会话，或新用户默认无任何后台权限且无法提升，则只能造成账号垃圾/信息泄露，不能接管后台。案例中用户列表接口仍要求登录，但创建接口未鉴权，说明鉴权是按接口零散实现的。

## 检测与防御

- 检测：审计所有用户创建/注册/导入接口的认证与角色校验；监控未登录状态下对 `/user/create`、`/register`、`/import` 等路径的成功写请求；关注短时间内批量创建账号的行为。
- 修复：在统一认证/授权中间件中覆盖所有写接口，管理端创建用户必须要求管理员角色；服务端固定分配角色，禁止客户端传入 `role`/`isAdmin` 等敏感字段。
- 加固：注册/创建接口增加验证码、邀请码或审批；对新账号做最小权限；记录创建者、来源 IP 与审计日志；定期清理异常账号。
