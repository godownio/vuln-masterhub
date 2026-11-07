---
id: web-generic-sqli-login-username-comment-universal-password
title: 登录用户名注入 + 注释符万能密码：枚举管理员用户名接管后台
type: scenario
domain: web
path: web/generic/sqli
technique: login-username-comment-universal-password
tags:
- web
- sqli
- login-bypass
- universal-password
- mysql
- username-enumeration
- comment-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:28:34+08:00'
  notes: 已对照原文与图37-41核对：username=111' 报错回显拼接SQL（sea_admin，密码MD5），原文实测 admin'#/1'or+1# 万能密码，并枚举 test 为管理员后 test'# 登录；未本地复现
url: /docs/web/generic/sqli/web-generic-sqli-login-username-comment-universal-password/
draft: false
kb_aliases:
- 用户名万能密码
- admin'# 登录绕过
- 1'or+1# 万能密码
- MySQL 注释符登录绕过
- 管理员用户名枚举
- 登录框 SQL 注入
---

## 一句话结论

登录接口把用户名直接拼进 SQL，攻击者用 `admin'#`（或 `1'or+1#`）让 `#` 注释掉后面的密码条件，即可用任意密码登录；若系统多用户使用、`admin` 不是真正的管理员，可通过响应差异枚举管理员用户名（如 `test`），再用 `test'#` 登录管理员后台。

## 原理

- 典型拼接：`SELECT * FROM sea_admin WHERE username='<输入>' AND password='<MD5>' LIMIT 1`。用户名未参数化，单引号可闭合字符串；MySQL 的 `#` 把后续内容注释掉，`AND password=...` 失效。
- 因此 `username=admin'#` 变为 `WHERE username='admin'`，只要存在 admin 用户即返回第一行并登录；密码填任意值不影响。
- `1'or+1#` 则是 `WHERE username='1' or 1#...`，`1` 恒真，返回表中第一行，适合不知道管理员用户名时“盲进”后台。
- 但多用户/多角色系统中，第一行或 admin 账号可能不是真正的管理员：文章遇到万能密码能进后台却只有个人数据，说明登录后的功能权限由具体账号决定。此时需要枚举真实管理员用户名。
- 用户名枚举可依据登录响应差异（错误提示、跳转、Set-Cookie、页面内容）或直接猜测常见管理员名；文章最终确定 `test` 为管理员，构造 `test'#'` 登录后获得管理权限。
- 密码在 SQL 中呈现为 32 位哈希，说明前端/后端先做了 MD5 再拼接；但用户名处仍是明文拼接，攻击面在用户名。

## 触发条件

- 登录接口用字符串拼接 SQL，用户名未参数化；
- 数据库为 MySQL（`#` 注释）或可用对应注释符（MSSQL `--`、Oracle `--`）；
- 登录查询返回用户记录并直接建立会话，未额外校验密码哈希；
- 系统存在可枚举/可猜测的管理员用户名。

## 利用步骤

1. 在用户名输入单引号，观察是否返回 SQL 错误并泄露拼接结构（如 `select * from sea_admin where username='111'' and password='...'`）。
2. 测试注释符万能密码：`admin'#`、`1'or+1#`、`admin'-- -`，密码随意；观察是否进入后台。
3. 若进入的不是管理员，记录当前账号权限；用常见管理员用户名列表（root、systemadmin、postgres、administrator、sysadmin、test 等）逐个配合 `'#` 测试。
4. 根据响应差异（成功/失败、跳转地址、Cookie、页面标题）确定真实管理员用户名。
5. 用 `<管理员名>'#` 登录，确认后台管理权限；在授权范围内验证功能，不修改生产数据。
6. 测试后退出并报告；建议修复为参数化查询并统一错误提示。

## PoC

```http
POST /admin/loginok.php HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin'%23&password=whatever&submit=%E7%99%BB%E5%BD%95
```

解码后的用户名：

```sql
admin'#
```

实际 SQL（示意）：

```sql
SELECT * FROM sea_admin WHERE username='admin'#' AND password='<MD5>' LIMIT 1
```

多用户系统枚举管理员：

```text
root'#        -> 非管理员/失败
systemadmin'# -> 非管理员/失败
test'#        -> 管理员后台
```

原文先用 `admin'#` 进入普通后台，最终用 `test'#` 获得管理员权限。

## 变体与关联

- 变体：`1'or+1#`、`' or 1=1#`、`admin'-- -`、`admin'/*`；不同数据库注释符不同（MySQL `#`/`-- `，MSSQL `--`，Oracle `--`）。
- 变体：用户名经过 URL 编码/大小写/双写绕过 WAF；密码字段也可能存在注入（见关联卡）。
- 关联：[[web-generic-sqli-login-password-unquoted-or-bypass]]（密码字段未加引号的 OR 恒真绕过，注入点不同）、[[web-generic-auth-username-enumeration-timing-lockout]]（用户名枚举的另一路径）。
- 边界：登录使用参数化查询、用户名白名单、统一错误页且无响应差异、管理员用户名不可猜时，利用受限。

## 检测与防御

- 检测：登录请求用户名含 `'`、`#`、`--`、`or`、`/*`；同一 IP 高频尝试不同用户名 + 注释符；登录响应出现 SQL 错误或异常跳转；短时间内大量用户名枚举。
- 防御：所有登录查询使用参数化/预编译，禁止字符串拼接；用户名只允许字母数字等白名单字符。
- 防御：登录失败统一提示，关闭 SQL 错误回显；对登录做速率限制、验证码与异常告警。
- 防御：管理员账号使用独立强口令与 MFA；后台按角色做服务端权限校验，不依赖登录账号的默认首页。
