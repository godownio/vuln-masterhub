---
id: web-generic-sqli-db-fingerprint-postgres-dameng-gaussdb
title: SQL 注入数据库指纹：PostgreSQL/达梦/GaussDB 的版本函数与系统视图差异
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-db-fingerprint-postgres-dameng-gaussdb
aliases:
- 数据库类型判断
- 信创数据库指纹
- PostgreSQL 指纹
- 达梦数据库判断
- GaussDB 判断
- current_database
tags:
- web
- sqli
- fingerprint
- postgresql
- dameng
- gaussdb
- database
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:27:02+08:00'
  notes: 已对照原文核对：PostgreSQL、达梦、GaussDB 的版本函数与系统视图差异及函数存在性判断均与原文一致；原文目标仅凭函数存在性判断大概率为 PostgreSQL，卡已如实表述；保留。
---

## 一句话结论

SQL 注入拿到回显或布尔差异后，可以用各数据库特有的版本函数、系统视图和函数存在性判断后端类型：PostgreSQL 支持 `version()`/`current_database()`，达梦支持 `@@VERSION`/`V$VERSION`，GaussDB 支持 `VERSION()`/`PG_VERSION`/`SHOW VERSION`；当 WAF 拦截版本关键字时，改用短函数存在性与报错差异继续判断。

## 原理

- 不同数据库的内置函数和系统视图不同：同一个查询在支持的数据库上返回正常结果，在不支持的数据库上报错或返回空。攻击者用“查询是否成功/返回内容是否包含产品名”作为指纹 oracle。
- PostgreSQL：`SELECT version()` 返回包含 `PostgreSQL` 的字符串；`SELECT current_database()` 返回当前库名；系统目录 `pg_catalog`、`pg_tables`、`pg_attribute` 可用。
- 达梦（DM）：兼容 Oracle/SQL Server 风格，支持 `SELECT @@VERSION`（类似 SQL Server）和 `SELECT * FROM V$VERSION`（Oracle 风格系统视图），后者返回值包含 `Dameng` 或 `DM Database`。
- GaussDB：`SELECT VERSION()` 返回包含 `GaussDB` 的字符串；兼容 PostgreSQL，存在 `PG_VERSION` 表，部分版本支持 `SHOW VERSION`。
- 国内信创改造使达梦、GaussDB 等数据库在业务中越来越常见；只看 `version()` 关键字容易被 WAF 拦截，因此需要函数存在性、短查询和错误差异等替代判断。

## 触发条件

- SQL 注入点有可观察的回显、布尔差异或错误信息。
- 当前数据库账号能执行 `SELECT` 和访问相应系统视图/函数；权限不足时可能返回权限错误，这本身也可作为指纹。
- WAF 可能拦截 `version`、`@@VERSION`、`V$VERSION` 等关键字；需要有替代查询。
- 注入点支持 UNION 或子查询，便于把函数返回值带到回显位。

## 利用步骤

1. 先用最通用的 `SELECT version()` 或 `SELECT @@VERSION` 试探，观察返回内容是否包含数据库产品名。
2. 若 PostgreSQL 特征出现，再用 `SELECT current_database()` 确认，并尝试 `pg_tables` 等系统目录。
3. 若返回达梦特征，尝试 `SELECT * FROM V$VERSION` 确认；若返回 GaussDB 特征，尝试 `SELECT * FROM PG_VERSION`/`SHOW VERSION`。
4. 关键字被 WAF 拦截时，改用函数存在性判断：把 `version()`、`current_database()` 等放进 UNION 回显位，或观察“函数不存在/权限不足”的报错差异。
5. 确认数据库类型后，再选择对应的元数据枚举与高危函数（如 PostgreSQL 的 `pg_tables`、`pg_read_file`、`COPY TO PROGRAM`）。

## PoC

```sql
-- PostgreSQL
SELECT version();
SELECT current_database();

-- 达梦（DM）
SELECT @@VERSION;
SELECT * FROM V$VERSION;

-- GaussDB
SELECT VERSION();
SELECT * FROM PG_VERSION;
SHOW VERSION;
```

UNION 注入中的用法示例（把返回值放到回显列）：

```sql
UNION SELECT version(), '2' --
UNION SELECT current_database(), '2' --
```

## 变体与关联

- 变体：MySQL 用 `@@version`/`version()`/`database()`；SQL Server 用 `@@VERSION`；Oracle 用 `SELECT * FROM v$version`；SQLite 用 `sqlite_version()`。
- 变体：用 `SELECT 1 FROM pg_tables LIMIT 1`、`SELECT 1 FROM V$VERSION` 等存在性查询做布尔判断，避免直接回显版本字符串。
- 变体：利用报错信息中的驱动/方言特征（如 `pg_`、`ORA-`、`DM`）辅助判断。
- 关联：[[web-generic-sqli-postgres-waf-comment-quote-bypass]]（PostgreSQL 注入点的 WAF 绕过）。
- 关联：[[web-generic-sqli-postgres-json-column-enum]]（确认 PostgreSQL 后的列名枚举）。
- 边界：注入点无回显、无布尔差异、无报错，且 WAF 拦截所有指纹关键字时，需要改用时间盲注/带外通道；权限极低的账号可能连系统视图都无法访问。

## 检测与防御

- 检测：SQL 中出现 `version()`、`@@VERSION`、`V$VERSION`、`PG_VERSION`、`current_database()` 等指纹查询，或大量不同方言的存在性探测。
- 防御：参数化查询，禁止拼接；数据库账号最小权限，限制对系统视图/函数的访问；WAF 对指纹关键字与函数组合做检测。
- 加固：错误信息不回显给客户端；统一错误页；对异常 SQL 语法/函数调用做审计与告警。
