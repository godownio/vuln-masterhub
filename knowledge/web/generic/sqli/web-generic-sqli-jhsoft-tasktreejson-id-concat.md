---
id: web-generic-sqli-jhsoft-tasktreejson-id-concat
title: JHSoft OA TaskTreeJSON.aspx 的 id 参数经 InitTaskTree 拼进任务树查询：SQL 注入审计线索
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-aspx-request-id-concat-task-query
aliases:
- TaskTreeJSON SQL注入
- JHSoft 任务树注入
- InitTaskTree 拼接
- id 参数任务查询
- 金和 OA 任务树
tags:
- sqli
- dotnet
- aspx
- oa
- jhsoft
- code-audit
- task-tree
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:22+08:00'
  notes: 已对照原文 img/12-13 核对 Page_Load 把 Request[id] 赋给 strParentID 并调用 InitTaskTree，后者拼接动态 SQL 后 ExecSQLReDataTable。未验证点：拼接 strParentID 的完整行被截图右边界截断、原文无 PoC/响应，卡已标 confidence low 作为审计线索，不能当作已证实漏洞。
---

## 一句话结论

JHSoft OA 的 `TaskTreeJSON` 页面把请求参数 `id` 赋给 `strParentID` 后传给 `InitTaskTree(strParentID)`，该方法用字符串拼接构造任务树相关的 SQL 并交给 `ExecSQLReDataTable` 执行；原文把它归为 SQL 注入，但截图中 `strParentID` 的具体拼接行被右侧截断、也没有 PoC，属于需要自行验证的代码审计线索（confidence low）。

## 原理

- `Page_Load`：`if (Session["UserCode"] != null) { strUser = Session["UserCode"].ToString(); } strParentID = base.Request["id"]; InitTaskTree(strParentID);`——`id` 未做类型/白名单校验，直接进入任务树查询方法。
- `InitTaskTree(string strParentID)` 先构造 `select a.TaskID, a.TaskNumber, a.TaskName, b.UserName as SendName, c.UserName as ExecName, a.TaskProgress...`，再拼接 `and a.TaskNumber in ( select distinct substring(TaskNumber,0,50) as TaskNumber from TaskManage where ...` 以及 `and a.TaskFinishFlag = 0 and a.TaskIsDel = 0`，最后 `dbOperator.ExecSQLReDataTable(text)` 执行。
- 该方法签名接收 `strParentID`，但截图右侧被截断，未直接看到 `strParentID` 拼进 SQL 的那一段；从“请求参数→方法参数→动态拼接 SQL 文本→直接执行”的代码形态判断，父节点 ID 通常会被拼进 `where`/子查询作为任务编号前缀条件，因此存在注入可能。
- 同一项目的其他页面（如 IncentivePlanFulfill）已证实同类 DAL `ExecSQLReDataTable`/`ExecSql` 直接执行拼接文本；该页面的风险模式一致。
- 页面只对 `Session["UserCode"]` 做取值，未对 `id` 做任何过滤；若页面可未登录访问，注入点即前置可达；若需登录，则在任意会话下均可测试。

## 触发条件

- 目标存在 `TaskTreeJSON` 页面（JHSoft OA 任务/流程模块）。
- `id` 参数进入 `InitTaskTree` 并被字符串拼接进 SQL（需依据实际二进制/完整源码确认截断部分）。
- 数据库为 MSSQL 或与拼接语法匹配的数据库，账号可执行注入表达式。
- 页面可访问（是否要求登录按目标确认）。

## 利用步骤

1. 请求 `?id=1` 记录正常响应（JSON 任务树）作为基线。
2. 依次测试 `id=1'`、`id=1 and 1=1--`、`id=1 and 1=2--`，观察结果差异或 SQL 报错。
3. MSSQL 下可尝试时间盲注：`id=1;WAITFOR DELAY '0:0:5'--` 或 `id=1' WAITFOR DELAY '0:0:5'--`，按实际闭合上下文选择引号。
4. 确认后逐位提取库名/表名/任务数据；有回显时改用联合/报错注入。

## PoC

```text
无 PoC。原文只给出 TaskTreeJSON 的 Page_Load 与 InitTaskTree 代码截图，
且 InitTaskTree 中拼接 strParentID 的完整行被截图右边界截断，未提供请求/响应验证。
```

```http
# 验证用最小请求（按实际闭合上下文调整）
GET /C6/<TaskTreeJSON 路径>?id=1%27%20AND%201=1-- HTTP/1.1
Host: target.example
```

## 变体与关联

- 变体：若 `id` 只做数字前缀匹配（如 `TaskNumber like 'id%'`），可尝试 `id=1' OR '1'='1`、`id=1%' AND 1=1--` 等不同闭合。
- 关联：[[web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version]]（同一产品已实测的 MSSQL 延时注入）；[[web-generic-sqli-jhsoft-homeservice-getuserinfo-getusersex]]（同产品的 ASMX 拼接注入）。
- 边界：这是低置信度代码审计线索——拼接行未完整展示、无复现、页面入口与鉴权未确认；不能直接当作已验证漏洞使用。

## 检测与防御

- 检测：`TaskTreeJSON` 请求的 `id` 出现单引号、`--`、`WAITFOR`、`IF(` 等特征；任务树接口返回 SQL 错误或响应时间异常。
- 修复：`id` 强制转换为整数/任务编号白名单，并使用参数化查询；不要拼接任何请求参数到 SQL 文本。
- 加固：统一数据访问层参数化；页面增加登录与对象级权限校验；对 SQL 错误统一脱敏。
