---
id: code-analysis-source-audit-dotnet-mvc-ilspy-route-search
title: .NET MVC 白盒审计：aspx Inherits 找 bin DLL、ILSpy 反编译，Global.asax/AreaRegistration 还原路由后全局搜 select/where
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: dotnet-mvc-ilspy-route-sink-search-audit
tags:
- code-analysis
- audit
- dotnet
- aspnet
- mvc
- ilspy
- routing
- sqli
- source-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T07:54:11+08:00'
  notes: 已对照原文与49张图核对：图01 目录结构（Global.asax/Web.config/bin/Areas/upload）；图02/03 aspx Inherits=GBLab.Web.Login；图04 ILSpy 打开 GBLab.Web.dll 定位 Login/UploadNewHandler；图08/09 Global.asax→MvcApplication.RegisterRoutes；图10 ManageAreaRegistration 区域路由；图13-15 Notepad++ 全局搜索 GetByName/Global.asax 与调用点回溯。审计流程与图一致。原文未写产品/版本，未设 affected_versions。dedup 最高分为卡自身，related 的 pentest-recon-dotnet-dll-download-decompile-audit 为黑盒下载 DLL 前置不同，非重复；dup-scan 无本篇 pair。该卡为审计方法、非漏洞利用，保留。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-dotnet-mvc-ilspy-route-search/
draft: false
kb_aliases:
- .NET 代码审计
- ILSpy 审计
- Global.asax 路由
- AreaRegistration
- Notepad++ 全局搜索 SQL
- aspx Inherits 找 DLL
- ASP.NET MVC 审计
---

## 一句话结论

拿到 ASP.NET MVC 源码/发布目录后，先看 `*.aspx` 的 `Inherits`/`CodeBehind` 定位 `bin` 下对应的 DLL 类，用 ILSpy 反编译；再从 `Global.asax` 的 `MvcApplication.RegisterRoutes` 与各 `Areas/*AreaRegistration` 还原 `{controller}/{action}/{id}` 路由，最后用 Notepad++/grep 在反编译代码里全局搜索 `select`/`where`/`update`/`FindAll` 等 sink，回溯调用者与参数来源，即可快速定位 SQL 注入、上传、越权等漏洞。

## 原理

- **目录结构**：典型 ASP.NET 发布目录含 `Global.asax`（应用级事件入口）、`Web.config`（连接串/认证/错误页）、`bin`（编译后的 DLL，后端逻辑所在）、`Areas`（区域路由）、`Views`、`upload`、`*.aspx`/`*.ashx`（页面与一般处理程序）。
- **从页面到代码**：`.aspx` 顶部 `<%@ Page ... Inherits="GBLab.Web.Login" %>` 或 `.ashx` 的 `<%@ WebHandler ... Class="JQueryUploadDemo.UploadNewHandler" %>` 直接给出命名空间+类名；在 ILSpy 中打开 `bin/GBLab.Web.dll` 即可跳到该类（`Login`/`UploadNewHandler`）。
- **路由还原**：`Global.asax` 的 `Application_Start` 调用 `RegisterRoutes`，默认路由通常为 `routes.MapRoute("Default", "{controller}/{action}/{id}", new { controller = "Home", action = "Index", id = UrlParameter.Optional })`；区域路由在 `Areas/<Area>/<Area>AreaRegistration.cs` 的 `RegisterArea` 中，如 `Manage/{controller}/{action}/{id}`。把 URL 映射到 Controller/Action 后，才能在 ILSpy 里找到真正的处理方法。
- **sink 搜索**：在反编译出的 C# 源码目录用 Notepad++/ripgrep 全局搜索 `select`、`where`、`update`、`FindAll(`、`Meta.DBO.Select(`、`FindAllByPage(`、`Execute(`、`SaveAs`、`File.`、`StreamWriter` 等，命中后看参数是否来自 `base.Request.Form/QueryString`。
- **回溯调用者**：一个实体方法（如 `T_User.ConfirmName`）可能被多个 Controller/Action 调用；全局搜索 `T_User.ConfirmName` 列出所有调用点，判断哪个 Action 可达、参数是否可控、是否有鉴权/类型限制。
- **参数处理辨析**：`Trim()`、`DefaultIsNullOrEmpty()`、`int.Parse` 等不是 SQL 安全过滤；`int` 类型参数天然安全，字符串参数需要看是否参数化/白名单。原文中 `GetByName`、`ConfirmName`、`GetPager` 的字符串参数均直接拼接。
- **扩散发现**：同一代码模板在部门/角色/岗位等 Controller 中复制，`ConfirmName` 每处只改表名；搜到一处后可批量搜索同构方法，快速估算漏洞面。

## 触发条件

- 获得 ASP.NET 应用的源码或发布目录（源码泄露、任意文件下载、供应链/托管泄露等）。
- 有 ILSpy（或 dnSpy）与全文检索工具（Notepad++、ripgrep、Agent Ransack）。
- 应用使用 ASP.NET MVC/WebForms 混合架构，路由/区域配置未混淆。
- 审计者能理解 C# 基础与 SQL/文件/命令 sink 模式。

## 利用步骤

1. 列目录，记录 `Global.asax`、`Web.config`、`bin`、`Areas`、`*.aspx`、`*.ashx`、`upload` 等关键位置。
2. 从 aspx/ashx 的 `Inherits`/`Class` 取命名空间类名；ILSpy 打开 `bin` 下 DLL，定位到该类。
3. 读 `Global.asax` → `RegisterRoutes`/`RouteConfig`，再逐个读 `Areas/*AreaRegistration.cs`，整理 URL → Controller/Action 映射。
4. 把 ILSpy 反编译的 C# 导出到本地目录，用 Notepad++ 全局搜索 `select`，逐个看 `Entity<T>.FindAll`/`Meta.DBO.Select` 的字符串拼接与参数来源。
5. 搜索 `where`、`update`、`FindAllByPage` 等继续扩大；对每个候选全局搜索方法名找调用者，确认可达 Action 与请求字段。
6. 对确认的注入/上传点构造 PoC（如 `WAITFOR DELAY`、`filename=x.asp`），运行时验证并记录。

## PoC

ILSpy 定位：

```text
Login.aspx: <%@ Page ... CodeBehind="Login.aspx.cs" Inherits="GBLab.Web.Login" %>
→ bin/GBLab.Web.dll → GBLab.Web.Login.btnSub_Click
UploadNewHandler.ashx: <%@ WebHandler ... Class="JQueryUploadDemo.UploadNewHandler" %>
→ bin 中 JQueryUploadDemo.UploadNewHandler.ProcessRequest
```

路由：

```csharp
// Global.asax.cs / RouteConfig
routes.MapRoute("Default", "{controller}/{action}/{id}",
    new { controller = "Home", action = "Index", id = UrlParameter.Optional });

// Areas/Manage/ManageAreaRegistration.cs
context.MapRoute("Manage_default", "Manage/{controller}/{action}/{id}",
    new { action = "Index", id = UrlParameter.Optional });
```

全局搜索：

```text
Notepad++ 查找: select
路径: 反编译输出目录
命中: GBLab.Entities/T_User.cs: Entity<T_User>.FindAll("select * from T_User where F_Account='" + username + "'")
回溯: 搜索 GetByName → Login.aspx.cs 与 LoginUserController.ActionUserLogin
```

## 变体与关联

- 变体：WebForms 项目从 `.aspx` 的 `CodeBehind` 找 `.aspx.cs`；无源码时从任意文件下载/路径泄露获取 `bin` DLL 再反编译。
- 变体：使用 dnSpy 动态调试、或直接把 DLL 丢进 ILSpy 的“搜索”功能按字符串/方法名检索。
- 关联：[[pentest-recon-dotnet-dll-download-decompile-audit]] 是黑盒下载 DLL 后反编译审计；本卡是已有发布目录/源码时的 MVC 路由还原与 sink 搜索流程。
- 关联：[[web-dotnet-entity-findall-concat-sqli-login-confirmname-getpager]] 与 [[web-dotnet-ashx-upload-getfiletypename-extension-asp-webshell]] 是本方法在目标应用上的产出。

## 检测与防御

- 对审计方：把“路由还原 + sink 全局搜索 + 调用者回溯”固化为 .NET 审计清单，注意区域路由与 WebForms 混合入口。
- 对防守方：发布目录最小化、删除源码/调试文件、`bin` DLL 混淆/加固只能提高成本；根本上是修复 SQL 拼接与上传校验；生产环境关闭详细错误与目录浏览。
