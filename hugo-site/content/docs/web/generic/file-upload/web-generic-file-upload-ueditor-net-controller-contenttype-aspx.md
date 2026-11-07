---
id: web-generic-file-upload-ueditor-net-controller-contenttype-aspx
title: UEditor .NET controller.ashx uploadfile 只校验 ContentType：改后缀上传 aspx webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: ueditor-net-controller-contenttype-aspx-upload
tags:
- web
- file-upload
- ueditor
- dotnet
- aspx
- webshell
- content-type
- rce
- iis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: UEditor .NET 1.4.3.3 / 1.5.0 / 1.3.6（原文截图搜索结果）；原文目标编辑器显示版本 1.4.3
verification:
  verified_by: verifier-V266
  verified_at: '2026-11-07T18:17:51+08:00'
  notes: 已对照原文与28张图核对：UEditor 1.4.3 帮助框、controller.ashx?action=uploadfile&encode=utf-8、.ASPXAUTH Cookie、AntSword连接 /Scripts/ueditor/net/upload/image/... 均与原文一致；受影响版本取自原文图14搜索结果（1.4.3.3/1.5.0/1.3.6，仅.NET），已在卡内注明来源与目标实际显示1.4.3。未验证点：原文复用公开PoC、请求体截图打码，未独立复现。
url: /docs/web/generic/file-upload/web-generic-file-upload-ueditor-net-controller-contenttype-aspx/
draft: false
kb_aliases:
- UEditor 1.4.3 .NET 任意文件上传
- controller.ashx uploadfile
- UEditor aspx webshell
- ASPXAUTH UEditor 上传
- UEditor ContentType 绕过
---

## 一句话结论

UEditor 的 .NET 版本 `controller.ashx?action=uploadfile` 只校验上传文件的 `Content-Type` 而不校验扩展名；攻击者把文件名改成 `.aspx` 并把 Content-Type 伪造成图片类型，文件落到 `/ueditor/net/upload/.../` 后由 IIS 按 aspx 解析执行，原文在登录教师系统后台后利用该 Nday 上传 webshell，AntSword 连接成功。

## 原理

- UEditor 是百度的富文本编辑器，.NET 版的文件上传入口为 `controller.ashx`（常见路径 `/Scripts/ueditor/net/controller.ashx` 或 `/ueditor/net/controller.ashx`），通过 `action=uploadfile` 处理上传。
- 受影响版本的 .NET 上传处理器只检查请求的 `Content-Type`（如图片类型），不校验/限制文件扩展名，也没有把上传目录排除在脚本执行之外。攻击者构造 multipart 请求：
  - `filename="shell.aspx"`（或 `1.aspx`）；
  - `Content-Type: image/jpeg`（伪造图片 MIME）；
  - 文件内容为 ASPX webshell；
  服务端按图片类型放行并保存为 `.aspx`，IIS 随后把该文件作为 ASP.NET 页面执行。
- 该问题主要影响 .NET 版本（PHP/JSP/ASP 版本的上传逻辑不同）；原文在 UEditor 1.4.3 的教师文档管理编辑器中确认版本，并使用公开 PoC 完成上传，Cookie 中出现 `.ASPXAUTH` 进一步确认 .NET 技术栈。
- 前置条件通常是能进入使用 UEditor 的后台/编辑功能；原文通过信息收集获得职工号并尝试默认密码 `123456` 登录后台，随后利用编辑器上传。

## 触发条件

- 目标使用 UEditor 受影响 .NET 版本（1.4.3.3/1.5.0/1.3.6，原文目标显示 1.4.3），且 `controller.ashx` 上传入口可达。
- 上传目录位于 Web 根下且 IIS 允许执行 `.aspx`（默认允许）。
- 攻击者能访问编辑器上传功能：后台账号（弱口令/默认口令/越权）或前台暴露的编辑器接口。
- 服务端仅校验 Content-Type、未做扩展名白名单与内容检测。

## 利用步骤

1. 信息收集/弱口令进入使用 UEditor 的后台（原文用职工号 + 默认密码 123456）。
2. 打开文档管理/新增文档，确认编辑器为 UEditor 1.4.3（帮助→关于 UEditor）。
3. 搜索并获取该版本 .NET 任意文件上传的公开 PoC，构造上传请求到 `/Scripts/ueditor/net/controller.ashx?action=uploadfile&encode=utf-8`。
4. 设置 multipart 文件名为 `xxx.aspx`、Content-Type 为图片类型，文件内容为 ASPX webshell；携带后台 `.ASPXAUTH` Cookie。
5. 从响应中取得上传路径（如 `/Scripts/ueditor/net/upload/image/2025.../xxx.aspx`），访问确认 webshell 执行。
6. 用 AntSword 等客户端连接该 aspx 地址，获得服务器权限。

## PoC

无独立 PoC（原文复用公开 PoC，关键请求体在截图中打码）。请求形态：

```http
POST /Scripts/ueditor/net/controller.ashx?action=uploadfile&encode=utf-8 HTTP/1.1
Host: target.example
Cookie: .ASPXAUTH=<后台会话>
Content-Type: multipart/form-data; boundary=...

--boundary
Content-Disposition: form-data; name="file"; filename="shell.aspx"
Content-Type: image/jpeg

<%@ Page Language="C#" ... %>  <!-- ASPX webshell 内容 -->
--boundary--
```

原文用该方式上传成功后，AntSword 连接 `/Scripts/ueditor/net/upload/image/...aspx` 成功。

## 变体与关联

- 与 `web-generic-file-upload-ueditor-filepathformat-traversal` 的区别：该卡利用 `filePathFormat` 模板目录穿越写任意路径（MCMS/UEditor 1.4.3.3）；本卡利用 .NET 上传处理器只校验 Content-Type，直接上传 aspx 到上传目录。
- 与 `web-generic-file-upload-ueditor-default-whitelist-xml-xss` 的区别：该卡是默认白名单导致的 XSS；本卡是可执行脚本上传 getshell。
- 同类 .NET 上传：`web-generic-file-upload-dotnet-blacklist-only-asp-aspx`、`web-generic-file-upload-dotnet-uploadpicture-aspx-webshell`；本卡是第三方编辑器 UEditor 的 Nday。
- 变体：修改 Content-Type 为 `image/png`/`image/gif`；文件名使用 `.aspx;.jpg`、`.asa`、`.ashx` 等 IIS 可解析扩展；结合上传目录解析配置。

## 检测与防御

- 升级/修补 UEditor 到安全版本，或移除不必要的 `controller.ashx` 上传入口；后台编辑器限制仅可信管理员可用。
- 上传接口做扩展名白名单（仅图片/文档）、内容魔数与图像解码校验，不信任客户端 Content-Type；文件名随机化并剥离路径。
- 上传目录移出 Web 根，或在 IIS 中禁止上传目录执行 `.aspx/.ashx/.asmx/.config` 等脚本；设置 `Content-Disposition: attachment`。
- 后台强制强密码/多因素，禁用默认口令 `123456`；限制后台访问来源。
- 监控：`controller.ashx?action=uploadfile` 上传文件名含 `.aspx/.ashx/.asmx`、Content-Type 与扩展名不一致、上传后立即访问该文件。
