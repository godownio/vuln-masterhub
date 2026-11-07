---
id: web-generic-file-upload-dotnet-ava-convert-uploadfile-saveas
title: 某应用云平台 Services/Convert/UploadFile.aspx 任意文件上传：原始文件名直接 SaveAs 到 ~/Upload/Video
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-webforms-upload-saveas-no-validation
tags:
- web
- dotnet
- aspnet
- webforms
- file-upload
- saveas
- arbitrary-file-write
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V221
  verified_at: '2026-11-07T06:52:39+08:00'
  notes: 已对照原文图09-12核对：VideoGuid 拼 MapPath、原始 FileName 直拼 SaveAs，无扩展名/内容校验。图05 搜索结果同时存在 Services.Convert.UploadFile 与 Services.WeikeCutOut.UploadFile 两个同名类，图10 页指令为 WeikeCutOut.UploadFile，而图12 PoC 请求 /Services/Convert/UploadFile.aspx，卡中已如实并列两处证据、不强行断定页面归属；按图12 修正 PoC 为无 VideoGuid、无 Cookie 的 POST（响应 Set-Cookie 下发 ASP.NET_SessionId/PrivateKey 并返回 Success）。原文仅验证 test.jpg 上传，未验证 aspx 落地执行，confidence=medium 保留。dedup 候选 uploadpicture/eis/ccflow 为不同产品链。
url: /docs/web/generic/file-upload/web-generic-file-upload-dotnet-ava-convert-uploadfile-saveas/
draft: false
kb_aliases:
- UploadFile.aspx 任意文件上传
- ASP.NET WebForms SaveAs 上传
- VideoGuid 路径拼接
- 原始文件名直存
- 未校验扩展名上传
---

## 一句话结论

某应用云平台的 `POST /Services/Convert/UploadFile.aspx`（原文图12 的 PoC 路径；程序集内同时存在 `AVA.ResourcesPlatform.AdminUI.Services.Convert.UploadFile` 与 `AVA.ResourcesPlatform.AdminUI.Services.WeikeCutOut.UploadFile` 两个同名类，图10 的 `UploadFile.aspx` 页指令为 `Inherits="...Services.WeikeCutOut.UploadFile"`）在 `Page_Load` 中取 `Request.Files[0]`，用客户端原始 `FileName` 直接拼到 `Server.MapPath("~/Upload/Video/" + Request.QueryString["VideoGuid"] + "/")` 后 `file.SaveAs(...)`，没有任何扩展名、Content-Type 或内容校验；攻击者可上传任意文件（原文以 `test.jpg` 验证成功，代码路径同样允许 `.aspx` 等可执行扩展落到 Web 目录）。

## 原理

- 上传代码：`HttpPostedFile file = this.Request.Files[0]; string fileName = file.FileName; string path = Server.MapPath("~/Upload/Video/" + this.Request.QueryString["VideoGuid"] + "/"); if (!Directory.Exists(path)) Directory.CreateDirectory(path); string filename = path + file.FileName; file.SaveAs(filename);`。
- 客户端 `filename` 完全可控，代码没有 `Path.GetFileName()`、扩展名白名单、魔数/图片二次渲染或 Content-Type 校验；`file.SaveAs` 按字节原样写入。
- `VideoGuid` 来自 query string，被拼进 `MapPath` 的虚拟路径；若包含 `../` 可能尝试跳出 `Upload/Video`（IIS `MapPath` 通常拒绝应用根之上的路径），但至少可以在 `Upload/Video` 下创建任意子目录。
- 保存目录位于应用目录 `~/Upload/Video/` 下，IIS 默认会把该目录中的 `.aspx` 交给 ASP.NET 处理；若该目录未被额外配置为禁止脚本执行，上传 `.aspx` 即可能形成 WebShell。原文只验证了 `test.jpg` 上传成功，未演示 `.aspx` 落地/执行。
- 鉴权：原文上传请求本身未携带 Cookie，响应通过 `Set-Cookie` 下发 `ASP.NET_SessionId` 与 `PrivateKey`，即 PoC 是在无既有会话的情况下直接拿到 `Success` 的；该页面是否匿名可达还需结合全局/MVC 鉴权配置（文章另提到大量 MVC 动作用 `IgnoreRightFilter` 匿名放行）按目标实例确认。

## 触发条件

- 目标为使用该 `UploadFile.aspx` 代码的 .NET 应用（文章称“mou 应用云平台”，程序集 `AVA.ResourcesPlatform.*`）。
- 上传页面可访问，`Request.Files` 与 `VideoGuid` 参数可达。
- `~/Upload/Video/` 目录可写（代码会自动创建子目录），且应用池对站点目录有写权限。
- 若目标是 WebShell，需 IIS/应用配置允许该目录下的脚本扩展被解析；否则至少是任意文件写入。

## 利用步骤

1. 访问 `POST /Services/Convert/UploadFile.aspx`（原文请求未带 `VideoGuid`；带 `?VideoGuid=<任意值>` 时会在 `~/Upload/Video/` 下创建对应子目录），multipart 上传一个测试文件（如 `test.jpg`），确认响应 `Success`。
2. 将 `filename` 改为目标扩展名（如 `shell.aspx`），内容为 ASPX 代码；注意文件名不要含路径分隔符（代码直接拼接）。
3. 观察响应是否为 `Success`；成功即写入 `~/Upload/Video/<VideoGuid>/shell.aspx`。
4. 访问对应 URL，验证是否能解析执行；若目录禁止脚本，则只能作为任意文件写入/覆盖。
5. 原文仅完成第 1 步的 `test.jpg` 上传验证，未展示 `.aspx` 上传与访问结果。

## PoC

原文验证请求（`test.jpg` 上传成功）：

```http
POST /Services/Convert/UploadFile.aspx HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVBf7Cs8QWsfwC82M

------WebKitFormBoundaryVBf7Cs8QWsfwC82M
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

<FILE_BYTES>
------WebKitFormBoundaryVBf7Cs8QWsfwC82M--
```

响应 `200 OK`，`Set-Cookie` 下发 `ASP.NET_SessionId` 与 `PrivateKey`，body 为 `Success`。将 `filename` 换成 `shell.aspx` 并写入对应内容即为免校验上传测试（原文未执行）。

## 变体与关联

- 变体：`VideoGuid` 可控制子目录名，尝试 `..`、绝对路径、NTFS 流等（受 `MapPath`/IIS 限制）。
- 变体：`filename` 可尝试双扩展（`shell.aspx.jpg`）、大小写（`.ASPX`）、`.ashx/.asmx/.config`、尾点/空格等，取决于 IIS 的请求过滤与处理程序映射。
- 关联：文章还提到 MVC `UploadNewsImg` 使用 `[IgnoreRightFilter]` 匿名访问并把任意文件写入 `~/Upload/News/` 后返回 URL，代码同样缺少扩展名校验；该入口原文未给 PoC，故未单独建卡。
- 同类：ASP.NET WebForms 原始文件名 SaveAs 上传、dotnet 黑名单只拦 asp/aspx、CCFlow IIS 上传 web.config。

## 检测与防御

- 修复：上传接口使用服务端生成的随机文件名，扩展名按业务白名单映射（不要相信客户端 `FileName`/Content-Type），校验魔数或做图片二次渲染；上传目录移出 Web 根并禁用脚本执行。
- 检测：上传请求 `filename` 含 `.aspx`、`.ashx`、`.asmx`、`.config`、双扩展或异常大小写；`~/Upload/Video/` 新增可执行文件；随后对该路径的访问请求。
- 加固：IIS 请求过滤拒绝可执行扩展；上传目录设置 `web.config` 禁止处理程序；`VideoGuid` 做格式白名单（如 GUID）；接口加鉴权与审计。
