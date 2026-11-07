---
id: web-generic-file-upload-jucheap-app-videoupload-original-extension
title: JuCheap APPController VideoUpLoad 未授权上传：原始文件名后缀直存 UpLoad\EventVideo，仅限制 2MB
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-webapi-unauth-multipart-original-extension-video-upload
tags:
- web
- dotnet
- aspnet
- webapi
- file-upload
- unrestricted-upload
- webshell
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:25:56+08:00'
  notes: 已对照原文与图 18 核对：VideoUpLoad(WorkId,FileStr) 无 token 校验、APPController 类级 AllowAnonymous；uploadVideo 先查 t_workorder 再 uploadVideoTemp，后者仅校验非空与 ContentLength<=2097152，取客户端文件名最后一个点起（含点）作为后缀，SaveAs 到 UpLoad\EventVideo；原文请求 /He.in/VideoUpLoad?WorkId=1，filename=evil.aspx，响应 200 JSON 但未展示 body/路径/执行，故 confidence=medium。dup-scan 与 uploadAttachment、UploadNewsImg 的 likely_duplicate 均裁决非同一链（端点/请求格式/落盘目录/限制不同），保留。
url: /docs/web/generic/file-upload/web-generic-file-upload-jucheap-app-videoupload-original-extension/
draft: false
kb_aliases:
- JuCheap VideoUpLoad
- /api/APP/VideoUpLoad
- uploadVideoTemp
- 视频上传 aspx
- 原始后缀上传 EventVideo
---

## 一句话结论

JuCheap 的 `VideoUpLoad(string WorkId, string FileStr)` 动作没有 token+Authorize 校验（所在 `APPController` 类级 `[AllowAnonymous]`），服务层 `uploadVideo` 把 `Request.Files` 交给 `uploadVideoTemp`：它只检查文件非空和 `ContentLength <= 2097152`，扩展名直接取客户端原始文件名最后一个点之后的内容（含点），以“时间戳+4 位随机数+原后缀”保存到站点 `UpLoad\EventVideo` 并返回访问路径；上传 `evil.aspx`（小于 2MB）即可把脚本写入 Web 目录，构成未授权任意文件上传，是否直接 getshell 取决于 IIS 对该目录脚本的解析配置。原文仅给出 HTTP 200 的复现请求，未展示返回路径与访问执行结果。

## 原理

- 入口：`JuCheap.Web` 中 `[System.Web.Http.HttpPost] public HttpResponseMessage VideoUpLoad(string WorkId, string FileStr)`，直接 `_helpService.uploadVideo(WorkId, FileStr)`；原文 PoC 走 `/api/APP/VideoUpLoad?WorkId=1`（API 控制器路由前缀 `/api/APP`），截图请求行显示部署前缀形如 `/He.in/VideoUpLoad?WorkId=1`。
- 鉴权：该动作没有像同控制器其他 API 那样读取 `Request.Headers.Get("token")` 并 `Authorize`；`APPController` 类上标注 `[System.Web.Http.AllowAnonymous]`，因此匿名可达。原文 PoC 请求也未携带 token/Cookie。
- 服务层：`uploadVideo(string WorkId, string FileStr)` 取 `HttpContext.Current.Request.Files`（`FileStr` 参数实际未用于文件内容）；先按 `WorkId` 查 `t_workorder`，再无条件调用 `uploadVideoTemp(files)`。
- 落盘：`uploadVideoTemp(HttpFileCollection files)` 遍历 `files.AllKeys`，对每个 `HttpPostedFile`：
  - 条件只有 `!string.IsNullOrEmpty(httpPostedFile.FileName)` 且 `httpPostedFile.ContentLength <= 2097152`；
  - `text2 = DateTime.Now.ToString("yyyyMMddHHmmss") + random.Next(1000, 9999)`；
  - `text3 = httpPostedFile.FileName.Substring(httpPostedFile.FileName.LastIndexOf('.')).ToLower()`（**包含点**，例如 `.aspx`）；
  - `filename = Path.Combine(AppDomainAppPath, "UpLoad\\EventVideo") + "\\" + text2 + text3`；
  - `httpPostedFile.SaveAs(filename)`，返回 `filePaht = "/UpLoad/EventVideo/" + text2 + text3`。
- 成立关键：扩展名完全来自客户端原始文件名，没有白名单/黑名单、没有 Content-Type 或魔数校验；唯一约束是 2MB 大小。站点 `UpLoad\EventVideo` 位于 Web 应用目录内，若 IIS 未禁止脚本执行，`.aspx` 会被编译；即使禁止，仍是任意文件上传/覆盖原语。
- 顺序细节：`uploadVideoTemp` 在 `t_workorder` 判空/使用之前执行，所以即使 `WorkId` 不存在，文件也会先写入；随后 `t_workorder.EventYId` 的空引用异常被 catch，接口返回 502，但文件已落盘。使用有效 `WorkId` 才能拿到正常的 200 与附件记录。
- 原文证据边界：请求含 `filename="evil.aspx"`、内容为 `<%@ Page ... %><%Response.Write("Hello World");%>`，响应为 `HTTP/1.1 200 OK`、`Content-Type: application/json`（StringContent），但截图中未展示响应体中的路径，也未访问该 aspx 验证执行；因此本卡按“未授权任意文件上传原语”收录，RCE 结论需在目标上确认上传目录可执行。

## 触发条件

- 目标为使用 JuCheap.Web / JuCheap.Services 代码的 .NET 应用，`/api/APP/VideoUpLoad`（或原文截图中的部署前缀路径）可达。
- `APPController` 的 `AllowAnonymous` 生效，且 `VideoUpLoad` 未额外校验 token。
- 上传文件大小不超过 2MB（原文 `ContentLength <= 2097152`）。
- 应用池账户对站点 `UpLoad\EventVideo` 有写权限（目录不存在会创建）；若要 getshell，IIS 需允许该目录下的 `.aspx`/`.ashx` 等脚本执行。

## 利用步骤

1. 确认 `POST /api/APP/VideoUpLoad?WorkId=<id>` 匿名可达；`WorkId` 可用目标已有的工单 ID（原文用 1），无效 ID 也可能先落盘再报错。
2. 构造 multipart 请求，文件字段名与上传字段（原文为 `file`）按目标表单；文件名设为 `evil.aspx`，内容为小于 2MB 的最小 ASPX 页面（如 `<% Response.Write("test"); %>`）。
3. 发送请求，观察响应 JSON 中的 `path`/`id`；若返回 502 但文件已写，可尝试枚举 `/UpLoad/EventVideo/<时间戳+随机数>.aspx`。
4. GET 返回的路径，确认 IIS 是否解析执行；原文未做此步，实际测试请使用无害标记页。
5. 若可执行，替换为命令执行/文件管理/内存马；也可尝试 `.ashx`、`.asmx`、`.config` 等扩展。

## PoC

原文复现请求（截图请求行为 `/He.in/VideoUpLoad?WorkId=1`；正文按 API 控制器规则写作 `/api/APP/VideoUpLoad`）：

```http
POST /api/APP/VideoUpLoad?WorkId=1 HTTP/1.1
Host: <target>
Connection: close
User-Agent: Mozilla/5.0
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 245

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="evil.aspx"
Content-Type: application/octet-stream

<%@ Page Language="C#" %><%Response.Write("Hello World");%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```http
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=<new>; path=/; HttpOnly
X-AspNetMvc-Version: 5.2
X-AspNet-Version: 4.0.30319

<JSON 响应体原文截图未展示；按代码成功时含 path=/UpLoad/EventVideo/<时间戳+随机数>.aspx 与 id>
```

说明：响应状态与 `StringContent` 说明请求到达了业务代码，但原文未展示路径与访问结果；验证时请使用无害标记内容。

## 变体与关联

- 变体（扩展名）：`.aspx`、`.ashx`、`.asmx`、`.svc`、`.config`；`text3` 取最后一个点之后的全部内容并转小写，`shell.aSpX` 同样得到 `.aspx`。
- 变体（文件大小）：只限制 ≤2MB，小马/内存马足够；超过 2MB 的文件被跳过，`returnFlag` 保持 false。
- 变体（WorkId）：有效工单 ID 得到 200 和附件记录；无效 ID 仍会先写文件，随后空引用异常返回 502，可配合文件名枚举/时间戳爆破定位落盘文件。
- 关联：[[web-generic-file-upload-jucheap-app-uploadattachment-base64-aspx]]（同控制器 `uploadAttachment` Base64 后缀可控上传，已实测 aspx 执行）、[[web-generic-file-upload-jucheap-newsmanage-uploadnewsimg-aspx]]（同系统 MVC `[IgnoreRightFilter]` 匿名上传）。
- 同类：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]、[[web-generic-file-upload-dotnet-ava-convert-uploadfile-saveas]] 等“原始后缀 + Web 目录”上传。
- 边界：上传目录禁止脚本、请求过滤拦截可执行扩展、动作补鉴权或后缀白名单时，RCE 不成立；原文未验证本接口的 aspx 访问执行。

## 检测与防御

- 请求检测：`VideoUpLoad` 的 multipart 文件名以 `.aspx`/`.ashx`/`.asmx`/`.config`/`.svc` 结尾；请求无 token 却调用视频上传；`WorkId` 为不存在的值或高频枚举；文件内容含 `<%@`、`<%`、`eval(` 等特征。
- 主机检测：`UpLoad\EventVideo` 目录新增脚本文件；w3wp 进程向该目录写入 `.aspx`；IIS 日志中对 `/UpLoad/EventVideo/*.aspx` 的访问与编译错误；`t_attachment` 中出现异常 Type=4 记录。
- 修复：上传动作补 token+Authorize；扩展名使用服务端白名单映射（视频只允许 `.mp4`/`.webm` 等），不要取客户端 `FileName` 后缀；校验 Content-Type 与文件魔数；服务端随机命名；上传目录移出 Web 根或禁止脚本执行。
- 加固：API 控制器避免类级 `AllowAnonymous` 覆盖全部动作；`uploadVideoTemp` 先校验 `WorkId` 对应工单存在再写文件；WAF 拦截脚本后缀；定期扫描 `UpLoad` 目录中的可执行文件。
