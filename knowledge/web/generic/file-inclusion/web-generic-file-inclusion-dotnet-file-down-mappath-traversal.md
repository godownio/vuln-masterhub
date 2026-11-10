---
id: web-generic-file-inclusion-dotnet-file-down-mappath-traversal
title: ASP.NET file_down.aspx 的 file 参数直拼 Server.MapPath("../upfile/affix/")：../ 回跳下载源码与任意站点内文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: dotnet-server-mappath-relative-base-traversal-download
aliases:
- file_down.aspx 任意文件下载
- Server.MapPath 相对路径穿越
- ../upfile/affix/ 下载
- ASP.NET 源码下载
- D:\web\upfile\affix 报错泄露
tags:
- web
- dotnet
- aspnet
- iis
- file-download
- arbitrary-file-read
- server-mappath
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T12:03:42+08:00'
  notes: 已对照原文与图 14-18 核对：/admin/file_down.aspx?file=123123 触发 FileNotFoundException，错误页泄露 D:\web\upfile\affix\123123（图14）；file=../../admin/file_down.aspx 下载 971 字节源码（图17/18），源码为 string fileName=Request["file"].ToString(); string filePath=Server.MapPath("../upfile/affix/"+fileName); Response.WriteFile(fileInfo.FullName)，与卡内代码路径一致；图16 印证 Server.MapPath 不允许前导 .. 越过应用根。卡片对相对基址、回跳层数、附件文件名清洗、报错泄露物理路径的解释成立。dedup top1 为自身 exact；次高 web-generic-file-inclusion-dotnet-ava-download-aspx-server-mappath 判 likely_duplicate(0.9439)，但该卡是 Server.MapPath("~"+file) 站根下载，本卡是相对基址 ../upfile/affix/ + ../../admin 回跳并先经报错泄露路径，入口/基址/回跳深度/PoC 不同，按同 sink 变体保留；dup-scan 相关 pair 均 related。未验证点：未对靶场重放下载。
---

## 一句话结论

`/admin/file_down.aspx` 把请求参数 `file` 直接拼进 `Server.MapPath("../upfile/affix/" + fileName)` 再 `Response.WriteFile`，既没有限制 `../` 也没有限制下载目录；传 `file=../../admin/file_down.aspx` 可以回跳到 admin 目录，把下载页自身的 C# 源码以附件形式下载下来，从而泄露绝对路径、上传目录与后续利用点。

## 原理

- **代码路径**：页面 `Page_Load` 中 `string fileName = Request["file"].ToString();` → `string filePath = Server.MapPath("../upfile/affix/"+fileName);` → `new FileInfo(filePath)` → 设置 `Content-Disposition: attachment`、`Content-Type: application/octet-stream` → `Response.WriteFile(fileInfo.FullName)`。参数没有 `Path.GetFullPath`/基目录校验，也没有扩展名或 `..` 过滤。
- **相对基址**：`Server.MapPath` 以当前应用根为基准解析相对路径；本应用中该页位于 `/admin/` 应用下，`../upfile/affix/` 落在 `D:\web\upfile\affix\`（错误页证实）。因此再追加 `../../admin/file_down.aspx` 会经过 `D:\web\upfile\affix\..\..\admin\` 回到 `D:\web\admin\file_down.aspx`。
- **报错泄露绝对路径**：先传一个不存在的 `file=123123`，页面抛 `System.IO.FileNotFoundException`，错误信息直接给出 `D:\web\upfile\affix\123123`，暴露站点物理路径与上传目录。
- **顶层限制**：`Server.MapPath` 不允许 `..` 把路径解析到应用根之上，超过深度的请求会抛“无法使用前导 .. 在顶级目录上退出”；只要 `..` 数量恰好回到目标目录即可，不需要无限穿越。
- **源码下载**：`file=../../admin/file_down.aspx` 命中真实文件，返回 971 字节的 ASPX 源码；`Content-Disposition` 里的原始 `fileName` 含 `../`，浏览器会清洗成 `___admin_file_down.aspx` 之类的本地文件名。拿到源码后可确认上传落盘目录 `../upfile/affix/`，并与上传漏洞串成 getshell 链。
- **为什么成立**：文件下载功能把“用户输入”与“物理路径”直接拼接，且以附件形式回写任意可读文件；ASP.NET 的 MapPath 只做路径解析、不做授权，`FileInfo`/`WriteFile` 也不校验文件是否属于允许下载的目录。

## 触发条件

- 目标为 ASP.NET/IIS 应用，存在 `file_down.aspx` 这类“按文件名下载”的页面。
- `file` 参数可控且直接拼接到 `Server.MapPath` 的相对基址之后，没有 `..`/目录/扩展名校验。
- 目标文件在应用根可解析范围内且进程有读权限；`web.config`、`.aspx`、`.cs`、日志、备份等均可读。
- 页面可访问（本例为后台路径，需已登录或该页未做鉴权）。
- 需要知道或猜测相对基址与目标文件路径（报错信息可帮助确定）。

## 利用步骤

1. 访问 `/admin/file_down.aspx?file=123123`，触发 `FileNotFoundException`，从错误页读取物理路径（本例 `D:\web\upfile\affix\123123`）与源码行号。
2. 按基址推导回跳层数：`../upfile/affix/` 的上一层是 `D:\web`，再回 `admin` 需要 `../../admin/<file>`。
3. 请求 `file=../../admin/file_down.aspx`，下载页面自身源码；确认 `Response.WriteFile` 与 `../upfile/affix/` 拼接逻辑。
4. 用同样方式下载 `web.config`、`web.config.bak`、`Default.aspx.cs`、`bin/*.dll`、日志等，提取连接字符串、密钥与上传目录。
5. 结合已获得的后台上传功能，把 webshell 落到 `../upfile/affix/` 并访问执行。
6. 若 `..` 被部分过滤，尝试 URL 编码 `%2e%2e%2f`、反斜杠 `..\`、双写 `....//`、分号/空格等变体。

## PoC

```http
GET /admin/file_down.aspx?file=123123 HTTP/1.1
Host: target:27689

HTTP/1.1 500 Internal Server Error
...
异常详细信息: System.IO.FileNotFoundException: 未能找到文件“D:\web\upfile\affix\123123”。
```

```http
GET /admin/file_down.aspx?file=../../admin/file_down.aspx HTTP/1.1
Host: target:27689

HTTP/1.1 200 OK
Content-Disposition: attachment;filename=../../admin/file_down.aspx
Content-Type: application/octet-stream

<%@ Page Language="C#" Debug="true" trace="false" validateRequest="false" %>
...
string filePath = Server.MapPath("../upfile/affix/"+fileName);
...
Response.WriteFile(fileInfo.FullName);
```

```text
浏览器保存为：___admin_file_down.aspx（971 字节）
```

## 变体与关联

- 变体：`file=../web.config`、`file=../web.config.bak`、`file=../bin/<assembly>.dll`、`file=../Default.aspx.cs`；按基址调整 `../` 数量。
- 变体：`..%2f`、`..%5c`、双重编码、`....//`、`..;/`，取决于 IIS/ASP.NET 解码顺序与请求过滤。
- 关联：`[[web-generic-file-inclusion-dotnet-ava-download-aspx-server-mappath]]` 是另一应用的 `Server.MapPath("~"+file)` 任意文件下载（同一 sink、不同基址与参数）；本卡是相对基址 `../upfile/affix/` + `../` 回跳，触发条件与 PoC 不同。
- 关联：`[[pentest-recon-app-log-stacktrace-class-source-leak]]`（报错/堆栈泄露源码与路径）、`[[web-generic-file-upload-filename-fixed-length-truncation-aspx]]`（本链下载源码后确认上传目录并落 webshell）。
- 边界：若应用把下载文件限制在固定目录、使用文件 ID 映射、或 `Server.MapPath` 前做 `Path.GetFullPath` 基目录校验，则 `..` 不可用；`Server.MapPath` 不允许越过应用根，目标必须在应用可解析范围内。

## 检测与防御

- 检测：`file_down.aspx`/`download.aspx` 请求的 `file` 参数含 `..`、`%2e%2e`、`%2f`、`%5c`、`web.config`、`.aspx`、`.cs`、`.dll`；响应为 `application/octet-stream` 且 `Content-Disposition` 文件名异常；错误页暴露 `D:\...` 物理路径。
- 修复：不要用用户输入拼物理路径；用文件 ID/白名单映射到固定下载目录；必须用路径时先 `Path.GetFullPath` 归一化，再校验结果位于允许基目录内，并做扩展名白名单。
- 加固：下载接口鉴权与审计（用户/IP/文件/结果）；关闭详细错误页（`customErrors mode="On"`、`debug="false"`），避免物理路径与源码泄露；`web.config`/源码/备份移出 Web 根。
- 响应：发现源码/配置被下载后，轮换其中所有凭据与密钥，排查上传目录中的 webshell 与后续命令执行。
