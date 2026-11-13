---
id: web-java-component-allegra-branding-uploadfile-path-traversal
title: Allegra branding!uploadFile 任意文件上传：uploadedFileName 与 fileToReplace 可控，路径/后缀不限（CVE-2024-22510）
type: scenario
domain: web
path: web/java/component
technique: allegra-branding-uploadfile-path-traversal
aliases:
- CVE-2024-22510
- Allegra 任意文件上传
- BrandingAction uploadFile
- branding!uploadFile.action
- fileToReplace 路径穿越
- logos 目录写文件
tags:
- java
- struts
- allegra
- trackplus
- file-upload
- path-traversal
- arbitrary-write
- cve-2024-22510
cve:
- CVE-2024-22510
affected_versions: Allegra < 7.5.1（原文明确）
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:19:09+08:00'
  notes: 已对照原文13184与3/3截图核对：正文影响版本Allegra<7.5.1明确；CVE-2024-22510为原文标题明示（ZDI表未列该编号，表中有2023-22527 uploadSimpleFile为不同入口）；img03请求POST branding!uploadFile.action?uploadedFileName=1.txt&fileToReplace=../../test，multipart内容qwe，响应success:true/base64=cXdl，与卡中路径拼接(fileNameToReplace可控、removeExtension+.ext)分析一致；该请求未带Cookie/认证头，与卡触发条件相符。卡对listmapping无后缀落地难点的说明与代码逻辑一致。dedup候选为MES/Struts2/小智等不同产品入口，非同链。
---

## 一句话结论

Allegra 的 `branding!uploadFile.action` 把请求参数 `uploadedFileName` 与 `fileToReplace` 直接用于构造落盘路径：先拼 `logosDir/fileToReplace` 并在存在时删除，再把上传文件 `Files.move` 到 `logosDir/removeExtension(fileToReplace).uploadedFileExt`；两个参数都可控且不校验 `..` 与后缀，攻击者用 `fileToReplace=../../test` 即可把任意内容写到 logos 目录之外（CVE-2024-22510，影响 < 7.5.1），该原语也是同系列反序列化链的落地步骤。

## 原理

- **入口与参数**：`BrandingAction#uploadFile` 接收 `uploadedFileName`（上传文件名）与 `fileToReplace`（要替换的品牌文件名），调用 `uploadFile(fileNameToReplace, uploadedFileName, uploadedFile)`。
- **路径拼接**：`logosDirAbsPath = HandleHome.getTrackplus_Home() + "/logos"`；`fileToReplaceAbsPath = logosDirAbsPath + "/" + fileNameToReplace`。若该文件存在则 `Files.delete` 删除；随后 `uploadedFileNewPath = logosDirAbsPath + "/" + FilenameUtils.removeExtension(fileNameToReplace) + "." + uploadedFileExt`，把临时上传文件 `Files.move(..., REPLACE_EXISTING)` 到该路径。
- **校验缺失**：`fileNameToReplace` 没有任何 `../`/绝对路径过滤，`uploadedFileExt` 直接取上传文件名的后缀；因此 `fileToReplace` 可以穿越到 logos 目录之外，`uploadedFileName` 可以决定写入文件的后缀。代码最后把写入的文件读成 base64 返回（`getBase64Img`），可用来确认写入内容。
- **实际危害**：可覆盖应用目录下的配置/模板/脚本文件；结合同产品反序列化（CVE-2024-22505）可把恶意序列化文件放到 `trackdata/excelImport/1/listmapping` 等预期路径，或配合 Web 可执行目录写 JSP（取决于部署与后缀限制）。
- **文件名细节**：`removeExtension(fileToReplace) + "." + uploadedFileExt` 会给目标名追加后缀；若要落成无后缀的 `listmapping`，需利用上传文件名无后缀（得到 `listmapping.`，在 Windows 上尾点可能被规范化）或其他文件写入原语。原文未给出这一参数的精确构造，复现时需按目标文件系统调整。

## 触发条件

- 目标为 Allegra < 7.5.1，`branding!uploadFile.action` 可达（原文请求未带认证头/Cookie）。
- `trackplus_Home/logos` 目录存在且 Web 进程可写；目标路径所在目录可写。
- 攻击者能发送 multipart 请求并控制 `uploadedFileName`、`fileToReplace`。

## 利用步骤

1. 确认产品与路径（`/allegra/branding!uploadFile.action`）。
2. 构造 multipart 请求：URL 参数 `uploadedFileName=1.txt&fileToReplace=../../test`，文件字段 `file` 内容为要写入的数据。
3. 服务端删除 `logos/../../test`（若存在）并把上传文件移动到 `logos/../../test.txt`（后缀来自 uploadedFileName），响应返回 `{"success":true,"base64":"..."}`。
4. 按需把 `fileToReplace` 指向目标配置/模板/序列化文件路径，`uploadedFileName` 控制后缀；确认写入后继续后续利用。
5. 清理写入文件（若可写权限允许）。

## PoC

```http
POST /allegra/branding!uploadFile.action?uploadedFileName=1.txt&fileToReplace=../../test HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3G4hchXfFuDRJiD
Content-Length: 155

------WebKitFormBoundary3G4hchXfFuDRJiD
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain

qwe
------WebKitFormBoundary3G4hchXfFuDRJiD--
```

响应（原文截图）：

```json
{"success":true,"base64":"data:image/txt;base64,cXdl"}
```

（`cXdl` 即 `qwe`，证明写入内容可控；实际落盘路径为 `logosDir/../../test.txt`。）

## 变体与关联

- **后缀变体**：`uploadedFileName` 改成 `.jsp`/`.war`/`.xml` 等，取决于目标目录是否被 Web 容器解析/加载。
- **路径变体**：`fileToReplace` 用不同数量的 `../` 指向配置、模板、计划任务文件等；也可以指向反序列化链所需的 `trackdata/excelImport/1/listmapping`。
- **同系列 CVE**：文件读取（CVE-2024-22507，[[web-java-component-allegra-download-attachment-filename-traversal-jwt-key]]）、反序列化（CVE-2024-22505，[[web-java-deserialization-allegra-renderfieldmatch-listmapping]]）、zipslip（CVE-2024-22504，[[web-java-component-allegra-import-allegra-format-zipslip]]）。
- **同类组件上传**：[[web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload]]、[[web-java-component-dahua-material-file-upload-webshell]]。

## 检测与防御

- **检测（Web 日志）**：`branding!uploadFile.action` 的 `fileToReplace` 含 `../`/绝对路径，`uploadedFileName` 为脚本后缀；响应 `success:true` 且 base64 内容与上传内容一致；随后出现新文件写入/配置变更。
- **检测（文件）**：`trackplus_Home/logos` 目录外出现与品牌文件同名的新文件；应用目录配置/模板被修改；Web 目录新增 JSP/脚本。
- **防御**：升级到 7.5.1+；`fileToReplace` 只允许固定文件名白名单（logo 文件），并用 `getCanonicalPath()` 校验必须位于 logos 目录；`uploadedFileExt` 白名单（png/jpg/svg 等）且文件名随机化；非必要不把品牌上传接口暴露给未认证用户。
