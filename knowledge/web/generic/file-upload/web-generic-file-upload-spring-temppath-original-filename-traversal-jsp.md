---
id: web-generic-file-upload-spring-temppath-original-filename-traversal-jsp
title: Spring 上传接口 tempPath + getOriginalFilename 直接拼接：../ 穿越写 JSP 到 Tomcat webapps getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-filename-path-traversal
aliases:
- picUpload 路径穿越
- getOriginalFilename 未过滤
- tempPath 拼接上传
- 上传穿越写 Tomcat webapps
- 任意文件上传 getshell
tags:
- web
- file-upload
- java
- spring
- path-traversal
- arbitrary-write
- jsp
- tomcat
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:29:43+08:00'
  notes: 已对照原文与图19/20/21核对：CourseResourceController /picUpload 中 tempPath + getOriginalFilename 直接拼接，../../ 穿越写 Tomcat webapps 下哥斯拉 JSP，whoami=root；未复跑
---

## 一句话结论

Spring 上传接口把配置项 `tempPath` 与客户端提供的 `file.getOriginalFilename()` 直接用 `/` 拼接后交给 `FileOutputStream`，未取 basename、未做规范化校验；攻击者用 `../` 作为文件名前缀即可跳出上传目录，把 JSP 写入同机 Tomcat 的 `webapps` 目录并 getshell。

## 原理

- 典型代码模式：
  - `String path = appConfig.getTempPath();`
  - `String fileName = file.getOriginalFilename();`
  - `new FileOutputStream(new File(path + "/" + fileName))`
  - 全程没有 `Paths.get(path).resolve(fileName).normalize().startsWith(path)` 之类的边界校验，也没有 `FilenameUtils.getName()` 取 basename。
- `getOriginalFilename()` 返回 multipart 请求头里客户端完全可控的 `filename` 值。Spring 的 `StandardMultipartHttpServletRequest` 默认不会剥离 `../`，因此 `../` 会原样进入路径拼接。
- `File` 本身不做沙箱：`new File("/tmp/upload/../../../opt/tomcat/webapps/x.jsp")` 会按操作系统路径语义解析到上传目录之外；只要进程对目标目录有写权限，`FileOutputStream` 就会创建/覆盖该文件。
- 上传接口返回的 URL 往往同样拼接 `fileName`，因此响应里的路径回显可以确认穿越是否生效，也便于定位落盘后的访问 URL。
- 若目标同机存在 Tomcat，`webapps/<app>/` 下的 `.jsp` 会被容器当 JSP 编译执行；上传一个哥斯拉/冰蝎 JSP 即可获得命令执行。该链路不依赖上传目录本身可解析，而是借路径穿越把文件送到“可解析且可访问”的目录，绕开了“上传目录禁止执行”的常见加固。

## 触发条件

- 上传接口接收 `MultipartFile`，并使用客户端原始文件名参与保存路径拼接。
- 保存目录计算没有规范化/边界校验，且未对 `../`、绝对路径、反斜杠做过滤。
- 服务进程对目标目录（如 Tomcat `webapps`、应用静态目录、cron/systemd 目录）有写权限。
- 目标容器会把落盘后缀当脚本解析（JSP/Tomcat 场景）。
- 上传接口可达（未授权，或低权限账号即可调用）。

## 利用步骤

1. 获取接口与源码：从 Swagger/前端 JS 找到上传路由，或先通过任意文件读取拿到服务 jar 反编译，确认 `getOriginalFilename()` 直接拼接。
2. 确认上传目录与目标 Web 目录在同一文件系统、且进程可写；通过报错、响应 URL 回显或已读到的配置推断绝对路径。
3. 计算从上传目录到 Tomcat `webapps` 的相对路径，例如 `../../../../opt/tomcat-8.5.41/webapps/cat/`。
4. 构造 multipart 请求，`filename` 填穿越路径加 JSP 文件名，正文放哥斯拉/冰蝎 JSP 或最小命令执行 JSP。
5. 从响应 JSON 的 `url` 字段确认写入路径；访问 `http://target/cat/<shell>.jsp`，用哥斯拉连接并执行 `whoami` 验证权限。

## PoC

```http
POST /<app>/picUpload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="../../../../opt/tomcat-8.5.41/webapps/cat/shell.jsp"
Content-Type: image/jpeg

<%! String xc="..."; /* 哥斯拉 JSP payload */ %>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"error":0,"url":["https://target/<app>/../../../../opt/tomcat-8.5.41/webapps/cat/shell.jsp"]}
```

随后访问 `https://target/cat/shell.jsp`，用哥斯拉以 `JAVA_AES_BASE64` 载荷连接，命令执行回显 `root`。

## 变体与关联

- 变体：`filename` 用绝对路径（`/opt/tomcat/webapps/shell.jsp`）直接覆盖目标；Windows 下用 `..\..\` 或盘符路径。
- 变体：过滤 `../` 时用 `..%2f`、`....//`、`..././`、反斜杠或双重编码绕过（取决于解码位置）。
- 变体：目标目录不是 Tomcat，也可写 `authorized_keys`、cron、systemd、应用配置文件，或覆盖已有 JSP/模板实现持久化。
- 关联：[[web-generic-file-upload-multipart-filename-traversal-ssh-key]]（同类 multipart filename 穿越，落点改为 SSH 公钥）、[[web-generic-file-upload-roothub-custompath-traversal-no-extension]]、[[web-generic-file-upload-langflow-v2-filename-traversal-arbitrary-write]]、[[web-generic-file-upload-single-replace-dotdot-bypass]]（过滤绕过）。
- 边界：取 basename、白名单后缀、保存路径规范化并校验前缀、上传目录与 Web 目录跨文件系统、进程低权限且目标目录不可写时，利用失败。

## 检测与防御

- 检测：multipart `filename` 中出现 `../`、`..\`、绝对路径、编码后的 `%2e%2e`；上传保存路径落在配置的上传目录之外；Web 目录出现新增 `.jsp/.jspx` 文件；上传响应 URL 包含穿越片段。
- 修复：保存前只取 basename，或完全使用服务端生成的随机文件名与安全后缀；用 `Path.normalize()` 后校验 `startsWith(uploadDir)`；上传目录禁止脚本解析并放在 Web 根之外。
- 加固：上传服务以最小权限运行，不能写 Tomcat webapps、cron、systemd；上传目录与运行目录隔离；对 Web 目录新增脚本文件做完整性监控与告警。
