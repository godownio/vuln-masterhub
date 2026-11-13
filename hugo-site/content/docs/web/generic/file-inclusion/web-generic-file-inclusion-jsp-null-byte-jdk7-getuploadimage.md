---
id: web-generic-file-inclusion-jsp-null-byte-jdk7-getuploadimage
title: JSP getuploadimage.jsp 的 00 截断任意文件读取：图片后缀校验与 JDK 1.7.0_40 前 NUL 路径截断（CVE-2023-47473）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: jsp-null-byte-path-truncation-file-read
tags:
- java
- jsp
- file-read
- null-byte
- path-truncation
- jdk
- windows
- auth-bypass
- cve-2023-47473
cve:
- CVE-2023-47473
affected_versions: JDK < 1.7.0_40（原文测试 1.7.0-b147；1.7.0_40 起增加 NUL 路径检查）
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V613
  verified_at: '2026-11-12T19:52:17+08:00'
  notes: 已对照原文《由00截断造成的文件读取(CVE-2023-47473分析)》通读全文并逐张核对 5 张图：图01 filter-mapping SessionControl_UserLogin -> /*；图02 doFilter 遍历异常页 endsWith 后放行；图03 exceptions=.gif/.jpg/.css/.js/.bmp/image.jsp/abbutus.html/showImage.jsp，getuploadimage.jsp 以 image.jsp 结尾命中白名单；图04 java -version 为 1.7.0-b147（D:\Fuwushe\java\bin）；图05 Burp GET getuploadimage.jsp?imageURL=C:\Windows\win.ini%001.png 返回 200、Content-Type image/jpeg，响应体即 win.ini 内容。CVE-2023-47473 为原文标题明确标注；JDK<1.7.0_40（1.7.0_40 起 isInvalid() 检查 \u0000）为原文明确表述；PoC、过滤器逻辑、getFileName/getFileType 代码与卡片一致；affected_versions 已正确设置。dedup 除自身外均为 new，MES/OA 普通路径穿越/上传类卡机制不同非同链；dup-scan 无涉及本卡的 pair。未实际复现请求；frontmatter 无 sources/source_url（validator 禁止该字段）。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-jsp-null-byte-jdk7-getuploadimage/
draft: false
kb_aliases:
- 00 截断文件读取
- '%00 截断'
- getuploadimage.jsp
- imageURL 任意文件读取
- JDK 1.7.0_40 NUL 检查
- SessionControl_UserLogin 后缀白名单绕过
- CVE-2023-47473
---

## 一句话结论

在 JDK 1.7.0_40 之前的 Windows 部署中，Java 不检查路径字符串里的 NUL（`\u0000`），而底层 Win32 文件 API 会在 NUL 处截断路径；因此向 `getuploadimage.jsp` 的 `imageURL` 传入 `C:\Windows\win.ini%00.png` 时，Java 侧的后缀校验看到的是 `.png` 而放行，`new File(imageURL)`/`FileInputStream` 实际打开的却是 NUL 之前的 `C:\Windows\win.ini`，再叠加登录过滤器用 `endsWith("image.jsp")` 做后缀白名单（`getuploadimage.jsp` 正好以 `image.jsp` 结尾），即可未授权读取服务器任意可读文件。

## 原理

- **鉴权白名单用 `endsWith` 判断**：`SessionControl_UserLogin` 过滤器映射 `/*`，`doFilter` 遍历 `exceptionPages`，只要 `requestURI.endsWith(exceptionPage)` 成立就跳过登录校验。例外列表形如 `{".gif", ".jpg", ".css", ".js", ".bmp", "image.jsp", "abbutus.html", "showImage.jsp"}`。`/oa/common/components/upload/getuploadimage.jsp` 以 `image.jsp` 结尾，因此命中白名单、无需会话即可访问。
- **文件读取入口**：该页面从 `request.getParameter("imageURL")` 取用户可控路径；`StringUtil.getFileName` 取最后一个 `\` 后的文件名，`StringUtil.getFileType` 取最后一个 `.` 后的后缀并转小写，要求后缀为 `gif/png/bmp/jpg/jpeg` 之一才继续；随后 `new File(imageURL)` + `FileInputStream` 按 128 字节循环把文件内容写进 HTTP 响应（`Content-Type: image/jpeg`）。
- **为什么 NUL 能同时骗过校验与文件打开**：`%00` 经 URL 解码后在 Java 字符串中是 `\u0000`，它只是一个普通字符：`getFileType` 用 `lastIndexOf('.')` 取后缀时看到的是 NUL 之后的 `.png`，类型校验通过。把同一个字符串交给 `new File(...)`/`FileInputStream` 时，JVM 会把它转成操作系统路径；旧版 JDK 在 Windows 上直接将该字符串作为 C 风格路径传给 Win32 API，Windows 在第一个 NUL 处截断，于是实际打开的是 NUL 之前的部分（`C:\Windows\win.ini`）。校验看到“后缀”和实际打开的“路径”不一致，即为截断绕过。
- **JDK 1.7.0_40 的修复**：新版在路径解析时增加 `isInvalid()` 检查——`status = (this.path.indexOf('\u0000') < 0) ? CHECKED : INVALID;`，路径含 NUL 直接判为非法（抛 `InvalidPathException`/IO 异常），截断链失效。
- **前提是 Windows**：Win32 路径 API 以 NUL 为终止符；Linux 的 `open(2)` 同样按 C 字符串处理，但该应用/文章环境为 Windows（安装目录 `D:\Fuwushe\java\bin`，`java -version` 为 `1.7.0-b147` 64-Bit Server VM），在其他平台上行为需实测，不能直接套用。
- **危害**：读取配置、数据库连接串、源码、密钥等任意 Web 进程可读文件；响应类型是图片但内容是文件原文，可直接外带。

## 触发条件

- 目标为 Windows 上的 Java/JSP 应用，运行时 JDK **< 1.7.0_40**（原文 `1.7.0-b147` 实测；升级到 1.7.0_40+ 后 NUL 路径直接非法）。
- 存在类似 `getuploadimage.jsp` 的页面：读取用户可控路径、仅按 Java 字符串后缀做图片类型校验、未做 `getCanonicalPath`/目录白名单校验。
- 登录过滤器使用 `endsWith` 等后缀白名单，且该页面路径恰好以白名单后缀结尾（如 `image.jsp`）。
- 攻击者可访问该页面并能在参数中发送 `%00`（中间件/WAF 未拦截 URL 编码的 NUL）。
- 目标文件对 Web 进程账户可读。

## 利用步骤

1. 确认过滤器白名单：抓取未登录请求，观察哪些后缀/路径不需会话；尝试访问 `/oa/common/components/upload/getuploadimage.jsp`，若未被重定向到登录页即命中 `image.jsp` 后缀白名单。
2. 构造读取路径：`imageURL=<目标绝对路径>%00.<图片后缀>`（如 `C:\Windows\win.ini%001.png`）。
3. 发送 GET 请求，观察响应 `Content-Type: image/jpeg` 但内容是目标文件文本。
4. 替换目标路径读取其他文件（配置文件、源码、密钥）；NUL 后的后缀任选 `png/jpg/gif/bmp/jpeg` 之一。
5. 若返回空/异常，检查 JDK 版本（`java -version`）、是否 Windows、WAF 是否拦截 `%00`、以及目标文件权限。

## PoC

```http
GET /oa/common/components/upload/getuploadimage.jsp?imageURL=C:\Windows\win.ini%001.png HTTP/1.1
Host: target:9090
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

响应（原文实测，HTTP/1.1 200，`Content-Type: image/jpeg`）：

```text
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
CMCDLLNAME32=mapi32.dll
CMC=1
...
```

读取其他文件时把 `C:\Windows\win.ini` 换成目标路径，保留 `%00` 与图片后缀即可。

## 变体与关联

- **后缀白名单变体**：多数“图片/附件读取”接口都按字符串后缀判断类型，00 截断的适用面取决于 JDK 版本与操作系统；Java 层用 `endsWith(".png")`、`lastIndexOf('.')`、正则后缀等实现都可能中招。
- **上传场景对应手法**：文件名/路径中的 NUL 同样可截断落盘文件名或扩展名校验，见 [[web-generic-file-upload-null-byte-path-truncation]]；Windows 上还可用 NTFS 数据流（`file.jsp::$DATA`）绕过扩展名，见 [[web-generic-file-upload-windows-ntfs-data-stream-extension-bypass]]；Zip 条目名中的 NUL 在 Windows 解压时也会截断，见 [[web-generic-file-upload-zip-entry-nul-windows-truncation]]。
- **鉴权变体**：过滤器用 `endsWith` 判断白名单属于典型的“后缀匹配代替精确路径”缺陷；类似问题可配合路径穿越、分号/编码差异扩大。
- **关联**：同目录其他任意文件读取卡（如 CMS/ERP 的 download 参数穿越）在“路径可控 + 无 canonical 校验”上根因一致，可组合测试。
- **边界**：JDK 1.7.0_40+、Linux 部署、或应用先做 `getCanonicalPath`/`Paths.normalize` 前缀校验时，本手法不成立；原文仅验证 Windows + JDK 1.7.0-b147。

## 检测与防御

- **修复**：升级 JDK 到 1.7.0_40 及以上（消除 NUL 路径截断）；对所有文件读取接口使用 `getCanonicalPath()` 并校验是否位于允许目录下，拒绝含 `\u0000`、`..`、绝对路径的输入；文件类型校验改用服务端白名单 + 文件头 magic 校验，不要只信字符串后缀。
- **鉴权**：过滤器不要用 `endsWith` 做后缀白名单；应使用精确路径/受控资源目录，或对所有业务接口统一鉴权。
- **检测**：WAF/日志监控 URL 参数中的 `%00`/`\u0000`、`imageURL` 等参数出现绝对路径（`C:\`、`/etc/`）与图片后缀拼接；响应 `Content-Type` 为图片但内容为文本/配置；同一来源对多个文件路径的批量请求。
- **排查**：检查 `getuploadimage.jsp` 等读取接口的访问日志与响应大小；确认 JDK 版本与部署平台；若已读取敏感配置，轮换其中凭据。
