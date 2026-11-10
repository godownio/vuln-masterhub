---
id: web-generic-file-inclusion-jfinalcms-common-download-filekey-traversal
title: JFinalCMS 前台 /common/file/download 的 fileKey 直拼 Web 根路径：../../ 穿越读取任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: jfinalcms-common-file-download-filekey-path-traversal
tags:
- web
- java
- jfinalcms
- cms
- arbitrary-file-read
- file-download
- path-traversal
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:59:44+08:00'
  notes: 已对照原文与图05-06核对：/common/file/download 的 File(new File(webRoot+fileKey))、仅 exists 判断、octet-stream 循环输出、Content-Disposition;fileName=flag.txt、7 层 ../ 读到 flag{test}、请求无 Cookie 均一致；已把正文『写文件时』更正为『读取时』。未复现
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-jfinalcms-common-download-filekey-traversal/
draft: false
kb_aliases:
- JFinalCMS 前台任意文件读取
- /common/file/download
- fileKey 路径穿越
- 下载接口任意文件读取
- fileKey=../../../../flag.txt
---

## 一句话结论

JFinalCMS 前台 `/common/file/download` 把请求参数 `fileKey` 直接拼到 `PathUtils.getWebRootPath()` 后面 `new File(...)` 打开，只判断 `File.exists()` 就读取并回写响应，没有规范化路径或过滤 `../`；未登录提交 `fileKey=../../../../../../../flag.txt` 即可 200 返回 Web 根目录外的文件内容，`Content-Disposition` 还带出原文件名。

## 原理

- **拼接式路径**：`File file = new File(PathUtils.getWebRootPath() + fileKey);`，`fileKey` 完全由请求控制，没有 `..`/绝对路径/分隔符过滤；读取时又用同一个拼接结果 `new FileInputStream(new File(PathUtils.getWebRootPath()+fileKey))`。
- **只校验存在性**：代码只有 `if (!file.exists()) throw new HttpMediaTypeNotAcceptableException("文件不存在");`，没有 `getCanonicalPath()` 后判断是否仍在 Web 根目录内。`../` 解析后的真实文件存在，检查就通过。
- **响应回写**：设置 `Content-Type: application/octet-stream; charset=UTF-8`、`Content-Length`、`Content-Disposition: attachment; fileName=URLEncoder.encode(file.getName())`，然后按 1024 字节循环读文件写到 `response.getOutputStream()`，因此能把任意可读文件原样下载。
- **前台未鉴权**：原文 PoC 的请求没有携带 `JSESSIONID`/Cookie，说明该 `/common` 路由在未登录状态可达；攻击面比后台删除更大，可匿名读取配置、数据库口令、源码、日志等。
- **穿越深度**：`fileKey` 从 Web 根目录开始，用 `../` 逐级上跳；`file.getName()` 只影响响应里的文件名，不影响实际读取路径。原文用 7 层 `../` 读到 Web 根之外的 `flag.txt`。

## 触发条件

- 目标 JFinalCMS 暴露 `/common/file/download` 路由，且 `fileKey` 参数可控。
- 目标文件对应用进程用户可读（配置文件、源码、备份、系统文件等）。
- 无需登录（原文 PoC 无 Cookie）；若版本加了鉴权，则需要低权限账号。
- 原文未给出受影响版本号，测试环境为 Spring Boot/JFinalCMS 实例；CVE 未提及。

## 利用步骤

1. 确认路由：直接访问 `/common/file/download?fileKey=xxx`，看是否返回文件或“文件不存在”。
2. 用已知存在的文件（如 `index.html`、`config.properties`）校准 Web 根目录与 `../` 深度。
3. 构造 `fileKey=../../../../../../../flag.txt`（层数按部署深度调整），发送 GET。
4. 观察响应：200、`Content-Disposition` 带文件名、body 为文件内容；保存响应即可。
5. 扩大目标：`config.properties`、`application.yml`、`WEB-INF/classes/*.class`、数据库备份、日志、`/etc/passwd`（应用以 root 运行时）等。
6. 若返回 404/异常，尝试 URL 编码 `%2e%2e%2f`、双写 `....//`、Windows `..%5c`，或换用 `/common/file/download` 的其它参数名。

## PoC

```http
GET /common/file/download?fileKey=../../../../../../../flag.txt HTTP/1.1
Host: 127.0.0.1:8888
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

响应：

```http
HTTP/1.1 200
Content-Disposition: attachment;fileName=flag.txt
Content-Type: application/octet-stream;charset=UTF-8
Content-Length: 1024
Connection: close

flag{test}
```

原文截图中 7 层 `../` 成功读到 Web 根目录外的 `flag.txt`；文件名由服务端 `file.getName()` 取到，说明路径穿越已生效。

## 变体与关联

- **编码绕过**：若后续版本加了 `../` 黑名单，尝试 `%2e%2e%2f`、`..%2f`、`..%5c`、`....//`、双重 URL 编码；Java `File` 在 Windows 同时接受 `/` 与 `\`。
- **绝对路径**：本卡是字符串拼接 `webroot + fileKey`，传 `/etc/passwd` 会变成 `webroot/etc/passwd`，通常仍需 `../`；若代码改为 `new File(fileKey)` 则可直接绝对路径，见 [[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]。
- **同产品 FileManager**：[[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]] 是 JFinalCMS 后台 FileManager 的 `path/currentpath` 任意读/写/下载，并涉及 JFinalFilter 对 jsp 直连的拦截；本卡是前台 `/common/file/download` 的 `fileKey`，端点、参数与鉴权状态不同。
- **读取后的利用**：读 `config.properties`/`application.yml` 拿数据库口令、第三方密钥；读源码找更多接口；读备份/日志获取会话或凭据；应用以 root 运行时读 `/etc/shadow`。
- **边界**：只能读进程有权限的文件；目录不可读；大文件会按 1024 字节循环输出，注意响应大小与超时。

## 检测与防御

- **规范化 + 根目录约束**：打开文件前 `getCanonicalFile()`，校验 `canonicalPath.startsWith(webRootCanonical + File.separator)`；拒绝包含 `..`、绝对路径、分隔符的 `fileKey`。
- **不要用客户端路径**：文件下载用服务端 ID 映射到固定目录下的文件（如数据库记录 ID → 路径），不把路径片段交给客户端。
- **鉴权与权限**：`/common/file/download` 应要求登录并校验文件归属；应用进程用低权限用户运行，Web 根目录外不放敏感配置。
- **检测**：监控下载请求中的 `../`、`%2e`、`..%5c`、异常长的路径和高频枚举；对 200 返回的 `Content-Disposition` 文件名与请求参数不一致的情况告警。
- **合规**：仅在授权环境测试；读取到的凭据按敏感数据处理。
