---
id: web-generic-file-inclusion-mee-admin-common-file-filepath-traversal
title: mee-admin CommonFileController 任意文件下载：/mee/common/file 的 filePath 直接拼接导致路径穿越
type: scenario
domain: web
path: web/generic/file-inclusion
technique: mee-admin-common-file-filepath-traversal
tags:
- java
- spring-boot
- file-download
- path-traversal
- arbitrary-file-read
- mee-admin
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:40:25+08:00'
  notes: 已对照原文、图17-27与源码核对：CommonFileController @RequestMapping("/common/file")、@Value("/meeadmin/files")、new File(file_base_dir + File.separator + filePath) 无规范化，PoC filePath=../../../flag；原文 img/24 另一次请求显示 404，卡内已注明以 file_base_dir 实际深度与响应体为准；已把 @Value 修正为原文硬编码值。未复跑。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-mee-admin-common-file-filepath-traversal/
draft: false
kb_aliases:
- mee-admin 任意文件下载
- /mee/common/file
- CommonFileController
- filePath 路径穿越
- mee admin file download
---

## 一句话结论

mee-admin 的公共文件下载接口 `/mee/common/file` 把请求参数 `filePath` 直接拼到固定目录 `file_base_dir` 后面构造 `File`，未做规范化或白名单校验；攻击者传入多级 `../` 即可逃逸文件目录，下载服务器上的任意文件（如 `/flag`、配置文件、私钥）。

## 原理

- 反编译可见 `CommonFileController`（`com.mee.common.web`）使用 `@RequestMapping("/common/file")`，类中 `file_base_dir` 由 `@Value("/meeadmin/files")` 注入（原文为硬编码值，未使用属性占位符）。
- 下载方法签名类似 `download(HttpServletResponse response, String filePath, String fileName)`，核心是 `File file = new File(file_base_dir + File.separator + filePath)`，然后 `new FileInputStream(file)` 并通过 `FileCopyUtils.copy` 写回响应；`fileName` 只用于生成 `Content-Disposition` 的下载文件名。
- `filePath` 完全来自请求参数，拼接前没有 `getCanonicalPath()`、没有"结果必须在 `file_base_dir` 内"的校验。`/meeadmin/files` 加 `../../../` 可逐级上溯到根目录，再拼目标文件名即可读取任意路径。
- 原文的修复版本是在拼接前加 `if (filePath.contains("..") || filePath.contains("/")) { return; }`；这正说明漏洞版本缺少该判断。该黑名单只针对 `..` 与 `/`，在 Windows 目标上仍可能被盘符绝对路径（如 `C:\Windows\win.ini`）绕过。
- 危害取决于进程权限：可读应用配置（数据库口令、第三方密钥）、`/flag`、SSH 私钥、`/proc/self/environ` 等；配合源码泄露/备份文件可进一步 RCE。

## 触发条件

- 目标部署 mee-admin，`/mee/common/file` 路由可达。
- 端点未鉴权，或攻击者已有任意低权限会话（原文环境直接请求即可命中）。
- 应用进程对目标文件有读权限。
- 目标 `file_base_dir` 已知或可通过报错、默认路径 `/meeadmin/files`、目录扫描推断。

## 利用步骤

1. 探测 `/mee/common/file?fileName=1.txt&filePath=1.txt`，确认接口存在且能返回文件内容/触发下载。
2. 用多级 `../` 上溯：`filePath=../../../flag`、`filePath=../../../../etc/passwd`，按 `file_base_dir` 的深度调整层数。
3. 读取应用配置与密钥：`application.yml`、`application.properties`、`/proc/self/environ`、`~/.ssh/id_rsa` 等；下载文件名用 `fileName` 控制，便于保存。
4. Windows 目标尝试 `filePath=C:/Windows/win.ini` 或 `C:\Windows\win.ini`（若黑名单只拦 `..` 与 `/`）。
5. 用下载到的凭据做最小化验证，确认后停止扩大；测试时避免读取与目标无关的隐私数据。

## PoC

```http
GET /mee/common/file?fileName=1.txt&filePath=../../../flag HTTP/1.1
Host: target:8080
```

```http
GET /mee/common/file?fileName=passwd&filePath=../../../../etc/passwd HTTP/1.1
Host: target:8080
```

响应头包含 `Content-Disposition: attachment;filename="..."`，响应体为目标文件内容。原文称该 PoC 下载成功；其截图中的一次请求显示 404，实战需按 `file_base_dir` 实际深度调整 `../` 层数并以响应体为准。

## 变体与关联

- 变体：`filePath` 用 URL 编码/双写（`%2e%2e%2f`、`....//`）尝试绕过简单黑名单；Windows 用盘符或反斜杠路径。
- 变体：同类 Java 文件下载接口若只用 `String.contains("..")` 过滤，仍可能被绝对路径、符号链接或规范化差异绕过。
- 关联：[[web-generic-file-inclusion-jfinalcms-common-download-filekey-traversal]]、[[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]（同为 Java 下载接口路径穿越，可直接对比参数拼接方式）、[[web-generic-file-inclusion-windows-backslash-download-traversal]]（Windows 反斜杠变体）。
- 边界：接口加了鉴权、`filePath` 做了规范化并校验前缀、或进程无读权限时，读取失败；仅能下载固定目录内文件时价值下降为日志/配置泄露。

## 检测与防御

- 检测：`/common/file`、`/mee/common/file` 的 `filePath` 参数含 `..`、`/`、`\`、盘符、`%2e`；同一来源连续请求系统文件与配置文件名；响应为 `application/octet-stream` 且文件名异常。
- 防御：对 `filePath` 做 `getCanonicalPath()` 后校验必须位于 `file_base_dir` 之内（前缀比较需带分隔符），拒绝绝对路径与 `..`；不要只做字符串 `contains` 黑名单。
- 防御：下载接口加认证与资源级授权，文件名与路径使用服务端映射 ID 而非用户传入路径；限制可下载目录与文件类型。
- 加固：生产环境及时应用官方修复/升级；对下载量、异常路径与敏感文件访问做审计告警。
