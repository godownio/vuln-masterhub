---
id: web-generic-file-inclusion-dotnet-ava-download-aspx-server-mappath
title: 某应用云平台 download.aspx 任意文件下载：file 参数直拼 Server.MapPath("~"+file) 读取站点内 web.config 等
type: scenario
domain: web
path: web/generic/file-inclusion
technique: dotnet-server-mappath-tilde-file-download
aliases:
- download.aspx 任意文件下载
- Server.MapPath 路径拼接
- web.config 下载
- ASP.NET 任意文件读取
- file 参数未校验
tags:
- web
- dotnet
- aspnet
- file-download
- arbitrary-file-read
- server-mappath
- web-config
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V221
  verified_at: '2026-11-07T06:40:41+08:00'
  notes: 已对照原文 content.md 与图17/18核对：Download.Page_Load 的 GetFormValue("File").UrlDecode → Server.MapPath("~"+text) → File.Exists → ResponseFile，PoC 为 GET /download.aspx?file=/web.config 且带 ASP.NET_SessionId/PrivateKey；未展示响应体，卡片已标注。dedup 候选 jhsoft-downloadbgimage 等同 sink 不同产品，判为不同链。
---

## 一句话结论

某应用云平台的 `download.aspx` 在 `Page_Load` 中把请求参数 `File` 原样取出并做 URL 解码后，直接拼成 `Server.MapPath("~" + file)`，只判断文件存在就交给 `ResponseFile` 下载；由于没有虚拟路径白名单、`..` 过滤或扩展名限制，攻击者传 `file=/web.config` 即可下载站点根下的 `web.config`、`.aspx` 源码、`.dll`、日志等任意文件。

## 原理

- 代码路径：`string text = base.Request.GetFormValue("File").UrlDecode();` → `string text2 = base.Server.MapPath("~" + text);` → `if (!File.Exists(text2)) throw ...` → `FileInfo fileInfo = new FileInfo(text2);` → `ResponseFile(Page.Request, Page.Response, fileInfo.Name, fileInfo.FullName, domain.DownloadSpeed * 1024 * 1024);`。
- `Server.MapPath("~" + text)` 把 `~` 解释为应用根目录；`text` 以 `/` 开头时即变成站点内绝对虚拟路径，例如 `/web.config` → `C:\...\web.config`。代码没有把 `text` 限制在某个下载子目录，也没有拒绝 `..` 或敏感扩展名。
- `File.Exists` 只判断文件存在，不判断是否允许下载；`ResponseFile` 按物理路径读取并回写响应，因此任意可读文件都能被下载。
- 危害：`web.config` 常含数据库连接字符串、machineKey、AppSettings 密钥；`.aspx/.cs/.dll` 可辅助源码审计；日志/备份可能含会话与账号信息。
- 原文 PoC 携带 `ASP.NET_SessionId` 与 `PrivateKey` Cookie；接口是否可匿名访问取决于该页面/全局鉴权配置，但参数拼接缺陷本身与鉴权无关。

## 触发条件

- 目标为使用该 `download.aspx` 代码的 .NET 应用（文章称“mou 应用云平台”，反编译自 `AVA.ResourcesPlatform.*` 程序集）。
- `download.aspx` 可访问（登录或匿名取决于部署），`File` 参数可达。
- 目标文件在站点根目录内且进程有读权限；`Server.MapPath` 不允许 `..` 跳出应用根，因此主要是站点内任意文件读取。
- 未被 WAF/自定义过滤器拦截 `web.config`、`.aspx`、`.dll` 等敏感路径。

## 利用步骤

1. 访问 `download.aspx`，先用一个正常文件确认接口可用（如 `file=/images/logo.png`）。
2. 将 `file` 改为站点根下的敏感文件：`/web.config`、`/Global.asax`、`/bin/<assembly>.dll`、`/App_Data/*.mdf`、日志文件等。
3. 观察响应头 `Content-Disposition` 与响应体，下载文件内容。
4. 从 `web.config` 提取连接字符串、machineKey、AppSettings 密钥；从 DLL/源码继续审计其它漏洞。
5. 原文 PoC 为 `GET /download.aspx?file=/web.config`；响应截图未完整展示，但代码路径与文章结论为“成功下载”。

## PoC

```http
GET /download.aspx?file=/web.config HTTP/1.1
Host: <target>
Cookie: ASP.NET_SessionId=<session>; PrivateKey=<key>
```

原文截图确认 `Download.aspx` 的 `Page_Load` 使用 `Server.MapPath("~" + text)` 且无路径校验，并给出上述请求；未展示完整响应内容。

## 变体与关联

- 路径变体：`file=/App_Data/...`、`file=/bin/...`、`file=/Views/...`、`file=/web.config.bak`；`~` 前缀固定后可用 `/` 指向站点内绝对虚拟路径。
- 编码变体：`%2f`、`%5c`、双重 URL 编码，取决于 `UrlDecode` 与 IIS 解析顺序。
- 关联：下载 `web.config`/DLL 后可继续做源码审计，定位上传、反序列化、SQL 注入等二次漏洞；本文章中的上传接口即来自反编译审计。
- 同类：ASP.NET `Server.MapPath` 拼接下载、ResponseFile 任意文件读取、`dotnet-handler-gettxt-path-read`。

## 检测与防御

- 修复：把可下载文件移出 Web 根，使用文件 ID 映射物理路径；若必须用路径，先限制到固定下载目录，`Path.GetFullPath` 归一化后校验必须位于基目录内，并加扩展名白名单。
- 检测：`download.aspx` 请求中 `file` 含 `web.config`、`.aspx`、`.dll`、`.config`、`..`、`%2f`、`%5c`；同一会话短时间下载多个敏感文件；响应为 `application/octet-stream` 且文件名异常。
- 加固：对下载接口做鉴权与审计日志（用户/IP/文件/时间/结果）；`web.config` 配置 `requestFiltering` 拒绝敏感扩展；最小权限运行。
