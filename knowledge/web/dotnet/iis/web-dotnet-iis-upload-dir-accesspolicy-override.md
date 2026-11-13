---
id: web-dotnet-iis-upload-dir-accesspolicy-override
title: 上传目录禁执行绕过：上传 web.config 把 handlers accessPolicy 改为 Read,Write,Execute,Script，让落地的 SOAP/ASPX 生效
type: scenario
domain: web
path: web/dotnet/iis
technique: iis-webconfig-accesspolicy-script-enable
aliases:
- accessPolicy 修改
- 403.1 Forbidden 绕过
- 上传目录禁止执行绕过
- web.config 覆盖 accessPolicy
- Shell2asmx.soap
- Read,Write,Execute,Script
tags:
- iis
- web-config
- accesspolicy
- upload-directory
- script-execution
- forbidden
- soap
- webshell
- dotnet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:44:23+08:00'
  notes: 已对照原文及截图核对：图 03 /uploads/Shell2asmx.soap 返回“HTTP 错误 403.1 - Forbidden：您尝试从某个目录运行 CGI、ISAPI 或其他可执行程序，但该目录不允许运行可执行文件”，与原文 0x03 的 handlers accessPolicy=Read,Write 限制对应；图 04 覆盖为 accessPolicy=Read,Write,Execute,Script 的新 web.config 后同一 URL 返回 MyWebService 服务页（含 shellInject 方法）。403.1→200 的因果与卡内 PoC 一致；.soap→ASP.NET 处理器为既有全局映射的说明合理。与自解析执行卡（把 .config 本身映射为脚本）为不同技术，互链成立；dedup 候选（CCFlow、托管模块后门、WebDAV、download.aspx）均不同链。未在本机复跑。
---

## 一句话结论

管理员常用目录级 `web.config` 的 `<handlers accessPolicy="Read,Write">` 禁止上传目录执行脚本（访问已落地的 `.aspx`/`.soap` 返回 `403.1 Forbidden`）；如果攻击者仍能往该目录写文件，就可再次上传一个 `web.config` 把 `accessPolicy` 改成 `Read,Write,Execute,Script`，覆盖父级策略，使之前上传的脚本处理器重新生效并执行。

## 原理

- **accessPolicy 的作用**：IIS 的 `handlers` 节有一个 `accessPolicy` 属性，控制该目录下处理器允许的访问类型（`Read`、`Write`、`Execute`、`Script` 的组合）。管理员把上传目录限制为 `Read,Write`（或只读）时，即使文件已经落盘且扩展名被映射到 ASP.NET 处理器，请求也会在处理器执行前被拒绝，典型错误是 `HTTP 错误 403.1 - Forbidden：您尝试从某个目录运行 CGI、ISAPI 或其他可执行程序，但该目录不允许运行可执行文件`。
- **配置继承与覆盖**：IIS 配置按目录层级合并，子目录的 `web.config` 默认可以覆盖父级/站点级的可覆盖节。攻击者在同一上传目录写入新的 `web.config`，把
  `<handlers accessPolicy="Read,Write,Execute,Script">`（可同时保留或重新添加所需处理器）写入，就替换了该目录的访问策略。
- **为什么能执行已有文件**：此前上传的 `.soap`/`.aspx` 文件（例如 SOAP WebService 形式的 Webshell）已经由全局处理器映射到 ASP.NET；限制它的只是目录 `accessPolicy`。策略被改为包含 `Script`（脚本）后，同一个请求不再被 403.1 拦截，ASP.NET 正常编译/执行该文件，WebService 页面（案例 `MyWebService` 的 `shellInject` 方法）即可被调用。
- **利用前提**：攻击者拥有该目录的写权限（能上传/覆盖 `web.config`），并且 `handlers` 节未被 `overrideModeDefault="Deny"` 锁定；如果被锁定，写入的 web.config 会触发 500.19，无法覆盖。
- **与“自解析执行”的区别**：本卡不要求把 `.config` 本身映射成脚本，而是利用 web.config 的目录策略覆盖能力，为已经落地的正常脚本文件“解封”；两者可以串联（先解锁再写自解析配置）。

## 触发条件

- 目标 IIS 站点的上传目录可写（任意文件上传/写文件），且能写入文件名 `web.config`。
- 该目录存在目录级 `web.config` 把 `accessPolicy` 限制为 `Read,Write`（或等价禁令），使已上传的 `.aspx/.soap/.ashx` 返回 403.1。
- `handlers` 配置节允许本地覆盖（applicationHost.config 未锁定该节或允许 override）。
- 全局/父级已有把目标扩展名映射到 ASP.NET 处理器的配置（如 `.soap` → `System.Web.Services.Protocols.SoapHttpHandler` 等），否则解锁后仍无处理器可用。

## 利用步骤

1. 找到允许上传且位于 Web 根内的目录（如 `/uploads`），尝试访问已上传的 `.aspx` 或 `.soap`：返回 `403.1 Forbidden`，确认目录被禁止脚本执行。
2. 构造新的 `web.config`，把 `handlers` 的 `accessPolicy` 设为 `Read,Write,Execute,Script`；如需，可显式添加目标扩展名的处理器映射。
3. 通过上传接口/任意写把 `web.config` 写入该目录（覆盖原配置；可先记录原内容以便还原）。
4. 再次请求之前落地的脚本文件（案例 `/uploads/Shell2asmx.soap`），确认不再 403.1，而是返回 SOAP 服务页/执行结果。
5. 调用 SOAP 方法或访问 Webshell 执行命令（案例 `MyWebService` 的 `shellInject`）。
6. 若写入后出现 500.19，说明 `handlers` 节被锁定，改试其它未锁定节（如 `httpHandlers`）或换目录/其它上传点。

## PoC

```xml
<!-- 上传目录下新写入的 web.config -->
<system.webServer>
  <handlers accessPolicy="Read,Write,Execute,Script">
  </handlers>
</system.webServer>
```

```text
# 1) 解锁前的请求：403.1 Forbidden
GET /uploads/Shell2asmx.soap HTTP/1.1
Host: target

# 2) 上传上述 web.config 后，同一请求返回 SOAP 服务页
GET /uploads/Shell2asmx.soap HTTP/1.1
Host: target

HTTP/1.1 200 OK
MyWebService
支持下列操作。有关正式定义，请查看服务说明。
- shellInject
```

案例中解锁前为 `403.1`，覆盖配置后 SOAP Webshell 页面可访问并含 `shellInject` 方法；未在本机复跑。`accessPolicy` 的取值与是否允许覆盖取决于目标 IIS 版本与节锁定配置。

## 变体与关联

- 关联：[[web-dotnet-iis-webconfig-handler-self-execution]]（同一 web.config 写原语，用于把 `.config` 本身映射为 ASP/ASP.NET 页面执行）。
- 关联：[[web-dotnet-iis-managed-module-backdoor-bin-webconfig]]（web.config 注册托管模块 DLL 的后门）。
- 关联：[[web-generic-file-upload-ccflow-iis-webconfig-aspx]]（上传 web.config 注册 aspx 处理器）。
- 变体：`accessPolicy` 可改为只加 `Script`，避免 `Execute` 触发其它策略；也可对特定 path 单独注册 handler 并把 accessPolicy 写在该 handler 上。
- 变体：若 `handlers` 节被锁定，可尝试 `httpHandlers`（经典模式）、`security/requestFiltering` 相关节，或改用已允许执行的目录（如站点根、bin、App_Code）。
- 边界：`overrideModeDefault="Deny"` 锁定、应用程序池无托管代码、目标扩展名无处理器映射、上传目录被移出 Web 根时，本路径失效；修改配置可能触发 500.19 或应用重启，暴露痕迹。

## 检测与防御

- **配置锁定**：在 `applicationHost.config` 中对 `handlers`/`httpHandlers` 等节设置 `overrideModeDefault="Deny"`，禁止上传目录本地覆盖；上传目录使用只读、无脚本执行的应用池或独立虚拟目录。
- **上传治理**：禁止上传 `web.config`/`*.config`；上传目录移出 Web 根；对上传文件做重命名与内容校验。
- **检测**：监控上传目录出现/修改 `web.config`；同一目录先返回 403.1、随后出现配置写入与 200 脚本响应的组合；IIS 500.19 错误；w3wp 派生子进程（cmd/powershell）。
- **响应**：删除恶意 web.config、恢复原配置，审计同目录上传文件与访问日志，检查 SOAP/ASPX Webshell 是否被调用。
