---
id: web-generic-auth-dotnet-extensionlessurlhandler-aspx-endswith-bypass
title: .NET OA 全局鉴权绕过：ExtensionlessUrlHandler 让 .aspx/ 附加路径仍命中页面，EndsWith(".aspx") 检查被后缀跳过
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-extensionlessurlhandler-aspx-endswith-auth-bypass
aliases:
- ExtensionlessUrlHandler 绕过
- .aspx 路径后缀绕过
- .aspx/ 未授权访问
- EndsWith aspx 绕过
- TransferRequestHandler 路径信息
- 某和OA 全局绕过
- JHSoft.Log 绕过
tags:
- dotnet
- iis
- webforms
- auth-bypass
- path-normalization
- extensionless-url
- httphandler
- httphandler-pipeline
- jhsoft
- oa
- aspx
cve: []
severity: critical
confidence: high
affected_versions: 某和OA协同办公管理系统 C6
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:32:21+08:00'
  notes: 已对照原文与全部 9 图核对：Web.config 中 ExtensionlessUrlHandler-Integrated-4.0 path=*. verb=* type=System.Web.Handlers.TransferRequestHandler、modules runAllManagedModulesForAllRequests=true、JHSoft.Log.LogHttpModule（Init 注册 AcquireRequestState），AcquireRequestState 中 text=Request.Path.ToLower() 且仅 text.EndsWith('.aspx') 分支做 SqlFilter、随后会话为空按放行清单重定向；请求 /c6/JHsoft.web.Workflat/SetImageModule.aspx/id/121212 返回含 __VIEWSTATE 表单（图06）、/isconnect.aspx 白名单直通（图05），均与卡一致。说明：Request.Path 保留尾段使 EndsWith 为 false 是从绕过实测反推（原文未贴变量值）；.ashx/.asmx 缺口原文为推断，卡内已用'可能'表述。原文明确 C6，已 set-versions。无 sources/文章ID/URL；dedup 均 new。
---

## 一句话结论

.NET WebForms 应用启用 `ExtensionlessUrlHandler`（`path="*."` → `System.Web.Handlers.TransferRequestHandler`，经典模式下 `aspnet_isapi.dll`/`DefaultHttpHandler`）后，`/xxx.aspx/任意路径` 或 `/xxx.aspx/` 这类“带尾部分段”的 URL 仍会被路由到 `xxx.aspx` 页面（尾部作为 PathInfo 被忽略）；与此同时，全局 HttpModule 的鉴权只在 `Request.Path.ToLower().EndsWith(".aspx")` 为真时执行。给真实 URL 追加 `/id/121212` 或尾部 `/` 后 `EndsWith(".aspx")` 变为 false，鉴权、登录重定向乃至 SQL 注入过滤整段被跳过，而未登录请求仍然命中目标页面——于是任意 `.aspx` 功能接口都可未授权访问。

## 原理

- **ExtensionlessUrlHandler 的由来**：.NET 4.0 为让 WebForms 应用支持无扩展名 URL，提供 `ExtensionlessUrlHandler`：
  - 集成模式：`<add name="ExtensionlessUrlHandler-Integrated-4.0" path="*." verb="*" type="System.Web.Handlers.TransferRequestHandler" preCondition="integratedMode,runtimeVersionv4.0" />`，`path="*."` 匹配“没有扩展名”的 URL，`verb="*"` 覆盖所有方法；
  - 经典模式：映射到 `%WINDIR%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll`，由 `System.Web.DefaultHttpHandler` 处理；
  - 依赖 IIS 7+ 与 KB980368。
- **尾部路径仍命中 .aspx**：WebForms 的请求映射允许 `foo.aspx/bar/baz` 形式——`.aspx` 之后的部分作为 PathInfo 传给页面，页面代码正常执行；由于整个 URL 没有扩展名结尾（或以 `/` 结尾），IIS 交给 ExtensionlessUrlHandler，再由 TransferRequestHandler 走托管管道。`runAllManagedModulesForAllRequests="true"` 进一步让所有请求都经过托管模块。
- **鉴权模块的判断缺陷**：JHSoft.Log 的 `LogHttpModule` 在 `Init` 中注册 `AcquireRequestState` 事件，事件里 `string text = context.Request.Path.ToLower();`，随后只在 `text.EndsWith(".aspx")` 的分支内执行 `SqlFilter`（敏感字符检查）和会话校验：
  - 会话为空且路径不在内置放行清单（登录/注册/验证码等大量 .aspx 白名单）时，重定向到登录页；
  - 分支条件是“路径以 .aspx 结尾”，而 `Request.Path` 保留客户端原始路径，不做 `..`/尾段规范化。
- **为什么绕过成立**：请求 `/c6/JHsoft.web.Workflat/SetImageModule.aspx/id/121212` 时：
  1. `Request.Path` = `/c6/.../SetImageModule.aspx/id/121212`，不满足 `EndsWith(".aspx")`，鉴权分支整段跳过；
  2. IIS/ASP.NET 仍把请求路由到 `SetImageModule.aspx`，PathInfo 为 `/id/121212`，页面正常执行并返回内容。
  因此“路径不以 .aspx 结尾”既没有让请求 404，又让全局检查失效，形成全局未授权访问。
- **另一个缺口**：模块只对 `.aspx` 做 SQL 过滤/鉴权，`.ashx`、`.asmx` 等扩展名天然不在检查范围；这类接口即使路径正常结尾也可被直接访问。

## 触发条件

- 目标为 IIS 7+、.NET 4.0 的 WebForms 应用，Web.config 配置了 `ExtensionlessUrlHandler`（集成或经典模式），且 `runAllManagedModulesForAllRequests="true"`。
- 全局鉴权实现在 HttpModule 中，依赖 `Request.Path` 的后缀（`EndsWith(".aspx")`）决定是否检查，而不是按规范化路由/处理程序判断。
- 目标存在任意 `.aspx` 功能页（尤其是无独立鉴权的接口页、存在 SQL 注入的页面）。
- 服务器/处理程序允许 `.aspx/尾段` 形式映射（默认 WebForms 行为）。

## 利用步骤

1. 读取目标 `Web.config`（或从已知泄露/备份获取），确认存在 `ExtensionlessUrlHandler` 与自定义鉴权模块（如 `JHSoft.Log.LogHttpModule`）。
2. 直接请求目标页面建立基线：`GET /c6/JHsoft.web.Workflat/SetImageModule.aspx`，预期被 302 重定向到登录页。
3. 追加尾段再请求：`GET /c6/JHsoft.web.Workflat/SetImageModule.aspx/id/121212`，或 `GET /.../SetImageModule.aspx/?id=2222`；若返回页面内容（而非登录跳转），说明 `EndsWith(".aspx")` 分支被跳过。
4. 对目标功能接口套用该后缀（如存在注入的 `RssModulesHttp.aspx`：`/RssModulesHttp.aspx/?interfaceID=1`），在未登录状态下发送攻击 payload。
5. 对 `.ashx`/`.asmx` 接口直接测试：这些扩展名不在模块的 `.aspx` 检查范围内，可能无需后缀即可访问/注入。
6. 验证响应中是否包含真实业务数据（如 `__VIEWSTATE` 表单、列表数据），不要仅凭 200 状态码判定成功。

## PoC

```http
### 基线：被重定向到登录页
GET /c6/JHsoft.web.Workflat/SetImageModule.aspx HTTP/1.1
Host: target

### 绕过：追加路径段后页面正常执行（响应含 __VIEWSTATE / 业务表单）
GET /c6/JHsoft.web.Workflat/SetImageModule.aspx/id/121212 HTTP/1.1
Host: target

### 另一种形式：.aspx 后加斜杠 + 查询串
GET /c6/JHsoft.web.Workflat/SetImageModule.aspx/?id=2222 HTTP/1.1
Host: target
```

判定要点：响应从 302 登录跳转变为 200 且 body 出现目标页面的表单/`__VIEWSTATE`/业务内容；对无表单的接口可用唯一 canary 数据确认操作确实执行。

## 变体与关联

- **其他后缀判断绕过**：同样思路适用于 `EndsWith(".jsp")`、`contains(".do")`、`startsWith("/api")` 等基于原始 URI 的鉴权；可结合 `;`、`%2f`、`%00`、大小写、双写等变体。
- **.ashx/.asmx 缺口**：模块只检查 `.aspx` 时，`.ashx`（一般处理程序）和 `.asmx`（WebService）可能完全绕过 SQL 过滤与登录校验，是独立于尾段绕过的第二条路径。
- **MVC/API 路由**：启用 ExtensionlessUrlHandler 的应用若同时有 MVC/WebAPI 路由，`/Controller/Action/参数` 形式天然无扩展名，鉴权若依赖后缀会全部失效。
- **经典模式差异**：经典模式下 aspnet_isapi.dll 对 PathInfo 的映射行为与集成模式略有不同，但“后缀检查 + 尾段路由”组合仍然成立。
- **关联利用**：全局绕过本身只是访问控制缺陷，实际危害取决于被暴露的接口（SQL 注入、文件上传、任意文件读写、反序列化等）；本卡的 SQL 注入实例见关联卡。

## 检测与防御

- **不要用 URL 后缀做鉴权**：在模块中改为基于规范化后的路由/处理程序/控制器 Action 判断，先 `Path.GetFullPath`/`Uri` 规范化并去掉 PathInfo，再做白名单/黑名单。
- **默认拒绝**：鉴权逻辑改为“除明确放行的静态资源与登录接口外一律检查”，而不是“只在 .aspx 结尾时检查”；`.ashx`/`.asmx` 必须纳入同一套检查。
- **关闭不必要的 ExtensionlessUrlHandler**：若应用不需要无扩展名 URL，移除该 handler 及 `runAllManagedModulesForAllRequests`；需要时明确限制可匹配的路径与 verb。
- **IIS 层限制**：对 `.aspx` 的 PathInfo 使用做校验（拒绝包含额外路径段的请求），或配置 request filtering 拒绝异常 URL；在 IIS 授权规则中对所有 handler 统一要求认证。
- **检测**：WAF/日志中关注 `*.aspx/`、`*.aspx;`、`.aspx%2f`、`.aspx?` 等异常形态；对被跳转到登录页的路径建立基线，告警同一路径带尾段后返回 200 的请求。
- **审计**：检查 Web.config 中的 `handlers`、`modules`、`runAllManagedModulesForAllRequests` 与自定义 HttpModule；用未登录会话对全部 .aspx/.ashx/.asmx 接口做尾段变体扫描。
