---
id: web-dotnet-deser-json-net-serializationbinder-whitelist-bypass
title: JsonSerializationBinder 白/黑名单绕过：产品内置 PowerShellLauncher.Run 任意方法调用或 WindowsIdentity 绕过 IsSecurityCritical（CVE-2024-23478）
type: scenario
domain: web
path: web/dotnet/deserialization
technique: json-net-serializationbinder-whitelist-blacklist-bypass
tags:
- dotnet
- json.net
- serializationbinder
- deserialization
- whitelist-bypass
- objectdataprovider
- windowsidentity
- cve-2024-23478
cve:
- CVE-2024-23478
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:14:16+08:00'
  notes: 已对照原文核对；JsonSerializationBinder 放行条件、程序集名校验、PowerShellLauncher.Run/ObjectDataProvider POC、WindowsIdentity 与 IsSecurityTransparent 新补丁(图04)均一致；WindowsIdentity 为原文半链思路，作为变体保留不拆卡；CVE-2024-23478 原文明确；原文无受影响版本区间
url: /docs/web/dotnet/deserialization/web-dotnet-deser-json-net-serializationbinder-whitelist-bypass/
draft: false
kb_aliases:
- ISerializationBinder 绕过
- CVE-2024-23478
- PowerShellLauncher.Run 反序列化
- WindowsIdentity 黑名单绕过
- Json.NET Binder 补丁绕过
---

## 一句话结论

很多 Json.NET 补丁用自定义 `ISerializationBinder` 做类型白名单/黑名单：SolarWinds ARM 的 `JsonSerializationBinder` 允许“产品自身类型，或非 SecurityCritical 且非 MarshalByRef 的类型”，并要求程序集名匹配。这个条件可被两条路绕过：一是从产品白名单类型里找一个危险方法（如 `SolarWinds.ARM.PowerShellTools.PowerShellLauncher.Run(string, Dictionary<string,object>)`），用 `ObjectDataProvider` 反射调用；二是挑一个既非 SecurityCritical 也非 MarshalByRef 的框架类型（如 `WindowsIdentity`）。厂商后续把 `IsSecurityCritical` 换成 `IsSecurityTransparent` 并增加泛型/数组/布局检查（CVE-2024-23478）。

## 原理

- **Binder 的职责**：Json.NET 在遇到 `$type` 时调用 `ISerializationBinder.BindToType(assemblyName, typeName)`，返回的 Type 会被实例化；因此 binder 是反序列化类型管控的核心位置。
- **SolarWinds ARM 的校验逻辑**：
  - `type = Type.GetType(typeName)`，失败则 `Assembly.Load(assemblyName).GetType(typeName, true, true)`；
  - 放行条件：`(isSupportedPnType(type) || (!type.IsSecurityCritical && !type.IsMarshalByRef))`，并且类型的程序集名与 `assemblyName` 相等；
  - `isSupportedPnType` 用产品类型全名集合与 `Type.GetType` 反查父类/接口判断“属于产品白名单”。
- **思路一：白名单内的危险方法**。白名单类型是产品自身代码，其中难免有执行外部命令、写文件、启动 PowerShell 的方法。Json.NET 的 `ObjectDataProvider` gadget 可以指定 `ObjectInstance`（此处填白名单类型）与 `MethodName`/`MethodParameters`，在反序列化时对该实例调用任意方法。示例 `PowerShellLauncher.Run(string, Dictionary<string,object>)` 直接接收命令与参数，等价于任意命令执行。`ArrayList` 在默认 allowlist 中可用于承载参数，因此整条链只需要一个“产品内方法”作为 sink。
- **思路二：黑名单条件过窄**。`!type.IsSecurityCritical && !type.IsMarshalByRef` 只排除标记为 SecurityCritical 或 MarshalByRef 的类型；大量框架类型两者皆 false（如 `WindowsIdentity`），能通过检查。只要能找到这类类型上的可用 gadget，就能在补丁后继续 RCE。厂商随后把条件改为 `IsSecurityTransparent` 并附加泛型/数组/自动布局检查，使大多数类型不可再用。
- **程序集名校验不是安全边界**：`$type` 字符串里可以自带正确程序集全名（名称、Version、Culture、PublicKeyToken），binder 的相等比较只验证“类型确实来自该程序集”，不阻止攻击者选择该程序集内的任意类型。

## 触发条件

- 目标使用 Json.NET（Newtonsoft.Json）且 `TypeNameHandling` 允许 `$type`（Auto/Objects/All）。
- 应用使用类似的自定义 ISerializationBinder：白名单/黑名单条件基于“产品类型集合”或 SecurityCritical/MarshalByRef 等弱属性，而非严格枚举。
- 攻击者能提交 `$type` JSON 到反序列化入口。
- classpath 中存在可被 ObjectDataProvider 调用的方法，或存在满足黑名单条件的可用 gadget 类型。

## 利用步骤

1. 获取/枚举产品程序集，列出 binder 白名单类型与可用方法（文章用工具遍历 DLL，找到 `OperatingSystemHelper.CreateTextFile` 与 `PowerShellLauncher.Run` 两个可利用点）。
2. 挑选参数可控、能执行命令/写文件的方法；确认其所在类型在 `isSupportedPnType` 白名单内。
3. 构造 ObjectDataProvider JSON：`MethodName` 为目标方法，`MethodParameters.$values` 为参数列表，`ObjectInstance.$type` 为白名单产品类型（程序集全名照抄）。
4. 将 JSON 注入 `FormDataJson`/`selectionState` 等反序列化入口，触发方法调用。
5. 若白名单路径被修，尝试思路二：选 `IsSecurityCritical=false && IsMarshalByRef=false` 的框架类型（如 WindowsIdentity）配合可用 gadget。
6. 验证命令执行/文件落地；若被拦截，检查 binder 是否已换成 IsSecurityTransparent + 泛型/数组检查的新补丁。

## PoC

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Run",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": [
      "cmd.exe",
      {
        "$type": "System.Collections.Generic.Dictionary`2[[System.String, mscorlib],[System.Object, mscorlib]], mscorlib",
        "/c": "calc"
      }
    ]
  },
  "ObjectInstance": {
    "$type": "SolarWinds.ARM.PowerShellTools.PowerShellLauncher, SolarWinds.ARM.PowerShellTools, Version=23.2.1.103, Culture=neutral, PublicKeyToken=2ca8767897d7025a"
  }
}
```

## 变体与关联

- 变体：`pn.humster.OperatingSystemHelper::CreateTextFile(string, string, bool, Encoding)` 可作为任意文件写入 sink。
- 变体：黑名单绕过使用 `WindowsIdentity`（`IsSecurityCritical=false`、`IsMarshalByRef=false`）；文章只说明其可用，未给出完整利用链，实际利用需自行拼接 WindowsIdentity gadget。
- 关联：[[web-dotnet-deser-solarwinds-arm-iformtemplate-typenamehandling]]（同一产品的反序列化入口与泛型值 sink）。
- 关联：[[web-dotnet-deser-servicehandler-typenamehandling]]（无 binder 的 TypeNameHandling 基础场景）。

## 检测与防御

- 检测：请求 JSON 含 `$type`、`ObjectDataProvider`、`MethodName`、`MethodParameters`、`PowerShellLauncher`、`WindowsIdentity`、`OperatingSystemHelper` 等关键字；binder 日志中出现被拒绝或异常的类型绑定。
- 检测：w3wp/IIS 进程出现异常子进程（cmd/powershell）、非预期文件写入。
- 防御：不要把“类型是否 SecurityCritical/MarshalByRef”当安全边界；使用严格枚举的类型白名单（精确全名 + 程序集 + PublicKeyToken），默认拒绝所有非业务 DTO；禁用 TypeNameHandling 或改用 System.Text.Json 的严格模型；升级到修复 IsSecurityTransparent/泛型检查的版本；对反序列化入口做 schema 校验与行为监控。
