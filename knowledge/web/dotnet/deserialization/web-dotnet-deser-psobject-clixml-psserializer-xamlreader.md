---
id: web-dotnet-deser-psobject-clixml-psserializer-xamlreader
title: PSObject + ObjectDataProvider gadget：反序列化构造函数读 CliXml 交给 PSSerializer.Deserialize，经 XamlReader.Parse 执行 ObjectDataProvider
type: scenario
domain: web
path: web/dotnet/deserialization
technique: psobject-clixml-psserializer-xamlreader-odp
aliases:
- PSObject gadget
- PSSerializer.Deserialize
- CliXml 反序列化
- PowerShell 反序列化 gadget
- System.Management.Automation PSObject
- ObjectDataProvider XAML
tags:
- dotnet
- binaryformatter
- deserialization
- psobject
- powershell
- clixml
- psserializer
- xamlreader
- objectdataprovider
- gadget
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:24+08:00'
  notes: 已对照原文 img03 构造函数截图核对 CliXml→PSSerializer.Deserialize；原文无生成代码且未展开 PSSerializer→XamlReader 中间步骤，confidence medium 与证据边界表述如实；未复现（未验证点：ObjectDataProvider 经 CLIXML 到达 XamlReader.Parse 的具体触发路径）。
---

## 一句话结论

`System.Management.Automation.PSObject` 的 `ISerializable` 反序列化构造函数会读取 `SerializationInfo` 里的 `CliXml` 字符串并交给 `PSSerializer.Deserialize`；攻击者用 `info.SetType(typeof(PSObject))` + 恶意 `CliXml` 包装序列化流，即可让 PowerShell 的 CLIXML 反序列化器重建攻击者指定的对象图并到达 `XamlReader.Parse`，解析 `ObjectDataProvider` 执行命令（需要目标加载 System.Management.Automation；该链为文章文字结论，仅有构造函数截图佐证，未经完整复现）。

## 原理

- **入口构造函数**：`PSObject(SerializationInfo info, StreamingContext context)` 的实现（文章 img03）为：`info.GetValue("CliXml", typeof(string))` 取出字符串，非空则 `PSObject.AsPSObject(PSSerializer.Deserialize(clixml))`；空则抛异常。也就是说，`PSObject` 本身只是一个"把 CliXml 字符串送进 PSSerializer"的包装。
- **PSSerializer 的类型重建**：`PSSerializer.Deserialize` 是 PowerShell 的 CLIXML 反序列化入口，CLIXML 可携带类型名（TN/TS 等元数据）并按类型重建对象、设置属性。文章结论是：把 `ObjectDataProvider` 的 XML/XAML 作为 CliXml 值传入，链子最后调用 `XamlReader.Parse` 解析该内容，进而由 `ObjectDataProvider`（`MethodName=Start`、`ObjectInstance=Process`）执行命令。XamlReader.Parse 是这条链的 sink。
- **攻击者包装**：与 TFRP 类似，生成端实现 `ISerializable` 包装类：`info.SetType(typeof(PSObject))`、`info.AddValue("CliXml", <恶意 CLIXML/XAML>)`，再用 BinaryFormatter 序列化。反序列化端按 `SetType` 创建 PSObject 并进入上述构造函数。
- **为什么成立**：反序列化构造函数把完全受控的字符串交给一个"会按类型名重建对象"的解析器（PSSerializer），随后进入 XAML 解析；两个解析器都不把输入当作纯数据，于是形成从序列化流到任意方法调用的通道。
- **证据边界**：文章只给出 PSObject 构造函数的截图（证明确实调用 `PSSerializer.Deserialize`）和"最后调用 XamlReader.Parse"的文字结论，未展开 PSSerializer 内部到 XamlReader 的中间步骤，也未给出该 gadget 的生成代码；该 gadget 出自 ysoserial.net，本卡置信度 medium。

## 触发条件

- 存在可控制序列化流的 BinaryFormatter 入口（或能被其他格式携带到 BinaryFormatter 的入口）。
- 目标进程加载了 `System.Management.Automation`（PowerShell 程序集）。
- 反序列化端未限制 PSObject / 未禁用 BinaryFormatter。

## 利用步骤

1. 确认反序列化入口可控且目标具备 PowerShell 程序集。
2. 构造恶意 `CliXml` 内容：按文章思路放入 `ObjectDataProvider` 对应的 XML/XAML（`Process.Start` + `cmd /c <命令>`）。
3. 用 `ISerializable` 包装：`info.SetType(typeof(PSObject))`，`info.AddValue("CliXml", clixml)`，BinaryFormatter 序列化后投递。
4. 反序列化时 PSObject 构造函数读取 CliXml → `PSSerializer.Deserialize` → `XamlReader.Parse` → `ObjectDataProvider` 执行命令。

## PoC

原文未给出可运行的 PSObject 生成侧 PoC（仅构造函数反编译截图与文字链路描述）；结构示意：

```csharp
[Serializable]
public class PSObjectMarshal : ISerializable
{
    private readonly string _cliXml;
    public PSObjectMarshal(string cliXml) { _cliXml = cliXml; }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        info.SetType(typeof(System.Management.Automation.PSObject));
        info.AddValue("CliXml", _cliXml); // 恶意 CLIXML/XAML
    }
}
// BinaryFormatter.Serialize(stream, new PSObjectMarshal(payload)) 后投递
```

## 变体与关联

- 关联：[[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]（同样以 XamlReader.Parse 为 sink，但由 TFRP 的 ForegroundBrush 触发）、[[web-dotnet-deser-xamlimageinfo-lazyfilestream-xamlreader-rce]]（Json.NET 入口的 XamlReader gadget）。
- 边界：目标没有 PowerShell 程序集时不可用；PSObject 常在 PowerShell Remoting/序列化场景中出现，也是该 gadget 的自然入口。

## 检测与防御

- 检测：序列化流中出现 `PSObject`、`CliXml`、`System.Management.Automation`、`PSSerializer`、`XamlReader` 等特征；反序列化进程随后加载 PowerShell 程序集并派生 `cmd.exe`/`powershell.exe`。
- 修复：禁用 `BinaryFormatter`；对反序列化类型做白名单（排除 PSObject）；不需要 PowerShell 的服务端进程限制 System.Management.Automation 加载。
- 加固：升级 .NET Framework 并使用最新反序列化防护配置；对 PowerShell CLIXML 输入只走受控的 `PSSerializer.Deserialize` 白名单路径。
