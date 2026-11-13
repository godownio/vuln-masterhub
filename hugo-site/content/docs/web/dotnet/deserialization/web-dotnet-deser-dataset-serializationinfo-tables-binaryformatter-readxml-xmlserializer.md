---
id: web-dotnet-deser-dataset-serializationinfo-tables-binaryformatter-readxml-xmlserializer
title: DataSet 反序列化二段载体：Tables_0 字段经 DeserializeDataSetSchema 再走 BinaryFormatter，XmlDiffGram 经 ReadXml 再走 XmlSerializer（含 TypeSpoof 变体）
type: scenario
domain: web
path: web/dotnet/deserialization
technique: dataset-iserializable-tables-binaryformatter-xmldiffgram-xmlserializer
tags:
- dotnet
- binaryformatter
- deserialization
- dataset
- system-data
- gadget
- xmldiffgram
- xmlserializer
- second-order
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:26+08:00'
  notes: 已对照 img04-09 核对 DataSet 反序列化构造函数、DeserializeDataSetSchema 的 Tables_0 BinaryFormatter 路径、DeserializeDataSetData 的 XmlDiffGram/ReadXml 路径、DataSetTypeSpoof 字段与 PoC；XmlSerializer 段为文章文字结论（img09 仅展示 ReadXml）；未复现。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-dataset-serializationinfo-tables-binaryformatter-readxml-xmlserializer/
draft: false
kb_aliases:
- DataSet gadget
- DataSet.Tables_0
- DeserializeDataSetSchema
- DataSetOldBehaviour
- DataSetTypeSpoof
- XmlDiffGram ReadXml
- DataSet 二次反序列化
- ysoserial DataSet
---

## 一句话结论

`System.Data.DataSet` 的 `ISerializable` 反序列化构造函数会把 SerializationInfo 中的字段当作"内部序列化状态"再次反序列化：`RemotingFormat=Binary` 时 `DataSet.Tables_0` 的 byte[] 会被 `DeserializeDataSetSchema` 直接交回 `BinaryFormatter.Deserialize`，`RemotingFormat=Xml` 时 `XmlDiffGram` 字符串会经 `ReadXml` 走到 `XmlSerializer.Deserialize`——把内层 TextFormattingRunProperties 等 gadget 字节/XML 塞进这些字段即可 RCE；`DataSetTypeSpoof` 是同一链的序列化元数据变形。

## 原理

- **入口构造函数**：`DataSet(SerializationInfo info, StreamingContext context, bool ConstructSchema)` 遍历 SerializationInfo，读取 `DataSet.RemotingFormat`（`SerializationFormat.Binary/Xml`）与 `SchemaSerializationMode.DataSet`；当 `remotingFormat == Xml && !ConstructSchema` 时提前返回，否则调用 `this.DeserializeDataSet(info, context, remotingFormat, schemaSerializationMode)`（文章 img04）。
- **两条内层反序列化路径**（`DeserializeDataSet` 依次调用 `DeserializeDataSetSchema` 与 `DeserializeDataSetData`）：
  - **Schema 路径（BinaryFormatter）**：`DeserializeDataSetSchema` 在 `remotingFormat != Xml` 且 `SchemaSerializationMode=IncludeSchema`（构造函数默认值，payload 不显式填该键也成立）时按 `info.GetInt32("DataSet.Tables.Count")` 循环，对每个 `DataSet.Tables_<i>` 取 byte[] 包进 `MemoryStream`，再 `new BinaryFormatter(null, new StreamingContext(context.State, false)).Deserialize(stream)` 还原 `DataTable`（文章 img05/06）。攻击者把 Tables_0 设成内层 gadget（如 TextFormattingRunProperties）的 BinaryFormatter 字节，反序列化到这里即触发。
  - **Data 路径（XmlSerializer）**：`DeserializeDataSetData` 在 `remotingFormat == Xml` 时取 `info.GetValue("XmlDiffGram", typeof(string))`，用 `XmlTextReader` 交给 `DataSet.ReadXml(..., XmlReadMode.DiffGram)`；DataSet 解析 DiffGram 内嵌的类型/schema 信息时会调用 `XmlSerializer.Deserialize`（文章 img09）。把 DiffGram 内容指向 ExpandedWrapper<XamlReader,ObjectDataProvider> 等 XmlSerializer gadget 即可 RCE（即 DataSetOldBehaviour 链）。
- **填充必要字段**：除 payload 字段外，还需按截图填写 `DataSet.RemotingFormat=Binary`、`DataSet.DataSetName`、`DataSet.Namespace`、`DataSet.Prefix`、`DataSet.CaseSensitive`、`DataSet.LocaleLCID=0x409`、`DataSet.EnforceConstraints`、`DataSet.ExtendedProperties`、`DataSet.Tables.Count=1` 等，使反序列化流程顺利走到 payload 分支。
- **DataSetTypeSpoof 变形**：不用 `info.SetType(typeof(System.Data.DataSet))`，而是在 SerializationInfo 上直接写 `AssemblyName = "mscorlib"` 与 `FullTypeName = typeof(System.Data.DataSet).AssemblyQualifiedName`（文章 img07/08）；调用的类与链完全一致，属针对类型记录/绑定检查的元数据变形。
- **DataSetOldBehaviourFromFileGenerator**：同一 DataSetOldBehaviour（XmlDiffGram/XmlSerializer）链的变体，DiffGram XML 改由本地文件提供。
- **为什么成立**：DataSet 为兼容 Remoting 场景实现了自定义序列化，并把 SerializationInfo 里的字节/XML 视为"自己写出的可信内部状态"再次反序列化；攻击者能控制 SerializationInfo 时，外层 DataSet 就成了把恶意内层 gadget 送进 BinaryFormatter/XmlSerializer 的合法"拖运容器"。

## 触发条件

- 存在可控制序列化流的 BinaryFormatter 入口（Tables_0/Schema 路径），或能触达 DataSet 反序列化构造函数的其它入口。
- `System.Data`（.NET Framework 自带 GAC 程序集）可用。
- 内层 gadget 的依赖满足（BinaryFormatter 路径常配 TextFormattingRunProperties/TypeConfuseDelegate；XmlSerializer 路径配 ExpandedWrapper/XamlReader）。
- 反序列化端未禁用 DataSet 或未做类型白名单。

## 利用步骤

1. 生成内层 payload：如 TFRP（`cmd /c calc`）的 BinaryFormatter 字节；或 XmlSerializer 用的 ExpandedWrapper XML。
2. 实现 `ISerializable` 包装类（或直接构造 SerializationInfo）：`info.SetType(typeof(System.Data.DataSet))`，按 img04 填写全部 DataSet 字段，令 `DataSet.Tables.Count=1`、`DataSet.Tables_0=<内层字节>`（Xml 路径则填 `XmlDiffGram`）。
3. `BinaryFormatter.Serialize` 得到外层流并投递。
4. 反序列化构造函数 → `DeserializeDataSet` → `DeserializeDataSetSchema` → 对 Tables_0 执行 `BinaryFormatter.Deserialize` → 内层 TFRP → `XamlReader.Parse` → 命令执行。

## PoC

```csharp
public class DataSetMarshal : ISerializable
{
    private readonly byte[] _fakeTable; // 内层 BinaryFormatter payload（如 TFRP 字节）
    public DataSetMarshal(byte[] inner) { _fakeTable = inner; }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        info.SetType(typeof(System.Data.DataSet));
        info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
        info.AddValue("DataSet.DataSetName", "");
        info.AddValue("DataSet.Namespace", "");
        info.AddValue("DataSet.Prefix", "");
        info.AddValue("DataSet.CaseSensitive", false);
        info.AddValue("DataSet.LocaleLCID", 0x409);
        info.AddValue("DataSet.EnforceConstraints", false);
        info.AddValue("DataSet.ExtendedProperties", (System.Data.PropertyCollection)null);
        info.AddValue("DataSet.Tables.Count", 1);
        info.AddValue("DataSet.Tables_0", _fakeTable);
    }
}
```

## 变体与关联

- 变体：`DataSetTypeSpoof` —— 用 `AssemblyName`/`FullTypeName` 代替 `SetType`，链不变，用于针对 SerializationInfo 类型记录的过滤/检测。
- 变体：`DataSetOldBehaviour` / `DataSetOldBehaviourFromFileGenerator` —— 走 `XmlDiffGram` → `ReadXml` → `XmlSerializer.Deserialize` 路径，接 XmlSerializer 系 gadget；后者 XML 由本地文件提供。
- 关联：[[web-dotnet-deser-toolboxitemcontainer-stream-field-binaryformatter]]（同类二段 BinaryFormatter 载体）、[[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]（常用的内层载荷）、[[web-dotnet-deser-sharepoint-toolshell-cve-2025-53770]]（SharePoint ExcelDataSet.CompressedDataTable 入口，同属 DataSet 家族的无 Binder BinaryFormatter 利用）。
- 边界：.NET Core/.NET 5+ 默认不支持 BinaryFormatter；目标禁用 DataSet 远程格式或替换为安全序列化时该链失效。

## 检测与防御

- 检测：序列化流中出现 `System.Data.DataSet`、`DataSet.Tables_0`、`DataSet.RemotingFormat`、`XmlDiffGram`、`SchemaSerializationMode` 等字段名；`BinaryFormatter.Deserialize` 调用栈以 `DataSet.DeserializeDataSetSchema` 为外层；Xml 路径出现 `DataSet.ReadXml → XmlSerializer.Deserialize`。
- 修复：禁用 `BinaryFormatter`；不要反序列化不可信的 DataSet（尤其是 Remoting 格式）；对反序列化入口使用 `SerializationBinder` 白名单并禁止 DataSet。
- 加固：升级 .NET Framework；服务端不处理来自客户端的原始 DataSet 序列化数据；WAF/EDR 检测上述字段名与调用栈特征。
