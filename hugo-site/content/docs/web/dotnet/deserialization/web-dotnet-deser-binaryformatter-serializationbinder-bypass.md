---
id: web-dotnet-deser-binaryformatter-serializationbinder-bypass
title: BinaryFormatter SerializationBinder 黑名单绕过：BindToType 返回 null 不阻断（FastBindToType 回退）+ 类型名改用 AssemblyQualifiedName 等可解析变体绕过字符串比对
type: scenario
domain: web
path: web/dotnet/deserialization
technique: binaryformatter-serializationbinder-null-fallback-typename-parsing-bypass
tags:
- dotnet
- binaryformatter
- deserialization
- serializationbinder
- blacklist-bypass
- type-name-parsing
- dataset-gadget
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:52:21+08:00'
  notes: 已对照12447原文与全部17图核对：图01 ISerializable 序列化键值、图02 流内程序集记录、图03 Surrogate 生命周期图、图04 binder 断点、图05 ObjectReader.Bind 的 m_binder.BindToType→null→FastBindToType 回退源码、图06 FormatterServices.GetTypeFromAssembly、图07/09/10 FastBindToType/TypeNAssembly 缓存、图08 黑名单抛异常对照、图11 calc 弹出、图12 原生POC typeName=System.Data.DataSet、图13/15/16 修改后 AQN typeName 导致 Equals 不命中并 return Type.GetType、图14 Type.GetType(AQN) 返回 DataSet、图17 dnSpy 空白/换行变体解析输出，均与卡片一致。原文未标注 .NET 受影响版本（仅演示环境），未设 affected_versions。dedup 与 Json.NET binder、Java resolveClass、U9/Remoting 入口类卡均非同链（本卡缺陷点为 ObjectReader.Bind 的 null 回退 + Type.GetType 解析等价类）。PoC 未复跑。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-binaryformatter-serializationbinder-bypass/
draft: false
kb_aliases:
- SerializationBinder 绕过
- BindToType 返回 null
- FastBindToType 回退
- ObjectReader.Bind
- Type.GetType 类型名怪癖
- DataSet gadget
- FullTypeName AssemblyQualifiedName
- ysoserial.net DataSetGenerator
---

## 一句话结论

用 `SerializationBinder` 给 `BinaryFormatter` 做类型黑名单时，`BindToType` 命中黑名单后返回 `null` 并不会阻止反序列化——`ObjectReader.Bind` 会回退到 `FastBindToType` 照常加载该类型；而只按 `typeName` 字符串精确比对的黑名单还可被 `AssemblyQualifiedName`（以及空白、前导点、引号、大小写等仍可解析的变体）绕过，最终让被禁的 DataSet gadget 正常反序列化并弹出计算器。

## 原理

- **null 不是拒绝**：`BinaryFormatter.Deserialize` 进入 `ObjectReader.Bind(assemblyString, typeString)`：先调用 `m_binder.BindToType(...)`，只有当返回的 `Type` 为 `null` 时才调用 `FastBindToType(assemblyString, typeString)` 继续解析。也就是说 binder 返回 `null` 的语义是“我不处理，走默认解析”，而不是“拒绝该类型”。黑名单想要真正拦截必须 `throw`（或返回无害类型并确保后续不执行），否则 `FastBindToType` 会用 `TypeCache`/`Assembly.Load` + `GetTypeFromAssembly` 把原始危险类型找回来。
- **字符串比对可被解析等价形式绕过**：如果 binder 用 `typeName.Equals("System.Data.DataSet")` 这类精确比对，攻击者只要让序列化流里的 `typeName` 变成另一个仍能被 `Type.GetType` 解析的写法即可。ysoserial.net 的 `DataSetGenerator` 原本用 `info.SetType(typeof(DataSet))`（流内 typeName 为 `System.Data.DataSet`），改成 `info.FullTypeName = typeof(DataSet).AssemblyQualifiedName` 后 typeName 变为 `System.Data.DataSet, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089`，黑名单 miss，而 `Type.GetType(AQN)` 仍返回 `System.Data.DataSet`。
- **Type.GetType 解析很宽容**：.NET 内部类型解析器对 AQN 允许大量变体——标记之间的空白（U+0009/U+000A/U+000D/U+0020）通常被忽略；类型名可以 `.` 开头（如 `.System.Data.DataSet`）；程序集名可用引号包裹且不区分大小写（`"system.data"`、`MsCoRlIb`）；属性值可加引号（即使不正确）；只给 `PublicKeyToken`/`PublicKey` 即可；属性顺序任意、允许附加任意属性（`Foo=bar`）；属性值支持 `\"`、`\n` 等转义。任何“字符串黑名单”都要面对这些解析等价类。
- **危害成立的条件**：应用确实在不可信输入上调用 `BinaryFormatter.Deserialize`（或 SoapFormatter/LosFormatter/NetDataContractSerializer/ObjectStateFormatter 等同等不限制多态反序列化的 formatter），且防护依赖自定义 binder 而非彻底禁用/白名单精确类型。此时攻击者用 ysoserial.net 生成 DataSet 等 gadget 流，修改 typeName 形式即可绕过。
- 本文用 Visual Studio 调试验证：binder 对 `typeName.Equals("System.Data.DataSet")` 的断点在 AQN 形式下不命中，`Type.GetType` 返回 DataSet，反序列化完成后弹出计算器，证明绕过链完整。

## 触发条件

- 目标 .NET 应用使用 `BinaryFormatter`（或同类 formatter）反序列化攻击者可控数据。
- 应用注册了自定义 `SerializationBinder` 做黑名单/白名单，且实现存在以下任一缺陷：命中后 `return null` 而非抛异常；用字符串精确比对 `typeName`；未同时校验 `assemblyName`；未规范化类型名。
- 攻击者能构造/修改序列化流（直接提交、反序列化入口、或从 ysoserial.net 生成后修改）。

## 利用步骤

1. 定位入口：识别 `BinaryFormatter.Deserialize` 及其输入来源，确认是否有自定义 `SerializationBinder`。
2. 审计 binder：命中黑名单时是 `throw` 还是 `return null`；比对的是 `typeName` 还是 `assemblyName`；是否用 `Type.GetType`/`Assembly.GetType` 解析。
3. 若返回 null：直接用 ysoserial.net 生成被“禁止”的 gadget（如 `DataSetGenerator`），`null` 会被 `FastBindToType` 回退解析，黑名单形同虚设。
4. 若字符串比对：修改 gadget 生成器，把 `info.SetType(typeof(<gadget>))` 换成 `info.FullTypeName = typeof(<gadget>).AssemblyQualifiedName`；或用等价的解析变体（前后空白/换行、前导 `.`、引号包裹程序集名、大小写变化、属性乱序/附加属性）。
5. 发送反序列化流，触发 gadget 执行命令（本文弹出 calc，实际可反弹 shell/写文件）。

## PoC

```csharp
// 典型的“看起来有防护”的 binder：命中黑名单返回 null（无效）
public override Type BindToType(string assemblyName, string typeName)
{
    if (typeName.Equals("System.Data.DataSet"))
    {
        return null;            // 错误：ObjectReader.Bind 会回退 FastBindToType
    }
    return Type.GetType(typeName);
}
```

```csharp
// 正确拦截应抛出异常（或白名单精确放行）
if (typeName.Equals("System.Data.DataSet")) throw new Exception("blocked");
```

```csharp
// 绕过：让流内 typeName 变成 AssemblyQualifiedName
Type type = typeof(System.Data.DataSet);
info.FullTypeName = type.AssemblyQualifiedName;   // 黑名单字符串比对 miss
// 其余 DataSet.RemotingFormat / Tables 等字段按 gadget 结构填充
```

```text
# Type.GetType 可解析的等价变体示例
System.Data.DataSet, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
\n\nSystem.Data.DataSet,\n\n System.Data,\n Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\n
.System.Data.DataSet,"System.Data", Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
System.Data.DataSet, "system.data", version=4.0.0.0, culture=neutral, publicKeyToken=b77a5c561934e089
```

## 变体与关联

- 变体：黑名单用 `assemblyName` 判断而忽略 `typeName`、或反之，都可被另一维度绕过；缓存 `TypeNAssembly` 以 `typeName` 为 key，注意同名不同类型/不同程序集的缓存混淆。
- 变体：使用 `SerializationBinder` 做白名单时，若白名单类型本身可被 `ObjectDataProvider`/反射调用危险方法，也会被用来实现 RCE（见 JSON.NET binder 卡思路）。
- 变体：`SoapFormatter`、`LosFormatter`、`NetDataContractSerializer`、`ObjectStateFormatter` 与 `BinaryFormatter` 一样执行不受限多态反序列化，binder 缺陷同理。
- 关联：[[web-dotnet-deser-json-net-serializationbinder-whitelist-bypass]]（Json.NET 的 binder 白名单逻辑绕过）、[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]（BinaryFormatter gadget 的类型检查开关绕过）、[[web-dotnet-deser-remoting-typefilterlevel-full]]（TypeFilterLevel 放开后的反序列化面）、[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（ViewState 场景的 BinaryFormatter gadget）。
- 边界：binder 对未知类型抛异常、按精确白名单（类型+程序集）放行、禁用 BinaryFormatter、输入不可控或已被签名保护时，链路不成立。

## 检测与防御

- 检测：应用中 `BinaryFormatter.Deserialize` 的调用与自定义 binder 实现审计；序列化流中出现 `System.Data.DataSet`/`TypeConfuseDelegate`/`ObjectDataProvider` 等 gadget 类型名及其 AQN/空白变体；w3wp/IIS 进程异常创建子进程（calc/powershell/cmd）。
- 防御：彻底禁用 `BinaryFormatter` 及同类 formatter（.NET 5+ 已默认禁用）；必须使用时用精确类型+程序集的 allowlist，未知类型直接 `throw`，不要依赖字符串黑名单；反序列化前做签名/HMAC；升级 .NET 并使用安全的序列化格式（JSON/Protobuf 且关闭多态类型解析）；对反序列化入口做网络隔离与最小权限。
