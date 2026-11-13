---
id: web-dotnet-deser-json-net-gettersecurityexception-propertygrid
title: JSON.NET GetterSecurityException gadget：SecurityException.Method getter 触发 BinaryFormatter 反序列化，PropertyGrid.SelectedObjects 递归读取属性完成 RCE
type: scenario
domain: web
path: web/dotnet/deserialization
technique: json-net-gettersecurityexception-propertygrid-gadget
aliases:
- GetterSecurityException
- GetterSecurityExceptionGenerator
- SecurityException.Method
- PropertyGrid SelectedObjects
- System.Windows.Forms.PropertyGrid gadget
- JSON.NET PropertyGrid gadget
- ByteArrayToObject
tags:
- dotnet
- deserialization
- json.net
- newtonsoft
- ysoserial.net
- gadget-chain
- binaryformatter
- propertygrid
- securityexception
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V666
  verified_at: '2026-11-13T08:53:02+08:00'
  notes: 已对照原文8图核对：SecurityException.Method getter→getMethod→ByteArrayToObject→BinaryFormatter.Deserialize、setter→ObjectToByteArray→BinaryFormatter.Serialize、PropertyGrid CreateChildren→GetPropEntries→PropertyDescriptor2.GetValue 逐图一致；payload 文本可视化截图与卡内外层 JSON 字段（PropertyGrid Version=4.0.0.0/PublicKeyToken=b77a5c561934e089、SelectedObjects、SecurityException 的 ClassName/Message/ExceptionMethod/HResult/Action/Zone/Method 等）一致，Method 为 AAEAAAD 开头的 BinaryFormatter Base64；ysoserial.net GetterSecurityExceptionGenerator 经 JsonNet_deserialize 弹计算器有截图。复核修正：BinaryFormatter Base64 前缀 AAEAAG→AAEAAAD。dedup 10 候选全 new、dup-scan 无 pair，无需删卡；affected_versions 原文未标注受影响区间（仅程序集版本），保持为空。
---

# 一句话结论

当 .NET 应用用 Json.NET（Newtonsoft.Json）反序列化攻击者可控 JSON 且 `TypeNameHandling` 非 None 时，`$type` 可实例化 `System.Windows.Forms.PropertyGrid` 并把 `SelectedObjects` 指向一个 `System.Security.SecurityException`；PropertyGrid 的 setter 在 `Refresh → CreateChildren → GridEntry.GetPropEntries` 中遍历该对象所有属性并调用 getter，从而读取 `SecurityException.Method`——其 getter 会把 `m_serializedMethodInfo` 交给 `ByteArrayToObject → BinaryFormatter.Deserialize`，攻击者预先塞入的 BinaryFormatter gadget 随即执行，形成 `JSON.NET → PropertyGrid setter → getter → BinaryFormatter` 的完整 RCE 链（ysoserial.net 的 GetterSecurityException 生成器实现）。

# 原理

- **链路 1：SecurityException.Method 是“getter 里的 BinaryFormatter 入口”**。mscorlib 的 `System.Security.SecurityException` 有一个 `public MethodInfo Method` 属性（`[ComVisible(false)]`）：getter `getMethod()` 直接 `return (MethodInfo)SecurityException.ByteArrayToObject(this.m_serializedMethodInfo)`；对应的 setter 用 `SecurityException.ObjectToByteArray(value as RuntimeMethodInfo)` 赋值。两个内部方法都基于 BinaryFormatter：`ObjectToByteArray` 用 `BinaryFormatter.Serialize(memoryStream, obj)` 后 `ToArray()`；`ByteArrayToObject` 用 `new BinaryFormatter().Deserialize(new MemoryStream(array))`。也就是说，只要让 `m_serializedMethodInfo` 里是一段恶意 BinaryFormatter 序列化数据，读取 `Method` 属性就等于执行 `BinaryFormatter.Deserialize`——这就是链路 1 的可复用“getter 触发反序列化”原语。
- **为什么 JSON.NET 能塞进这段字节**：`SecurityException` 是 `[Serializable]` 且实现 `ISerializable`，Newtonsoft.Json 对这类类型按其 `SerializationInfo` 条目反序列化（而非普通属性 setter）。文章 payload 中的 `ClassName`、`Message`、`ExceptionMethod`、`HResult`、`Source`、`Action`、`Method`、`Zone` 等字段正是 Exception/SecurityException 的序列化条目名；`Method` 条目被赋予 Base64 编码的 BinaryFormatter 载荷字节串（截图中以 `AAEAAAD...` 开头，即 BinaryFormatter 流头），最终落到 `m_serializedMethodInfo`。
- **链路 2：PropertyGrid 把“设置属性”变成“读取所有属性”**。`System.Windows.Forms.PropertyGrid.SelectedObjects` 的 setter 逻辑复杂，核心是调用 `Refresh()` → `RefreshProperties`/`UpdateSelection`/`CreateChildren`；`GridEntry.CreateChildren` 调用 `this.GetPropEntries(this, this.PropertyValue, this.PropertyType)`，后者遍历对象的 PropertyDescriptor 集合并逐个执行 `propertyDescriptor2.GetValue(component)`——`GetValue` 即调用对应属性的 getter。于是把 `SelectedObjects` 设为含 `SecurityException` 的数组，就会自动触发 `SecurityException.Method` 的 getter，无需受害者再访问任何属性。
- **两条链路拼接即完整攻击链**：外层 JSON.NET 选择 `$type = System.Windows.Forms.PropertyGrid`（GAC 程序集 `System.Windows.Forms, Version=4.0.0.0, PublicKeyToken=b77a5c561934e089`），其 `SelectedObjects` 数组里放 `$type = System.Security.SecurityException` 的对象、`Method` 填 BinaryFormatter gadget 的 Base64；反序列化外层 JSON 时 PropertyGrid 的 setter 立即遍历属性 → 触发 Method getter → BinaryFormatter 反序列化内层载荷 → 代码执行（文章 PoC 弹出计算器）。
- **该 gadget 的价值**：它由两个“看起来无害”的 BCL 类型组合而成（mscorlib 的 SecurityException + WinForms 的 PropertyGrid），不在常见 Json.NET 危险类型黑名单里，可作为 `ObjectDataProvider`/`TypeConfuseDelegate` 等经典 gadget 被封堵时的替代链；内层 BinaryFormatter 载荷可换任意 BinaryFormatter gadget（如 TypeConfuseDelegate、TextFormattingRunProperties），最终权限取决于进程身份。

# 触发条件

- 应用用 Newtonsoft.Json（Json.NET）反序列化不可信 JSON，且 `TypeNameHandling` 为 `All`/`Objects`/`Auto` 等允许 `$type` 的配置（或使用了等效的允许类型实例化的自定义 binder）。
- 目标为 .NET Framework（全量框架，GAC 中有 `System.Windows.Forms`；纯 .NET Core/5+ 默认不带 WinForms 的场景不适用），进程可加载 WinForms 程序集。
- 目标进程允许在 gadget 内部调用 `BinaryFormatter.Deserialize`（.NET Framework 默认允许；.NET 5+ 默认禁用 BinaryFormatter 需显式开关）。
- 攻击者能提供内层 BinaryFormatter 序列化载荷（ysoserial.net `-g TypeConfuseDelegate -f BinaryFormatter` 等生成后 Base64）。

# 利用步骤

1. 生成内层 BinaryFormatter 载荷并 Base64 编码（例：ysoserial.net 用 TypeConfuseDelegate/TextFormattingRunProperties gadget 执行命令）。
2. 按文章结构构造外层 JSON：`$type` 为 `System.Windows.Forms.PropertyGrid`，`SelectedObjects` 数组内放 `$type` 为 `System.Security.SecurityException` 的对象，序列化条目含 `ClassName`、`Message`、`ExceptionMethod`、`HResult`、`Action`、`Zone` 以及 `Method = <base64>`。
3. 将 JSON 发送到使用 Json.NET 反序列化的入口；反序列化过程中 PropertyGrid 的 setter 遍历属性，`Method` getter 触发内层 BinaryFormatter 反序列化，命令执行。
4. ysoserial.net 中对应生成器为 `GetterSecurityExceptionGenerator`（文章用其 `JsonNet_deserialize` 验证，弹计算器）。

# PoC

```text
payload = {
  "$type": "System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
  "SelectedObjects": [
    {
      "$type": "System.Security.SecurityException",
      "ClassName": "System.Security.SecurityException",
      "Message": "Security error.",
      "InnerException": null,
      "HelpURL": null,
      "StackTraceString": null,
      "RemoteStackTraceString": null,
      "RemoteStackIndex": 0,
      "ExceptionMethod": null,
      "HResult": -2146233078,
      "Source": null,
      "Action": 0,
      "Method": "<Base64(BinaryFormatter gadget)>",
      "Zone": 0
    }
  ]
}
```

（`Method` 内容为 ysoserial.net BinaryFormatter gadget 的 Base64；文章环境通过 `JsonNet_deserialize(payload)` 验证成功启动计算器。）

# 变体与关联

- 链路 1 可单独复用：任何“读取某对象属性”的 getter 触发点（数据绑定、属性网格、序列化/日志打印、`ToString` 遍历等）只要能让目标读到 `SecurityException.Method`，即可触发其中的 BinaryFormatter 反序列化；PropertyGrid 只是文章给出的现成触发链。
- 与库内 `web-dotnet-deser-json-net-serializationbinder-whitelist-bypass`（Json.NET binder 白名单绕过）、`web-dotnet-deser-servicehandler-typenamehandling`（TypeNameHandling.All 入口）互补：本卡解决“入口允许 $type 后用什么 gadget”的问题，可作为 ObjectDataProvider/TypeConfuseDelegate 之外的新链。
- 内层 BinaryFormatter 载荷可替换为任意 BinaryFormatter gadget；外层 `$type` 也可换成其它“setter 触发属性遍历”的 WinForms 类型（同类思路）。
- 文章为 2023 年 Hexacon 会议 .NET 反序列化 gadget 研究的一部分，ysoserial.net 已内置对应生成器，便于直接复现/改造。

# 检测与防御

- 根本修复：Json.NET 反序列化不可信输入时把 `TypeNameHandling` 设为 `None`（默认值），不要反序列化用户可控的 `$type`；必须保留多态时使用严格的 `ISerializationBinder` 白名单（仅允许业务 DTO）。
- 升级/禁用 BinaryFormatter：.NET 5+ 默认禁用；.NET Framework 可通过配置与代码避免 `BinaryFormatter.Deserialize`；本链依赖目标进程内 BinaryFormatter 可用。
- 检测特征：请求体中出现 `$type` 且值为 `System.Windows.Forms.PropertyGrid`/`System.Security.SecurityException`；同一 JSON 中同时出现 `SelectedObjects`、`ExceptionMethod`、`Action`、`Zone`、`Method` 等序列化条目名；`Method` 值为以 `AAEA` 开头的长 Base64（BinaryFormatter 流头）。WAF/JSON 解析网关可按这些键值与类型名告警。
- 主机侧：ysoserial.net 生成的载荷在进程内加载 WinForms/BinaryFormatter 相关程序集，可由 .NET 反序列化防护产品（如 YSoSerial 检测规则）与异常调用栈（`SecurityException.getMethod → ByteArrayToObject → BinaryFormatter.Deserialize`）识别。
