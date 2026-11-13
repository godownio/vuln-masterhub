---
id: web-dotnet-deser-remoting-typefilterlevel-full
title: .NET Remoting 未授权反序列化：BinaryServerFormatterSinkProvider 配 TypeFilterLevel.Full 直接接收 BinaryFormatter 载荷
type: scenario
domain: web
path: web/dotnet/deserialization
technique: dotnet-remoting-typefilterlevel-full-deserialization
tags:
- dotnet
- deserialization
- remoting
- binaryformatter
- typefilterlevel
- unauth
- rce
- ecostruxure
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V587
  verified_at: '2026-11-12T14:09:04+08:00'
  notes: 已对照原文及全部3张截图核对：图01 GetFilteredSinkProvider 对 TCP 用 BinaryServerFormatterSinkProvider、HTTP 用 SoapServerFormatterSinkProvider，且两分支均 TypeFilterLevel.Full；图02 ConfigureRemoting 中 RemotingServices.Marshal(s_Factory, serverObjectUri, typeof(ProviderFactory)) 与卡片一致，原文正文明确 ObjectUri=IONServicesProviderFactory.soap、注册代码 ChannelServices.RegisterChannel(channel,false)、默认端口57777；图03 复现命令 ExploitRemotingService.exe tcp://192.168.4.151:57777/IONServicesProviderFactory.soap raw AAEAAAD...，异常栈显示 BinaryServerFormatterSink.ProcessMessage -> ObjectReader/TextFormattingRunProperties 反序列化路径（InvalidCastException 将 ObjectDataProvider 转 System.Windows.Media.Brush），但无命令执行回显，卡片 confidence=medium、PoC 说明与利用步骤均已如实标注。ZDI-23-1795 仅作为 alias，原文未给出 CVE，cve 保持空；原文未给出受影响版本区间，affected_versions 保持空。dedup top 为卡自身，其余候选为 ERP OpenServerDialog/U9/金蝶等其它 BinaryFormatter 入口或 ViewState/TypeNameHandling 场景，非同一链；库内无其他 .NET Remoting 卡，保留。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-remoting-typefilterlevel-full/
draft: false
kb_aliases:
- .NET Remoting 反序列化
- TypeFilterLevel.Full
- BinaryServerFormatterSinkProvider
- SoapServerFormatterSinkProvider
- ExploitRemotingService
- ZDI-23-1795
---

## 一句话结论

.NET Remoting 服务端通道若使用 `BinaryServerFormatterSinkProvider`（或 SOAP 版）且把 `TypeFilterLevel` 配成 `Full`，任何能访问该端口的客户端都能在 Remoting 消息里塞入任意 BinaryFormatter 序列化对象，服务端反序列化时不限制类型，从而用 ysoserial.net 的 gadget 实现未授权 RCE；Schneider Electric EcoStruxure PME 的 `GetFilteredSinkProvider` 正是该配置，通道默认监听 TCP 57777 并 Marshal `ProviderFactory` 到 `IONServicesProviderFactory.soap`。

## 原理

- **Remoting 通道与 SinkProvider**：.NET Remoting 的服务端通道由 `IChannel` + 一系列 Sink 组成，格式化 Sink 负责把消息体序列化/反序列化。`BinaryServerFormatterSinkProvider` 使用 `BinaryFormatter` 处理请求流。
- **TypeFilterLevel 的作用**：`BinaryFormatter` 默认在反序列化时限制可实例化的类型（`Low`/`Full`）。`Full` 允许还原任意可序列化类型及其 `ISerializable` 构造、`ObjectDataProvider`、`TextFormattingRunProperties` 等 gadget，等价于把反序列化入口完全交给攻击者；`Low` 只允许基础类型。
- **配置缺陷**：`RemotingCommon.GetFilteredSinkProvider(bool isTcp)` 对 TCP 返回 `new BinaryServerFormatterSinkProvider { TypeFilterLevel = TypeFilterLevel.Full }`，对 HTTP 返回同样 Full 的 `SoapServerFormatterSinkProvider`；`CreateChannel` 用该 provider 创建 `TcpChannel`/`HttpChannel`，随后 `ChannelServices.RegisterChannel(channel, false)`（不启用安全）。
- **对象暴露**：`ObjectRegistration.ConfigureRemoting()` 调用 `RemotingServices.Marshal(s_Factory, serverObjectUri, typeof(ProviderFactory))`，把 `PowerMeasurement.IONServices.ProviderFactory` 发布到 `IONServicesProviderFactory.soap`；端口从配置读取，默认 57777。
- **为什么能 RCE**：Remoting 协议在建立连接和调用对象时会反序列化消息内容；Full 级别下攻击者可发送 `AAEAAAD...` 的 BinaryFormatter 流，服务端 `ObjectReader.Deserialize` 触发 gadget 链（如 `TextFormattingRunProperties` → `ObjectDataProvider`）执行任意代码，进程权限通常为服务账户（ZDI 通告描述为 LOCAL SERVICE）。
- **可达性**：该服务用于 PME 内部组件间通信，默认无认证、无类型过滤，攻击者只需网络可达 57777 且知道 ObjectUri 即可；不需要任何凭据。

## 触发条件

- 目标运行受影响版本的 Schneider Electric EcoStruxure Power Monitoring Expert（PME）或其他采用相同 Remoting 配置的 .NET 应用；原文未给出具体版本区间。
- Remoting 端口可达（默认 TCP 57777，HTTP 通道时另计）。
- 服务端通道使用 `BinaryServerFormatterSinkProvider`/`SoapServerFormatterSinkProvider` 且 `TypeFilterLevel=Full`。
- 目标 .NET 运行时 classpath 上存在可用 gadget（ysoserial.net 常用链通常可用）。
- 客户端需能生成对应格式的 Remoting 请求（ExploitRemotingService 的 `raw` 模式）。

## 利用步骤

1. 端口扫描确认 57777/tcp 或配置的 Remoting 端口开放，结合产品指纹判断 PME。
2. 用 `ExploitRemotingService` 的 `raw` 模式，向 `<protocol>://<host>:<port>/IONServicesProviderFactory.soap` 发送 ysoserial.net 生成的 BinaryFormatter 载荷。
3. 服务端在 Remoting 消息处理阶段用 `BinaryServerFormatterSink.ProcessMessage` 反序列化消息体，触发 gadget。
4. 选择与目标 .NET 版本匹配的 gadget（`TextFormattingRunProperties`、`ObjectDataProvider`、`ActivitySurrogateSelector` 等）执行命令。
5. 验证：使用 DNS/HTTP 回连或写入临时文件确认执行；原文复现截图仅显示反序列化异常（TextFormattingRunProperties 转换失败）与“找不到请求的服务”，未见命令回显，实际利用需按目标版本调整 gadget 与 ObjectUri。
6. 清理上传/落地的临时文件与日志痕迹。

## PoC

```text
# 原文复现命令（形态）
ExploitRemotingService.exe tcp://<target>:57777/IONServicesProviderFactory.soap raw AAEAAAD/////<ysoserial.net 生成的 BinaryFormatter 载荷>

# 服务端典型异常（说明进入了 BinaryFormatter 反序列化）
System.Runtime.Remoting.Channels.BinaryServerFormatterSink.ProcessMessage(...)
System.Runtime.Serialization.ObjectManager.CompleteISerializableObject(...)
Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties..ctor(...)
```

```text
# 通用利用形态
ysoserial.net -g TextFormattingRunProperties -f BinaryFormatter -c "<command>" -o base64
ExploitRemotingService.exe tcp://<host>:<port>/<ObjectUri> raw <base64>
```

说明：原文未给出可直接复用的 ObjectUri 之外的完整请求，也未展示命令执行回显；上述 PoC 依据原文命令与 ZDI 通告描述整理，置信度 medium。

## 变体与关联

- 变体：HTTP 通道使用 `SoapServerFormatterSinkProvider` 同样配置 Full；报文封装不同但反序列化风险一致。
- 变体：ObjectUri 可能随产品版本/配置变化，可从客户端配置文件、`RemotingConfiguration` 代码或网络流量中确认；`ExploitRemotingService` 也支持 `-s` 指定服务地址、`-u` 指定 URI。
- 关联：[[web-dotnet-deser-viewstate-machinekey-textformattingrunproperties]]（TextFormattingRunProperties gadget 的另一触发点）、[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]（.NET 类型检查绕过）、[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]（BinaryFormatter 入口对照）。
- 边界：`TypeFilterLevel=Low`、启用 remoting 认证/加密、端口不可达、目标缺少可用 gadget 或运行时版本不匹配时利用失败。

## 检测与防御

- 检测：访问 57777/tcp 等 Remoting 端口的非业务客户端；请求体出现 `AAEAAAD`/`/w` 开头的 BinaryFormatter 流；进程日志中出现 `BinaryServerFormatterSink.ProcessMessage`、`ObjectReader.Deserialize`、`TextFormattingRunProperties` 等反序列化栈。
- 防御：升级到厂商修复版本，或禁用不必要的 .NET Remoting；必须使用时将 `TypeFilterLevel` 降到 `Low` 并启用通道认证/加密。
- 加固：用防火墙限制 Remoting 端口仅对可信组件开放；服务账户最小权限；对 PME 服务器做网络分段，禁止从办公网直连 57777。
- 监控：对 Remoting 端口建立基线，告警异常客户端与反序列化异常激增。
