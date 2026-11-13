---
id: web-dotnet-deser-activemq-nms-objectmessage-body-binaryformatter
title: ActiveMQ NMS .NET 客户端 ActiveMQObjectMessage.Body 无类型校验反序列化：消费恶意 ObjectMessage 即触发 BinaryFormatter RCE
type: scenario
domain: web
path: web/dotnet/deserialization
technique: activemq-nms-objectmessage-body-binaryformatter-deserialization
aliases:
- ZDI-23-1281
- Apache ActiveMQ NMS RCE
- ActiveMQObjectMessage Body 反序列化
- NMS ObjectMessage 反序列化
- Apache.NMS.ActiveMQ BinaryFormatter
- Apache.NMS.AMQP 反序列化
- activemq-nms-openwire 漏洞
tags:
- dotnet
- binaryformatter
- deserialization
- activemq
- nms
- message-queue
- objectmessage
- client-side
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: activemq-nms-openwire < 2.1.0-rc1；Apache.NMS.ActiveMQ.dll < 2.1.0；Apache.NMS.AMQP.dll < 2.1.0（原文标记）
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T14:00:58+08:00'
  notes: 已对照原文与5图核对：图02 BeforeMarshall中 this.Formatter.Serialize(stream,this.body) 且 Formatter 为 BinaryFormatter；图03 Body getter 的 MemoryStream+可选解压+Deserialize 与卡内源码一致；图04 消费者 message.Body 触发并弹出计算器（TFRP gadget）；图05 TrustedClassFilter.BindToType + INmsDeserializationPolicy.IsTrustedType 白名单与补丁描述一致。affected_versions 按原文逐字设置三条（activemq-nms-openwire < 2.1.0-rc1；Apache.NMS.ActiveMQ.dll < 2.1.0；Apache.NMS.AMQP.dll < 2.1.0）。漏洞号 ZDI-23-1281，原文未提CVE，cve留空属实。dedup候选camel-jms-objectmessage(Java getObject)与ActiveMQ OpenWire createThrowable(Java broker)均非同链，.NET库内无NMS重复卡。PoC未本机复跑
---

## 一句话结论

Apache ActiveMQ 的 .NET 客户端库 NMS 在处理 `ActiveMQObjectMessage` 时，`Body` getter 直接对消息 `Content` 调用 `BinaryFormatter.Deserialize`，既不限制类型也不做校验；攻击者只要能让受害者客户端消费一条携带恶意序列化对象的 ObjectMessage（自己用 NMS 客户端发送，或向 broker 注入消息），受害者读取 `message.Body` 就会触发 .NET 反序列化 RCE（原文用 `TextFormattingRunProperties` gadget 弹出计算器）。受影响：`Apache.NMS.ActiveMQ.dll`（OpenWire）< 2.1.0、`Apache.NMS.AMQP.dll`（AMQP）< 2.1.0、`activemq-nms-openwire` < 2.1.0-rc1。

## 原理

- **NMS 消息类型与 ObjectMessage**：NMS 的消息体系包括 `ActiveMQBlobMessage`、`ActiveMQBytesMessage`、`ActiveMQMapMessage`、`ActiveMQObjectMessage`、`ActiveMQStreamMessage`、`ActiveMQTextMessage` 等，其中 `ActiveMQObjectMessage : ActiveMQMessage, IObjectMessage, IMessage` 专门承载 .NET 对象 body，内部使用 `BinaryFormatter` 序列化/反序列化，且没有任何类型限制。
- **发送侧（序列化）**：调用 `producer.Send(IObjectMessage)` 后，`ActiveMQMessageMarshaller.LooseMarshal` 先调用 `activeMqMessage.BeforeMarshall(wireFormat)`；`ActiveMQObjectMessage.BeforeMarshall()` 中若 `this.body != null`，就创建 `MemoryStream`，用 `this.Formatter.Serialize(stream, this.body)`（默认 `BinaryFormatter`）把 body 序列化进 `this.Content`，随后随 OpenWire 消息发送。也就是说攻击者无需手工构造二进制流，直接用 NMS 客户端把恶意对象作为 body 发送即可完成“序列化 gadget”。
- **消费侧（反序列化，漏洞点）**：客户端拿到消息后类型转换为 `IObjectMessage`，一旦访问 `message.Body` getter：`body == null` 时创建 `MemoryStream(this.Content)`（若连接启用压缩则先解压），然后执行 `this.body = this.Formatter.Deserialize(stream)`。`Content` 完全来自远端消息，`Formatter` 默认是 `BinaryFormatter`，没有 `SerializationBinder`/白名单/类型校验，因此消息里的任意 `ISerializable`/gadget 类型都会被实例化并执行其反序列化逻辑。
- **触发面**：漏洞位于 NMS **客户端库**，不是 broker。凡使用受影响版本 NMS 客户端（OpenWire 的 `Apache.NMS.ActiveMQ.dll` 或 AMQP 的 `Apache.NMS.AMQP.dll`）并调用 `consumer.Receive()` 后访问 `IObjectMessage.Body`（或任何会触发该 getter 的封装）的应用，都会在消费不可信消息时执行反序列化。ZDI 公告也指出需要与库交互，具体攻击向量依实现而定。
- **gadget**：原文使用 `TextFormattingRunProperties`（`Microsoft.PowerShell.Editor.dll`）作为外层 gadget，其反序列化路径最终经 `XamlReader.Parse`/`ObjectDataProvider` 执行 `Process.Start`；任何 BinaryFormatter gadget（DataSet、TypeConfuseDelegate、ActivitySurrogateSelector 等）同样可用——只要目标进程能加载对应程序集。
- **补丁原理**：2.1.0 引入 `TrustedClassFilter : SerializationBinder`，在 `BindToType(assemblyName, typeName)` 中先把类型加载出来，再用 `INmsDeserializationPolicy.IsTrustedType(destination, type)` 判断；不在白名单时抛出 `SerializationException("Forbidden {type.FullName}! ...")`，从而把“反序列化任意类型”收紧为“只允许策略显式信任的类型”。补丁同时支持按 destination 配置自定义白名单。

## 触发条件

- 受害者使用受影响版本的 NMS .NET 客户端：`Apache.NMS.ActiveMQ.dll` < 2.1.0（OpenWire）或 `Apache.NMS.AMQP.dll` < 2.1.0（AMQP），且代码会读取 `IObjectMessage.Body`（或调用会触发该 getter 的 API）。
- 攻击者能向受害者订阅的 queue/topic 发送消息：broker 未授权/弱口令、攻击者拥有生产者权限，或能中间人篡改/注入 OpenWire/AMQP 消息。无需接触受害者主机。
- 消息内容能被构造成 ObjectMessage（用 NMS 客户端发送即可），且消息中引用的 gadget 类型程序集在受害者进程可见（如 `Microsoft.PowerShell.Editor.dll`），或存在其他可用 BinaryFormatter gadget。
- 客户端连接配置允许（压缩/非压缩均会走到同一个 `Deserialize`）。

## 利用步骤

1. **确认目标**：受害者客户端为 NMS .NET 且版本 < 2.1.0，并会消费 ObjectMessage（`consumer.Receive() as IObjectMessage` 后访问 `Body`）。
2. **准备 gadget**：用 ysoserial.net 生成 `TextFormattingRunProperties`（或其他 BinaryFormatter gadget）载荷，命令如 `calc`。
3. **发送恶意 ObjectMessage**：用任意 NMS 客户端连接同一 broker，把 gadget 对象设置为 `IObjectMessage` 的 body 后 `producer.Send(...)`；发送时 `BeforeMarshall` 会用 `BinaryFormatter` 把 gadget 序列化进消息 `Content`。
4. **等待消费**：受害者客户端收到消息并访问 `message.Body`，`BinaryFormatter.Deserialize(Content)` 实例化 gadget 并执行命令（原文演示弹出计算器）。
5. **扩大影响**：可对订阅同一 destination 的所有客户端投递；若 broker 对外暴露且无鉴权，直接远程利用。

## PoC

原文演示的核心代码（简化；gadget 由 ysoserial.net 生成，未在本机复跑）：

```csharp
// 攻击者生产者：把恶意 gadget 作为 ObjectMessage body 发送
// gadget 示例：TextFormattingRunProperties 包装的 calc 载荷
Uri connecturi = new Uri("activemq:tcp://127.0.0.1:61616");
IConnectionFactory factory = new NMSConnectionFactory(connecturi);
using (IConnection connection = factory.CreateConnection())
using (ISession session = connection.CreateSession())
{
    IDestination destination = SessionUtil.GetDestination(session, "queue://FOO.zzz");
    using (IMessageProducer producer = session.CreateProducer(destination))
    {
        connection.Start();
        vulnProducer producerObj = new vulnProducer();   // 设置恶意 body（TFRP gadget）
        producerObj.producer();                           // Send -> BeforeMarshall -> BinaryFormatter.Serialize
    }
}

// 受害者消费者（< 2.1.0）：读取 Body 即触发反序列化
IObjectMessage message = consumer.Receive() as IObjectMessage;
if (message.Body != null)   // Body getter -> BinaryFormatter.Deserialize(this.Content) -> RCE
{
    Console.WriteLine("message received");
}
```

`ActiveMQObjectMessage.Body` getter 关键逻辑（原文调试源码）：

```csharp
get {
    if (this.body == null) {
        if (this.Content == null) return null;
        Stream stream = new MemoryStream(this.Content, writable: false);
        if (this.Connection != null && this.Compressed)
            stream = this.Connection.CompressionPolicy.CreateDecompressionStream(stream);
        this.body = this.Formatter.Deserialize(stream);
    }
    return this.body;
}
```

## 变体与关联

- **gadget 复用**：外层 gadget 见 [[web-dotnet-deser-textformattingrunproperties-xamlreader-odp-gadget]]；其它 BinaryFormatter gadget 如 DataSet（见 [[web-dotnet-deser-binaryformatter-serializationbinder-bypass]] 中的利用与绕过讨论）可直接替换。
- **协议双入口**：OpenWire（`Apache.NMS.ActiveMQ.dll`）与 AMQP（`Apache.NMS.AMQP.dll`）两个 provider 在 < 2.1.0 均受影响，同一 ObjectMessage 语义。
- **其它 MQ 反序列化面**：Java 侧 ActiveMQ 的 JMS `ObjectMessage` 同样因 `getObject()` 反序列化成为历史攻击面；本卡是 .NET NMS 客户端侧的对等场景。
- **补丁绕过思路**：2.1.0 的 `TrustedClassFilter` 使用 `INmsDeserializationPolicy` 白名单；若应用自定义策略过宽（信任基类/接口/常见程序集），仍可能引入可利用类型，需按“精确白名单 + 禁用 BinaryFormatter”评估。

## 检测与防御

- **修复**：升级到 `activemq-nms-openwire` ≥ 2.1.0 / `Apache.NMS.ActiveMQ.dll`、`Apache.NMS.AMQP.dll` ≥ 2.1.0；配置最小化的 `INmsDeserializationPolicy` 白名单。
- **根治**：业务层不要反序列化不可信消息体；改用安全的序列化格式（JSON/Protobuf + 严格 schema），或在 .NET 中禁用 BinaryFormatter（.NET 5+ 默认禁用并抛异常）。
- **架构**：broker 开启认证授权，限制谁能向生产队列发送消息；客户端只消费可信来源的 destination；对消息来源做网络隔离与 TLS。
- **检测**：监控 ObjectMessage/二进制消息中的 BinaryFormatter 流特征（`AAEAAAD/////` 头、`BinaryFormatter` 类型记录字符串），重点匹配 `TextFormattingRunProperties`、`ObjectDataProvider`、`System.Data.DataSet`、`TypeConfuseDelegate` 等 gadget 类型名；对消费端进程异常创建子进程（calc/cmd/powershell）告警。
