---
id: web-java-framework-spring-actuator-jolokia-getproperty-config-disclosure
title: Spring Boot Actuator Jolokia 未授权调用 SpringApplicationAdminMXBean#getProperty 读取配置明文（如 security.user.password）
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-jolokia-springapplicationadmin-getproperty
aliases:
- /jolokia getProperty
- /actuator/jolokia getProperty
- SpringApplicationAdminMXBeanRegistrar
- jolokia 读取 security.user.password
- Actuator 配置明文读取
tags:
- java
- spring
- spring-boot
- actuator
- jolokia
- jmx
- mbean
- information-disclosure
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:33:52+08:00'
  notes: 已对照原文核对：/jolokia(1.x)、/actuator/jolokia(2.x) EXEC org.springframework.boot:name=SpringApplication,type=Admin#getProperty，arguments security.user.password 与原文一致；属原文“敏感信息明文获取”场景；未复跑。
---

## 一句话结论

当 Spring Boot 应用的 `/jolokia`（1.x）或 `/actuator/jolokia`（2.x）端点未授权暴露时，攻击者可通过 Jolokia 的 EXEC 请求调用 `org.springframework.boot:name=SpringApplication,type=Admin` MBean 的 `getProperty` 操作，直接读取 Environment 中的原始配置值（如 `security.user.password`、数据库口令、第三方密钥），绕过 `/env` 端点常见的敏感值脱敏。

## 原理

- Jolokia 把 JMX MBean 以 HTTP JSON API 暴露：POST 一个带 `mbean`、`type: "EXEC"`、`operation`、`arguments` 的对象，即可调用指定 MBean 的方法。
- Spring Boot 的 `SpringApplicationAdminMXBeanRegistrar` 会把一个 Admin MBean 注册为 `org.springframework.boot:name=SpringApplication,type=Admin`。该 MBean 的 `getProperty(String key)` 直接调用 `ApplicationContext.getEnvironment().getProperty(key)`。
- 与 Actuator `/env` 不同：`/env` 会对名字含 `password`、`secret`、`key`、`token` 等敏感字段做 `******` 脱敏，而 MBean 的 `getProperty` 返回的是 Environment 里的原始字符串，因此可用于取回明文口令。
- 该 MBean 能读任意配置键，攻击者可用 `/jolokia/list` 先确认 MBean 与 operation 存在，再按常见键名读取：`security.user.password`、`spring.security.user.password`、`spring.datasource.password`、`spring.redis.password`、自定义的 AK/SK 配置等。
- 前提是应用引入了 `jolokia-core` 且把 Jolokia 端点暴露出来；Spring Boot 1.x 默认暴露较多端点，2.x 需要显式 `management.endpoints.web.exposure.include` 包含 `jolokia`。

## 触发条件

- 应用使用 `spring-boot-starter-actuator` 并引入 `jolokia-core`，Jolokia 端点（`/jolokia` 或 `/actuator/jolokia`）可访问且未鉴权。
- `SpringApplicationAdminMXBeanRegistrar` 已注册 Admin MBean（引入 Actuator 后的常见默认行为）。
- 攻击者知道或能猜出配置键名；可通过 `/actuator/env`、`/jolokia/list`、heapdump 或应用默认键名辅助。

## 利用步骤

1. 探测端点：请求 `/jolokia` 或 `/actuator/jolokia`，返回 Jolokia 版本/能力 JSON 说明可访问；请求 `/jolokia/list` 或 `/actuator/jolokia/list` 搜索 `SpringApplication` 与 `getProperty`。
2. 按版本构造 EXEC JSON：1.x POST 到 `/jolokia`，2.x POST 到 `/actuator/jolokia`，`Content-Type: application/json`。
3. 在 `arguments` 中逐个尝试敏感键：`security.user.password`、`spring.security.user.password`、`spring.datasource.password`、`spring.redis.password`、`spring.mail.password`、`jwt.secret` 等。
4. 拿到明文口令后做最小化验证（登录管理台/数据库/Redis），确认后停止扩大；同时可用同一个 `getProperty` 读取内网地址与第三方密钥。
5. 若目标对 `getProperty` 做了键名过滤，可换用 `/actuator/jolokia/exec` 路径写法或改用其他可读配置的 MBean。

## PoC

Spring Boot 1.x：

```http
POST /jolokia HTTP/1.1
Host: target:8080
Content-Type: application/json

{"mbean": "org.springframework.boot:name=SpringApplication,type=Admin","operation": "getProperty", "type": "EXEC", "arguments": ["security.user.password"]}
```

Spring Boot 2.x：

```http
POST /actuator/jolokia HTTP/1.1
Host: target:8080
Content-Type: application/json

{"mbean": "org.springframework.boot:name=SpringApplication,type=Admin","operation": "getProperty", "type": "EXEC", "arguments": ["spring.datasource.password"]}
```

返回 JSON 的 `value` 字段即配置明文。

## 变体与关联

- 变体：把 `arguments` 换成任意配置键，批量读取数据源、Redis、邮件、云厂商 AK/SK、JWT 签名密钥等。
- 变体：Jolokia 还支持 `SEARCH`、`LIST`、`READ`，可先枚举 MBean 再选能读配置或能触发危险操作的对象。
- 关联：[[web-java-framework-spring-actuator-env-config-backup-path]]（`/env` 信息泄露，但敏感值可能被脱敏）、[[web-java-framework-spring-actuator-heapdump-credential-leak]]（另一种取明文凭据的入口）、[[web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce]]（同一 Jolokia 入口升级为 RCE）。
- 边界：Jolokia 端点被鉴权/关闭、`jolokia-core` 未引入、Admin MBean 被移除或 `getProperty` 被限制时，该读取不成立。

## 检测与防御

- 检测：`/jolokia`、`/actuator/jolokia` 出现 `org.springframework.boot:name=SpringApplication,type=Admin`、`getProperty`、`security.user.password`、`spring.datasource.password` 等字符串；对同一端点的批量键名尝试。
- 防御：关闭或鉴权 Jolokia 端点，`management.endpoints.web.exposure.include` 不要把 `jolokia` 暴露给外部；升级到默认不暴露敏感端点的版本。
- 防御：敏感配置使用外部密钥管理（Vault/KMS/环境变量注入），避免以明文属性存在于 Environment；轮换可能已泄露的口令与密钥。
- 加固：Actuator/Jolokia 仅绑定内网或独立管理端口，纳入统一认证、来源 IP 白名单与审计。
