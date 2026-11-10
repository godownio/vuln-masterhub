---
id: web-java-framework-spring-actuator-env-ak-sk-oss-db-takeover
title: Actuator env 未授权：从 propertySources 里捞 AK/SK 与数据源口令，一路接管 OSS 与 MySQL
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-env-ak-sk-oss-db-takeover
aliases:
- actuator env 泄露 AK/SK
- Spring Boot 环境变量泄露云密钥
- actuator/env 拿数据库口令
- 云账号接管 OSS 存储桶
- 多接口 springboot 泄露链
tags:
- spring
- actuator
- credential-leak
- aliyun
- oss
- mysql
- cloud-takeover
cve: []
severity: critical
confidence: low
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:32:30+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文仅文字描述 /actuator/env 泄露 ak/sk 与 mysql 口令并「云接管」，未给出具体配置项名与版本，卡内 propertySources 字段名与 OSS/MySQL 利用步骤按端点一般语义补充、属示例；触发条件中误留的 api.weixin 已修正为云厂商 API
---

## 一句话结论

Spring Boot 的 `/actuator/env` 未授权时，`propertySources` 会把配置中心地址、云厂商 `accessKey`/`secretKey`、数据库 URL 与账号口令按原样列出来；攻击者用这对 AK/SK 登录云控制台或 ossutil/oss-browser 就能列出并下载对象存储里的备份与业务数据，用数据源口令就能直连 MySQL——一次未授权读端点被放大成云资源接管加数据库沦陷。

## 原理

- **env 端点的语义就是"把 Environment 摊开"**：它遍历 `systemProperties`、`systemEnvironment`、各 `Config resource 'file [application.yml]'` 等属性源，返回每个属性名、值与 `origin`。运维为了排障常把 `management.endpoints.web.exposure.include` 开到 `env`（甚至 `*`），却不加认证。
- **为什么 AK/SK 一定在里面**：云 SDK 的标准接法是 `spring.cloud.alicloud.access-key`/`secret-key` 或自定义 `oss.access-key`，这些就是普通配置项；`keys-to-sanitize` 默认只按 key 名匹配 `password`/`secret`/`key`/`token` 等模式，而 `access-key` 这类名字经常不在默认脱敏表里（脱敏表是**名字匹配**，不是内容检测），所以密钥以明文出现。
- **为什么危害被放大**：AK/SK 是账号级凭证，作用域在云侧，与 Web 应用的鉴权无关；拿到后攻击面从"这台 Web 服务器"变成"这个云账号下这个 AK 能访问的所有资源"。数据库口令同理，MySQL 往往对内网开放，而攻击者已在这些网段里有立足点。
- **与"改路径即安全"的误区**：`management.endpoints.web.base-path` 改成非常规路径只是减少被扫描到的概率；一旦路径通过配置文件泄露、错误页或目录爆破暴露，端点本身仍然无认证。
- **链式特征**：同一应用常常同时暴露 `/actuator/env`、`/actuator/heapdump`、`/actuator/configprops`，env 给结构化配置、heapdump 给内存中的明文对象，两者互补。

## 触发条件

- 目标为 Spring Boot 应用，`management.endpoints.web.exposure.include` 含 `env`（或 `*`），且无 Spring Security / 网关鉴权。
- 应用中存在云厂商 AK/SK、OSS endpoint/bucket 名、数据源账号口令等敏感配置项，且未加入 `keys-to-sanitize`。
- 攻击者可达云厂商 API（控制台/OSS 走公网即可）或目标数据库端口（MySQL 通常需内网可达）。

## 利用步骤

1. 枚举 actuator 路径（默认 `/actuator/env`；base-path 可能被改名），确认响应里有 `propertySources`。
2. 在 `systemEnvironment` 与 `Config resource ... application.yml` 两类来源中搜 `access-key`、`secret-key`、`endpoint`、`bucket`、`spring.datasource`、`jdbc:`、`password`。
3. 用泄露的 AK/SK 调云厂商的只读接口（如列出 bucket、列对象）确认凭证有效与权限范围；不要下载或删除业务数据。
4. 用 `endpoint`/`bucket` 与 AK/SK 在 ossutil/oss-browser 里列出桶内对象，证明可读。
5. 用 `spring.datasource.url/username/password` 直连 MySQL，只查 `version()`、`current_user()` 与库名列表作为证据。
6. 顺带检查 `/actuator/heapdump`、`/actuator/configprops`、`/actuator/mappings`，把 heapdump 里内存中的明文密钥与 env 交叉验证。

## PoC

```http
GET /actuator/env HTTP/1.1
Host: target

# 响应中关注（示例字段名，按实际配置项命名）
# propertySources[].properties["spring.cloud.alicloud.access-key"].value
# propertySources[].properties["spring.cloud.alicloud.secret-key"].value
# propertySources[].properties["spring.datasource.url"].value
```

```text
判据：env 返回 200 且 propertySources 中出现 access-key/secret-key 明文；
用该 AK/SK 调云侧 list 接口返回 200 而非 InvalidAccessKeyId；
用数据源口令可建立 MySQL 会话（只读一条 version()）。
```

## 变体与关联

- 关联：[[web-java-framework-spring-actuator-env-config-backup-path]]（同一端点泄露内部下载路径的另一条落地）、[[cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover]]（同一 sink 的不同来源：Nacos 配置详情）、[[cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover]]（前端 JS 泄露 AK/SK）、[[web-java-framework-shiro-actuator-heapdump-key-account-forgery]]（heapdump 取密钥的另一条 actuator 链）。
- 变体：`/actuator/env/<name>` 单属性读取可绕过整页被 WAF 拦的情况；若 env 被禁用但 `heapdump` 开放，直接从堆里搜 `LTAI` 前缀与 `secret` 附近字符串。
- 边界：AK/SK 可能只有最小权限（如仅限某个 bucket 前缀），此时"云接管"降级为"单桶可读"；数据库若只允许内网并做了账号白名单，口令泄露未必可直连；`keys-to-sanitize` 配全的应用会让 env 只剩脱敏值。

## 检测与防御

- 检测：`/actuator/env`、`/actuator/heapdump`、`/actuator/configprops` 的未授权访问；响应体中出现 `LTAI`、`access-key`、`jdbc:mysql` 等特征；云侧出现来自非业务出口 IP 的 `ListBuckets`/`ListObjects` 调用；MySQL 出现来自异常源 IP 的登录。
- 防御：actuator 只在内网管理口暴露并加认证（Spring Security 或网关 mTLS）；`exposure.include` 最小化，关闭 env/heapdump/configprops；把 AK/SK 换成实例角色/STS 临时凭证并定期轮转；`keys-to-sanitize` 覆盖自定义命名；数据库口令走密管服务，不以明文配置下发。
