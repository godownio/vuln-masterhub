---
id: web-java-framework-spring-actuator-mappings-env-classpath-gadget-recon
title: Spring Boot Actuator 未授权 mappings + env 作攻击面侦察：从隐藏路由拿到 sink，从 jar 清单选型本地 JNDI 工厂 gadget
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-actuator-mappings-env-classpath-gadget-recon
tags:
- java
- spring-boot
- actuator
- recon
- information-disclosure
- classpath
- gadget-selection
- jndi
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:51:43+08:00'
  notes: 已对照 16536 原文与 img/01-16 核对：/actuator/mappings 的 handler=com.example.demo.controllers.Index#lookup(String)、predicate={GET [/lookup]}、descriptor=(Ljava/lang/String;)Ljava/lang/String;、以及 source() 的 /source_tr15d0 与图02 逐字一致；/actuator/env 的 application.properties 来源（spring.datasource.url=jdbc:h2:mem:memdb、driverClassName=org.h2.Driver、origin 含 demo-0.0.1-SNAPSHOT.jar 行号）与图03 一致；trustSerialData=false 与原文第 52-58 行一致。已修正卡片 3 处不精确表述：① 原卡只写 env 会返回 java.class.path/CLASSPATH/BOOT-INF/lib，实际原文主要靠 application.properties 来源的 spring.datasource.* 与 systemProperties 的 trustSerialData 判断，已按原文改写原理、PoC 返回片段与步骤 4；② PoC 的 env 返回片段补上原文真实字段（含 trustSerialData=false），删掉原文没有的 CLASSPATH 假设；③ 边界段补“java.class.path 被脱敏时改看 driverClassName”的退路。另：卡片主动把危害限定为侦察、不声称 RCE，符合原文定位；作者跳过 LDAP 链与远程调试环境两段（前者与已 verified 卡 web-java-deserialization-jndi-ldap-local-factory-h2-init-rce 同链、后者属环境准备）的处理成立。未验证点：未复现 actuator 请求；原文本例 JDK17+trustSerialData=false 的绕过结论属机制推导+已有同链卡支撑。未 set-versions（原文未声明 Spring Boot 受影响版本区间）。未访问原文 URL/未访问
    github 源码。
url: /docs/web/java/framework/spring/web-java-framework-spring-actuator-mappings-env-classpath-gadget-recon/
draft: false
kb_aliases:
- /actuator/mappings
- /actuator/env 依赖清点
- Actuator 未授权侦察
- 从 env 读 classpath jar 列表
- 隐藏路由发现
- 本地工厂 gadget 选型
---

## 一句话结论

当 Spring Boot 的 Actuator 端点未鉴权暴露时，`/actuator/mappings` 会把所有 HandlerMapping 的 `handler`、`predicate`、`patterns`、`descriptor` 全部列出（包含作者以为"没文档就没人知道"的隐藏调试路由），`/actuator/env` 的 `propertySources` 又会把 `application.properties` 来源里的 `spring.datasource.url`/`driverClassName`、JVM 系统属性（如 `com.sun.jndi.ldap.object.trustSerialData=false`），以及存在时的 `java.class.path`、`BOOT-INF/lib` 依赖 jar 名一并返回；两者组合相当于给攻击者一份"入口清单 + 依赖/配置清单"，可直接决定后续用哪个本地 `ObjectFactory` gadget（如 tomcat-jdbc + h2）去打 JNDI。

## 原理

- **`/actuator/mappings` 的数据源**：该端点序列化 `RequestMappingHandlerMapping`、`SimpleUrlHandlerMapping` 等所有 `HandlerMapping` 的映射条目，每条包含 `handler`（`类#方法(签名)`）、`predicate`（`{GET [/lookup]}`）、`details.handlerMethod`（`className`/`name`/`descriptor`）与 `requestMappingConditions`（`methods`、`patterns`、`consumes`、`produces`、`params`、`headers`）。这些元数据由框架在启动时注册，不看注解是否对外公开，因此隐藏路由（如 `/source_xxx` 取源码、`/lookup` 做 JNDI）同样在其中。
- **为什么这比目录扫描高效**：`dirsearch` 只能基于字典猜路径，而 mappings 直接给出精确 pattern 与 HTTP 方法，甚至连参数签名 `(Ljava/lang/String;)Ljava/lang/String;` 都暴露，攻击者可以据此构造正确的调用形式，避免"扫到路径但参数错"的空转。
- **`/actuator/env` 的依赖与配置清点**：`propertySources` 会逐个列出每个属性来源（`systemProperties`、`Config resource 'class path resource [application.properties]'`、`applicationConfig` 等）。原文这类工程里，`application.properties` 来源直接把 `spring.datasource.url=jdbc:h2:mem:memdb`、`spring.datasource.driverClassName=org.h2.Driver` 连同所在的 `demo-0.0.1-SNAPSHOT.jar` 行号一起返回，等于告诉攻击者"H2 驱动在 classpath 上"；同一端点还暴露了 `com.sun.jndi.ldap.object.trustSerialData=false` 这类 JVM 系统属性，直接决定该走"远程 codebase"还是"`javaNamingReference` + 本地工厂"。若 `systemProperties` 里带 `java.class.path` 或 `BOOT-INF/lib` 路径，则能得到更完整的 jar 名与版本清单。攻击者据此判断"目标 classpath 上有没有可用的本地 ObjectFactory / gadget"，而不是盲打。
- **为什么依赖清单决定利用路线**：高版本 JDK 已禁止 LDAP 远程 codebase 与 `javaSerializedData`，只剩"`javaNamingReference` + 本地 `ObjectFactory`"这一支；本地工厂能把 Reference 属性转成 JDBC 连接的（tomcat-jdbc `DataSourceFactory`、Druid `DruidDataSourceFactory`、ViburDBCP 等）需要对应 jar 在 classpath 上，而能执行代码的驱动（如 H2 的 `INIT=CREATE ALIAS`）也需要 jar 存在且版本支持。看到 `h2-*.jar` + `tomcat-jdbc` 才值得走这条链；只看到 `h2` 没有工厂时可换其他工厂或别的驱动。
- **为什么是"侦察"而不是"漏洞"**：Actuator 暴露本身是配置错误（`management.endpoints.web.exposure.include` 过宽、未加 Spring Security）；它的危害取决于后续链路，本卡只负责把"隐藏路由 + 依赖清单"这两份输入稳定地取到并转成 gadget 选型结论。

## 触发条件

- 目标 Spring Boot 应用把 Actuator 端点暴露在可访问路径上，且 `management.endpoints.web.exposure.include` 包含 `mappings`、`env`（或 `*`）。
- 未启用 Spring Security 对该路径的认证，或认证可绕过（路径改写、前缀匹配缺陷）。
- 攻击者能访问该 base-path（默认 `/actuator`，也可能被改成自定义前缀，可用 `config.js`、错误页、`/actuator` 常见变体或目录扫描定位）。

## 利用步骤

1. 探测 base-path：请求 `/actuator`、`/actuator/mappings`、`/actuator/env`、`/actuator/health`，观察是否返回 JSON（返回 200 且含 `contexts`/`propertySources` 即暴露）。
2. 拉 `/actuator/mappings`，在返回 JSON 里搜索 `patterns`、`handler`，筛出非业务路由（名字含 `source`、`debug`、`test`、`lookup`、`admin`、`internal`），并记录对应 HTTP 方法与参数签名。
3. 对筛出的隐藏路由逐个请求，读取其功能（如取源码、做 JNDI lookup、做数据源测试），确定 sink 类型。
4. 拉 `/actuator/env`，逐条读 `propertySources`：先看 `application.properties` 等配置来源里的 `spring.datasource.*`/自定义 key，再看 `systemProperties` 里的 `trustSerialData`、`java.class.path` 与 `BOOT-INF/lib`，整理出依赖清单（重点看 `h2`、`tomcat-jdbc`、`druid`、`commons-collections`、`aspectjweaver`、`xstream` 等）。
5. 根据 sink + 依赖清单选定利用路线：JNDI sink 且存在本地 JDBC 工厂 jar → 走 `javaNamingReference` + 本地工厂 + 驱动侧危险参数；反序列化 sink 且存在 gadget → 走对应 gadget 链。
6. 若 `env` 已把敏感 key 脱敏，仍可从非敏感 key、`origin` 与 jar 清单获得足够信息；缺失的信息再从 mappings 里的隐藏路由（如"取源码"接口）补齐。

## PoC

```http
GET /actuator/mappings HTTP/1.1
Host: target
```

返回片段（关键字段）：

```json
{
  "contexts": {
    "application": {
      "mappings": {
        "dispatcherServlets": {
          "dispatcherServlet": [
            {"handler": "com.example.demo.controllers.Index#lookup(String)",
             "predicate": "{GET [/lookup]}",
             "details": {"handlerMethod": {"className": "com.example.demo.controllers.Index",
                                           "name": "lookup",
                                           "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"}}},
            {"handler": "com.example.demo.controllers.Index#source()",
             "predicate": "{GET [/source_tr15d0]}",
             "details": {"handlerMethod": {"className": "com.example.demo.controllers.Index",
                                           "name": "source"}}}
          ]
        }
      }
    }
  }
}
```

```http
GET /actuator/env HTTP/1.1
Host: target
```

返回片段（原文实测的依赖与配置清点，来自 `application.properties` 来源与系统属性）：

```json
{"propertySources":[
  {"name":"Config resource 'class path resource [application.properties]' via location 'optional:classpath:/'",
   "properties":{
     "spring.datasource.url":{"value":"jdbc:h2:mem:memdb","origin":"class path resource [application.properties] from demo-0.0.1-SNAPSHOT.jar - 2:23"},
     "spring.datasource.driverClassName":{"value":"org.h2.Driver","origin":"... - 3:35"}}},
  {"name":"systemProperties","properties":{
     "com.sun.jndi.ldap.object.trustSerialData":{"value":"false"},
     "java.class.path":{"value":".../BOOT-INF/lib/h2-*.jar:.../BOOT-INF/lib/tomcat-jdbc-*.jar:..."}}}]}
```

```text
# 侦察结论示例：存在 /lookup 的 JNDI sink + classpath 有 tomcat-jdbc 与 h2 + trustSerialData=false
# → 选型：LDAP 返回 javaNamingReference（走 decodeReference 分支而非远程 codebase/javaSerializedData），
#   javaFactory=org.apache.tomcat.jdbc.pool.DataSourceFactory，
#   url 用 jdbc:h2:...;INIT=CREATE ALIAS ...;CALL ...
```

## 变体与关联

- 变体：`/actuator/mappings` 被单独关闭时，`/actuator/env`、`/actuator/beans`、`/actuator/configprops`、`/actuator/conditions` 仍可能暴露；`beans` 与 `conditions` 能给出 bean 类型与自动配置，等价于依赖清点。
- 变体：base-path 被改成随机前缀时，从 `config.js`、`application.yml` 泄露、错误页堆栈、`/actuator/*` 变体字典中恢复；也可用 heapdump 里的字符串定位。
- 关联：[[web-java-framework-spring-actuator-env-config-backup-path]]（同一 `env` 端点，但目标是配置/备份路径泄露，不是依赖清单）、[[web-java-framework-spring-actuator-heapdump-credential-leak]]（`heapdump` 端点泄露凭据）、[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]（本卡侦察结论最常指向的利用链）、[[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]（改用 Druid 工厂的变体）。
- 边界：目标给 Actuator 加了认证、只暴露 `health`/`info`、或 `mappings`/`env` 未在 `exposure.include` 中时，该侦察不成立；`env` 若对 `java.class.path` 也做了脱敏，依赖清点要换 `beans`/`conditions`/heapdump，或改从 `application.properties` 来源里的 `spring.datasource.driverClassName` 之类间接判断。

## 检测与防御

- 加固：`management.endpoints.web.exposure.include` 只保留 `health`、`info`；生产环境关闭 `mappings`、`env`、`beans`、`configprops`、`heapdump`、`threaddump`；必要时把 base-path 与业务路径分离到独立端口。
- 加固：Actuator 路径纳入 Spring Security 认证与授权，明确拒绝未认证访问；不要依赖"路径改名"作为安全措施。
- 检测：访问 `/actuator/mappings`、`/actuator/env`、`/actuator/beans`、`/actuator/heapdump` 的请求（尤其非运维来源 IP）、连续的 Actuator 端点枚举、紧随其后对隐藏路由的探测。
- 响应：确认暴露范围，轮换 `env` 中出现过的凭据，检查是否已有人使用依赖清单走了 JNDI/反序列化链。
