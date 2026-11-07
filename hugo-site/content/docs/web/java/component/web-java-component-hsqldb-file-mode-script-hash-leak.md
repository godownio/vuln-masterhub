---
id: web-java-component-hsqldb-file-mode-script-hash-leak
title: HSQLDB file 模式：JDBC URL 指定路径落盘与 .script 无盐 MD5 口令摘要泄露
type: scenario
domain: web
path: web/java/component
technique: hsqldb-file-mode-database-file-write-hash-disclosure
tags:
- java
- hsqldb
- jdbc
- file-write
- password-hash
- credential
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:41+08:00'
  notes: 已对照原文与 img01-02 核对：jdbc:hsqldb:file 生成 1.log/1.properties/1.script/1.lck，.script 中 CREATE USER ... PASSWORD DIGEST 'e10adc3949ba59abbe56e057f20f883e' 与 MD5(123456) 一致；该链需能取回 .script（或配合任意文件读取），原文为本地测试；未复跑。
url: /docs/web/java/component/web-java-component-hsqldb-file-mode-script-hash-leak/
draft: false
kb_aliases:
- HSQLDB file 模式写文件
- jdbc:hsqldb:file
- .script 口令哈希
- HSQLDB PASSWORD DIGEST
- HSQLDB 密码 MD5 碰撞
---

## 一句话结论

HSQLDB 文件模式（`jdbc:hsqldb:file:<path>`）会在 URL 指定目录创建 `.script`、`.log`、`.properties`、`.lck`（以及可选的 `.data`）等数据库文件；`.script` 中的 `CREATE USER ... PASSWORD DIGEST '<MD5>'` 保存的是无盐 MD5 口令摘要，攻击者一旦能通过可控 JDBC URL 落盘并取回文件（或经任意文件读取/备份泄露拿到 `.script`），即可离线碰撞出数据库用户口令。

## 原理

- HSQLDB 文件模式把数据库持久化为 SQL 脚本 + 事务日志 + 属性文件：
  - `.script`：表结构与数据的 SQL 语句；
  - `.log`：事务日志；
  - `.properties`：数据库配置；
  - `.lck`：文件锁；
  - `.data`：可选的二进制表数据文件。
- 新建数据库时，驱动按 URL 中的路径和库名创建这些文件。URL 可控时，攻击者可让目标进程在自身有写权限的任意目录生成固定后缀的文件。
- `.script` 的初始化内容包含 `CREATE USER "aaaa" PASSWORD DIGEST 'e10adc3949ba59abbe56e057f20f883e'`、`ALTER USER ... SET LOCAL TRUE`、`GRANT DBA TO ...` 等语句。该 32 位十六进制值就是口令的 MD5；原文示例 `e10adc3949ba59abbe56e057f20f883e` 的碰撞结果为 `123456`。
- 无盐、无迭代的 MD5 可被彩虹表/GPU 快速碰撞；若该口令被复用，可进一步横向到数据库或其他系统。
- 约束：文件后缀固定、内容主要由驱动生成（用户名、口令等部分可控）；打开已存在的数据库仍需有效凭据；文件写入受目标目录权限限制。单独的写文件原语不等于任意内容、任意后缀的任意文件写入。

## 触发条件

- 攻击者可控制 HSQLDB JDBC URL（数据源配置、连接测试、JDBC 注入等），URL 使用 `file:` 前缀并能指定目录，目标进程对该目录有写权限。
- 或攻击者能以任意文件读取、备份下载、目录遍历等方式获取 HSQLDB 文件模式数据库的 `.script`。
- 目标数据库使用口令认证，`.script` 中存在 `PASSWORD DIGEST`。

## 利用步骤

1. 提交 `jdbc:hsqldb:file:/目标目录/库名` 并触发连接；驱动初始化数据库，目录中出现 `库名.script`、`库名.log`、`库名.properties`、`库名.lck`。
2. 读取 `库名.script`，定位 `CREATE USER "<user>" PASSWORD DIGEST '<hash>'`。
3. 用 hashcat/john 或在线 MD5 库碰撞 32 位摘要（原文示例直接还原为 `123456`）。
4. 用还原出的口令尝试登录该数据库，或复用至其他系统；同时评估写文件能力是否可用于覆盖/放置其他文件。

## PoC

触发文件模式建库的代码：

```java
String dbUrl = "jdbc:hsqldb:file:C:/Users/xxx/Downloads/1";
Connection connection = DriverManager.getConnection(dbUrl, "aaaa", "123456");
```

生成的 `1.script` 关键片段：

```sql
CREATE USER "aaaa" PASSWORD DIGEST 'e10adc3949ba59abbe56e057f20f883e'
ALTER USER "aaaa" SET LOCAL TRUE
CREATE SCHEMA PUBLIC AUTHORIZATION DBA
GRANT DBA TO "aaaa"
```

其中 `e10adc3949ba59abbe56e057f20f883e` 为 MD5("123456")，原文用在线 MD5 碰撞站还原。

## 变体与关联

- 文件模式支持相对路径与绝对路径；不同版本创建的文件集合可能略有差异（`.data` 仅在二进制表数据时出现）。
- 若攻击者只能写不能读，可结合后续任意文件读取、备份下载或日志外带把 `.script` 取回。
- 同属 HSQLDB 驱动特性族：[[web-java-component-hsqldb-jdbc-url-property-expansion-exfil]]（URL 占位符外带）、[[web-java-component-hsqldb-call-static-method-rce]]（CALL 静态方法 RCE）。
- 边界：目标目录不可写、数据库未使用口令认证、`.script` 被权限保护、口令为高强度随机值时，碰撞不现实；文件写本身受固定后缀限制。

## 检测与防御

- 检测：JDBC URL 中出现 `jdbc:hsqldb:file:` 指向非常规目录；应用目录或临时目录突然出现 `.script`/`.log`/`.properties`/`.lck` 文件；`.script` 被外部读取或下载。
- 防御：禁止用户控制 JDBC URL 与数据库文件路径；限制应用进程的目录写权限；不要把数据库文件放在 Web 可访问目录。
- 加固：数据库用户使用高强度随机口令；对 HSQLDB 数据文件做访问控制与完整性监控；敏感环境避免使用无盐 MD5 摘要的口令存储方式。
