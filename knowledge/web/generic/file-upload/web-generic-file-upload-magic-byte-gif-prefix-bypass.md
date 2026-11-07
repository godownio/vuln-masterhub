---
id: web-generic-file-upload-magic-byte-gif-prefix-bypass
title: 文件头魔数只比对前 4 字节，GIF89a 前缀即可夹带 PHP 代码
type: scenario
domain: web
path: web/generic/file-upload
technique: magic-byte-prefix-bypass
aliases:
- 文件头绕过
- 魔数校验绕过
- GIF89a 图片马
- 文件头检测
- upload-labs 文件头
tags:
- web
- file-upload
- magic-bytes
- file-header
- gif
- webshell
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:21+08:00'
  notes: 已对照原文与图29/31/32核对：后端 fread(4) 后 bin2hex 比对 89504E47/FFD8FFE0/47494638，GIF89a 前 4 字节为 47494638，拼接后并可配合 Content-Type=image/gif 上传。卡中 printf GIF89a 前缀 PoC 与原文一致。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

后端只读取上传临时文件的前 4 个字节并与图片魔数白名单比较时，在 PHP 代码前拼接 `GIF89a`（十六进制 `47 49 46 38 39 61`，前 4 字节 `47 49 46 38`）即可通过校验，文件仍按 `.php` 落盘执行。

## 原理

- 校验代码典型形式为：`$bin = fread($file, 4); ... if (!in_array(bin2hex($bin), ["89504E47","FFD8FFE0","47494638"]))`。
- 它只取前 4 字节，并且把“前 4 字节等于某个图片魔数”当作“整个文件是图片”。GIF 的完整文件头是 `GIF89a`（6 字节），前 4 字节 `GIF89a` 的十六进制正是 `47 49 46 38`，与白名单中的 GIF 值完全一致。
- 校验没有解析图片结构、没有检查后续字节、没有验证文件是否可被图片库解码，因此把任意 PHP 代码追加在 `GIF89a` 之后仍然通过。
- 文件名不受该检查影响，仍为 `.php`，Apache/PHP 按后缀解析，追加的代码随即执行。

## 触发条件

- 上传接口使用“读取固定长度文件头 + 十六进制比较”的方式校验图片类型。
- 校验长度不超过 4 字节，或白名单值取自图片魔数的前 4 字节；GIF 在允许类型内。
- 文件名后缀未做独立严格白名单，或可用其他手法保留 `.php`。

## 利用步骤

1. 上传正常 PNG 成功、上传 TXT 失败，确认存在文件头校验。
2. 用十六进制编辑器查看允许类型（如 GIF）的魔数，确认校验只比较前几位。
3. 在 PHP 代码前加上对应的魔数字符串，保存为 `.php` 文件。
4. 抓包把 `Content-Type` 改为 `image/gif` 后上传，访问落地文件确认执行。

## PoC

```bash
printf 'GIF89a' > shell.php
printf '<?php phpinfo(); ?>' >> shell.php
xxd -l 16 shell.php
```

输出前 4 字节应为 `47 49 46 38`。上传：

```bash
curl -s -X POST 'http://target/upload.php' \
  -F 'file=@shell.php;filename=shell.php;type=image/gif' \
  -F 'submit=Upload'
```

若后端同时校验 MIME，`type=image/gif` 与之配合即可。

## 变体与关联

- 变体：PNG 用 `\x89PNG\r\n\x1a\n`、JPEG 用 `\xFF\xD8\xFF\xE0` 前缀；若校验读取更多字节，需要构造完整合法图片头，或使用真实图片+文件包含。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]（只校验 MIME 时的更简单版本）；[[web-generic-file-upload-image-render-payload-survival]]（后端会重新渲染图片时，单纯前缀不够）。
- 边界：若后端调用 `getimagesize()` 或图像解码库验证完整结构，仅有魔数前缀会失败。

## 检测与防御

- 检测：上传文件的魔数与扩展名/声明类型不一致但前几字节匹配；PHP 文件以 `GIF89a` 等图片魔数开头；上传目录出现带图片头的脚本文件。
- 防御：用 `finfo_file()`/`getimagesize()` 解析完整文件；对图片重新编码后再落盘（注意二次渲染绕过）；扩展名白名单与随机重命名；上传目录禁止脚本解析。
