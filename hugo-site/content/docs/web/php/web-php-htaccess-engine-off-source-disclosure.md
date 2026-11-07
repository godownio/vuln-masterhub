---
id: web-php-htaccess-engine-off-source-disclosure
title: .htaccess 关闭 PHP engine 导致目录内 PHP 源码被明文返回
type: scenario
domain: web
path: web/php
technique: htaccess-engine-off-source-disclosure
tags:
- php
- apache
- htaccess
- source-disclosure
- misconfiguration
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:39:51+08:00'
  notes: 已对照原文与图13-17核对：PHP 文档 engine 指令为 PHP_INI_ALL，可经 .htaccess 覆盖；图14/15 正常访问 leak.php 执行输出 123，图16 写入 php_flag engine 0 后，图17 直接返回源码 <?php echo 123;?>。卡片描述准确。原文测试环境 PHP 8.5.0RC3、Apache 2.4.65，非受影响区间，未设置 versions。PoC 未在本机执行。
url: /docs/web/php/web-php-htaccess-engine-off-source-disclosure/
draft: false
kb_aliases:
- php_flag engine 0
- 关闭 PHP 解析
- .htaccess 源码泄露
- PHP 源码明文下载
---

## 一句话结论

在可写的 `.htaccess` 中加入 `php_flag engine 0` 会让该目录下的 PHP 文件不再被解释器处理，Apache 直接以静态文件返回，从而把 `index.php`、配置文件等源码明文交给攻击者。

## 原理

- mod_php 的 `engine` 指令控制是否为该目录启用 PHP 解析，级别为 `PHP_INI_ALL`，可通过 `.htaccess` 的 `php_flag engine 0` 关闭。
- 关闭后，`.php` 文件不再进入 PHP 解释器，Apache 按普通静态文件处理并按 MIME 类型返回，响应体就是文件原始内容。
- 与“读取文件”类漏洞的区别：无需经过 PHP 的 `file_get_contents`/`include`，因此 `open_basedir`、`disable_functions` 不参与；只要 Apache 能读、客户端能请求到该文件即可。
- 该配置是可逆的，攻击者可先下载源码，再写回 `engine 1` 或删除 `.htaccess` 恢复业务，降低被发现概率。

## 触发条件

- Apache + mod_php，`.htaccess` 可写且 `AllowOverride` 允许 `Options`/`FileInfo` 等相应覆盖；
- 目标目录存在需要保密的 PHP 源码/配置（数据库口令、密钥、flag 等）；
- 攻击者能请求这些 `.php` 路径。

## 利用步骤

1. 写入或上传 `.htaccess`，内容为 `php_flag engine 0`。
2. 直接请求目标 `.php` 文件，确认响应为源码而非执行结果。
3. 下载 `config.php`、`flag.php`、框架入口等，提取密钥、数据库凭据或 flag。
4. 复原配置以避免影响业务与暴露。

## PoC

`.htaccess`：

```apache
php_flag engine 0
```

请求：

```http
GET /leak.php HTTP/1.1
```

原本返回 `123` 的页面，现在返回明文：

```php
<?php echo '123'; ?>
```

## 变体与关联

- `RemoveHandler .php`、`RemoveType .php`、`SetHandler default-handler` 也可达到“不解析”的效果。
- 与 `.htaccess` handler 覆盖相反：前者把非 PHP 当 PHP 执行，本技巧把 PHP 当静态文件泄露。
- 若只想读单个文件，`ErrorDocument` 表达式与 `%{file:}` 更隐蔽；若能写 `.htaccess`，auto_prepend 自包含通常可直接 RCE，价值更高。
- 关联：备份文件/源码泄露、`.git` 泄露、编辑器临时文件泄露。

## 检测与防御

- 生产环境 `AllowOverride None`，禁止上传 `.htaccess` 与点文件；上传目录禁止脚本解析。
- 监控 `.htaccess` 出现 `engine`、`RemoveHandler`、`SetHandler default-handler` 等指令；监控对 `.php` 文件的响应 Content-Type 是否变为 `text/plain`/`application/octet-stream`。
- 敏感配置不要放在 Web 根目录；密钥使用环境变量并限制文件权限。
- 定期扫描 Web 目录中的 `.htaccess` 变更，纳入文件完整性监控。
