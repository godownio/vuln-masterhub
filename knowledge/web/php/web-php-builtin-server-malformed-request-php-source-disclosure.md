---
id: web-php-builtin-server-malformed-request-php-source-disclosure
title: PHP 内置开发服务器（php -S）被畸形/流水线请求读出 .php 源码：先拿源码再打通后续反序列化链
type: scenario
domain: web
path: web/php
technique: php-builtin-server-request-desync-source-disclosure
aliases:
- php -S 源码泄露
- PHP 内置服务器源码泄露
- 畸形请求读取 php 源码
- 关闭 Content-Length 自动更新
- 双请求流水线读源码
tags:
- php
- source-disclosure
- dev-server
- php-s
- request-parsing
- ctf
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:49:49+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文只给出「bp 构造 GET /flag.php 后再跟一个 GET /、关闭更新 Content-Length」与读到 flag.php 的现象，未解释服务端解析原因，卡内已据实标 confidence=low 并把机制写成按现象推断、需按目标版本实测，PoC 与利用步骤未超出原文范围；受影响版本区间原文未给，故未设置 affected_versions
---

## 一句话结论

目标跑的是 PHP 内置开发服务器（`php -S`，本例 PHP 7.4.21）时，除常规路径爆破外，还可以用 Burp 构造「同一连接上先后两个请求行」的畸形/流水线报文（关闭 “Update Content-Length”、保留 CRLF）请求 `/flag.php`，使服务器把它当静态资源处理并**返回源码原文而不是执行结果**；拿到源码后才知道后续的类定义、魔术方法与被禁函数，从而拼出可用的反序列化 RCE 链。

## 原理

- 内置开发服务器是为调试而写的极简实现，对请求的解析、URI 归一化与「是否交给 PHP 解释器」的判定比 nginx+php-fpm 宽松得多：当请求形态不符合它的预期（多余请求行、被手工改短的 `Content-Length`、保留的换行），它可能走静态文件分支，直接把文件字节写回响应。
- 因此这条链的价值不在「读文件」本身，而在**它绕过了解释执行**：`/flag.php` 正常请求会执行并只回显 `highlight_file` 之外的输出，畸形请求才会把 `<?php ... ?>` 原样吐出来。
- 源码一旦可读，后续攻击面立刻改变：能看到类结构、魔术方法、`unserialize` 入口、`disable_functions` 的范围（本例据此确认 `exec` 未被禁），于是可以把「盲猜 payload」变成「按源码构造 POP 链」。
- 这条路径与「扫备份文件」「`.git` 泄露」「`engine=off`」并列，属于**信息收集阶段的源码获取手段**，是否成立取决于目标是否真的用了内置服务器（`Server: PHP/7.4.21 Development Server` 响应头、响应里带 `X-Powered-By` 且无 nginx/apache 头）。

## 触发条件

- 目标确实由 `php -S` 启动（响应头 `Server: PHP/<ver> Development Server`；本例 7.4.21 所在区间存在该解析异常）。
- 目标文件为 `.php` 且位于 Web 根内，路径可枚举（本例爆破得到 `flag.php`、`hint.php`）。
- 客户端能完全控制报文（Burp/自写 socket），可关闭「自动更新 Content-Length」并保留 CRLF 换行。
- 正文未给出服务端解析层的确切原因，机制部分为按现象推断，复现需按目标版本实测。

## 利用步骤

1. 读响应头确认服务端是 `PHP/* Development Server`（不是 nginx/Apache）。
2. 目录/文件名爆破，得到 `.php` 列表（本例 `flag.php`、`hint.php`）。
3. 在 Burp 中关闭 `Update Content-Length`（Repeater 的 “Update Content-Length” 取消勾选），并在 Proxy 选项里把换行显示/保留设为 CRLF。
4. 构造报文：先写 `GET /flag.php HTTP/1.1` 与 `Host:`，空行后再放一个 `GET / HTTP/1.1`，发送（必要时把 `Content-Length` 手工调小）。
5. 响应中若出现 `<?php` 原文，即成功；用同样手法读 `hint.php` 等被引用的包含文件。
6. 依据源码定位 `unserialize` 入口与类定义，构造 POP 链；`hint.php` 里若提示 `disable_functions`，先挑未被禁用的函数（本例 `exec`），再打命令执行。

## PoC

```http
GET /flag.php HTTP/1.1
Host: target

GET / HTTP/1.1
Host: target
```

用 socket 直接发（保留 `\r\n`、不自动改 `Content-Length`）：

```python
import socket
req = (b"GET /flag.php HTTP/1.1\r\nHost: target\r\n\r\n"
       b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
s = socket.create_connection(("target", 80), timeout=5)
s.sendall(req)
print(s.recv(65535).decode("utf-8", "replace"))   # 出现 <?php 即源码泄露
```

## 变体与关联

- 变体：同源思路的源码获取——`.git`/`.svn`、备份文件（`.php.bak`、`~`、`.swp`）、`php://filter` 包含、`engine=off` 的 `.htaccess`。
- 变体：拿到源码后常见接力是「反序列化 POP 链」或「禁用函数绕过」，本例正是前者：`hint.php` 确认 `exec` 可用后，用 `a/b/c/d` 四个类串出 `call_user_func($_GET)`。
- 关联：[[web-php-htaccess-engine-off-source-disclosure]]（`.htaccess` 关闭引擎导致源码直出）、[[web-php-deserialization-destruct-tostring-get-invoke-call-user-func]]（拿到源码后落地的 POP 链）、[[web-nodejs-vite-dev-server-source-leak-fs]]（开发服务器源码泄露的同类思路）。
- 边界：生产环境用 nginx/Apache + php-fpm 时该手法无效；PHP 后续版本可能已修正解析行为，需按版本实测；目标若禁止目录枚举则只能靠路径字典命中。

## 检测与防御

- 检测：同一连接出现多个请求行、`Content-Length` 小于实际 body 的请求；对 `.php` 的响应体中出现 `<?php` 字面量；`Server: PHP/* Development Server` 暴露在公网。
- 修复：不要把 `php -S` 用于任何对外服务，开发服务器只监听 `127.0.0.1`；生产用 nginx/Apache + php-fpm 并正确配置 `try_files`/`location ~ \.php$`。
- 加固：关闭 `expose_php`；不在 Web 根放置 `flag.php`/`hint.php` 这类含敏感逻辑与提示的文件；上线前用响应头与畸形报文做自检。
