---
id: web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell
title: AI 内容检测只扫前 1KB + .htaccess AddType：2KB 填充后上传 PHP webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: ai-first-1kb-scan-padding-htaccess-webshell
tags:
- web
- file-upload
- ai-detection
- waf-bypass
- htaccess
- apache
- php
- webshell
- padding
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:04:40+08:00'
  notes: 已通读原文 MalCraft 段并核对：.php 被拒/ .txt 成功/ .htaccess 成功、一句话木马.txt 触发 'AI detected malicious content in the first 1KB of the file'、2KB 'A' 填充 + \r\n + PHP 代码后上传成功、.htaccess 写 AddType application/x-httpd-php .txt、读取 config.php 与 shell_exec find 找到 admin/db_backup.conf 等，均与卡片一致。『只扫前1KB』由报错文案与填充后成功共同支持，卡片已注明按目标确认。PoC 为内容构造示意，未在本机执行；CTF 题无组件版本。
url: /docs/web/generic/file-upload/web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell/
draft: false
kb_aliases:
- AI 检测只看前 1KB
- 填充绕过内容检测
- .htaccess AddType txt
- MalCraft
- 文件上传 AI 分析绕过
- 前 1KB 扫描绕过
---

## 一句话结论

上传接口用 AI/内容分析检测恶意文件，但只扫描文件前 1KB，且黑名单只拦 `.php` 等脚本后缀、允许 `.txt` 与 `.htaccess`；攻击者先上传 `.htaccess` 把 `.txt` 映射到 PHP handler，再上传一个前面填充 2KB 垃圾字节、后面跟 PHP 代码的 `.txt`，恶意代码落在扫描窗口之外，最终 `.txt` 被 Apache 当 PHP 执行，获得 webshell。

## 原理

- 上传过滤分两层：
  - 扩展名黑名单：`.php` 被拒，但 `.txt`、`.htaccess` 等未被拒。
  - 内容分析：AI/规则引擎检查文件内容，但只读取前 1KB（错误信息明确提示 “AI detected malicious content in the first 1KB of the file”）。
- 攻击者利用“检测窗口 ≠ 完整文件”：
  - 前 1KB 放无害填充（如 2048 个 `A`），让检测器看到的是正常文本；
  - 在 1KB 之后（如 2048 字节后）放 `<?php ... ?>`，检测器不扫描该区域。
- `.htaccess` 的 `AddType application/x-httpd-php .txt`（或 `SetHandler`）让上传目录下所有 `.txt` 由 PHP 解析；Apache 在 `AllowOverride` 允许时读取该文件。
- 文件内容仍是文本，扩展名仍是 `.txt`，但解析器选择被 `.htaccess` 改写，PHP 代码被执行。
- 该手法适用于任何“只扫描前 N 字节/只扫描头部”的内容检测（AI 或传统 AV），填充长度只需超过扫描窗口；也可用合法文件头（JPEG/PNG magic）填充，进一步降低可疑度。

## 触发条件

- 上传接口允许 `.htaccess` 落盘，且上传目录的 Apache `AllowOverride` 为 `FileInfo`/`All`。
- 内容检测只读取文件前 N 字节（如 1KB），或只对头部做特征匹配。
- 黑名单未阻止 `.txt` 等可被 `.htaccess` 重新映射的后缀；或允许无后缀/点开头文件。
- 上传目录可被 Web 访问，且 PHP handler 可用。
- 攻击者能上传至少两个文件（配置 + payload）。

## 利用步骤

1. 侦察上传接口：尝试 `.php`（应被拒）、`.txt`（应成功）、`.htaccess`（确认是否允许）；观察 AI 检测错误信息中的扫描范围。
2. 上传 `.htaccess`：
   ```apache
   AddType application/x-httpd-php .txt
   ```
3. 构造 payload：`padding = "A" * 2048`，后接 `\r\n` 与 PHP 代码（如读取 `config.php` 或执行 `shell_exec`）。
4. 上传 `.txt`，确认返回“上传成功”而非 AI 检测拦截；若仍拦截，增加填充长度或改用合法图片头。
5. 访问上传后的 `.txt` URL，验证 PHP 执行；用 webshell 读取配置、列目录、找隐藏文件。
6. 清理 `.htaccess` 与 webshell（授权测试后）。

## PoC

```apache
# .htaccess
AddType application/x-httpd-php .txt
```

```php
<?php
$padding = str_repeat("A", 2048);
$phpcode = "<?php echo file_get_contents('/var/www/html/config.php'); ?>";
file_put_contents("shell.txt", $padding . "\r\n" . $phpcode);
// 上传 shell.txt，访问 /uploads/shell.txt
```

```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=...
...
```

PoC 为上传内容构造示意，未在本机执行；实际扫描窗口、允许后缀与 Apache 配置需按目标确认。

## 变体与关联

- 变体：用 JPEG/PNG 文件头 + 填充 + PHP 代码，绕过图片类型校验与头部检测；或用 polyglot 文件。
- 变体：`.user.ini`（PHP-FPM `auto_prepend_file`）、`.htaccess` 的 `SetHandler`/`php_value auto_prepend_file`、`AddHandler` 等等价配置。
- 变体：检测只扫描前 N 字节时，把恶意内容放在文件尾部/压缩包注释/多段 multipart 的后续部分。
- 关联卡片：[[web-generic-file-upload-htaccess-handler-override]]（.htaccess handler 覆盖通用手法）、[[web-generic-file-upload-encrypted-webshell-av-bypass]]（加密 webshell 绕过 AV）、[[web-generic-file-upload-blacklist-double-write-bypass]]（后缀黑名单绕过）。
- 注意：本例为 AI×Cybersecurity Challenge MalCraft；真实环境需具体分析检测器扫描范围、Apache 配置与上传目录权限。

## 检测与防御

- 防御：内容检测必须覆盖完整文件/流，不能只扫前 N 字节；对文件尾部、压缩包、多段内容同样扫描；使用多引擎/沙箱动态分析。
- 防御：禁止上传 `.htaccess`/`.user.ini` 等服务器配置；上传目录 `AllowOverride None`；文件存储到 Web 根之外，通过下载脚本鉴权读取。
- 防御：上传目录禁用脚本执行（`php_admin_flag engine off`、独立域名/对象存储）；对图片重新编码，去除多余数据。
- 检测：上传目录出现 `.htaccess`/`.user.ini`；`.txt` 等非脚本后缀被 PHP 解析；文件前 1KB 与整体熵/内容不一致；Web 目录新增可执行内容。
- 响应：删除恶意配置与 webshell、恢复 Apache 配置、审计上传目录、轮换可能泄露的配置凭据。
