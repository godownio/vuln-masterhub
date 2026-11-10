---
id: defense-incident-response-linux-web-intrusion-triage-checklist
title: Linux Web 服务器入侵应急排查清单：UID0/登录用户/sudoers、隐藏与近期文件、rc.d/init.d、crontab、systemd、软件包
type: scenario
domain: defense
path: defense/incident-response
technique: linux-web-intrusion-triage-checklist
tags:
- incident-response
- linux
- triage
- persistence
- user-audit
- cron
- systemd
- webserver
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:31:04+08:00'
  notes: 已对照原文图12-14/17-55核对历史命令备份、netstat//proc/exe、UID0/shadow/sudoers、usermod -L+userdel -r、/tmp 隐藏文件、find -atime、rc.local/rc5.d/init.d、crontab、rpm/dpkg/systemctl 排查步骤；清单顺序与原文一致。
url: /docs/defense/incident-response/defense-incident-response-linux-web-intrusion-triage-checklist/
draft: false
kb_aliases:
- Linux 入侵排查
- 应急响应排查清单
- 可疑用户排查
- 隐藏文件排查
- rc.d init.d 后门
- crontab 排查
- systemd 自启排查
---

## 一句话结论

Linux Web 服务器被入侵（篡改/WebShell/跳转）后，按固定顺序做主机排查：先备份 `.bash_history` 等证据，再依次查网络连接与进程、UID 0/可登录/sudo 用户、敏感目录隐藏文件与近期访问文件、SysV 启动项（`rc*.d`/`init.d`/`rc.local`）、各用户 crontab、systemd enabled 单元与软件包；每条线索都要与管理员确认，发现可疑项按「先断进程、再删文件/配置、最后复查」处置。

## 原理

- **攻击者通常留下多层痕迹**：WebShell/不死马、后门账号、隐藏文件、启动脚本、计划任务、服务自启可能同时存在；只清理一处会复燃。
- **网络/进程**：`netstat -antp` 对照管理员开放端口，异常监听/外联（如陌生 IP 连入非业务端口）用 `ls -l /proc/<pid>/exe` 确认实际程序；`top`/`ps aux` 发现异常用户占用与可疑命令行。
- **用户层**：`awk -F: '$3==0{print $1}' /etc/passwd` 查 UID 0 隐藏账户；`awk '/\$1|\$6/{print $1}' /etc/shadow` 查可密码登录账户；`grep -v '^#\|^$' /etc/sudoers | grep 'ALL=(ALL)'` 查 sudo 权限。可疑账号先 `usermod -L` 锁定，再 `userdel -r` 删除（连同家目录）。
- **文件层**：`ls -al /tmp` 找 `.shell.php`、`..shell/` 等隐藏文件/目录；`find <dir> -iname "*" -atime 1 -type f` 按访问时间找近一天被动过的文件；WebShell 查杀工具（如河马 `./hm scan /www/wwwroot/`）输出 `result.csv` 后要人工复核，同名 `.png` 也可能是 PHP 后门。
- **启动层**：`runlevel` 确认运行级别；`/etc/rc.local` 是否被追加命令；`/etc/rc5.d/` 是否有无对应软件包的 `S*` 脚本（本案 `S666shell -> /etc/init.d/shell.sh`）；`/etc/init.d` 下异常脚本。
- **计划任务**：`crontab -l -u <用户>` 逐用户查（含 `www`；`www` 是 Web 服务账号，不可误删），`crontab -l` 查 root；关注 `while true`、写 shell、下载执行等条目；精确删除用 `crontab -e -u <用户>`，全清用 `crontab -r [-u <用户>]`。
- **服务/软件包**：`systemctl list-unit-files | grep enabled` 比全量列表更快；对可疑 `*.service` 看 `/etc/systemd/system/<svc>` 的 `ExecStart`，kill 进程后 `systemctl disable` 并删除单元文件；`rpm -qa`/`dpkg -l` 查非管理员安装的包。
- **为什么按顺序**：先固定证据（历史命令、日志、进程/网络快照），再处置；先杀进程/断持久化再删文件，避免不死马/cron 复燃；每条结论与管理员核对，防止误删正常服务。

## 触发条件

- 已确认或高度怀疑 Linux Web 服务器被入侵（首页篡改、WebShell、异常外联、CPU 异常等）。
- 具备 root/等效权限与 SSH 访问，能执行排查命令。
- 有管理员可确认哪些账号/服务/端口/文件是正常业务。
- 日志与文件未被攻击者完全清除（否则需从备份/流量设备补证）。

## 利用步骤（排查顺序）

1. 证据固定：`cp .bash_history shell_sw`、`cp /root/.bash_history /root/shell_root`；保存 `ps aux`、`netstat -antp`、`crontab -l`、`systemctl list-unit-files` 输出与时间戳。
2. 网络与进程：`netstat -antp` 对照开放端口；`ls -l /proc/<pid>/exe` 核实程序路径；`top`、`ps aux | grep <用户>` 找异常进程与命令行。
3. 用户：UID 0、shadow 可登录、sudoers 三连；可疑账号 `usermod -L` → 确认 → `userdel -r`；家目录一并处理。
4. 文件：`ls -al /tmp`、`/dev/shm`、Web 目录隐藏文件；`find ... -atime 1` 找近期文件；WebShell 查杀 + `result.csv` 复核。
5. 启动项：`runlevel`、`/etc/rc.local`、`/etc/rc*.d`、`/etc/init.d`；发现可疑 `S*` 链接先看目标脚本，再删链接与脚本。
6. 计划任务：逐用户 `crontab -l -u` 与 root；记录并删除恶意条目。
7. 服务与包：`systemctl list-unit-files | grep enabled`、可疑 unit 文件、`rpm -qa`/`dpkg -l` 复核。
8. 复查与加固：重启后再查进程/文件/计划任务/启动项；修补入口漏洞、上 WAF/补丁、轮换凭据。

## PoC

```bash
# 证据
cp ~/.bash_history shell_sw; sudo -s; cp /root/.bash_history /root/shell_root

# 网络/进程
netstat -antp
ls -l /proc/<pid>/exe
top; ps aux | grep www

# 用户
awk -F: '$3==0{print $1}' /etc/passwd
awk '/\$1|\$6/{print $1}' /etc/shadow
grep -v '^#\|^$' /etc/sudoers | grep 'ALL=(ALL)'
usermod -L <user>; userdel -r <user>

# 文件
ls -al /tmp
find /opt -iname "*" -atime 1 -type f
./hm scan /www/wwwroot/ && cat result.csv

# 启动项
runlevel
cat /etc/rc.local
ls /etc/rc5.d/
ls -l /etc/rc5.d/S666shell
cat /etc/init.d/shell.sh

# 计划任务
crontab -l -u <user>; crontab -l

# systemd / 软件包
systemctl list-unit-files | grep enabled
cat /etc/systemd/system/<svc>.service
rpm -qa    # CentOS
dpkg -l    # Ubuntu/Debian
```

说明：命令来自文中实验流程，`<pid>/<user>/<svc>` 为占位；未在生产环境执行。

## 变体与关联

- [[defense-incident-response-process-immortal-webshell-kill-writer]]：本清单第 4/6/5 步遇到不死马时的专门处置顺序。
- [[pentest-persistence-linux-passwd-uid0-hidden-user]]：UID 0 隐藏账户的植入手法，对应本清单的用户排查。
- [[pentest-persistence-linux-cron-reverse-shell]]：cron 持久化手法，对应计划任务排查。
- [[defense-incident-response-linux-c2-watchdog-cleanup-order]]、[[defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing]]：其他 Linux 应急场景，可与本清单组合。
- 变体：发行版差异（CentOS `rpm`/`chkconfig`/`rc.d` vs Ubuntu `dpkg`/`systemd`）；容器环境需额外查镜像层与挂载卷；宝塔等面板需查其计划任务与面板日志。
- 边界：攻击者清空日志/历史、使用 rootkit 隐藏进程/文件、或系统为只读容器时，需借助外部流量/EDR/备份取证。

## 检测与防御

- 检测：FIM 监控 Web 目录/`/etc`/`/tmp` 异常变更；auditd 监控 `crontab`、`/etc/rc*.d`、`/etc/init.d`、`systemd` unit 文件；EDR 监控 `www-data` 起 shell、异常 `while true` 写文件。
- 检测：定期跑本清单（用户/启动项/cron/服务/包）并基线化，发现新增 UID 0、可登录账号、sudo 条目、启动脚本、enabled 服务。
- 防御：最小权限（Web 用户不可写代码目录、上传目录禁执行）；禁用不需要的编译/解释器；补丁与 WAF；SSH 限源与密钥登录；日志集中到远端。
- 响应：按清单顺序处置并复查；重启验证；轮换所有可能泄露的凭据。
