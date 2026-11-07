---
id: defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing
title: Linux 挖矿应急响应：auth.log 定位 SSH 爆破源与被替换 sshd，dnsmasq 日志溯源矿池域名并识别 kinsing 家族
type: scenario
domain: defense
path: defense/incident-response
technique: linux-authlog-ssh-bruteforce-sshd-backdoor-dnsmasq-mining-kinsing
aliases:
- SilentMiner
- SSH 爆破溯源
- sshd 被替换后门
- dnsmasq 日志挖矿域名
- tracker-miner 伪装
- kinsing 挖矿家族
tags:
- incident-response
- forensics
- linux
- auth-log
- ssh-bruteforce
- sshd-backdoor
- dnsmasq
- mining
- kinsing
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:10:17+08:00'
  notes: 已对照原文与图 2-6、9 核对：火眼提取 /var/log/auth.log，爆破源 192.168.145.131、失败 258 次；sudo tee sshd 与 service sshd restart 定位 /usr/sbin/sshd；dnsmasq.log 过滤得 tombaky.com；tracker-miner 经 AI/检索归为 kinsing；问卷图 9 五项答案与卡一致。未在本地镜像复跑脚本。
---

## 一句话结论

对磁盘镜像的 `/var/log/auth.log` 统计 `Failed password` 可定位 SSH 爆破源 IP 与失败次数（本例 `192.168.145.131`、258 次）；同一日志里的 `sudo ... tee sshd` 与 `service sshd restart` 暴露攻击者用 root 权限覆盖 `/usr/sbin/sshd` 的后门；再从 `dnsmasq.log` 过滤 `.cn/.com` 域名得到矿池域名，并按 `tracker-miner` 伪装路径与进程特征把挖矿样本归到 kinsing 家族。

## 原理

- **auth.log 是 SSH 认证事件的事实来源**：`sshd`/PAM 会记录 `Failed password for <user> from <ip> port <port> ssh2`、`error: maximum authentication attempts exceeded for <user> from <ip>`、`Disconnecting authenticating user ... Too many authentication failures` 等行。按 `Failed password` 计数即可量化爆破；按 `from <ip>` 聚合即可定位源地址。本例 258 次失败全部来自 `192.168.145.131`，并伴随 “maximum authentication attempts exceeded”，说明是自动化字典/暴力尝试而非正常误输。
- **成功登录后的 sudo 记录暴露后门写入**：日志中 `sudo: lee : TTY=pts/0 ; PWD=/home/lee ; USER=root ; COMMAND=/usr/bin/tee sshd` 表明低权限用户 `lee` 通过 sudo 以 root 执行 `tee`，把内容写到名为 `sshd` 的文件；后续多次 `tee -a` 追加，再执行 `service sshd restart`。结合绝对路径可判定被篡改的是 `/usr/sbin/sshd`，攻击者借此植入可持久化的 SSH 后门（例如记录口令、追加公钥或替换认证逻辑）。
- **dnsmasq.log 暴露矿池/C2 域名**：dnsmasq 的查询日志包含客户端、查询域名、时间等字段。挖矿样本需要解析矿池域名，按 `.cn`、`.com` 等后缀过滤并统计出现频率，可把正常域名噪声压下去；本例命中 `tombaky.com`。域名本身不等于恶意，需结合查询时间、客户端、进程与文件落地综合判断。
- **路径/字符串映射到家族**：镜像中出现 `/usr/lib/x86_64-linux-gnu/tracker-miners-2.0` 与 `tracker-miner` 字样，看似合法的桌面索引组件，但该路径/名称与主机的实际软件包不一致（例如系统未安装 tracker 或文件哈希/签名不匹配），属于挖矿样本常见的“伪装成系统组件”。已知 kinsing 家族会伪装为 `tracker-miner`/`kdevtmpfsi` 等进程名，因此可归为 kinsing。
- **为什么把这几步串起来**：爆破获得 SSH 凭据 → 登录后 sudo 覆盖 `sshd` 持久化 → 下载/运行挖矿样本 → 通过 DNS 解析矿池域名。日志、DNS、文件系统三类证据互相印证，比单一日志更可靠。

## 触发条件

- 可获取 Linux 主机磁盘镜像或在线主机的 `/var/log/auth.log`、`/var/log/dnsmasq.log`（或 syslog/journal 中对应内容），且日志未被攻击者清空。
- SSH 允许密码认证并记录失败/成功事件；`sudo` 记录保留 `COMMAND=` 字段。
- dnsmasq 开启了查询日志（`log-queries`），或存在其他 DNS 日志/流量。
- 文件系统保留可疑二进制/路径/进程名，或可对镜像做 `strings`/哈希/包完整性比对。
- 有基本日志分析工具（grep/awk/Excel/火眼等取证工具）。

## 利用步骤

1. **固定证据**：对磁盘镜像只读挂载或复制日志；记录镜像哈希、日志文件哈希与时间范围，避免在原始证据上直接操作。
2. **定位 auth.log**：在镜像的 `/var/log/`、`/var/log/journal/` 或分区 5 等位置找 `auth.log`、`secure`、`auth.log.1`；确认时间范围覆盖事件。
3. **统计爆破**：
   ```bash
   grep -c "Failed password" auth.log
   grep "Failed password" auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -nr
   grep -E "Accepted|maximum authentication attempts|Disconnecting authenticating user" auth.log
   ```
   本例得到 258 次失败、源 `192.168.145.131`；若日志轮转，需要合并 `auth.log*` 并去重。
4. **查成功登录与 sudo**：筛 `Accepted`、`sudo:`、`COMMAND=`，重点看 `tee`/`cp`/`chmod`/`service sshd restart` 等写系统文件或重启服务的命令；本例定位 `/usr/sbin/sshd`。
5. **分析 DNS**：
   ```bash
   grep -iE '\.(cn|com)$' dnsmasq.log | awk '{print $NF}' | sort | uniq -c | sort -nr | head
   ```
   结合查询时间与客户端 IP，筛出 `tombaky.com` 等矿池/C2 域名。
6. **定位挖矿样本**：在文件系统中搜索 `tracker-miner`、`kdevtmpfsi`、`kinsing` 等字符串/路径，检查文件哈希、签名、所属包与进程命令行；本例路径 `/usr/lib/x86_64-linux-gnu/tracker-miners-2.0` 与合法 `tracker-miners` 包不符。
7. **处置**：隔离主机/封禁源 IP 与域名；从官方源重装 `openssh-server` 恢复 `/usr/sbin/sshd`；删除挖矿进程、定时任务、服务和载荷；轮换 SSH 密钥/口令与所有可能泄露的凭据；复查 `authorized_keys`、`/etc/passwd`、crontab、systemd 服务与 `ld.so.preload`。

## PoC

以下为只读分析片段，不对应具体镜像路径；计数和字段位置需按日志格式调整：

```bash
# 1) 失败次数与源 IP
grep "Failed password" auth.log | wc -l
grep "Failed password" auth.log | grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' \
  | sort | uniq -c | sort -nr

# 2) 成功登录、sudo 与 sshd 写入/重启
grep -nE "Accepted|sudo:|tee|service sshd restart" auth.log

# 3) DNS 查询中的可疑域名
grep -iE '\.(cn|com)$' dnsmasq.log | awk '{print $NF}' | sort -u

# 4) 挖矿样本路径/字符串
find / -iname '*tracker-miner*' -o -iname '*kinsing*' 2>/dev/null
strings -a /suspicious/binary | grep -iE 'tracker-miner|kinsing|stratum|pool'
```

原文在问卷中给出的结论是：攻击者 IP `192.168.145.131`、失败次数 258、后门文件 `/usr/sbin/sshd`、恶意域名 `tombaky.com`、挖矿家族 `kinsing`。不同镜像的日志轮转和字段可能不同，以上命令需按实际格式调整。

## 变体与关联

- **日志被清空**：转查 journald 二进制日志、`wtmp/btmp/lastlog`、bash history、systemd journal 备份、EDR/防火墙日志与 DNS 流量；不要只依赖 `auth.log`。
- **密钥登录/无爆破**：若攻击者用泄露的私钥直接登录，`Failed password` 可能为 0；应重点看 `Accepted publickey`、异常源 IP/时间、`authorized_keys` 变更。
- **后门形态**：除直接替换 `sshd` 外，还可能是 PAM 模块、`authorized_keys` 追加、`/etc/ld.so.preload`、systemd 服务或 SSH 配置 `ForceCommand`；需做包完整性校验和配置 diff。
- **挖矿家族识别**：`tracker-miner`、`kdevtmpfsi`、`kinsing` 是常见伪装/家族名；最终应以样本哈希、矿池域名、命令行和持久化机制综合定性，不要只凭文件名。
- 关联：[[defense-incident-response-docker-tomcat-mining-triage]]（容器内 Tomcat 挖矿入侵溯源）、[[defense-incident-response-linux-c2-watchdog-cleanup-order]]（Linux C2/看门狗清除顺序）、[[pentest-lateral-movement-internal-ssh-root-weak-password]]（SSH 弱口令横向）。

## 检测与防御

- **认证侧**：禁用 SSH 密码认证，改用密钥/证书；限制来源 IP；部署 fail2ban/SSHGuard 对失败次数限速与封禁；开启 MFA。
- **完整性侧**：用 `dpkg -V openssh-server`/`rpm -Va`、AIDE/Tripwire 监控 `/usr/sbin/sshd`、PAM、`authorized_keys`、`/etc/ssh/sshd_config`；禁止普通用户对系统二进制所在目录写权限，审计 `sudo tee`/`cp` 到系统路径的命令。
- **网络侧**：集中采集 DNS 查询日志，阻断/告警已知矿池域名与新注册可疑域名；限制主机出站 3333/4444/5555/7777/14444 等矿池常用端口。
- **检测特征**：同一 IP 短时间内大量 `Failed password`、`maximum authentication attempts exceeded`；`sudo` 命令中出现 `tee`/`cp` 写 `sshd` 并伴随 `service sshd restart`；`tracker-miner`/`kdevtmpfsi`/`kinsing` 进程或文件；DNS 查询集中到单一陌生域名。
