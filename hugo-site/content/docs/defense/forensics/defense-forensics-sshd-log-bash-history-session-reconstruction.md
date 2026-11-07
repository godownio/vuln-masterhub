---
id: defense-forensics-sshd-log-bash-history-session-reconstruction
title: SSH 日志取证：sshd.log + bash_history 关联还原攻击者登录与命令会话
type: scenario
domain: defense
path: defense/forensics
technique: sshd-log-bash-history-session-reconstruction
tags:
- forensics
- ssh
- auth-log
- bash-history
- incident-response
- session-reconstruction
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:40+08:00'
  notes: 已对照原文与图片44-53核对：2221 端口、首次成功登录、异常 root 登录、whoami/./setup 会话序列一致；已修正指纹来自 Failed publickey 行；PoC 未复跑。
url: /docs/defense/forensics/defense-forensics-sshd-log-bash-history-session-reconstruction/
draft: false
kb_aliases:
- SSH 日志分析
- sshd.log 取证
- bash_history 会话还原
- 异常登录定位
- 公钥指纹
- 攻击者命令序列
---

## 一句话结论

把 `sshd.log` 中的 `Accepted password/publickey`、`Starting session`、`Disconnected` 与 `bash_history` 的时间戳对齐，可以还原攻击者的登录会话：先定位 SSH 服务 IP:PORT 和首个成功登录，再找异常时间/来源的 root 登录及其公钥指纹，最后按会话时间窗提取第一条和最后一条命令，形成完整时间线。

## 原理

- **sshd 日志字段**：`Accepted password for <user> from <ip> port <port> ssh2` 表示认证成功；`Accepted publickey for <user> ... ssh2: <算法> <指纹>` 还会给出公钥指纹（`Failed publickey` 行同样带 `ssh2: <算法> <指纹>`，可暴露尝试过的攻击者公钥）；`Starting session: shell on pts/N for <user> from <ip> port <port>` 标记会话开始；`syslogin_perform_logout`/`Received disconnect`/`Disconnected from user` 标记结束。
- **服务地址**：`Server listening on 0.0.0.0 port 2221` 给出 SSH 服务监听地址/端口；题目中的“SSH Server IP:PORT”通常指被攻击服务器的地址（结合日志中的目标 IP）。
- **会话时间窗**：一次登录 = 一条 `Accepted ...` + `Starting session`，到对应的 `Disconnected/Received disconnect` 结束；窗口内的命令历史属于该会话。
- **bash_history 时间戳**：若启用了 `HISTTIMEFORMAT`，历史文件会有 `#<epoch>` 行；没有时间戳时，用登录/登出时间和文件顺序做近似，或从 auditd/进程日志补全。
- **异常判定**：root 在凌晨登录、来源 IP 与常规办公网不同、失败后紧接成功、使用密码而非公钥、登录后执行侦察/下载/提权命令（`whoami`、`uname -a`、`cat /etc/passwd`、`wget`、`tar`、`shred`、`./setup`）都是高价值信号。
- **公钥指纹**：`Accepted/Failed publickey` 行的指纹可唯一标识攻击者使用的密钥；与 `~/.ssh/authorized_keys`、其他主机日志比对可做横向关联。

## 触发条件

- 拿到 `sshd.log`/`auth.log` 与用户 `bash_history`（或 auditd/命令日志）。
- 日志保留时间戳、用户名、源 IP、端口、认证方式、会话开始/结束记录。
- 能确定目标服务器的 IP/端口（日志中的监听地址或题目给定资产）。
- 历史文件保留攻击者会话的命令（未被清除/截断）。

## 利用步骤

1. **服务地址**：搜索 `Server listening on`，记录监听地址/端口；结合题目/资产确定服务器 IP 与端口。
2. **成功登录列表**：提取所有 `Accepted password/publickey`，按时间排序；第一条即首次成功登录。
3. **异常登录**：按用户（root）、时间（凌晨/非工作时段）、源 IP（陌生/境外）、认证方式（密码）筛选；常见异常是 root 在凌晨从新 IP 登录。
4. **公钥指纹**：在 `Accepted/Failed publickey` 行提取 `ssh2: <算法> <指纹>`，记录攻击者公钥；本例攻击者最终用密码登录，指纹来自一次 `Failed publickey` 尝试。
5. **会话边界**：从异常 `Accepted` 行向下找 `Starting session`，再找 `Disconnected`/`Received disconnect`/`syslogin_perform_logout`，确定会话起止时间。
6. **命令序列**：在该时间窗内读取 `bash_history`：第一条命令通常是 `whoami`/`id`/`uname -a`，最后一条是登出前执行的命令（如 `./setup`）；按时间戳或文件顺序排列。
7. **交叉验证**：用 `last`/`lastlog`、`wtmp`、`auditd`、进程/网络日志复核；检查 `authorized_keys` 是否被追加、`/tmp` 下载文件、cron/systemd 持久化。

## PoC

```bash
# 1) 服务监听地址/端口
grep -n "Server listening" sshd.log

# 2) 成功登录（按时间排序）
grep -E "Accepted (password|publickey)" sshd.log | sort

# 3) 首次成功登录
grep -E "Accepted (password|publickey)" sshd.log | sort | head -1

# 4) 异常 root 登录（示例：凌晨 04:00）
grep -E "Accepted .* for root" sshd.log | grep "04:0"

# 5) 会话起止
grep -nE "Accepted|Starting session|Disconnected|Received disconnect|syslogin_perform_logout" sshd.log

# 6) 命令历史
cat bash_history.txt
# 若带 HISTTIMEFORMAT：
grep -n '^#' bash_history.txt | head
```

Python 关联示例：

```python
import re
from datetime import datetime

log = open("sshd.log", encoding="utf-8", errors="ignore").read().splitlines()
events = []
for line in log:
    m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*(.*)", line)
    if not m:
        continue
    ts, msg = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"), m.group(2)
    if "Accepted" in msg or "Starting session" in msg or "Disconnected" in msg:
        events.append((ts, msg))

for ts, msg in sorted(events):
    print(ts, msg)
```

从 `bash_history` 按会话窗口过滤：

```python
start = datetime(2024, 2, 19, 4, 0, 14)
end = datetime(2024, 2, 19, 4, 38, 17)
# 若历史行带 #epoch 时间戳，解析后只保留 [start, end] 内的命令
```

## 变体与关联

- **仅公钥登录**：`Accepted publickey` 的指纹是核心 IOC；与 `authorized_keys` 中的 key 指纹比对，判断是否被植入。
- **无 bash_history**：用 auditd `EXECVE`、`lastcomm`、`/proc` 残留、shell 历史备份（`.bash_history-`、`~/.zsh_history`）补全。
- **日志被清除**：检查 `wtmp`/`btmp`、journald、SIEM 副本、文件系统未分配空间恢复。
- **横向移动**：用攻击者源 IP/公钥指纹搜索其他主机日志，判断是否扩散。
- **关联卡片**：[[defense-detection-ssh-bruteforce-alert-iptables-block]]（SSH 爆破检测）；[[pentest-lateral-movement-ssh-key-history-autospread-cron]]（SSH 密钥/历史横向）。

## 检测与防御

- **日志集中**：把 sshd/auth.log 实时送到 SIEM，防止本地清除；保留 ≥90 天。
- **登录加固**：禁用 root 密码登录，强制公钥/多因素；限制源 IP；失败锁定/速率限制。
- **审计**：启用 `HISTTIMEFORMAT`、auditd 命令审计、`lastlog/wtmp` 保留；定期核查 `authorized_keys`。
- **告警**：root 非工作时段登录、陌生 IP、密码认证成功、短时间失败后成功、登录后下载/压缩/删除命令。
