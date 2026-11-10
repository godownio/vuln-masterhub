---
id: defense-incident-response-bash-history-hydra-useradd-uid0
title: Linux 应急历史命令取证：bash_history 定位 hydra/medusa 爆破与 useradd UID 0 后门
type: scenario
domain: defense
path: defense/incident-response
technique: bash-history-hydra-useradd-uid0-backdoor
tags:
- incident-response
- linux
- forensics
- bash-history
- hydra
- medusa
- useradd
- uid0
- backdoor-account
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:11:10+08:00'
  notes: 已对照图18 .bash_history（yum install hydra/medusa/masscan、hydra -M 5.txt ssh -l root -P pass.txt -e ns -T 20 -f -V -O good.txt、medusa 命令）、图19 who 显示 37.8.22.101 运行 hydra、图20 /usr/sbin/useradd -o -u 0 -g 0 r00t -p admin1234 与 passwd r00t 核对，关键命令与时间戳一致；属单一 bash_history 取证链。未复现。
url: /docs/defense/incident-response/defense-incident-response-bash-history-hydra-useradd-uid0/
draft: false
kb_aliases:
- bash_history 时间戳取证
- 历史命令发现爆破工具
- useradd -o -u 0 后门账户
- hydra medusa masscan 痕迹
- who 查看攻击者会话
- HISTTIMEFORMAT 时间线
---

## 一句话结论

检查带 `HISTTIMEFORMAT` 时间戳的 `.bash_history`，可把攻击者的操作还原成时间线：`yum install hydra/medusa/masscan` 安装爆破与扫描工具、用字典对 SSH 做爆破、`useradd -o -u 0 -g 0 r00t -p admin1234` 创建与 root 等权的后门账户、`passwd r00t` 改密码；`who` 还能看到来自外部 IP 的 hydra 会话。

## 原理

- **历史命令是攻击者操作的直接记录**：bash 在 `HISTTIMEFORMAT` 设置后，会以 `#<epoch 秒>` 注释行记录每条命令的时间；导出/查看 `.bash_history` 即可把命令与时间对应，形成时间线。
- **工具安装暴露意图**：`yum install hydra -y`、`yum install medusa -y`、`yum install masscan -y` 说明攻击者已有 root 或 sudo 权限，并准备做在线口令爆破与端口扫描；`hydra -M 5.txt ssh -l root -P pass.txt -e ns -T 20 -f -V -O good.txt` 是典型的 SSH 字典爆破命令。
- **成功结果落地**：`cat good.txt` 表示爆破结果被保存；`who`/`w` 中可看到 hydra 进程及其来源 IP（本题为 `37.8.22.101`），与历史命令互相印证。
- **后门账户**：`useradd -o -u 0 -g 0 r00t -p admin1234` 中的 `-o` 允许 UID 非唯一，`-u 0 -g 0` 使新账户与 root 等权；`-p` 直接指定密码（具体被解释为明文还是哈希取决于系统/passwd 实现），随后 `passwd r00t` 再次设置。该账户可长期登录且不依赖恶意二进制。
- **为什么历史可靠但不够**：历史文件可被攻击者删除/覆盖/禁用（`HISTFILE=/dev/null`、`unset HISTFILE`），因此需要与 `auth.log`、`auditd`、集中日志交叉验证；但本题历史未被清理，成为关键证据。

## 触发条件

- 能读取目标主机的 `/root/.bash_history`、`/home/*/.bash_history` 或镜像中的对应文件。
- shell 配置了 `HISTTIMEFORMAT` 或历史文件中保留了 `#<epoch>` 时间戳注释。
- 攻击者在交互式 shell 中执行了安装、爆破、建账户等命令，且未清理历史。
- 有 `who`/`w`/`last`/`ps` 等会话与进程证据可交叉。

## 利用步骤

1. 固定证据：复制 `.bash_history` 并记录哈希、mtime、所属用户；不要在原文件上直接操作。
2. 定位可疑命令：`grep -nE 'yum install|hydra|medusa|masscan|useradd|passwd|wget|curl|chmod|chattr' /root/.bash_history`。
3. 还原时间线：把 `#<epoch>` 转成可读时间，与 `auth.log` 的登录/爆破时间、文件 mtime 对齐。
4. 交叉会话：`who`、`w`、`last`、`ps auxww` 查看当前/历史登录来源与爆破进程；本题 `who` 显示 `37.8.22.101` 上运行 hydra。
5. 检查账户：`awk -F: '$3==0 {print}' /etc/passwd`、`getent passwd`，找出额外的 UID 0 账户；核对 `/etc/shadow` 与 sudoers。
6. 处置：删除后门账户、重置 root 及相关口令、封禁来源 IP、排查是否还有 authorized_keys/crontab/systemd/ld.so.preload 等持久化。

## PoC

```bash
# 1) 找可疑历史命令
grep -nE 'yum install|hydra|medusa|masscan|useradd|passwd|wget|curl' /root/.bash_history

# 2) 把 #epoch 转成可读时间（HISTTIMEFORMAT 注释行）
while IFS= read -r line; do
  case "$line" in
    \#*) printf '%s ' "$(date -d "@${line#\#}" '+%F %T')" ;;
    *)   printf '%s\n' "$line" ;;
  esac
done < /root/.bash_history

# 3) 当前/历史会话与爆破进程
who
w
ps auxww | grep -Ei 'hydra|medusa|masscan'

# 4) 查找额外 UID 0 账户
awk -F: '$3==0 {print $1, $3, $7}' /etc/passwd
```

本题历史中的关键行（时间戳已转写）：

```text
yum install hydra -y
yum install medusa -y
yum install masscan -y
hydra -M 5.txt ssh -l root -P pass.txt -e ns -T 20 -f -V -O good.txt
/usr/sbin/useradd -o -u 0 -g 0 r00t -p admin1234
passwd r00t
cat good.txt
```

## 变体与关联

- **无时间戳历史**：只有命令顺序，可用相邻文件 mtime、auth.log 登录时间、yum/dnf 日志（`/var/log/dnf.log`、`/var/log/yum.log`）补齐时间。
- **其他 shell**：`~/.zsh_history`（`EXTENDED_HISTORY` 带 `: <epoch>:<elapsed>;`）、fish 历史；root 的 history 可能在 `/root/.bash_history` 或镜像对应分区。
- **历史被清理**：转向 `auditd` 的 `execve`、`auth.log` 的 sudo/sshd 事件、包管理器日志、`/etc/passwd` mtime、进程内存中的命令历史。
- **账户持久化变体**：直接写 `/etc/passwd`、写 `/etc/shadow`、`useradd` + `chpasswd`、sudoers 添加、authorized_keys；见 [[pentest-persistence-linux-passwd-uid0-hidden-user]]。
- 关联：[[defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing]]（auth.log 视角的 SSH 爆破与 sshd 后门）。

## 检测与防御

- **检测**：集中采集 shell 历史/auditd 并保留时间戳；对 `yum install hydra/medusa/masscan`、`useradd -o -u 0`、`passwd`、批量 SSH 失败等组合告警；定期对比 UID 0 账户基线。
- **防御**：SSH 禁止 root 直接登录、强制密钥/MFA、fail2ban/速率限制；限制 yum/apt 安装权限；启用 auditd 监控 `/etc/passwd`、`/etc/shadow`、`sudoers` 修改。
- **响应**：删除后门账户并锁定 root 交互登录，轮换所有可能泄露的凭据，封禁爆破源 IP，排查 web/cron/systemd/ld.so.preload 等其他持久化。
