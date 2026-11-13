---
id: defense-incident-response-ssh-tunnel-forwarding-triage-mstshash
title: SSH 隧道应急排查：-L/-R/-D 转发的日志留痕差异、sshd 多连接/进程树特征与 RDP 流量 mstshash 溯源
type: scenario
domain: defense
path: defense/incident-response
technique: ssh-tunnel-forwarding-triage-mstshash-attribution
aliases:
- SSH 隧道排查
- SSH 转发应急响应
- ssh -R 反向隧道发现
- 跳板机隧道取证
- mstshash 溯源
- TPKT RDP 隧道识别
tags:
- incident-response
- forensics
- ssh
- tunnel
- port-forwarding
- pivoting
- rdp
- mstshash
- windows-event-log
- auth-log
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V508
  verified_at: '2026-11-11T04:37:21+08:00'
  notes: 已对照原文与26张图逐张核对：Windows OpenSSH 事件ID4(图07)、netstat双ESTABLISHED+PID核实(图08)、RdpCoreTS/LocalSessionManager(图10/11)、TPKT与mstshash=hackme(图12/13)、Linux pstree -CfNg -R(图18前)、key.py sshenc输出(图24)、example.sh解密出flag{test}(图26)均一致。修正卡片网连特征：原文两条ESTABLISHED为两个不同sshd.exe PID(9992/9676)而非同一PID，已按截图改写原理/步骤/PoC/检测。dedup：最高候选sshd-log-bash-history-session-reconstruction(cosine0.8958)为登录会话还原，非同链；dup-scan 30对无本篇。原文无组件版本/CVE，不设affected_versions。PoC未复跑。
---

## 一句话结论

攻击者用 SSH 端口转发把跳板机变成隧道节点时，主机侧可从三处发现异常：跳板机 OpenSSH/Operational（Windows）或 auth.log（Linux）中不明 IP 的登录记录、`netstat -ano` 中多条 ESTABLISHED 连接经 `tasklist` 核实均属 `sshd.exe`（登录会话与对外转发各一条）、以及 `pstree -agplU | grep ssh` 直接暴露的 `ssh -CfNg -R/-D/-L ...` 命令行；若隧道内转发的是 RDP，目标机虽无 SSH 日志，但 RDP 的 RdpCoreTS 操作日志与 TPKT 流量中的 `mstshash=<用户名>` cookie 可用于溯源发起侧账号。

## 原理

- **三种转发与监听位置**：`-L` 本地转发在攻击机（或发起端）监听端口，经 SSH 通道把流量送到目标机；`-R` 远程转发在跳板机/服务端监听端口，把连接回送到攻击机；`-D` 动态转发在发起端建立 SOCKS 代理。`-C` 压缩、`-f` 转后台、`-N` 不执行远程命令、`-g` 允许远程主机连本地转发端口，是隧道常用组合（如 `ssh -CfNg -R 2333:192.168.44.129:22 hackme@192.168.174.128`）。
- **进程树特征（最直接）**：在跳板机执行 `pstree -agplU | grep ssh`，可看到 `ssh` 客户端进程及其完整命令行（包括 `-CfNg -R 2333:...`），攻击者来不及清理时一眼可见；正常的 sshd 登录会话不会出现带 `-R/-D` 参数的子进程。
- **网络连接特征**：`netstat -ano | find "ESTABLISHED"`（Windows）或 `netstat -panto`（Linux）中，会出现正常主机不该有的转发连接：Windows 跳板机例中两条 ESTABLISHED 的 PID（9992、9676）经 `tasklist` 核实均为 `sshd.exe`——一条是攻击机连入 22 的登录会话，另一条是跳板机内网 IP（192.168.44.1:14850）主动连向目标 3389；Linux 远程转发例中同一 `ssh` 客户端 PID（5688）同时持有到攻击机的登录连接与到目标 22 端口的转发连接。正常 sshd 只有到客户端的一条登录连接，不会主动外连目标端口。转发端口监听在 0.0.0.0（如 `-D` 的 2333）是横向可达的重要迹象。
- **日志留痕差异**：
  - Windows 跳板机：事件查看器 `Applications and Services Logs → OpenSSH → Operational` 的事件 ID 4 记录 `Accepted password for <user> from <ip> port <port> ssh2`，只记录连接事实与来源 IP/端口，不记录执行的命令与返回结果。
  - Linux 跳板机：远程转发（-R）的 SSH 认证发生在攻击机上，跳板机 `auth.log` 往往没有对应登录记录；本地转发（-L）会在跳板机留下 `sshd[pid]: Accepted password for ...` 及 sshd 子进程/多连接，反而更容易发现。攻击机上的 sshd 日志（伪造的“目标”）会让排查方向错位。
  - 目标机（被转发到的主机，如 win10 的 3389）：若通过 SSH 隧道访问 RDP，目标机没有 SSH 日志；应按 RDP 日志排查——`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` 记录 RDP 隧道的连接/关闭（含 rdpcmd、rdplic、来源 IP 与端口），`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 记录会话登录/注销（不含 IP）。
- **流量特征与溯源**：跳板机↔目标机之间是 TPKT 封装的 RDP 流量（TPKT 为 COTP 与 TCP 的过渡协议），不是 SSH；攻击机↔跳板机之间才是 SSH/SSHv2 流量。RDP 连接请求中的 X.224 Cookie `mstshash=<用户名>` 取自客户端会话用户名，可作为溯源线索（示例 `mstshash=hackme` 与攻击机用户一致）。
- **局限性**：没有流量镜像时，仅靠跳板机日志较难发现隧道；远程转发还可能完全不在跳板机留登录日志。排查需要日志、连接表、进程列表与流量多点交叉。

## 触发条件

- 事件响应中可获得跳板机/目标机的进程列表、网络连接、事件日志或 pcap（至少其一）。
- 主机开启 OpenSSH 服务（Windows 可选功能或 Linux sshd），攻击者使用 SSH 转发建立隧道。
- 日志保留 OpenSSH Operational / auth.log / RDP 相关通道，且未被攻击者清除。
- 有对应时间窗可关联。

## 利用步骤

1. **跳板机日志**：Windows 查看 `OpenSSH/Operational` 事件 ID 4 的来源 IP/端口与时间；Linux 查看 `/var/log/auth.log` 中 `Accepted password/publickey for ... from <ip>`，标记与业务无关的来源 IP。
2. **网络连接**：Windows `netstat -ano | find "ESTABLISHED"`，按 PID 关联 `tasklist | findstr <pid>`，核对多条 ESTABLISHED 是否均属 sshd.exe、sshd/ssh 是否主动连向内部目标端口，以及 0.0.0.0 转发监听端口；Linux `netstat -panto`、`ss -tnp` 同法。
3. **进程树**：Linux `pstree -agplU | grep ssh` 或 `ps aux | grep ssh`，查找 `ssh -CfNg -R/-D/-L ...` 完整命令行；Windows 检查 sshd 子进程及命令行（如 Sysmon/EDR 进程树）。
4. **目标机 RDP 日志**：在 `RdpCoreTS/Operational` 中按时间关联来源 IP:端口与 `rdpcmd`/`rdplic` 事件；在 `LocalSessionManager/Operational` 看会话登录/注销与用户名。
5. **流量确认与溯源**：抓包过滤 `tcp.port==3389` 观察 TPKT/RDP 与 `mstshash` cookie；过滤 `ssh` 查看 SSHv2 握手与转发端口对应的加密流；将 `mstshash` 用户名与攻击机账号/其他日志比对。
6. **还原与处置**：结合目标机 `history`/`last`（Linux）或 RDP 会话记录还原操作；终止 ssh/sshd 转发进程、封禁来源 IP、关闭对外转发端口，并检查是否还有其他隧道。

## PoC

```text
# 1) 跳板机网络连接：sshd.exe 的多条 ESTABLISHED + 0.0.0.0 转发监听（Windows）
netstat -ano | find "ESTABLISHED"
tasklist | findstr "sshd"
# 输出示例：192.168.44.1:14850→192.168.44.128:3389 与 192.168.174.1:22→192.168.174.128:54954
# 两条 ESTABLISHED 的 PID 分别为 9992、9676，tasklist 核实均为 sshd.exe

# 2) Linux 跳板机：直接看到反向隧道命令行
pstree -agplU | grep ssh
# └─ssh,5688,5688 -CfNg -R 2333:192.168.44.129:22 hackme@192.168.174.128

# 3) Windows 跳板机 OpenSSH 日志（事件 ID 4）
# OpenSSH/Operational: Accepted password for lenovo from 192.168.174.128 port 54954 ssh2

# 4) RDP 流量中的 mstshash cookie（Wireshark / tshark）
tshark -r tunnel.pcap -Y "tcp.port==3389" -T fields -e data | grep -a mstshash
# Cookie: mstshash=hackme
```

## 变体与关联

- **SSH 日志会话还原**：拿到跳板机 sshd 日志与目标机 bash_history 后按时间窗还原攻击者命令（[[defense-forensics-sshd-log-bash-history-session-reconstruction]]）；本卡聚焦“隧道转发”留下的连接/进程/流量特征。
- **流量侧识别**：SSH 隧道形状可用 JA4SSH（200 包窗口的 Payload 长度众数与 ACK 统计）在不看内容的情况下识别（[[defense-detection-ja4ssh-ssh-traffic-fingerprint]]）。
- **解密还原**：若拿到 pcap 与相关主机内存，可从 sshd 进程内存提取 sshenc 会话密钥解密 SSH 流量（[[defense-forensics-openssh-session-key-memory-sshenc-pcap-decrypt]]），进一步确认转发的命令与数据。
- **变体**：`-D` 动态转发表现为 SOCKS 端口监听，客户端流量来自本机不同进程；`-L` 会留下 sshd 登录日志；Windows 上还可用 `Get-WinEvent -LogName OpenSSH/Operational` 批量筛选事件 ID 4。
- **边界**：远程转发认证在攻击机完成，跳板机可能没有任何登录日志；攻击者清理 history/进程后需依赖流量与网络设备日志（防火墙/NAT/NetFlow）。

## 检测与防御

- **检测**：OpenSSH/auth.log 中非常用来源 IP 的登录；sshd.exe PID 出现对外 ESTABLISHED（尤其连向 3389/22 等目标端口）与 0.0.0.0 转发监听端口；sshd 子进程命令行含 `-L/-R/-D/-N/-f/-g`；RDP RdpCoreTS 日志出现异常来源的隧道连接；流量中 TPKT/RDP 与 SSH 交织、`mstshash` 用户名异常。
- **检测**：JA4SSH 指纹识别隧道形状；NAT/防火墙日志中同一内网主机对外多条长连接；EDR 对 `ssh` 进程参数与网络行为的监控。
- **防御**：sshd 配置 `AllowTcpForwarding no`（按需给特定用户/组开启）、`PermitOpen` 限制目标、`GatewayPorts no` 禁止 0.0.0.0 转发监听；SSH 仅对内网/堡垒机开放，强制多因素与短会话；RDP 仅经 VPN/堡垒机访问并开启 NLA。
- **加固**：集中收集 OpenSSH/Operational、RdpCoreTS 与 auth.log，开启命令行审计（Sysmon Event ID 1/4688、auditd `execve`），保留 NetFlow/pcap 以便事后还原；定期检查跳板机的转发与监听端口。
