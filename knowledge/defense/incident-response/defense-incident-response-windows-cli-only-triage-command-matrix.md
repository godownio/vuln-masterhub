---
id: defense-incident-response-windows-cli-only-triage-command-matrix
title: 拿不到图形界面时的 Windows 应急排查：用 Get-WinEvent 的 FilterHashtable 时间窗、netstat -ano→PID→wmic 父进程链、tasklist /m 模块反查与 forfiles 时间窗，把日志/账户/网络/进程/服务/自启/共享七个面全部覆盖
type: scenario
domain: defense
path: defense/incident-response
technique: windows-cli-only-incident-triage-command-matrix
aliases:
- Windows 命令行应急排查
- 无 GUI 主机排查
- Get-WinEvent FilterHashtable
- netstat -ano 定位 PID
- wmic 父进程链
- tasklist /m 模块反查
- forfiles 时间窗搜文件
- 隐藏用户 $ 排查
tags:
- incident-response
- windows
- triage
- powershell
- command-line
- log-analysis
- process-tree
- persistence
- timeline
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:45:57+08:00'
  notes: 已对照原文核对：Get-WinEvent/FilterHashtable、netstat -ano、wmic 父进程、tasklist /m 与 /fi、forfiles /D 时间窗、net user 隐藏账户、wmic startup 字段、net share/Get-SMBShare 等命令与原文一致；原文为无版本排查手册，未设 affected_versions；本次核对未读取图片，仅依据正文
---

## 一句话结论

只能命令行操作 Windows 主机时，排查不必依赖任何第三方工具：用 `Get-WinEvent -FilterHashtable` 按 `LogName`/`ID`/`StartTime` 精确取日志，用 `netstat -ano` 拿到 PID 再 `wmic process where ProcessId=… get ParentProcessId` 一路追到 `services.exe` 还原进程树，用 `tasklist /m <dll>` 反查「哪个进程加载了可疑模块」，用 `forfiles /D -N` 把时间窗内的落地文件捞出来 —— 这四组命令加上账户、服务、自启、共享的枚举，就能在无 GUI 现场把七个面覆盖全。

## 原理

- **日志面：`Get-WinEvent -FilterHashtable` 比 `Where-Object` 快且可精确控窗**。哈希表支持 `LogName`/`ID`/`StartTime`/`EndTime`/`ProviderName` 等键，在 ETW 层过滤，不必把整个 evtx 读进管道；`-ListLog *` 先枚举日志名（`Microsoft-Windows-PowerShell/Operational` 这类名字必须来自这里，写错就是空结果）；`-MaxEvents N` 用于「今天最近 N 条」这种增量场景。
- **时间窗的坑**：`Get-Date -Hour` 只接受 0–23，想把窗口开到当天最后一刻必须写 `-Hour 23 -Minute 59`，否则构造出的 `EndTime` 会落到次日。
- **PowerShell 日志是脚本内容的金矿**：4104（Script Block Logging）直接记录被执行的脚本文本，4100（引擎状态/错误）辅助定位；两者一起查能还原无文件攻击的执行内容，比只看进程创建事件有用得多。
- **网络面：`netstat -ano` 的 `-o` 是枢纽**。`-a` 全部连接、`-n` 不解析、`-o` 给出 PID、`-b` 给出可执行文件名（需管理员）、`-r` 路由表；拿 `| findstr "ESTABLISHED"` 或 `| find "ESTABLISHED"` 过滤出活的出站连接，末尾就是 PID，再用进程面命令把这个 PID 还原成「路径 + 父进程 + 命令行」。
- **进程树是判断「谁拉起了它」的唯一可靠手段**：`wmic process where ProcessId=<pid> get ParentProcessId` 拿到父 PID，再对父 PID 重复，直到 `services.exe`——正常链是 `services.exe → svchost.exe → 业务进程` 或 `explorer.exe → 用户进程`；若出现 `w3wp.exe → cmd.exe → powershell.exe`、`sqlservr.exe → cmd.exe` 这类跨层跳跃，基本就是 webshell/数据库命令执行留下的痕迹。
- **模块反查：`tasklist /m <dll>` 解决的是「DLL 侧注入」**。`tasklist /m` 列出每个进程加载的模块，指定 DLL 名即反查所有加载它的进程；排查可疑 DLL（尤其落在用户可写目录的）时，这是从「文件」回到「宿主进程」的最短路径。
- **筛选器的比较运算符**：`tasklist /fi` 支持 `eq/ne/gt/lt/ge/le`，可按 `PID`/`IMAGENAME`/`MEMUSAGE`/`STATUS`/`SERVICES` 过滤，省掉 `findstr` 的误匹配（`tasklist | findstr 10004` 会把命令行里含该数字的进程也带出来）。
- **账户面：`$` 结尾的隐藏账户在 `net user` 里看不到**。`net user` 只列普通账户，隐藏账户（名字以 `$` 结尾）要用 `lusrmgr.msc`、`wmic UserAccount get` 或注册表 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` 下的 `ProfileImagePath` 才能确认——后者还能量出「系统里到底建过几个用户配置」，即使账户已被删、Profile 目录还在。
- **在线用户与登录时间**：`query user` 给出当前会话与登录时间（判断是否有人正连着），`net user <name>` 给出上次登录时间（判断账户是否被用过），`net localgroup administrators` / `Get-LocalUser` 给出权限归属。
- **自启面**：`wmic startup get Name,Command` 与 `Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User` 拿到「启动项 → 命令 → 位置 → 账户」四元组；`Location` 字段能区分 Run 键/启动目录/服务，是判断「谁写的」的关键。
- **服务/任务/共享/驱动面**：`net start` 看已启动服务，`tasklist /svc` 把服务映射到 PID（找出「服务宿主里跑着什么」），`schtasks` 列计划任务，`Get-SMBShare`/`net share` 看共享（横向移动与数据外带通道），`driverquery` 看驱动（BYOVD/rootkit 面）。
- **文件面：`forfiles /D -N` 是「按时间捞落地物」的标准姿势**。`/D -30` 取 30 天内修改的文件，`/S` 递归、`/M *.exe` 按掩码筛、`/C "cmd /c echo @path @fdate @ftime @fsize"` 输出路径与时间戳；配合 `%TEMP%`、`%APPDATA%`、`C:\Windows\Temp`、`Prefetch`、`amcache.hve` 这些固定落脚点，能在不装取证工具的情况下框出攻击者的投递时间。
- **为什么值得整理成矩阵而不是背单条命令**：应急现场的时间压力下，漏面比漏命令更致命；把「日志/账户/网络/进程/服务/任务/自启/共享/文件/时间」列成表，每面至少一条原生命令，才能在无网络、无工具、无 GUI 的三无环境下仍产出完整证据链。

## 触发条件

- 只能通过远程 shell / 串口 / 安全模式命令行操作 Windows 主机，无法使用图形界面或第三方取证工具。
- 主机疑似被入侵（异常外联、可疑进程、文件被改），需要在现场快速定位入口、持久化与影响面。
- 具备管理员权限（读取其它进程路径、`netstat -b`、安全日志、`driverquery` 都需要）。
- 安全日志未被清空（若已被 `wevtutil cl` 清过，需转从 Sysmon/EDR/网络侧取证）。

## 利用步骤

1. **先定时间窗**：从告警/用户描述里拿到大致时间，用 `Get-Date` 构造 `StartTime`/`EndTime`（`-Hour` 不超过 23），后续所有查询都复用这个窗口，避免逐条命令重复过滤。
2. **日志面**：`Get-WinEvent -ListLog *` 枚举日志名 → 按 `LogName`/`ID` 取安全日志（4624 登录、4688 进程创建、4698 任务创建、7045 服务安装）与 PowerShell 日志（4104 脚本块、4100 引擎）→ 记录关键时间点。
3. **账户面**：`net user` + `wmic UserAccount get` + `ProfileList` 三处交叉，确认是否有 `$` 隐藏账户、可疑新建账户、以及「Profile 目录存在但账户已删」的残留；`query user` 看当前在线会话。
4. **网络面**：`netstat -ano | findstr ESTABLISHED` 取出站连接与 PID；对可疑 PID 用 `Get-NetTCPConnection -State Established` 复核（PowerShell 版带进程名），并记录对端 IP/端口用于情报比对。
5. **进程面**：对每个可疑 PID 依次执行 `tasklist /fi "PID eq <pid>"`（确认映像名/会话/内存）、`wmic process where ProcessId=<pid> get CommandLine,ParentProcessId`（拿命令行与父进程）、再对父 PID 递归，画出到 `services.exe`/`explorer.exe` 的完整链；同时 `tasklist /m <可疑dll>` 反查模块宿主。
6. **持久化面**：`net start` + `tasklist /svc`（服务→PID）、`schtasks`（计划任务）、`wmic startup` / `Get-CimInstance Win32_StartupCommand`（自启）、`Get-SMBShare`/`net share`（共享）、`driverquery`（驱动）逐项过一遍，记录「路径 + 账户 + 触发器」。
7. **文件面**：用 `forfiles /P <目录> /S /M *.* /D -N /C "cmd /c echo @path @fdate @ftime @fsize"` 在 `%TEMP%`、`%APPDATA%`、`C:\Windows\Temp`、下载目录、`Prefetch` 上按时间窗捞文件；对命中的样本算哈希、看签名与版本信息。
8. **收口**：把以上七面的时间戳对齐成一条时间线，标注「首次出现/最后活动」，再决定隔离、取证副本与清除顺序。

## PoC

```powershell
# ---- 1) 日志面：先枚举日志名，再按时间窗+事件ID精确取 ----
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount
Get-WinEvent -FilterHashtable @{LogName='Security'; ID='4624'}
Get-WinEvent @{logname='Microsoft-Windows-PowerShell/Operational'; starttime=[datetime]::today} -MaxEvents 10
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational |
  Where-Object {$_.ID -eq '4100' -or $_.ID -eq '4104'}

$StartTime = Get-Date -Year 2023 -Month 1 -Day 1  -Hour 00 -Minute 00
$EndTime   = Get-Date -Year 2023 -Month 1 -Day 30 -Hour 23 -Minute 59   # Hour 上限 23
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$StartTime; EndTime=$EndTime}
```

```cmd
:: ---- 2) 账户面：net user 看不到 $ 结尾的隐藏账户 ----
net user
wmic UserAccount get Name,SID,Status,Disabled
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s | findstr /i ProfileImagePath
query user
net user <name>
net localgroup administrators
```

```cmd
:: ---- 3) 网络面 → 4) 进程面：从连接追到父进程链 ----
netstat -ano | findstr "ESTABLISHED"
netstat -ano | findstr "172.24.16.1"
tasklist | findstr "10004"
tasklist /fi "PID eq 9480"
tasklist /m uxtheme.dll
wmic process where ProcessId=14000 get ParentProcessId
wmic process where Name="javaw.exe" get ParentProcessId
wmic process get name,parentprocessid,processid
wmic process where "ProcessID=14000" get CommandLine
wmic process list full
```

```cmd
:: ---- 5) 服务 / 任务 / 自启 / 共享 / 驱动 ----
net start
tasklist /svc
schtasks /query /fo LIST /v
wmic startup get Name,Command
driverquery
net share
```

```powershell
Get-NetTCPConnection -State Established
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-List
Get-LocalUser
Get-SMBShare
```

```cmd
:: ---- 6) 文件面：按时间窗捞落地物 ----
forfiles /P C:\Windows\Temp /S /M *.exe /D -30 /C "cmd /c echo @path @fdate @ftime @fsize"
forfiles /P %APPDATA% /S /M *.bat /D -7  /C "cmd /c echo @path @fdate @ftime @fsize"
forfiles /S /M *.txt /C "cmd /c echo @path"
```

## 变体与关联

- **日志不可用时**：`wevtutil cl` 被清过则转向 Sysmon（1/11/13）、EDR 遥测、`Prefetch`/`amcache.hve`/`SRUM` 等「非日志产物」还原执行痕迹。
- **进程树被断链**：父进程已退出时 `ParentProcessId` 会指向一个已复用/不存在的 PID，此时改用进程创建时间排序 + 命令行里的父进程特征（如 `w3wp.exe` 的命令行）反推。
- **无 `wmic`（Win11 24H2 起默认移除）**：全部换 `Get-CimInstance Win32_Process` / `Win32_UserAccount` / `Win32_StartupCommand`，字段名一一对应（`ParentProcessId`、`CommandLine`）。
- **与「持久化三面排查」卡的区别**：那张聚焦 Run 键 / 计划任务 / 服务三条持久化入口的可疑项判定；本卡是「无 GUI 时先把七个面都覆盖到」的排查矩阵，持久化只是其中一面。
- **与「四要素打分」卡的区别**：那张是自研工具（`GetTcpTable2` + `WinVerifyTrust`）自动化打分；本卡全程用系统自带命令，不需要编译任何东西。
- 关联：[[defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction]]（evtx + PSReadLine 还原操作链）、[[defense-detection-windows-outbound-ip-authcode-autostart-suspicious-process-triage]]（同一批信号的自动化版本）、[[pentest-ad-mimikatz-token-elevate-lsadump-sam-hidden-account]]（`$` 隐藏账户的攻击侧做法）。

## 检测与防御

- **检测**：安全日志 4624（登录，关注类型 3/10 与异常源 IP）、4688（进程创建，关注父进程异常）、4698（任务创建）、7045（服务安装）、4720（账户创建）、4726（账户删除）；PowerShell 4104 脚本块、4100 引擎错误；Sysmon 1/3/11/13。
- **加固**：开启「审核进程创建」并启用命令行记录（`ProcessCreationIncludeCmdLine_Enabled`）、PowerShell 脚本块日志与转录；限制本地管理员组成员；清理不必要的共享与自启项；对 `%TEMP%`、`C:\Windows\Temp` 设置写入审计。
- **响应**：先取证（导出 evtx、`netstat` 快照、进程树、可疑文件哈希）再处置；处置顺序为「断网隔离 → 停服务/禁任务/删自启 → 删载荷 → 复查同入口是否还有其它载荷」；注意 `netstat` 与进程树是瞬时状态，必须在重启/清理前先落盘。
- **预防遗漏**：把本卡的七面做成排查清单（日志/账户/网络/进程/服务与任务/自启与共享/文件时间窗），现场按面打勾，避免只顺着一条线索深挖而漏掉持久化或横向移动痕迹。
