---
id: defense-detection-lateral-wmi-service-schtasks-log-footprint
title: 横向通道日志留痕对比：WMI 仅登录事件、服务创建 7045、计划任务文件与 smbexec 输出文件
type: scenario
domain: defense
path: defense/detection
technique: lateral-channel-log-footprint-comparison
aliases:
- 横向日志留痕对比
- WMI 横向无日志
- 7045 服务安装
- schtasks 远程任务文件
- smbexec __output
- 135 445 5985 日志差异
tags:
- windows
- detection
- lateral-movement
- wmi
- psexec
- smbexec
- schtasks
- event-log
- 7045
- 4672
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502-fix
  verified_at: '2026-11-11T03:40:36+08:00'
  notes: V502 修正：psexec（impacket）服务名为 4 位随机字母（XOGT），smbexec 服务名为 8 位（qDUkiwdM），psexec 上传 exe 名为 8 位；检测速查正则改为 ^[A-Za-z]{4}$（psexec）/ ^[A-Za-z]{8}$（smbexec）。
---

## 一句话结论

不同横向通道在 Windows 默认审计下的留痕差异很大：经 135 的 WMI 执行在原文测试中只留下安全日志的 4624 登录、4672 特殊登录与 4634 注销，没有 7045 服务安装；经 445 的 psexec 会在 System 日志留下 7045（服务名 PSEXESVC、镜像 `%SystemRoot%\PSEXESVC.exe`）；smbexec 的 7045 里 ImagePath 直接是 `%COMSPEC% /Q /c echo ... > \\%COMPUTERNAME%\C$\__output ... & del ...bat`；远程 schtasks 会创建计划任务并在 `C:\Windows\Tasks` 留下任务文件（现代系统为 `System32\Tasks` 加 4698 事件）。排查时应按通道核对对应日志，而不是只搜单一事件。

## 原理

- **WMI（135）的盲区**：原文在清空全部日志后使用 SharpWmi/WMIHACKER/wmiexec-pro，只观察到 Security 日志的 4624（登录，类型 3）、4672（为新登录分配特殊权限）、4634（注销），未出现 7045/服务安装类事件。原因是通过 WMI 的 `Win32_Process.Create`/事件消费者执行的进程由 `WmiPrvSE.exe` 派生，默认不会创建服务；而进程创建审计（4688/Sysmon EID 1）与 WMI-Activity Operational 日志是否可见取决于目标审计配置，很多环境未开启或不集中采集。
- **psexec 的强特征**：psexec/impacket psexec 经 SMB 上传服务二进制并创建临时服务，System 日志 7045 明确记录"服务已安装"，服务名常见 `PSEXESVC`（Sysinternals）或 4 位随机名（impacket psexec，文中 `XOGT`），服务文件路径指向 `%SystemRoot%\PSEXESVC.exe` 或 admin$ 上传的随机 exe（上传 exe 名是 8 位，如 `gRKuLZdb.exe`）。
- **smbexec 的强特征**：smbexec 把命令塞进服务 ImagePath，7045 的"服务文件名"字段直接包含 `%COMSPEC% /Q /c echo <命令> ^> \\%COMPUTERNAME%\C$\__output ... & del ...bat`，同时目标 C$ 出现 `__output` 与临时 bat；这串内容既是执行证据也是回显通道。
- **schtasks/at 的留痕**：远程创建计划任务会在任务目录留下任务定义文件（原文称 `C:\Windows\Tasks\xxx.txt`；Vista+ 实际多为 `C:\Windows\System32\Tasks\<任务名>`），并伴随 4698（任务创建）/4699（删除）事件；`at` 在 2012+ 已弃用但仍可添加作业，删除时提示改用 schtasks。
- **为什么按通道对照**：攻击者会根据日志可见性选通道（WMI 更"安静"，服务类更"响亮"）；防守方只盯 7045 会漏掉 WMI，只盯 4624 又会被大量正常登录淹没。把登录事件、服务/任务事件、进程创建、SMB/注册表遥测按时间线组合，才能覆盖不同通道。
- **边界**：原文的"WMI 无日志"是特定审计配置下的观察（清空日志、未提 Sysmon/4688/WMI-Activity）；在开启进程创建审计、Sysmon、WMI-Activity 与远程注册表审计的环境中，WMI 横向仍会留下大量痕迹。WinRM 的日志留痕原文未测试，需结合 WinRM Operational 日志与 5985 流量另行判断。

## 触发条件

- 防守方拥有目标主机的 Security/System 日志（最好含 Sysmon、WMI-Activity、PowerShell 日志）与网络/EDR 遥测。
- 怀疑存在横向移动，需要判断使用了哪条通道（135 WMI / 445 服务 / 计划任务 / 5985 WinRM）。
- 审计策略与日志采集范围已知，能够解释"看不到"是未执行还是未记录。

## 利用步骤

> 以下为防御方排查步骤。

1. 先确认审计基线：是否开启 4688 进程创建、Sysmon EID 1、WMI-Activity Operational、对象访问（4657）、PowerShell 脚本块日志；未开启时相应通道"无日志"不能作为未发生结论。
2. 拉取 Security 日志：按来源 IP/账户筛 4624 类型 3（网络登录）、4672（特殊权限）、4634（注销）；注意 WMI、psexec、smbexec、WinRM 都会产生这类事件，需继续区分。
3. 查 System 7045/4697/7040：存在 7045 且服务名为 PSEXESVC 或 4 位随机名（psexec）/ 8 位随机名（smbexec）、ImagePath 指向 `%SystemRoot%\*.exe`、admin$ 或包含 `%COMSPEC% /Q /c echo ... C$\__output` 时，分别指向 psexec 或 smbexec。
4. 查计划任务：`C:\Windows\System32\Tasks`（或原文所述 `C:\Windows\Tasks`）出现近期创建的任务文件，Security 4698/4699；任务动作指向临时 exe/命令时重点核查。
5. 查 WMI 痕迹：WmiPrvSE.exe 是否在登录事件后派生 cmd/powershell/cscript；WMI-Activity 日志中的 `Win32_Process` 创建、事件消费者/过滤器创建（如 `ActiveScriptEventConsumer`、`FilterToConsumerBinding`）；远程注册表写入。
6. 查文件与共享：C$ 下 `__output`/临时 bat、admin$ 下随机名 exe、`%windir%\Temp` 重定向文件、`C:\Windows\PSEXESVC.exe`。
7. 组合时间线（登录 → 服务/任务/WMI 对象 → 子进程 → 文件写入 → 外联），确定通道与来源，封禁并排查同源主机。

## PoC

无 PoC（检测研判场景）。可用查询速查：

```text
# 服务类
System 7045 / Security 4697：服务名 PSEXESVC 或 ^[A-Za-z]{4}$（psexec）/ ^[A-Za-z]{8}$（smbexec）；ImagePath 含 cmd.exe/%COMSPEC%/C$\__output/.bat
# 计划任务
Security 4698/4699；C:\Windows\System32\Tasks\* 与 C:\Windows\Tasks\* 新增
# WMI
Security 4624(type 3)+4672+4634；WmiPrvSE.exe 子进程；Microsoft-Windows-WMI-Activity/Operational；Sysmon WMI 事件
# 文件
\\target\C$\__output、\\target\admin$\<rand>.exe、%windir%\Temp\<rand>
```

## 变体与关联

- 关联：impacket psexec/atexec 的固定工件（REMCOMSVC 镜像、`\RemCom_communication` 管道、Temp 重定向）见 [[defense-detection-impacket-psexec-atexec-artifacts]]；本卡补跨通道日志留痕对比与 WMI 盲区。
- 关联：WMI 横向实现见 [[pentest-lateral-movement-wmihacker-wmi-dcom-135-139]] 与 [[pentest-lateral-movement-wmi-135-only-registry-output-custom-class]]；服务类实现见 [[pentest-lateral-movement-psexec-smb-service-hash-lateral]]。
- 变体：攻击者可清空日志（1102）或使用事件日志循环清理模块；原文测试前即清空五类日志以观察"干净"留痕，防守方应对 1102 与日志缺口告警。
- 边界：审计策略差异会导致完全不同的可见性；无 Sysmon/4688 时 WMI 通道几乎只剩登录事件，不能据此判定"无横向"。

## 检测与防御

- 检测：对 7045/4697 建立服务名与 ImagePath 规则（PSEXESVC、psexec 随机 4 位名、smbexec 随机 8 位名、`%COMSPEC%`、`__output`、`.bat`）；对 4698/4699 与任务目录新增做关联；对 WmiPrvSE 子进程、WMI-Activity 事件订阅创建、远程注册表写入做告警。
- 检测：监控 1102 日志清空、日志采集中断与时间线缺口；对短时间内"登录 → 服务/任务/WMI 对象 → 子进程"的序列打分。
- 防御：开启并集中采集 4688/Sysmon、WMI-Activity、PowerShell 日志；限制 135/445/5985 到管理网段；LAPS/唯一本地管理员口令；EDR 覆盖 WMI/服务/计划任务三类执行面。
- 响应：按通道提取工件（服务 exe、任务文件、`__output`、WMI 订阅），定位来源 IP 与账户，封禁并排查同源主机。
