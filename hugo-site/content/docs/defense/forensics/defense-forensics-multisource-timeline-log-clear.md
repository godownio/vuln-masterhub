---
id: defense-forensics-multisource-timeline-log-clear
title: 事件日志被批量清除后的多源时间线重建
type: scenario
domain: defense
path: defense/forensics
technique: multi-source-timeline-reconstruction
tags:
- forensics
- windows-event-log
- iis-log
- powershell-4104
- amcache
- timeline
- utc
- ransomware
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-G
  verified_at: '2026-11-04T19:22:44+08:00'
  notes: 已对照 content.md 与全部 50 张图片核对：IIS W3C 日志 UTC 与系统日志 UTC+8 的 8 小时时差、Defender 1116、PowerShell 4104 ScriptBlock、IIS 文本访问日志、applicationHost.config 修改时间与 inetpub\history 备份、System/Application 日志 104 清除事件均可与原文时间线对应；'进程证据≠入口证据' 与 '先确认现场已处置动作' 是原文第七节结论。原文未明确写出 wevtutil 命令，Amcache/ShimCache/Prefetch 为补充数据源而非原文直接使用。
  unverified:
  - 各日志保留周期与完整性以现场为准；Amcache/ShimCache/Prefetch 未在原文中出现，属通用补充
url: /docs/defense/forensics/defense-forensics-multisource-timeline-log-clear/
draft: false
kb_aliases:
- 日志被清溯源
- 多源时间线
- IIS 日志 UTC 时差
- ScriptBlock 取证
- Amcache 取证
---

## 一句话结论

勒索载荷落地后常立即用 `wevtutil` 批量清空事件日志，但只要攻击者没有同时清除 IIS 文本日志、PowerShell ScriptBlock 记录、Defender 事件、Amcache、文件时间戳和配置文件修改时间，就能用多源交叉印证重建从入口到加密的完整时间线。

## 原理

- **日志清理有边界**：`wevtutil cl` 清理的是 Windows 事件日志（`.evtx`），而 IIS 访问日志是 `%SystemDrive%\inetpub\logs\LogFiles\W3SVC<站点ID>` 下的文本文件，通常不在清理脚本范围内。
- **多数据源天然冗余**：同一行为会在多个位置留下痕迹——Web 请求在 IIS 日志，命令执行在 4688/4104，恶意文件在 Defender 1116/1117，程序执行在 Amcache/ShimCache/Prefetch，文件落盘与加密在 `$MFT`/USN/文件修改时间，配置变更在 `applicationHost.config` 及其 `history` 备份。
- **时区是最大陷阱**：IIS W3C 日志默认使用 UTC，Windows 事件日志使用本地时间（案例为 UTC+8）。不换算就会出现“Web 日志比系统日志早 8 小时”的错位，导致时间线完全对不上。
- **进程证据≠入口证据**：攻击者调用数据库工具不代表入口是 SQL 注入；进程层证据必须与 Web 访问日志、源码审计分开验证，否则会被误导性痕迹带偏。

## 触发条件

- 事件日志已被清空或部分清空，但至少保留一个独立数据源；
- 主机与日志源时间同步（NTP），且已知各日志的时区设置；
- 应急人员能在第一时间固定易失数据，避免重启或继续写入覆盖；
- IIS、PowerShell、Defender 等功能曾启用相应日志。

## 利用步骤

1. **先固定证据**：导出 IIS 日志目录、事件日志、`applicationHost.config` 与 `inetsrv\Config\history`、Amcache、Prefetch、USN Journal、文件时间戳；记录采集时间与主机时区。
2. **列出所有时间源**：IIS（UTC）、Security/System/Application（本地）、Defender Operational（本地）、PowerShell Operational（4104）、RDP LocalSessionManager（21/24/25）、文件系统时间。
3. **统一时区**：把 IIS 时间加 8 小时（UTC+8 场景）后再与系统日志对齐，先在小时间窗内验证一条已知请求。
4. **建立锚点**：以首次可疑 POST、Defender 查杀、4104 ScriptBlock、加密器落盘、日志清除事件（104/1102）为锚点。
5. **交叉印证**：同一时刻在 Web 日志、进程日志、文件时间、配置修改时间中寻找对应记录；无法对应的空白要标注为“未知”，不要补故事。
6. **还原攻击链**：按“试探 → 利用 → 命令执行 → 载荷落地 → 日志清除 → 加密”排列，标注每个节点的证据来源与置信度。

## PoC

```powershell
# Defender 查杀事件（1116 检测 / 1117 处置）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} |
  Select-Object TimeCreated, Id, Message

# PowerShell ScriptBlock 日志（4104），可看到解码后的脚本
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Select-Object TimeCreated, Message

# 日志被清除事件
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104,1102} |
  Select-Object TimeCreated, Id, Message
```

```powershell
# IIS 日志按时间窗筛选（注意 W3C 时间为 UTC）
Select-String -Path 'C:\inetpub\logs\LogFiles\W3SVC*\*.log' -Pattern 'GetDictResult'
```

```text
# 配置文件修改时间与历史备份
Get-Item C:\Windows\System32\inetsrv\config\applicationHost.config | Select LastWriteTime
Get-ChildItem C:\Windows\System32\inetsrv\config\schema, C:\inetpub\history -Recurse
```

## 变体与关联

- 变体：Linux 下 `journalctl` 被清后改用 auditd、bash history、文件 atime/mtime；云环境用 CloudTrail/VPC Flow Logs 补时间线；EDR 遥测独立于主机日志。
- 关联：[[defense-incident-response-ransomware-pre-encryption-cleanup]]（日志清除与加密前置行为）；[[web-dotnet-deser-servicehandler-typenamehandling]]（本案入口）；[[defense-detection-sqlps-lolbin-powershell]]（4104/进程证据）。
- 不确定点：案例未说明各日志的保留周期与是否完整，具体时间线以现场数据为准；本卡描述方法而非复现该事件。

## 检测与防御

- **日志外发**：Windows 事件日志实时转发到独立日志服务器或 SIEM，本机日志被清后仍有副本；IIS 日志目录纳入集中采集。
- **关键日志开关**：启用 PowerShell ScriptBlock（4104）与模块日志、4688 命令行审计、Sysmon、Defender Operational 日志。
- **时间同步**：所有主机与网络设备统一 NTP，采集时记录时区与日志格式，避免 UTC/本地时间错位。
- **证据保全**：应急第一步导出易失数据并计算哈希；保留 `inetpub\history` 等配置备份，配置修改时间常能反推临时修复动作。
- **检测**：监控 104/1102 日志清除事件、`wevtutil cl` 进程命令行、日志服务异常停止；对 IIS 日志中出现的高危无扩展名 POST 建立告警。
- **运营**：应急进场先询问现场已做过的处置（如封禁 URL、重启服务），否则可能在已封堵路径上重复排查。
