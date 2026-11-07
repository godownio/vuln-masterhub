---
id: defense-detection-sqlps-lolbin-powershell
title: SQLPS.exe 作为 PowerShell 替代宿主执行编码命令
type: scenario
domain: defense
path: defense/detection
technique: lolbin-sqlps-powershell-host
tags:
- sqlps
- lolbin
- powershell
- windows
- detection
- defender
- sqlserver
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-G
  verified_at: '2026-11-04T19:22:42+08:00'
  notes: 已对照 content.md 与全部 50 张图片核对：SQLPS.exe 路径（SQL Server 2019 150\Tools\Binn）、-nop -w hidden -enc、Defender 1116 Trojan:Win32/Commando.A!ml、运行身份 NT AUTHORITY\SYSTEM、SQL 服务账号 NT Service\MSSQLSERVER、ERRORLOG 无 sp_configure/xp_cmdshell 记录均与正文一致；'SQLPS 以 SYSTEM 运行说明来自 Web 层已提权上下文' 为原文第六节结论。SeImpersonatePrivilege 到 SYSTEM 的具体利用方式原文未展开，卡片已标为推断。
  unverified:
  - 未展示 -enc 明文与完整提权步骤；SeImpersonatePrivilege->SYSTEM 为推断
url: /docs/defense/detection/defense-detection-sqlps-lolbin-powershell/
draft: false
kb_aliases:
- SQLPS 免杀
- SQL Server PowerShell 宿主
- 替代 PowerShell 宿主
- sqlps -enc
---

## 一句话结论

攻击者用 SQL Server 自带的 `SQLPS.exe` 代替 `powershell.exe` 执行 `-nop -w hidden -enc` 编码命令，利用“数据库服务器上运行 SQL 工具很正常”的错觉和针对 PowerShell 进程名的监控盲区完成载荷拉取与内存执行。

## 原理

- **功能等价**：`SQLPS.exe` 是 SQL Server 附带的 PowerShell 宿主，底层同样加载 `System.Management.Automation`，支持 `-NoProfile`、`-WindowStyle hidden`、`-EncodedCommand` 等参数，能执行任意 PowerShell 脚本。
- **检测错位**：大量企业的命令行审计、进程名告警和运维排查规则以 `powershell.exe`、`pwsh.exe` 为对象，`sqlps.exe` 不在名单内；本次事件中安全软件最终是靠机器学习模型（威胁名带 `!ml`）检出，而非进程名规则。
- **环境伪装**：在数据库服务器上，SQL 相关工具运行 PowerShell 脚本看起来像正常运维，进程名本身就是保护色；攻击者还可借此误导应急人员往“SQL 注入 / xp_cmdshell”方向排查。
- **身份线索**：案例中 Defender 显示 `SQLPS.exe` 以 `NT AUTHORITY\SYSTEM` 运行，而 SQL Server 服务账号是 `NT Service\MSSQLSERVER`。若经 `xp_cmdshell` 拉起，子进程应继承 SQL 服务账号，因此 SYSTEM 身份反而说明命令来自 Web 层已提权的执行上下文，而非数据库链路。

## 触发条件

- 目标主机安装 SQL Server（案例为 SQL Server 2019，路径 `...\150\Tools\Binn\SQLPS.exe`）；
- 攻击者已取得命令执行能力，且能控制子进程命令行；
- 主机未启用或未集中采集 PowerShell ScriptBlock 日志（4104）、模块日志与带命令行的进程创建审计；
- 安全产品仅按进程名匹配 PowerShell，未对替代宿主做行为检测。

## 利用步骤

1. 在 Web 层或已控主机上获得命令执行；
2. 将 PowerShell 载荷编码为 Base64，构造 `SQLPS.exe -nop -w hidden -enc <base64>`；
3. 由 Web 工作进程或服务派生 `SQLPS.exe`，从远程 C2 拉取下一阶段载荷；
4. 载荷在内存中解密并执行（如通过 `VirtualAlloc` + `GetProcAddress` 运行 shellcode），减少落盘；
5. 若需要 SYSTEM，可利用工作进程令牌中的 `SeImpersonatePrivilege` 进一步提权后再次执行。

## PoC

仅展示命令行形态，不提供可执行载荷：

```text
"C:\Program Files (x86)\Microsoft SQL Server\150\Tools\Binn\SQLPS.exe" -nop -w hidden -enc <base64-encoded-command>
```

检测查询思路（Sysmon 进程创建）：

```text
Image endswith '\sqlps.exe'
AND (CommandLine contains '-enc' OR CommandLine contains '-encodedcommand'
     OR CommandLine contains '-nop' OR CommandLine contains '-w hidden')
AND ParentImage endswith '\w3wp.exe'
```

Windows 安全日志可用 4688（需启用命令行审计）按进程名与命令行筛选；PowerShell 4104 可看到解码后的脚本块。

## 变体与关联

- 变体：其他替代 PowerShell 宿主（`powershell_ise.exe`、自带的 SQL 管理 Shell、第三方运维工具宿主）以及 `mshta`、`rundll32` 等 LOLBin 组合；
- 关联：[[web-dotnet-deser-servicehandler-typenamehandling]]（Web 层未授权反序列化获得初始命令执行）；[[defense-forensics-multisource-timeline-log-clear]]（用 4104 与 Defender 事件补齐时间线）。
- 不确定点：案例未展示完整 `-enc` 明文与提权步骤，`SeImpersonatePrivilege` 到 SYSTEM 的具体利用方式为推断。

## 检测与防御

- **进程行为**：对 `sqlps.exe`、`pwsh.exe`、`powershell_ise.exe` 等替代宿主统一监控；重点看父进程为 `w3wp.exe`、`sqlservr.exe`、`wsmprovhost.exe` 的异常组合。
- **命令行特征**：`-enc`/`-EncodedCommand`、`-nop`、`-w hidden`、`-ep bypass` 与下载/内存执行关键字；对编码内容解码后再匹配。
- **日志**：启用 PowerShell ScriptBlock 日志（4104）、模块日志、转录；启用 4688 命令行审计并外发；部署 Sysmon 进程创建规则。
- **告警运营**：Defender 高危查杀（如 `Trojan:Win32/Commando.A!ml`）必须有人处置；连续告警说明攻击者仍在尝试，不能视为“已拦截”。
- **收敛面**：不需要 SQL PowerShell 功能的服务器可限制或移除 `sqlps.exe`；应用白名单只允许业务必需的二进制；限制 Web 工作进程派生 shell。
- **身份核查**：发现 `sqlps.exe` 以 SYSTEM 运行而 SQL 服务账号并非 SYSTEM 时，应优先怀疑 Web 层命令执行而非数据库存储过程。
