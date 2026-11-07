---
id: defense-incident-response-windows-persistence-triage-run-schtask-service
title: Windows 权限维持三面排查：Run 键、计划任务与自启动服务的可疑项定位
type: scenario
domain: defense
path: defense/incident-response
technique: windows-persistence-triage-run-schtask-service
tags:
- incident-response
- windows
- persistence
- registry
- scheduled-task
- service
- triage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:24:30+08:00'
  notes: 已对照原文 MISC4 与图14-23核对：Run 键指向 C:\Windows\System32\GroupPolicy\flag.bat、\login 任务以 SYSTEM 每分钟运行 w0rdpad.exe、serverr 服务 AUTO_START/LocalSystem 且 binPath 指向 PowerShell\Modules 下 DEDCYD.exe，均与截图一致；未验证点：未在原文主机复跑排查命令。
url: /docs/defense/incident-response/defense-incident-response-windows-persistence-triage-run-schtask-service/
draft: false
kb_aliases:
- Windows 持久化排查
- 权限维持排查
- Run 键排查
- schtasks 排查
- 自启动服务排查
- w0rdpad 伪装
---

## 一句话结论

在 Windows 主机上按 Run 键 → 计划任务 → 自启动服务三个高频入口逐项核对“可执行文件路径 + 运行账户 + 触发方式 + 文件元数据”，即可快速定位攻击者的权限维持项：Run 键指向 `GroupPolicy` 等非标准目录的脚本、根目录下以 SYSTEM 每分钟运行且用形近字伪装（`w0rdpad.exe`）的计划任务、服务 `binPath` 指向 PowerShell 模块目录中的可疑 EXE，都是典型信号。

## 原理

- Windows 的自动执行面很多，攻击者偏好无需交互、能获得高权限且容易伪装的入口：
  - **Run/RunOnce 注册表键**：位于 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 与 `HKLM\...\Run`，用户登录时由 Explorer 执行；HKCU 键普通用户可写，常用于用户态持久化。
  - **计划任务**：`schtasks`/Task Scheduler 支持按分钟重复、以 SYSTEM 运行、隐藏任务；任务名与程序名可伪装成系统更新/输入法/办公组件。根目录（`\`）下的简单任务名比 `\Microsoft\...` 下的标准任务更可疑。
  - **自启动服务**：`AUTO_START` 服务由 SCM 在开机时以配置的账户（常见 LocalSystem）启动；攻击者可把 EXE 放进 `Program Files`、`PowerShell\Modules` 等可信目录，并伪造文件描述/产品名。
- 合法程序通常位于 `C:\Windows\System32`、`C:\Program Files` 等标准目录，带有效数字签名、版本信息与一致的修改时间；攻击者常把载荷放在 `GroupPolicy`、模块缓存、`Temp`、`ProgramData` 等可写/少人看的目录，或用形近字（数字 `0` 代替字母 `o`）、伪造公司名（如把文件描述写成无关的 `PixlrCreativeBundle`/`GarageBand`）来降低肉眼识别率。
- 排查的核心不是“看到一项就判恶意”，而是把入口、路径、账户、触发器、签名/哈希、文件时间与沙箱/威胁情报交叉起来；多个弱信号叠加（非标准目录 + SYSTEM + 每分钟 + 无签名 + 形近字）才构成高置信度结论。

## 触发条件

- 已获得 Windows 主机交互权限（RDP/远程 shell）或离线镜像/注册表 hive。
- 需要排查攻击者是否留下持久化，或已发现可疑文件/进程需要定位其自启动方式。
- 能读取注册表、计划任务与服务配置；有文件哈希/签名/沙箱条件更佳。

## 利用步骤

1. **Run/RunOnce**：查询 HKCU/HKLM 的 Run、RunOnce、RunServices 以及 `Wow6432Node` 分支，记录值名与数据（可执行路径/命令行）：
   ```cmd
   reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s
   reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s
   reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /s
   ```
   重点看指向 `GroupPolicy`、`Temp`、`ProgramData`、用户目录的 `.bat/.cmd/.ps1/.exe`。
2. **计划任务**：导出所有任务及详细字段，关注任务名、作者、运行账户、触发器、动作路径、上次结果：
   ```cmd
   schtasks /query /fo LIST /v
   schtasks /query /tn "\login" /fo LIST /v
   ```
   可疑特征：位于根目录 `\`、名称过于通用（`login`、`update`、`svc`）、以 SYSTEM 运行、每分钟/登录触发、动作指向非标准路径或形近字程序（`w0rdpad.exe` vs `wordpad.exe`）。
3. **自启动服务**：列出所有服务并逐个查看可疑项的配置：
   ```cmd
   sc query state= all
   sc qc sererr
   ```
   重点看 `START_TYPE: AUTO_START`、`SERVICE_START_NAME: LocalSystem`、`BINARY_PATH_NAME` 是否指向 `PowerShell\Modules`、`ProgramData`、用户目录等非预期位置。
4. **验证文件**：对每个可疑二进制计算哈希、检查数字签名与版本信息、看创建/修改时间是否与系统文件一致：
   ```powershell
   Get-FileHash -Algorithm SHA256 <path>
   Get-AuthenticodeSignature <path> | Format-List
   (Get-Item <path>).VersionInfo | Format-List *
   ```
   记录文件描述/产品名/版权中的异常字符串（攻击者可能把数据或提示写进 EXIF/版本资源），但不要把元数据当作可信来源。
5. **补充面**：再查启动文件夹、`Winlogon` 的 `Shell/Userinit`、IFEO、WMI 永久事件订阅、COM 劫持、服务 DLL 劫持等；用 Sysinternals Autoruns 做交叉核对。
6. **时间线与处置**：把持久化项的创建/修改时间与登录日志（4624）、任务创建（4698）、服务安装（7045）、进程创建（4688/Sysmon 1）对齐；确认后先隔离/禁用再删除，保留证据副本。

## PoC

```cmd
:: Run 键
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s

:: 计划任务（全量与单项）
schtasks /query /fo LIST /v
schtasks /query /tn "\login" /fo LIST /v

:: 服务（全量与单项）
sc query state= all
sc qc sererr
```

```powershell
# 对可疑路径批量计算哈希与签名
$paths = @(
  "C:\Program Files\windows nt\accessories\w0rdpad.exe",
  "C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.0.0.1\DEDCYD.exe"
)
$paths | ForEach-Object {
  [pscustomobject]@{
    Path = $_
    SHA256 = (Get-FileHash -Algorithm SHA256 $_).Hash
    Signature = (Get-AuthenticodeSignature $_).Status
    Description = (Get-Item $_).VersionInfo.FileDescription
  }
} | Format-List
```

说明：以上为排查命令示例，未在原文主机上复跑；不同 Windows 版本的字段名/输出可能略有差异。

## 变体与关联

- **注册表其他入口**：RunOnce、RunServices、Winlogon `Shell/Userinit`、IFEO `Debugger`、COM `InprocServer32`、服务 `ImagePath`。
- **计划任务隐藏**：任务藏在 `\Microsoft\Windows\...` 子目录、使用 `schtasks /create /ru SYSTEM /sc minute`、动作通过 `cmd /c`/`powershell -enc` 间接执行。
- **服务伪装**：服务名与显示名仿系统组件、`binPath` 指向合法目录中的 DLL/EXE、使用 `svchost -k` 或服务 DLL 劫持。
- **无文件/内存**：WMI 事件订阅、注册表脚本、计划任务调用 PowerShell 从远程加载；需结合 4104/4688/Sysmon。
- 关联：[[pentest-persistence-windows-nine-mechanism-persistence-combo]]（攻击侧九种持久化）、[[defense-forensics-synaptics-file-infector-artifacts]]（Run 键取证）、[[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]（服务+看门狗清除顺序）。

## 检测与防御

- 检测：Sysmon 事件 1（进程创建）、11（文件创建）、13（注册表设置）、4698（计划任务创建）、7045（服务安装）；对根目录任务、SYSTEM 每分钟任务、非标准目录的 Run 值、服务 binPath 异常告警。
- 基线：维护合法的 Run 键/计划任务/服务清单与签名白名单，定期用 Autoruns 对比；监控 `System32\GroupPolicy`、`PowerShell\Modules` 等目录的写入。
- 加固：限制普通用户对 Run 键与任务计划目录的写权限；启用应用控制/签名强制；关闭不必要的计划任务与服务；对高权限账户启用最小权限。
- 响应：发现持久化项后先断网/隔离，保存注册表、任务 XML、服务配置与样本哈希，再按“停服务/禁任务/删注册表值 → 删载荷 → 复查”的顺序清理，并排查同一入口是否还有其他载荷。
