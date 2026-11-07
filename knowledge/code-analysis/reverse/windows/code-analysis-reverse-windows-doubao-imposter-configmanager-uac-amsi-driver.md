---
id: code-analysis-reverse-windows-doubao-imposter-configmanager-uac-amsi-driver
title: 仿冒豆包客户端 doubaoai-app.exe 投放链：UAC 提权、AMSI/ETW 补丁、Defender 策略禁用与内核驱动加载
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: fake-ai-client-dropper-uac-amsi-driver-chain
aliases:
- doubaoai-app.exe
- ConfigManager.exe
- 豆包仿冒木马
- AdobeAcrobatUpdate-8776
- AdobeAcrobatUpdate-F130
- AMSI xor eax eax ret
- NtLoadDriver 驱动加载
- 仿冒 AI 客户端投放器
tags:
- windows
- malware-analysis
- dropper
- uac-bypass
- amsi-bypass
- etw
- defender
- kernel-driver
- process-injection
- persistence
- c2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:27:15+08:00'
  notes: 已对照原文与29张图核对：SHA256/MD5、UAC runas(SEE_MASK_NOCLOSEPROCESS=0x40)、AMSI 31 C0 C3 90 90、Defender 策略值、杀软枚举名单、随机名驱动 37456 字节与 Type=1/Start=3/ErrorControl=0+NtLoadDriver、VirtualAlloc/WriteProcessMemory 注入、AdobeAcrobatUpdate-8776/F130 计划任务(XML LogonTrigger/HighestAvailable)、B2D6568600009934 与 C2 76.223.113.170:6789 均与原文及截图一致。未验证点：本库未复跑样本；'doubaoai-app.exe 从自身资源释放 ConfigManager.exe' 的'资源'来源为按投放器行为的合理推断，原文仅显示创建/执行；frontmatter 无 sources/source_url。
---

## 一句话结论

仿冒“豆包 AI 助手”的安装包 `doubaoai-app.exe` 在 `%Temp%` 释放并启动 `ConfigManager.exe`；后者以 `runas` 提权、改注册表禁用 Defender、内存补丁 `AmsiScanBuffer` 与 ETW、枚举杀软进程、写入并 `NtLoadDriver` 加载随机名内核驱动、注入 shellcode，并创建伪装成 Adobe 更新的计划任务持久化，随后连接 C2。

## 原理

- **两级投放**：`doubaoai-app.exe` 从自身资源释放 `ConfigManager.exe` 到 `%Temp%` 并执行；`ConfigManager.exe` 是真正的功能样本，负责提权、反检测、驱动、注入、持久化与网络通信。
- **UAC 提权**：`OpenProcessToken` + `GetTokenInformation(TokenElevation)` 判断是否管理员；非管理员时用 `ShellExecuteExA` 以 `runas` 动词重新启动自身，`lpVerb` 指向 `runas`，并设置 `SEE_MASK_NOCLOSEPROCESS` 等标志。
- **禁用 Defender**：写入 `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` 下的 `DisableAntiSpyware`、`DisableAntiVirus`、`DisableRealtimeMonitoring`、`DisableBehaviorMonitoring`、`DisableIOAVProtection`、`DisableScanOnRealtimeEnable` 等 DWORD 值（动态日志中可见写入 `01 00 00 00`）；同时查询/操作 `WinDefend` 服务与 `MsMpEng.exe`。
- **AMSI 内存补丁**：`sub_140001740` 加载 `amsi.dll`，取 `AmsiScanBuffer` 地址，`VirtualProtect` 改为可写可执行，写入 5 字节 `31 C0 C3 90 90`（`xor eax,eax; ret; nop; nop`），使扫描函数直接返回 0，再恢复内存保护。这是经典的用户态 AMSI 绕过，不修改磁盘文件。
- **ETW 禁用**：流程图中另有 `sub_140001A90` 负责禁用 ETW 事件，配合 AMSI 补丁降低安全产品对后续行为的可见性。
- **杀软枚举**：`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Next` 遍历进程，比对 `MsMpEng.exe`、`HipsDaemon.exe`、`360tray.exe`、`avp.exe`、`ekrn.exe`、`QQPCTray.exe`，并用 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetExitCodeProcess == STILL_ACTIVE` 判断是否真的在运行。
- **内核驱动加载**：`sub_1400037C0` 用性能计数器/时间生成 8 字符随机服务名与文件名，`GetTempPathA` 拼出 `%Temp%\<8字符>.sys`，把内置（XOR 解密）的 37456 字节驱动写入；在 `HKLM\SYSTEM\CurrentControlSet\Services\<随机名>` 创建 `Type=1`（内核驱动）、`Start=3`（手动）、`ErrorControl=0` 的服务项，`ImagePath` 指向临时驱动，然后通过 `ntdll!NtLoadDriver` 加载；失败时删除服务项与驱动文件。驱动文件被占用，需进安全模式才能删除。
- **代码注入**：`sub_140001C40` 用 `VirtualAlloc` 分配可执行内存、`WriteProcessMemory` 写入内置 shellcode、`VirtualProtect` 调整保护、`CreateThread` 执行，结束后清零并释放内存。
- **持久化**：创建计划任务 `AdobeAcrobatUpdate-8776`（指向桌面 `ConfigManager.exe`）与变体 `AdobeAcrobatUpdate-F130`（指向 `%Temp%\ConfigManager.exe`）；任务 XML 使用 `LogonTrigger`、`RunLevel=HighestAvailable`、`ExecutionTimeLimit=PT0S`，发布者显示为未验证的 `NetApp, Inc.` 以伪装成正常软件更新。
- **数据与 C2**：在 `%AppData%\Roaming\B2D6568600009934\` 写入 `HWID`、`SETTINGTIME` 等文件，动态日志显示 `ConfigManager.exe` 多次连接 `76.223.113.170:6789`；还修改 Internet Explorer 安全区域设置（`Zones`、`Flags`、`ZoneMap`、`ProxyBypass` 等），可能用于放宽后续下载/脚本执行限制。

## 触发条件

- 用户在 Windows 上从仿冒站点下载并运行伪装成豆包客户端的安装包（案例中由生成式 AI 答案推荐仿冒域名，见 GEO 投毒卡）。
- 用户具备管理员账户并能通过 UAC 提示（或样本利用其他方式获得高完整性）。
- 系统未启用阻止策略修改、驱动加载控制（如 HVCI/驱动黑名单）或未安装能拦截 AMSI 补丁/计划任务创建的 EDR。
- 出站网络允许连接 C2 端口。

## 利用步骤

1. 投放仿冒安装包 `doubaoai-app.exe`，诱导用户执行。
2. 样本释放 `ConfigManager.exe` 到 `%Temp%` 并启动；随后以 `runas` 请求管理员权限。
3. 提权成功后写 Defender 策略注册表、补丁 AMSI、禁用 ETW，并枚举杀软进程判断环境。
4. 生成随机名驱动，写入 `%Temp%\<随机>.sys`，注册 `Type=1/Start=3` 服务并 `NtLoadDriver` 加载。
5. 分配可执行内存写入 shellcode 并创建线程执行；创建 `AdobeAcrobatUpdate-*` 计划任务实现登录持久化。
6. 在 `%AppData%\Roaming\B2D6568600009934\` 写 HWID/配置，连接 `76.223.113.170:6789` 进行后续通信。
7. 授权分析时在隔离虚拟机/沙箱中进行，记录文件、注册表、计划任务与网络行为，不运行真实样本。

## PoC

样本与关键 IOC（用于检测，不提供样本）：

```text
doubaoai-app.exe  SHA256 b18e6df04b25b7f15e2ffb884315cc25abb0ff84ca30c6382543f9e4ae9243a3
                  MD5    b29624864550b151143c6a461ba6288d
ConfigManager.exe SHA256 0b901dcc4f13f0ddc65e886ca59fac64c78f9381cb0f27e80414773c263371af
                  MD5    e36064a805db9c95199814265a7f2225

落地：
%Temp%\ConfigManager.exe
%Temp%\<8位随机>.sys
%AppData%\Roaming\B2D6568600009934\HWID
%AppData%\Roaming\B2D6568600009934\SETTINGTIME
C:\Windows\System32\Tasks\AdobeAcrobatUpdate-8776
C:\Windows\System32\Tasks\AdobeAcrobatUpdate-F130

注册表：
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus=1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring=1
HKLM\SYSTEM\CurrentControlSet\Services\<8位随机>  Type=1, Start=3, ErrorControl=0

网络：
76.223.113.170:6789
```

AMSI 补丁的 5 字节机器码：

```text
31 C0 C3 90 90    ; xor eax,eax; ret; nop; nop
```

计划的持久化任务 XML 关键字段：

```xml
<Principal id="Author">
  <UserId>S-1-5-21-...</UserId>
  <LogonType>InteractiveToken</LogonType>
  <RunLevel>HighestAvailable</RunLevel>
</Principal>
<Triggers><LogonTrigger><UserId>DESKTOP-8C8PSSB\orange</UserId></LogonTrigger></Triggers>
<Actions Context="Author"><Exec><Command>C:\Users\orange\Desktop\ConfigManager.exe</Command></Exec></Actions>
```

以上来自原文静态/动态分析记录；本卡未复跑样本，IP 与主机路径为案例环境值，需结合自身环境比对。

## 变体与关联

- 计划任务变体：`AdobeAcrobatUpdate-8776` 与 `AdobeAcrobatUpdate-F130` 仅路径不同，说明攻击者可批量生成不同后缀与落地位置。
- 伪装变体：任务发布者显示 `(Not Verified) NetApp, Inc.`，可替换为其他常见软件厂商名；驱动服务名/文件名均为随机 8 字符。
- 投放链变体：仿冒对象可换成其他热门 AI 客户端/办公软件；上游入口可以是 GEO 投毒、仿冒广告、钓鱼站或捆绑安装器。
- 关联：GEO 投毒卡（`ai-security-rag-security-geo-poisoning-fake-ai-download-site`）；AMSI/ETW 硬件断点绕过卡（`pentest-c2-hardware-breakpoint-veh-amsi-etw-bypass`）；银狐 HelloGPT 安装包投放链（`pentest-c2-silverfox-hellogpt-installer-dropper-chain`）；BYOVD/驱动加载相关卡。
- 注意：AMSI 补丁与 Defender 策略修改都依赖管理员权限；若 UAC 被拒绝或策略被保护，链条会在提权阶段中断。驱动加载还可能被 HVCI、驱动签名策略或 Microsoft 易受攻击驱动列表拦截，本文未测试这些防护。

## 检测与防御

- 文件与进程：监控 `%Temp%\ConfigManager.exe`、`%Temp%\<8位随机>.sys`、`%AppData%\Roaming\B2D6568600009934\`；关注无签名或签名异常的“豆包”安装包；比对上述 SHA256。
- 注册表：监控 `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` 下 `Disable*` 值被批量写入；监控 `HKLM\SYSTEM\CurrentControlSet\Services\<随机名>` 新建且 `Type=1`、`Start=3`、`ImagePath` 指向 `%Temp%` 的服务项。
- 计划任务：监控名称匹配 `AdobeAcrobatUpdate-*` 但可执行文件不在 Adobe 安装目录、发布者未验证的任务；重点看 `LogonTrigger` + `HighestAvailable` + 指向用户目录的组合。
- 内存与 ETW：部署能检测 `AmsiScanBuffer` 被改为 `31 C0 C3` 的 EDR/内存扫描；关注 AMSI 提供程序失效与 ETW 会话异常；启用驱动加载审计与 HVCI。
- 网络：告警 `76.223.113.170:6789` 及类似非常规端口的周期连接；结合 DNS/代理日志关联 `ConfigManager.exe` 进程。
- 响应：隔离主机，删除计划任务与服务项，进安全模式删除驱动文件，轮换可能泄露的凭据，检查 `%AppData%` 数据目录与横向移动痕迹。
- 局限：原文样本在特定 Windows 环境分析，驱动加载、Defender 策略与 UAC 行为受系统版本/策略影响；本卡未在本机执行样本，IOC 需按环境验证。
