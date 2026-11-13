---
id: code-analysis-reverse-windows-r77-rootkit-stager-winlogon-deployment
title: r77-rootkit 用户态 rootkit 部署链：InstallStager 注入 winlogon + dllhost 进程镂空，Service64 释放载荷/注册表/命名管道/计划任务
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: r77-rootkit-stager-winlogon-deployment
aliases:
- r77-rootkit
- r77 rootkit 部署链
- InstallStager
- InstallStager.Service64
- $sxrconfig
- winlogon 注入 dllhost
- 用户态 rootkit 隐藏
tags:
- windows
- rootkit
- r77
- process-hollowing
- winlogon
- dllhost
- named-pipe
- persistence
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:56:18+08:00'
  notes: 已对照原文与45/45图核对：InstallStager 的 UnhookDLL(ntdll/kernel32)、Process.EnterDebugMode、提取 Service64、dllhost.exe + /Processid:<winlogon pid> + RunPE（图22）、winlogon→dllhost 进程树（图23）、Service64 的 FindResource/RegCreateKeyEx($sxrconfig)/DACL D:(A;OICI;GA;;;AU)/pid/svc64/CreateThread(ReflectiveDLLMain)/SeDebugPrivilege（图30/31）、$sxrchildproc 管道（图27）、r77 $77 隐藏规则（图28）与源码同源对比（图29/32）均与原文一致；r77 为 ring3 rootkit 的边界已写明。未在本机复现样本。
---

## 一句话结论

恶意 RAT 供应链把开源 r77-rootkit（ring3 无文件 rootkit）编译成 `InstallStager.exe` 与 `InstallStager.Service64.exe` 两个模块：C# InstallStager 先 unhook `ntdll.dll`/`kernel32.dll`、从资源取出 Service64，用 `RunPE`（进程镂空）把 dllhost.exe 作为 winlogon.exe 的子进程在 SYSTEM 下运行；Service64 再在 `HKLM\SOFTWARE\$sxrconfig` 写入 r77 配置与 `pid`/`svc64`、把 DACL 放开为 `D:(A;OICI;GA;;;AU)`、以命名管道 `\\.\pipe\$sxrchildproc*` 做 IPC，并 `CreateThread(ReflectiveDLLMain)` 把 r77 服务注入所有进程；r77 以 `$77` 前缀隐藏文件/目录/进程/注册表/服务/连接/命名管道/计划任务，形成用户态“隐身”层。

## 原理

- **r77-rootkit 是什么**：开源 ring3（用户态）rootkit，宣称“hides everything”：文件与目录、进程与 CPU/GPU 占用、注册表键值、服务、TCP/UDP 连接、junction、命名管道、计划任务；隐藏规则是 “Everything that starts with `$77` is hidden”，由注入到各进程的 r77 模块 hook API 与子进程实现。
- **部署链（文章整理流程图）**：Shellcode Installer（定位内嵌 Install.exe 偏移并进程镂空）→ Installer（把 stager.exe 写入注册表、创建计划任务、启动 powershell.exe）→ PowerShell（AMSI 绕过、反射调用 stager.exe）→ Stager（unhook ntdll/kernel32、解密加载 Service EXE、再进程镂空 Service EXE）→ r77 Service（unhook ntdll/kernel32、初始化 r77 服务、注入所有进程）→ Rootkit（hook API、hook 子进程）。
- **InstallStager.exe**：C# 程序，`Main` 中先 `UnhookDLL("ntdll.dll")`，在 Windows 10+/64 位下再 `UnhookDLL("kernel32.dll")`，`Process.EnterDebugMode()` 取得调试权限；从自身资源提取 `InstallStager.Service64.exe`，目标路径为 `C:\Windows\System32\dllhost.exe`，命令行带 `/Processid: <winlogon pid>`，取 `Process.GetProcessesByName("winlogon")[0].Id` 后调用 `RunPE.Run(path, cmdline, payload, id)`；结果进程树为 `winlogon.exe → dllhost.exe`（COM Surrogate，SYSTEM），即恶意代码藏在合法系统进程下。
- **Service64 的持久化/配置**：IDA 可见 `sub_...` 调用 `FindResource(0x65, "DLL")` 取内嵌 DLL、`RegCreateKeyEx(HKLM\SOFTWARE\$sxrconfig)`、`ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;OICI;GA;;;AU)")` 把键 DACL 设为所有用户完全访问、`SetValueEx("pid"/"svc64")` 记录进程号、最后 `CreateThread(..., StartAddress=ReflectiveDLLMain)` 反射加载；同时通过 `OpenProcessToken`/`LookupPrivilegeValue("SeDebugPrivilege")`/`AdjustTokenPrivileges` 提权到可注入其他进程。
- **命名管道 IPC**：代码用 `GetProcessIdOfThread`/`GetCurrentProcessId` 生成/匹配 `\\.\pipe\$sxrchildproc34226543a32`、`\\.\pipe\$sxrchildproc38764243a64`，`CreateFile` 连接后 `WriteFile` 写 4 字节、`ReadFile` 读回 1 字节，用于父/子进程间控制；管道名带 `$sxr` 前缀，配合 r77 的 `$77` 隐藏规则可避免在工具中显示。
- **与开源项目的同源证据**：文章将两模块与 r77-rootkit 源码/编译产物对比（Service.c 的 UnhookDLL、读取 `HKEY_LOCAL_MACHINE\SOFTWARE` 下 r77 Dll32/Dll64、TerminateR77Service、InstallR77Config、写 pid、注入所有进程；r77win.c 的 GetResource 等），确认样本由 r77-rootkit 编译而来；外层 CSStub2 用 Costura 把 InstallStager/UninstallStager/NirCmd 作为资源嵌入，并以 `MD5(固定字符串)` 作为 AES-ECB 密钥解密后释放执行。
- **为什么有效**：进程镂空让恶意 Service64 以 `dllhost.exe`（SYSTEM）身份运行，父进程是 winlogon，规避基于父进程/签名的检测；unhook ntdll/kernel32 降低 EDR 用户态 hook 可见性；r77 通过 API hook 对所有进程隐藏 `$77` 前缀对象；注册表存配置与计划任务保证重启后继续加载。
- **边界**：r77 是 ring3 rootkit，不能对抗内核态检测/ETW TI/内存扫描；`$77` 前缀与注册表键、命名管道、winlogon→dllhost 进程关系都是可观测点；样本依赖 SYSTEM 权限与能够注入 winlogon 的环境。

## 触发条件

- Windows 目标，攻击者已获得管理员/SYSTEM 权限（本链通过前置 loader/提权获得）。
- 能够写注册表 `HKLM\SOFTWARE`、创建计划任务、注入 winlogon/dllhost 等系统进程。
- 目标未启用会拦截跨进程注入、unhook、进程镂空的强 EDR/内核保护。
- 仅限授权恶意样本分析与防御验证。

## 利用步骤

（分析视角的链还原）

1. 外层 CSStub2 以 Costura 资源 + `MD5(固定串)` 派生的 AES-ECB 密钥解出 `InstallStager.exe`、`UninstallStager.exe`、`NirCmd` 并执行。
2. InstallStager 对自身进程 unhook `ntdll.dll`/`kernel32.dll`，开启 `SeDebugPrivilege`。
3. 从资源取出 `InstallStager.Service64.exe`，定位 winlogon.exe 的 PID。
4. 以 `C:\Windows\System32\dllhost.exe` 为目标进程执行 RunPE/进程镂空，使 Service64 在 SYSTEM 的 dllhost 中运行，父进程显示为 winlogon。
5. Service64 在 `HKLM\SOFTWARE\$sxrconfig` 写配置与 pid，放开 DACL，反射加载 r77 DLL。
6. r77 服务 unhook、注入所有进程并 hook API/子进程；随后 Installer 创建计划任务与注册表值（`$sxr-*`）实现重启保活。
7. 后续由 r77 隐藏 `$77`/`$sxr` 前缀的文件、注册表、服务、管道与计划任务，降低被用户发现概率。

## PoC

无 PoC（文章为样本逆向与同源对比，未提供可执行利用代码）。关键可观测点/代码特征：

```text
InstallStager.exe: UnhookDLL("ntdll.dll"); UnhookDLL("kernel32.dll"); Process.EnterDebugMode();
  ExtractResource("InstallStager.Service64.exe"); path="C:\\Windows\\System32\\dllhost.exe";
  pid = Process.GetProcessesByName("winlogon")[0].Id; RunPE.Run(path, cmdline, payload, pid);
Service64: RegCreateKeyEx(HKLM\SOFTWARE\$sxrconfig); DACL "D:(A;OICI;GA;;;AU)";
  SetValueEx("pid"/"svc64"); CreateThread(ReflectiveDLLMain);
Named pipe: \\.\pipe\$sxrchildproc34226543a32 / $sxrchildproc38764243a64
r77 隐藏前缀: "$77"
```

## 变体与关联

- **同源开源项目**：r77-rootkit 的 Installer/Service/Uninstall 模块可直接编译复用；样本是同一项目的恶意编译产物，外层用 CSStub2 + Costura 打包。
- **前置载体**：BAT 注释行加载器见 [[pentest-c2-clientfix-bat-comment-line-aes-gzip-assembly-load]]；注册表加密载荷 + 计划任务反射加载见 [[pentest-c2-registry-aes-gzip-scheduled-task-reflective-load]]。
- **注入技术**：进程镂空/PPID 伪造的系统机制见 [[pentest-c2-windows-process-hollowing-pe-injection]]、[[pentest-c2-windows-ppid-spoof-suspended-host-injection]]、[[pentest-c2-dll-hollowing-sec-image-cow-gac-camouflage]]。
- **下游 RAT**：SeroXen RAT 基于 Quasar RAT，其配置解密可参考 [[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]；Quasar 客户端执行流程见 [[code-analysis-reverse-windows-quasar-rat-client-execution-flow]]。
- **边界**：r77 只隐藏 `$77` 前缀对象；内核态 EDR、ETW TI、内存扫描、进程树异常（winlogon→dllhost）仍可发现。

## 检测与防御

- **进程树**：`winlogon.exe` 下出现 `dllhost.exe`（COM Surrogate）且命令行带 `/Processid:`/异常参数，或 `dllhost.exe` 加载非系统 DLL/内存 PE；`Process.EnterDebugMode`/`SeDebugPrivilege` 提权行为。
- **注册表**：`HKLM\SOFTWARE\$sxrconfig`、`$sxr-*` 随机键、值为大 Base64；键 DACL 被改为允许 `AU` 完全访问；`pid`/`svc64` 值。
- **命名管道/文件**：`\\.\pipe\$sxrchildproc*`；`$77`/`$sxr` 前缀的文件、服务、计划任务；系统目录出现 `$sxr-powershell.exe` 等副本。
- **内存/API**：进程内 ntdll/kernel32 代码段被修改（unhook）、r77 DLL 注入所有进程、API hook 与子进程 hook；ETW 事件断流。
- **防御**：启用内核态 EDR/ETW TI、Protected Process Light 保护 winlogon、限制跨进程注入与 `SeDebugPrivilege`；监控 winlogon 子进程与 dllhost 异常；定期审计 `HKLM\SOFTWARE` 随机键/异常 DACL；对 r77-rootkit 的 `$77` 规则做专项狩猎。
