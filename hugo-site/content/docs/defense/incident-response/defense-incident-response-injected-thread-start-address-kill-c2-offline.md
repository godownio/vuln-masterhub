---
id: defense-incident-response-injected-thread-start-address-kill-c2-offline
title: 注入线程手工清除：Process Explorer 按起始地址 0x0 定位、Sleep/IOCompletion 堆栈确认后 kill 线程使 C2 下线
type: scenario
domain: defense
path: defense/incident-response
technique: injected-thread-start-address-kill-c2-offline
tags:
- incident-response
- windows
- process-injection
- thread
- cobaltstrike
- metasploit
- sliver
- process-explorer
- memory-forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V431
  verified_at: '2026-11-09T18:44:41+08:00'
  notes: 已对照原文与图片核对：Process Explorer Threads 按 Start Address 排序出现 0x0（图 19/23/33）、CS 线程 8168 栈 KeDelayExecutionThread→ZwDelayExecution→KERNELBASE!SleepEx+0xa1（图 20）、CreateRemoteThread 注入线程 5512 栈 SleepEx+0xf 与 0x... No unwind info 自加密帧（图 24）、kill 后 CS 客户端 356/3140 掉线与附属线程自行退出（图 21/25/26）、MSF RuntimeBroker 7264 栈 ws2_32!select+mswsock!WSPStartup（图 27/28）、Sliver SecurityHealthSystray 7528 栈 GetQueuedCompletionStatusEx→ZwRemoveIoCompletionEx（图 29-31）均与原文一致；关键进程清单（System 4/Idle 0/Registry/Smss/Wininit/Winlogon/Explorer/Lsass/svchost 命令行确认）与原文一致，卡片将原文 svhost 笔误订正为 svchost。路径 defense/incident-response 合法，无文章 ID/URL/长段摘录；与 13853 的 Yara 检测卡为检测→清除互补关系，不重复；单一线程级清除场景，颗粒度合适。未验证点：GUI 操作未复现；PPL/跨会话限制按原文边界保留。
url: /docs/defense/incident-response/defense-incident-response-injected-thread-start-address-kill-c2-offline/
draft: false
kb_aliases:
- 线程级清除
- Process Explorer 线程堆栈
- Start Address 0x0
- kill 注入线程
- CS 线程下线
- 不可 kill 的关键进程
- 注入线程手工分析
---

## 一句话结论

对注入型 C2 不必结束整个进程：在 Process Explorer 的 Threads 页按 Start Address 排序，注入线程通常显示为 `0x0`（或不在任何模块内的地址）；打开 Stack 看到 `SleepEx`/`NtDelayExecution`、`select`、`GetQueuedCompletionStatusEx` 等等待调用与无 unwind info 的自加密内存帧，即可确认恶意线程；结束该线程可使 CS/MSF/Sliver 掉线，其他附属线程随后会自动退出。

## 原理

- **起始地址是快速筛选器**：正常线程的起始地址显示为「模块+偏移」（如 `ntdll!RtlAcquireSRWLockExclusive+0x330`、`SecurityHealthSystray.exe+0x5540`）；注入线程由 `VirtualAlloc`/APC/远程线程创建，起始地址常为 `0x0` 或非模块地址，在 Process Explorer/Process Hacker 的 Start Address 列一眼可见。
- **堆栈决定 C2 类型**：注入的 shellcode 在等待时会进入各自的休眠原语——
  - Cobalt Strike：`ntoskrnl!KeDelayExecutionThread` → `ntdll!ZwDelayExecution` → `KERNELBASE!SleepEx`，栈上还有 `0x...`（无 unwind info）帧指向 CS 休眠时自加密的内存区；sleep mask 让这些帧看起来像未知模块。
  - Metasploit：`ws2_32!select+0x1ce`（socket 等待）→ `mswsock!WSPStartup` → `ntdll!NtDeviceIoControlFile`。
  - Sliver：`KERNELBASE!GetQueuedCompletionStatusEx` → `ntdll!ZwRemoveIoCompletionEx`（IOCP 等待）。
- **为什么 kill 线程有效**：C2 的会话由这个核心线程维持，结束它即断开网络与指令循环；其他附属线程（如管道、注入辅助线程）失去核心后通常很快自行退出，无需逐个处理。
- **为什么不要直接杀进程**：部分被注入的是关键系统进程，结束会触发系统重启/黑屏/服务中断。必须区分可杀与不可杀：`System`（PID 4）、`System Idle Process`（PID 0）、`Registry`、`Smss`、`Wininit`、`Winlogon`、`Lsass`（杀后约一分钟强制重启）、`Explorer`（黑屏，可恢复）、`svchost`（承载大量服务，需先看命令行参数确认承载的服务）。不重要的进程可直接 kill。
- **注入技术的差异**：CS 默认按顺序尝试 self-injection `CreateThread` → `NtQueueApcThread-s` → `CreateRemoteThread` → `RtlCreateUserThread`（可在 profile 的 `execute` 块配置），不同技术产生的线程数量/栈不同；但最终都表现为「起始地址异常的线程 + 等待原语栈」，因此按线程栈判断比按注入技术判断更通用。
- **限制**：受保护进程（PPL）、跨会话进程可能无法打开/结束线程；线程结束后若持久化未清除，C2 可能重新注入；应先留证（TID、堆栈、网络连接、内存镜像）。

## 触发条件

- 已确认主机存在注入型 C2（Yara 命中、异常线程起始地址、可疑外联），且需要在不重启业务的情况下处置；
- 防守方有管理员权限，Process Explorer/Process Hacker 可打开目标进程；
- 目标进程不是 PPL/受保护进程，或保护级别允许查询线程；
- 已评估结束线程/进程对业务的影响（关键系统进程不可随意结束）。

## 利用步骤

1. 在 Process Explorer 中定位可疑进程（被注入的签名进程、svchost、SystemSettingsBroker、SecurityHealthSystray 等）；记录 PID、签名、命令行。
2. 右键 Properties → Threads，点击 Start Address 列排序，找 `0x0` 或明显不在模块内的起始地址。
3. 选中可疑线程 → Stack，检查调用栈：`KeDelayExecutionThread/SleepEx`（CS）、`select`（MSF）、`GetQueuedCompletionStatusEx`（Sliver），以及无 unwind info 的 0x... 帧（自加密内存）。
4. 记录 TID、Start Address、完整堆栈、进程网络连接（TCP/IP 页）作为证据；必要时先做内存镜像。
5. 点击 Kill 结束该线程；观察 C2 控制台是否掉线、进程内其余可疑线程是否逐步退出。
6. 若不重要的进程可直接结束整个进程；对关键进程只杀线程并继续排查持久化，避免系统不稳定。
7. 清理后复查同一进程是否被重新注入，并删除服务/计划任务/启动项等持久化。

## PoC

无 PoC（GUI 操作流程）。等价的线程枚举命令（只读，用于确认 Start Address 异常）：

```powershell
Get-Process -Id 356 | ForEach-Object { $_.Threads } |
  Select-Object Id, StartAddress, ThreadState, WaitReason
```

Process Explorer 观察点：Threads 页的 `Start Address = 0x0`、State 为 `Wait:DelayExecution`/`Wait:WrQueue`、Stack 中出现 `SleepEx`/`select`/`GetQueuedCompletionStatusEx` 与 `No unwind info` 帧。

## 变体与关联

- 变体：Process Hacker、System Informer 或 EDR 的线程视图也可完成同样的起始地址/堆栈分析；也可用 ETW/Get-InjectedThread 类工具自动筛出异常起始地址。
- 变体：线程受保护无法结束时可先 Suspend 冻结 C2，再重启或按持久化清理流程处理。
- 变体：若 C2 使用 sleep mask，堆栈帧指向加密内存，仍可通过 `SleepEx` 等等待原语与异常起始地址定位；加密让静态字符串检测失效，但不改变线程等待行为。
- 关联：[[defense-detection-unbacked-thread-start-address-injection-bypass]]（用 `NtQueryInformationThread`+`VirtualQueryEx` 自动判定非 MEM_IMAGE 起始地址）、[[defense-detection-cobaltstrike-memory-hunting-toolkit]]（Beacon 内存与配置检测）、[[defense-detection-sleep-obfuscation-telemetry-asymmetry-apc-vs-timer]]（sleep 混淆的遥测差异）、[[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]（进程/服务级清除顺序，本卡聚焦线程级）。
- 边界：结束线程前未留证会丢失 C2 配置与内存证据；杀线程不等于清除持久化，攻击者可能重新注入；PPL 进程无法操作；线程栈因 C2 版本/配置（syscall、sleep mask）不同而不同，需结合起始地址与网络行为综合判断。

## 检测与防御

- 检测：线程 `Start Address` 为 `0x0` 或不属于任何已加载模块；线程栈含 `SleepEx`/`NtDelayExecution`/`select`/`GetQueuedCompletionStatusEx` 与无 unwind info 帧；被注入进程出现与自身业务不符的外联端口（如任意高位端口）。
- 取证：处置前保存进程列表、线程堆栈、网络连接、内存镜像与 Yara 命中结果，便于后续溯源与规则更新。
- 防御：限制管理员权限与调试权限；启用 PPL/CFG/CIG、EDR 对跨进程 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 的行为告警；对关键系统进程启用保护；发现注入后优先按持久化链路彻底清理或重启。
