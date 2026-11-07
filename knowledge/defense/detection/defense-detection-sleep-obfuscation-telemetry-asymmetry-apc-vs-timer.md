---
id: defense-detection-sleep-obfuscation-telemetry-asymmetry-apc-vs-timer
title: 睡眠混淆的遥测不对称：APC 路线有 NtCreateThreadEx/线程回调/ETW TI 可见，Timer 队列全程 Ring3 缺乏内核遥测
type: scenario
domain: defense
path: defense/detection
technique: sleep-obfuscation-telemetry-analysis
aliases:
- SleepObfs 检测
- 睡眠混淆遥测面
- Timer 队列无内核遥测
- RtlCreateTimer Ring3
- ETW TI SUSPEND_THREAD
tags:
- windows
- sleep-obfuscation
- detection
- etw
- edr
- threat-hunting
- timer-queue
- apc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:51:14+08:00'
  notes: 已对照原文与 img/06-12、13-26、50-54 核对：APC 路线 NtCreateThreadEx 挂起线程/NtQueueApcThread、SentinelOne hook、PsSetCreateThreadNotifyRoutineEx、ETW TI SUSPEND_THREAD/RESUME_THREAD/CONTEXT_PARSE，Timer 路线 RtlCreateTimer/TpAllocTimer/TppInitializeTimer/TppWorkInitialize 全 Ring3 堆、Cronos 走 NtCreateTimer，均与原文一致；属检测分析卡，保留。
---

## 一句话结论

APC 型睡眠混淆需要 `NtCreateThreadEx(CREATE_SUSPENDED)` 与 `NtQueueApcThread`，会留下用户态 hook、`PsSetCreateThreadNotifyRoutineEx` 线程回调与 ETW Threat Intelligence 的 `SUSPEND_THREAD`/`RESUME_THREAD` 等遥测；而 Timer 队列型（`RtlCreateTimer → TpAllocTimer → TppInitializeTimer → TppWorkInitialize`）的回调和上下文全部在 Ring3 堆上初始化，不进入 Ring0，内核遥测几乎为空，检测必须依赖 Ring3 堆/栈扫描或 inline hook。

## 原理

- **APC 路线为何可见**：实现需要先 `NtCreateThreadEx` 创建一个挂起线程（`THREAD_CREATE_FLAGS_CREATE_SUSPENDED`），再通过 `NtQueueApcThread` 向该线程插入 `NtContinue` 等 APC。线程创建可被用户态 hook 拦截（如 SentinelOne 在 `NtCreateThreadEx` 放置的 hook），也可被驱动通过 `PsSetCreateThreadNotifyRoutineEx` 注册的内核线程创建/删除回调捕获；ETW Threat Intelligence 提供 `SUSPEND_THREAD`/`RESUME_THREAD`、`CONTEXT_PARSE` 等关键字，APC 与挂起/恢复线程操作会留下内核遥测。
- **Timer 路线为何不可见**：`CreateTimerQueueTimer` 最终走到 `RtlCreateTimer`，后者依次调用 `TpAllocTimer → TppInitializeTimer → TppWorkInitialize`，Timer 对象通过 `RtlAllocateHeap` 在进程堆上分配，回调、参数和 `CONTEXT` 都存放在堆内存中，整个过程由用户态代码完成，没有对应的系统调用进入 Ring0。因此内核 ETW/回调缺少“定时器注册”这类事件，Windows 原生遥测对该技术几乎是空白。
- **对比 Cronos**：`CreateWaitableTimerW` 会走到 `KernelBase!CreateWaitableTimerExW`，再通过 syscall 进入 Ring0（`NtCreateTimer`），因此可被内核侧遥测捕获；这与 Timer 队列定时器形成鲜明对比。
- **可用的检测面**：对 APC 路线，优先使用内核线程回调、ETW TI 关键字与用户态 API hook；对 Timer 路线，只能依赖 Ring3 的 Timer 堆枚举（如 TickTock 搜索 `TppTimerpCleanupGroupMemberVFuncs`、解析回调与 `CONTEXT`）、线程栈扫描（如 HSB 检查 `RtlpTpTimerCallback` 分发地址、非可执行页、跨模块帧）以及 `RtlCreateTimer`/`RtlRegisterWait` 的 inline hook。

## 触发条件

- 防守方需要在 Windows 上检测/狩猎睡眠混淆植入物；
- 已确认或怀疑目标使用 APC 或 Timer 队列型睡眠混淆；
- 具备用户态进程内存读取（扫描器）或内核 ETW/回调采集能力；
- 攻击者可能对 Ring3 hook 做绕过，因此不能把单一用户态 hook 当作可靠检测点。

## 利用步骤

本卡为防御分析，无攻击利用步骤。检测流程：

1. 先判断睡眠混淆类型：观察线程创建/挂起痕迹、APC 队列、`RtlCreateTimer`/`CreateTimerQueueTimer` 调用与 Timer 堆结构。
2. APC 路线：采集 `NtCreateThreadEx` 与 `NtQueueApcThread` 调用、`PsSetCreateThreadNotifyRoutineEx` 回调事件、ETW TI 的 `SUSPEND_THREAD`/`RESUME_THREAD`；结合 Elastic 等规则（如检测经 `NtTestAlert` 触发的 `VirtualProtect`）。
3. Timer 路线：用用户态扫描器枚举 Timer 堆，解析回调/参数/`CONTEXT`；同时扫描线程栈上的 `RtlpTpTimerCallback` 地址、非可执行页与跨模块帧；对 `RtlCreateTimer`/`RtlRegisterWait` 做入口完整性校验。
4. 将 Ring3 扫描结果与内核遥测做时间线关联，避免仅凭单一告警定性。

## PoC

无 PoC（防御分析卡）。可用观测点示例：

- ETW TI 关键字：`KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD`、`KERNEL_THREATINT_KEYWORD_RESUME_THREAD`、`KERNEL_THREATINT_KEYWORD_CONTEXT_PARSE`；
- 内核回调：`PsSetCreateThreadNotifyRoutineEx` 注册的线程创建/删除通知；
- 用户态扫描：Timer 堆中的 `TppTimerpCleanupGroupMemberVFuncs` 指针、`Timer callback`/`Timer parameter`、`CONTEXT.Rip`。

## 变体与关联

- **Cronos/WaitableTimer**：`CreateWaitableTimerW → CreateWaitableTimerExW → NtCreateTimer`，会进入 Ring0，检测面与 Timer 队列不同。
- **APC 睡眠混淆实现**：见 [[pentest-c2-apc-sleep-obfuscation-brc4-context-rop]]；Timer 队列实现见 [[pentest-c2-ekko-timer-queue-sleep-obfuscation]]。
- **检测绕过**：HSB 规则绕过见 [[pentest-c2-hsb-sleep-obfuscation-evasion-ntdll-gadget-stack-dup]]，TickTock 堆扫描绕过见 [[pentest-c2-ticktock-timer-heap-scan-bypass-call-addr-jmp-register]]，Ring3 inline hook 绕过见 [[pentest-c2-ring3-inline-hook-bypass-rtlcreatetimer-prologue]]。

## 检测与防御

- 对 APC 路线：以内核线程回调与 ETW TI 为主，用户态 hook 只作辅助；APC + 挂起线程 + `NtContinue` 的组合本身即高价值告警。
- 对 Timer 路线：接受“内核遥测空白”的现实，部署用户态 Timer 堆枚举与栈扫描；同时监控 `RtlCreateTimer`/`RtlRegisterWait` 入口完整性及私有可执行 stub。
- 栈完整性检测：栈加密/Stack Duplicate 会改变栈的连续性，可结合 `TEB.NtTib` 与栈回溯一致性检查。
- Ring3 hook 易被“复现首指令跳回”绕过，不应作为唯一检测点；长期看应把重心放在 Ring0 ETW 与内核回调。
- 本卡仅用于授权环境下的防御研究与检测建设。
