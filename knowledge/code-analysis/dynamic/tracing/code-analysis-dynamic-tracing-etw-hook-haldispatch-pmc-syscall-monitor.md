---
id: code-analysis-dynamic-tracing-etw-hook-haldispatch-pmc-syscall-monitor
title: ETW Hook 内核级 syscall 监控：替换 HalPrivateDispatchTable.HalCollectPmcCounters，栈上改写 SSDT 调用地址
type: scenario
domain: code-analysis
path: code-analysis/dynamic/tracing
technique: etw-hook-hal-private-dispatch-syscall-monitor
aliases:
- ETW Hook
- InfinityHook
- HalPrivateDispatchTable Hook
- EtwpReserveWithPmcCounters
- 内核级 syscall 监控
- PatchGuard 兼容 Hook
tags:
- windows
- kernel
- etw
- syscall
- hook
- sandbox
- tracing
- patchguard
- infinityhook
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V221
  verified_at: '2026-11-07T06:41:07+08:00'
  notes: 已对照原文全文与6张图核对：KiSystemCall64 栈上暂存 r10([rsp+40h])、EventID 0xF33/EVENT_DESCRIPTOR 0x501802/0x601802、EtwpReserveWithPmcCounters 的 Flags&0x800/HookIdCount、HalPrivateDispatchTable.HalCollectPmcCounters(+0x248) Hook 点、代理栈扫描改写 SSDT 地址、NtDelayExecution/NtClose/NtQuerySystemInformation(DebuggerDetect) 日志均一致。原文为监控/沙箱设计，未提供完整可编译驱动，confidence=medium 合理。
---

## 一句话结论

在 x64 Windows 内核中把 `HalPrivateDispatchTable.HalCollectPmcCounters`（表偏移 +0x248）替换为自己的代理函数，并配置 Circular Kernel Context Logger 的 `EVENT_TRACE_FLAG_SYSTEMCALL` 与 PMC `HookId=0xF33`，让每次用户态 syscall 的 ETW-Ti 记录路径都经过代理；代理在栈上按魔数 `0xF33` + `0x501802/0x601802` 定位 `KiSystemCall64` 暂存的系统调用函数地址（落在 SSDT 页范围内），将其改写为目标 detour，从而在不触发 PatchGuard 的情况下获得内核级 Native API 监控，能抓到绕过用户态 API Hook 的直接/间接系统调用。

## 原理

- Windows x64 的用户态 syscall 路径：`KiSystemCall64` 保存系统调用函数地址到栈上（`[rsp+40h]` 暂存 `r10`），调用 `PerfInfoLogSysCallEntry` 记录 ETW 事件，返回后从栈上恢复地址并 `call rax` 执行真正的 Nt 函数。若开启了 NT Kernel Logger 的 syscall 事件，控制流会进入 ETW 记录链：`PerfInfoLogSysCallEntry → EtwTraceSiloKernelEvent → EtwpLogKernelEvent → EtwpReserveWithPmcCounters → HalPrivateDispatchTable.HalCollectPmcCounters`。
- `HalPrivateDispatchTable` 位于内核 `.data`，PatchGuard 不监控该函数指针表；替换 `+0x248` 处的 `HalCollectPmcCounters` 不会像 SSDT Hook 那样触发 PatchGuard 蓝屏，且 Hook 完全在内核中，用户态看不到 inline hook 痕迹。
- 要让控制流真的走到 `EtwpReserveWithPmcCounters`，需同时满足：Logger 的 `Flags & 0x800`（PmcCounters 位）置位、`PmcData->HookIdCount != 0`、`PmcData->HookId[index] == HookId`。因此需要先用 `ZwTraceControl` 启动 CKCL 会话并设置 `EVENT_TRACE_FLAG_SYSTEMCALL`，再用 `ZwSetSystemInformation(SystemPerformanceTraceInformation, ...)` 配置 PMC Profile Source 与 `HookId=0xF33`。
- 代理函数在栈上搜索：先找 `USHORT 0xF33`，再在其后两格找 `0x501802`（Win11 23606 以前）或 `0x601802`（Win11 23606 及以后）的 `EVENT_DESCRIPTOR`；确认后继续遍历栈，找到落在 `g_SystemCallTable` 页范围内的指针，即为 `KiSystemCall64` 暂存的系统调用地址，把它替换成 detour 即可 Hook 对应 Native API。
- 只对目标进程生效：代理用 `PsGetCurrentProcessId()` 查进程白名单；`ExGetPreviousMode() == KernelMode` 时直接放行，避免接管内核自身调用。IRQL 需 `<= DISPATCH_LEVEL`。
- 对沙箱的价值：用户态 API Hook（如 Cuckoo 的 monitor.dll）会被 ntdll 重载、直接 syscall、间接 syscall（Hell's Gate）绕过；ETW Hook 位于 syscall 进入内核后的公共路径，能捕获这些调用。文章演示的样本使用间接系统调用，普通 Ring-3 Hook 抓不到，而该 Hook 记录到了 `NtDelayExecution`、`NtClose`、`NtQuerySystemInformation`（含 `DebuggerDetect` 行为）等调用。
- 沙箱工程化：内核侧用 MiniFilter 的 `FltSendMessage` 把调用记录发到 Ring-3；Hook `NtCreateThreadEx` 检测跨进程线程创建并把目标 PID 加入监控列表；对 `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` 记录反调试行为。堆栈检测可识别直接 syscall：检查返回地址是否落在正常用户模块（如 ntdll.dll），否则标记异常；间接 syscall 的调用链更像 `malware.exe → ntdll.dll → ntoskrnl.exe`，需要进一步判断跳转处是否为合法 `CALL`。

## 触发条件

- 目标为 x64 Windows；驱动需以内核权限加载（测试签名/禁用 DSE 或已有内核执行能力）。
- 能启动 Circular Kernel Context Logger 并配置 syscall/PMC 事件；部分 Windows 版本/安全策略可能限制 `ZwTraceControl`/`ZwSetSystemInformation`。
- `HalPrivateDispatchTable` 的布局与 `HalCollectPmcCounters` 偏移（+0x248）匹配目标版本；魔数 `0x501802`/`0x601802` 与 `0xF33` 的栈布局也随版本变化，需要按目标内核确认。
- 代理函数运行在 `DISPATCH_LEVEL` 以下，必须避免分页/阻塞操作；栈扫描范围用 `_AddressOfReturnAddress()` 与 KPCR 的栈上限（`gs:[0x1a8]`）界定。
- 若用于沙箱，需要配合进程白名单、MiniFilter 通信与用户态解析；只 Hook 目标样本，避免全局接管导致系统不稳定。

## 利用步骤

1. 启动 CKCL 会话：分配 `CKCL_TRACE_PROPERTIES`，设置 `Wnode.Guid = CkclSessionGuid`、`LogFileMode = EVENT_TRACE_BUFFERING_MODE`，调用 `ZwTraceControl(EtwpStartTrace, ...)`；成功后设置 `EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL` 并调用 `ZwTraceControl(EtwpUpdateTrace, ...)`。
2. 配置 PMC：用 `ZwSetSystemInformation(SystemPerformanceTraceInformation, EVENT_TRACE_PROFILE_COUNTER_INFORMATION)` 设置 `TraceHandle=2`、`ProfileSource[0]=1`，置位 `Flags.PmcCounters`；再用 `EVENT_TRACE_SYSTEM_EVENT_INFORMATION` 设置 `HookId[0]=0xF33`。
3. 保存 `HalPrivateDispatchTable.HalCollectPmcCounters` 原指针，把表项替换为 `ProxyEtwpReserveWithPmcCounters`。
4. 代理中检查 IRQL、PreviousMode 与目标 PID；在栈上搜索 `0xF33` 与 `0x501802/0x601802`，再找 SSDT 页范围内的函数指针；将其改写为对应 Nt API 的 detour。
5. detour 内记录参数、返回值、调用栈与 PID/TID，通过 `FltSendMessage` 发到用户态；调用原函数并返回。
6. Hook `NtCreateThreadEx` 等进程/线程操作，发现跨进程线程创建时把目标 PID 加入监控列表，覆盖注入到白进程或新拉起进程的行为。
7. 在用户态解析日志、打行为标签（如 `DebuggerDetect`、`RemoteThread`），并定期检查 Hook 是否被 PatchGuard/系统更新破坏。

## PoC

代理函数核心（内核 C）：

```c
void ProxyEtwpReserveWithPmcCounters(PVOID Context, ULONGLONG TraceBuff) {
    USHORT magic = 0xF33;
    ULONG sigOld = 0x501802, sigNew = 0x601802;
    PULONG rsp = _AddressOfReturnAddress();
    PULONG limit = (PULONG)__readgsqword(0x1a8);
    ULONG64 kthread = __readgsqword(0x188);
    ULONG syscallIndex = *(ULONG*)(kthread + 0x80);

    if (KeGetCurrentIrql() <= DISPATCH_LEVEL && ExGetPreviousMode() != KernelMode) {
        while (rsp <= limit) {
            if (*(PUSHORT)rsp == magic &&
                (rsp[2] == sigOld || rsp[2] == sigNew)) {
                for (; rsp <= limit; ++rsp) {
                    ULONG64 v = *(ULONG64*)rsp;
                    if (v >= PAGE_ALIGN(g_SystemCallTable) &&
                        v <= PAGE_ALIGN(g_SystemCallTable + PAGE_SIZE * 2)) {
                        if (LogManagerIsTargetProcess(PsGetCurrentProcessId()))
                            ProcessSyscall(syscallIndex, rsp); // 改写 *rsp 为 detour
                        break;
                    }
                }
                break;
            }
            ++rsp;
        }
    }
    g_oriHalCollectPmcCounters(Context, TraceBuff);
}
```

开启 syscall ETW 与 PMC（省略错误处理）：

```c
ckclProperty->Wnode.Guid = CkclSessionGuid;
ckclProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;
ZwTraceControl(EtwpStartTrace, ckclProperty, PAGE_SIZE, ckclProperty, PAGE_SIZE, &ret);
ckclProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
ZwTraceControl(EtwpUpdateTrace, ckclProperty, PAGE_SIZE, ckclProperty, PAGE_SIZE, &ret);

countInfo->EventTraceInformationClass = EventTraceProfileCounterListInformation;
countInfo->TraceHandle = 2;
countInfo->ProfileSource[0] = 1;
ZwSetSystemInformation(SystemPerformanceTraceInformation, countInfo, sizeof(*countInfo));

eventInfo->EventTraceInformationClass = EventTraceProfileEventListInformation;
eventInfo->TraceHandle = 2;
eventInfo->HookId[0] = 0xF33;
ZwSetSystemInformation(SystemPerformanceTraceInformation, eventInfo, sizeof(*eventInfo));
```

## 变体与关联

- 变体：不改 SSDT 地址，直接在代理中记录 syscall 参数/栈并放行，做纯观测；也可按 `systemCallIndex` 只 Hook 指定 Nt API。
- 变体：`GetCpuClock`（`EtwpReserveTraceBuffer` 路径）是更早的替换点，但在较新 Windows 已被修复，需改用 `EtwpReserveWithPmcCounters`。
- 变体：结合无限 Hook（InfinityHook）思路，把代理用于隐藏/重定向特定调用；这属于攻击性滥用，需评估 PatchGuard/HVCI 与稳定性风险。
- 关联：[[code-analysis-dynamic-tracing-ftrace-function-graph-syscall-error-locate]]（Linux 侧 syscall 跟踪）、[[pentest-c2-indirect-syscall-jmp-ntdll-syscall-stub]]（被本卡监控的间接系统调用手法）、[[pentest-c2-hells-gate-neighbor-ssn-recovery]]（直接 syscall 绕过用户态 Hook 的另一条路径）。
- 边界：魔数/偏移/`HalPrivateDispatchTable` 布局随 Windows 版本变化；PatchGuard 可能在未来版本覆盖该表；代理在 DISPATCH_LEVEL 执行，不能分页/阻塞；只 Hook 用户态发起的 syscall，内核直接调用需另做处理。

## 检测与防御

- 检测（针对该 Hook 本身）：`HalPrivateDispatchTable` 函数指针与磁盘/基线不一致；`HalCollectPmcCounters` 指向非 `hal.dll` 模块；ETW Logger 被异常启动/配置（CKCL 会话、`EVENT_TRACE_FLAG_SYSTEMCALL`、PMC HookId）；栈上出现非预期的 SSDT 地址改写或 detour 跳转。
- 检测（沙箱侧输出）：直接/间接 syscall 的返回地址不在 ntdll.dll；`NtCreateThreadEx` 跨进程调用；`THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER`；`NtQuerySystemInformation` 查询 `SystemModuleInformation` 等反调试/环境探测行为。
- 防御：启用 HVCI/内核代码完整性、PatchGuard 与驱动签名；监控 HAL 分发表与内核 `.data` 完整性；限制 `ZwTraceControl`/`ZwSetSystemInformation` 的调用权限；对 ETW 会话配置做审计；沙箱环境配合 VM 快照/重置与网络过滤。
- 加固：驱动加载白名单；对高价值主机启用基于虚拟化的监控（VT-x/EPT）作为 ETW Hook 的补充；对内核回调/函数指针做定期基线比对。
