---
id: defense-detection-nmi-stack-scan-unbacked-kernel-rootkit
title: NMI 中断全核堆栈捕获：从 TSS Ist3 machine frame 取 RIP/RSP 检测无模块内核 Rootkit
type: scenario
domain: defense
path: defense/detection
technique: nmi-stack-scan-unbacked-kernel-rootkit
tags:
- windows
- kernel
- rootkit
- detection
- nmi
- stack-scan
- kdmapper
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:27:06+08:00'
  notes: 已对照原文核对：KeRegisterNmiCallback/HalSendNMI 全核发送与延时、KPCR(IA32_GS_BASE)->TSS.Ist3->MACHINE_FRAME 取 RIP/RSP、RIP 不在模块范围的判据、高 IRQL 采集/分析分离与蓝屏限制均一致；与 PTE Walk 卡为不同检测维度，保留。未编译/复跑。
url: /docs/defense/detection/defense-detection-nmi-stack-scan-unbacked-kernel-rootkit/
draft: false
kb_aliases:
- NMI 检测 Rootkit
- KeRegisterNmiCallback
- HalSendNMI
- 不可屏蔽中断堆栈检测
- 无模块驱动检测
- 内核线程堆栈检查
---

## 一句话结论

向每个 CPU 核心发送不可屏蔽中断（NMI），在 `KeRegisterNmiCallback` 注册的回调中从 `KPCR` → `TSS.Ist3` → `MACHINE_FRAME` 取出被打断线程的 `RIP`/`RSP`，判断 RIP 是否落在任何已加载内核模块范围内；Kdmapper 等手动映射的 Rootkit 线程返回地址通常不在合法模块中，因此可被捕获，且 NMI 无法被普通内核代码屏蔽。

## 原理

- **中断打断线程**：IPI/DPC/APC/NMI 都能打断 CPU 上正在执行的线程；NMI 是不可屏蔽中断，优先级最高，适合做“全核快照”。
- **每核发送 NMI**：`KeRegisterNmiCallback` 注册回调，`HalSendNMI` 按 `KAFFINITY_EX` 向指定核心发送；同一时间只能处理一个 NMI，需在核心之间加延时等待回调完成。
- **从 TSS 取现场**：x64 下 `IA32_GS_BASE` 指向当前 CPU 的 `KPCR`，`KPCR+0x8`（`KPCR_TSS_BASE_OFFSET`）取 TSS 指针；NMI 使用 IST3 栈，`MACHINE_FRAME = TSS.Ist3 - sizeof(MACHINE_FRAME)`，其中保存了被打断现场的 `RIP` 与 `RSP`。
- **合法性判定**：用 `SystemModuleInformation`/`PsLoadedModuleList` 遍历已加载模块，若 `RIP` 不在任一 `[ImageBase, ImageBase+ImageSize]` 内，则很可能是无模块驱动/内核 shellcode；文章给出的判断函数对 HAL/PatchGuard 做了排除说明。
- **高 IRQL 约束**：NMI 回调运行在高 IRQL，必须只做“采集”（读 TSS/machine frame、保存 RIP/RSP），把堆栈分析推迟到低 IRQL；直接在回调里调用 `RtlWalkFrameChain` 等复杂函数可能蓝屏。
- **局限**：Rootkit 线程必须相对活跃才能被命中；若攻击者使用模块踩踏或 .data ptr 劫持等不依赖高频线程的通信方式，NMI 可能扫不到（文章因此另介绍 .data ptr 通信）。

## 触发条件

- 防守方拥有内核驱动能力，能注册 NMI 回调并读取 KPCR/TSS。
- 目标为 x64 Windows，使用 IST3 作为 NMI 栈（需按目标版本确认偏移/结构）。
- Rootkit 采用 Kdmapper 式手动映射且存在活跃线程；模块踩踏场景不适用。
- 回调必须遵守高 IRQL 约束，采集与分析分离。
- 需准备合法模块列表并处理 HAL/PatchGuard 等白名单。

## 利用步骤

1. 在驱动中调用 `KeRegisterNmiCallback(NmiCallback, NmiContext)` 注册回调。
2. 用 `ExAllocatePool2` 分配 `KAFFINITY_EX`，遍历 `KeQueryActiveProcessorCount(0)` 的每个核心，`KeInitializeAffinityEx` + `KeAddProcessorAffinityEx` 后调用 `HalSendNMI`。
3. 每次发送后 `KeDelayExecutionThread` 延时（如 100ms），确保该核心的 NMI 回调执行完毕，再处理下一个核心。
4. 在 `NmiCallback` 中读取 `IA32_GS_BASE` 得到 KPCR，取 TSS，计算 `machineFrame = tss->Ist3 - sizeof(MACHINE_FRAME)`，保存 `machineFrame->rip/rsp` 到上下文。
5. 回到低 IRQL 后遍历已加载模块，判断保存的 RIP 是否在模块范围内；不在则标记为可疑无模块 Rootkit 线程。
6. 记录命中的 RIP/RSP、核心号与时间，结合 PTE Walk/页表扫描进一步确认映射页。

## PoC

核心代码（基于文章代码，省略结构体定义与错误处理）：

```c
PVOID registration_handle = KeRegisterNmiCallback(NmiCallback, NmiContext);

for (ULONG core = 0; core < KeQueryActiveProcessorCount(0); core++) {
    KeInitializeAffinityEx(ProcAffinityPool);
    KeAddProcessorAffinityEx(ProcAffinityPool, core);
    HalSendNMI(ProcAffinityPool);
    KeDelayExecutionThread(KernelMode, FALSE, &delay); // 等待回调完成
}

KeDeregisterNmiCallback(registration_handle);
```

```c
NmiCallback(_In_ BOOLEAN Handled)
{
    UINT64 kpcr = __readmsr(IA32_GS_BASE);
    TASK_STATE_SEGMENT_64* tss =
        *(TASK_STATE_SEGMENT_64**)(kpcr + KPCR_TSS_BASE_OFFSET);
    PMACHINE_FRAME machineFrame = tss->Ist3 - sizeof(MACHINE_FRAME);
    CheckStack(machineFrame->rip, machineFrame->rsp); // 仅采集，分析延后
}
```

```c
BOOLEAN IsInModule(UINT64 RIP, PSYSTEM_MODULES modules) {
    for (INT i = 0; i < modules->module_count; i++) {
        PRTL_MODULE_EXTENDED_INFO m = ...;
        if (RIP >= (UINT64)m->ImageBase && RIP <= (UINT64)m->ImageBase + m->ImageSize)
            return TRUE;
    }
    return FALSE;
}
```

## 变体与关联

- **中断类型**：IPI、DPC、APC 也能打断线程，但 NMI 不可屏蔽、覆盖全核，更适合对抗 Rootkit；不同中断的可观测性与副作用不同。
- **采集与分析分离**：回调只保存现场，低 IRQL 再做 `RtlWalkFrameChain`/模块比对，避免高 IRQL 蓝屏。
- **组合检测**：NMI 命中可疑 RIP 后，用 PTE Walk 确认该地址是否有模块外可执行页，或用内存特征扫描确认镜像。
- **关联**：[[defense-detection-pte-walk-kdmapper-unbacked-executable-pages]]（页表扫描）、[[pentest-privilege-escalation-kdmapper-unsigned-driver-manual-map-trace-cleanup]]（被检测的 Kdmapper 手法）、[[pentest-c2-win32k-data-ptr-hijack-kernel-communication]]（不依赖高频线程的 .data ptr 通信，可规避 NMI）。

## 检测与防御

- **部署**：作为 EDR/反作弊的内核检测模块，周期性或按需对全核发 NMI；对命中模块外 RIP 的线程告警并采样。
- **误报控制**：HAL、PatchGuard、驱动临时映射等可能不在模块列表；维护白名单并记录版本差异。
- **性能与稳定性**：全核 NMI 有开销且不能频繁触发；回调严格短小，延时等待回调完成，避免在高负载/关键路径频繁扫描。
- **对抗升级**：攻击者可用模块踩踏、.data ptr 劫持、低活跃线程规避 NMI；防御需结合 PTE Walk、调用栈完整性、内核回调与 ETW TI 多源关联。
