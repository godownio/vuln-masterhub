---
id: code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch
title: NtQuery* 调试信息反调试：DebugPort/DebugObjectHandle/DebugFlags 与参数篡改绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: ntquery-debug-info-argument-patch
aliases:
- NtQueryInformationProcess 反调试
- ProcessDebugPort 0x7
- ProcessDebugObjectHandle 0x1E
- ProcessDebugFlags 0x1F
- NtQueryObject 绕过
- ZwSetInformationThread ThreadHideFromDebugger
tags:
- windows
- anti-debug
- ntdll
- ntqueryinformationprocess
- ntqueryobject
- zwsetinformationthread
- reversing
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:45:38+08:00'
  notes: 已对照原文与图片02核对：0x7/0x1E/0x1F、CheckRemoteDebuggerPresent、SystemKernelDebuggerInformation、NtQueryObject、ZwSetInformationThread 参数绕过一致；PoC 未复跑。
---

## 一句话结论

样本通过 `NtQueryInformationProcess` 查询 `ProcessDebugPort(0x7)`、`ProcessDebugObjectHandle(0x1E)`、`ProcessDebugFlags(0x1F)`，或通过 `CheckRemoteDebuggerPresent`、`NtQuerySystemInformation(SystemKernelDebuggerInformation)`、`NtQueryObject`、`ZwSetInformationThread(ThreadHideFromDebugger)` 判断是否被调试；绕过方法是在这些 API 的参数/返回值处下断，把查询类参数改成无关值（如 `NtQueryObject` 的 class 改为 0）、把 `ZwSetInformationThread` 的第二个参数改为 0，或直接改返回值和后续条件跳转。

## 原理

- **`NtQueryInformationProcess` 的信息类**：
  - `ProcessDebugPort`（0x7）：被调试时返回非 0 的调试端口（常见为 `-1`/全 F），未调试时为 0。
  - `ProcessDebugObjectHandle`（0x1E）：被调试时返回非 NULL 的调试对象句柄。
  - `ProcessDebugFlags`（0x1F）：返回调试标志；为 0 表示处于调试状态（原文口径）。
- **`CheckRemoteDebuggerPresent`**：内部通常走 `NtQueryInformationProcess(ProcessDebugPort)`，只是封装；不仅能查当前进程，也能查其他进程。
- **`NtQuerySystemInformation(SystemKernelDebuggerInformation)`**：返回 `SYSTEM_KERNEL_DEBUGGER_INFORMATION`，`DebuggerEnabled == 1` 表示系统处于调试状态（内核调试器/调试启动配置）。
- **`NtQueryObject`**：通过 `ObjectInformationClass` 查询对象信息；反调试可用它枚举/识别调试对象。原文的绕过是把第二个参数（信息类）改为 0（`ObjectBasicInformation`），使样本拿到无关信息/失败，从而跳过检测。
- **`ZwSetInformationThread(ThreadHideFromDebugger=0x11)`**：把当前线程从调试器隐藏/分离；样本用它阻止调试。绕过是在调用前把第二个参数改为 0，使 `ThreadInformationClass` 变为无效/无操作（原文口径），或直接 patch 调用。
- **为什么参数/返回值篡改有效**：这些 API 都是用户态可拦截的 ntdll 导出；检测逻辑依赖特定参数与返回值。改变参数让 API 返回“未调试”或失败，或改变返回值/条件跳转，即可让分支走向正常路径。

## 触发条件

- 目标 Windows PE 在启动/主逻辑中调用上述 ntdll API 做反调试。
- 分析者能在调试器中拦截 ntdll 导出（下断点、hook、patch），并控制参数/返回值。
- 样本未对 API 返回结果做多处交叉校验，或校验可一并 patch。

## 利用步骤

1. 在 IDA/x64dbg 中搜索 `NtQueryInformationProcess`、`CheckRemoteDebuggerPresent`、`NtQuerySystemInformation`、`NtQueryObject`、`ZwSetInformationThread` 的导入/调用。
2. 对 `NtQueryInformationProcess`：在调用处确认信息类（第二个参数）是 0x7/0x1E/0x1F；把类改成无关值，或在返回后把输出缓冲区/`eax` 改成“未调试”的值（DebugPort=0、DebugObjectHandle=0、DebugFlags=1）。
3. 对 `NtQueryObject`：把第二个参数（`ObjectInformationClass`）改为 0，或让调用返回失败。
4. 对 `ZwSetInformationThread`：把第二个参数（`ThreadInformationClass`）改为 0，或直接跳过调用。
5. 对 `NtQuerySystemInformation`：把 `SystemKernelDebuggerInformation` 返回结构中的 `DebuggerEnabled` 改为 0。
6. 如果不想逐个改 API，可在 ntdll 对应函数入口写 hook/`ret`，统一返回“未调试”；或在每个检测后的条件跳转处改 ZF。
7. 继续运行，确认不再触发退出/弹窗，直到主逻辑。

## PoC

原文未给出可执行 PoC；按原文 API 清单整理的调试器操作要点（未在本机执行）：

```text
NtQueryInformationProcess(ProcessHandle, Class, Info, Len, RetLen)
  Class 0x7  ProcessDebugPort         被调试 -> 非 0（常见 -1）
  Class 0x1E ProcessDebugObjectHandle 被调试 -> 非 NULL
  Class 0x1F ProcessDebugFlags        被调试 -> 0

CheckRemoteDebuggerPresent(hProcess, &bDebugged)
NtQuerySystemInformation(SystemKernelDebuggerInformation, &info, ...)
  info.DebuggerEnabled == 1 -> 调试状态

NtQueryObject(Handle, ObjectInformationClass, ...)
  绕过：ObjectInformationClass = 0

ZwSetInformationThread(ThreadHandle, ThreadInformationClass, ...)
  ThreadHideFromDebugger = 0x11
  绕过：ThreadInformationClass = 0
```

说明：原文只给出 API 与“改参数/改返回值”的思路，未提供样本、地址或脚本；具体寄存器/栈参数位置需按目标架构与调用约定确认。

## 变体与关联

- 变体（检测 API）：`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`、`NtQuerySystemInformation`、`NtQueryObject`、`ZwSetInformationThread`、`NtSetInformationThread`。
- 变体（绕过）：改参数、改返回值、条件断点改 ZF、hook ntdll 导出、patch 调用点、在内核态隐藏调试对象。
- 关联：[[code-analysis-reverse-anti-debug-peb-fields-patch]]（PEB 字段检测）；[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（Loader 用 DebugPort/DebugFlags 做环境检测）；[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]（调试器 API 组合）；[[code-analysis-reverse-anti-debug-tls-callback-pe-null-patch]]（TLS 回调中的 API 检测）。
- 边界：样本若直接系统调用（SSN）绕过 ntdll hook、或用内核驱动验证调试状态，用户态参数篡改会失效；需要内核调试/驱动 patch。

## 检测与防御

- 检测：样本导入/调用上述 ntdll API；同一进程多次查询 DebugPort/DebugFlags；`ZwSetInformationThread(ThreadHideFromDebugger)` 调用；ntdll 代码段被 hook/patch。
- 防御（反反调试）：交叉验证多个 API/PEB 字段、直接系统调用、内核态检测、对 ntdll 代码段做完整性校验；分析侧优先用硬件断点与脚本化返回值修改，减少 patch 痕迹。
