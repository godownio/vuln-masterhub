---
id: code-analysis-reverse-windows-load-image-notify-callback
title: PsSetLoadImageNotifyRoutine 驱动监控 DLL 加载：模块路径、进程过滤与加载顺序验证
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-load-image-notify-callback
aliases:
- PsSetLoadImageNotifyRoutine
- 映像加载通知回调
- DLL 加载顺序监控
- 内核模块加载监控
- EPROCESS ImageFileName
- LoadImageNotify
tags:
- windows
- kernel-driver
- callback
- load-image
- dll
- monitoring
- edr
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:46:02+08:00'
  notes: 已对照原文与图片09核对：PsSetLoadImageNotifyRoutine、EPROCESS ImageFileName 0x450、notepad.exe 过滤、ntdll→kernel32 加载顺序一致；已修正 insmod 为 Windows 驱动加载工具；PoC 未编译运行。
---

## 一句话结论

内核驱动调用 `PsSetLoadImageNotifyRoutine` 注册回调后，每次进程/驱动映射 PE 映像（DLL/SYS/EXE）都会收到 `FullImageName`、`ProcessId` 与 `PIMAGE_INFO`；用 `PsLookupProcessByProcessId` 取 EPROCESS 并按 `ImageFileName` 过滤目标进程，即可按加载顺序打印 ntdll→kernel32→其他 DLL 的完整路径，用于验证系统 DLL 的装载顺序、监控模块加载或辅助 EDR 检测。

## 原理

- `PsSetLoadImageNotifyRoutine(PIMAGE_INFO_ROUTINE routine)` 注册一个加载映像通知回调；在 `DriverEntry` 中调用，卸载时用 `PsRemoveLoadImageNotifyRoutine` 注销。
- 回调签名 `VOID routine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)`：`FullImageName` 是映像路径（如 `\Device\HarddiskVolume3\Windows\System32\ntdll.dll`），`ProcessId` 是加载进程，`ImageInfo` 含 `ImageBase`、`ImageSize`、`SystemModeImage` 等。
- 过滤进程：`PsLookupProcessByProcessId(ProcessId, &pEprocess)` 取 EPROCESS 指针；`EPROCESS.ImageFileName`（示例偏移 0x450，随 Windows 版本变化）是 15 字节的进程名，可在回调中只打印目标进程（如 notepad.exe）的模块。
- 加载顺序：进程创建时内核先映射 ntdll.dll，再映射 kernel32.dll 等；回调按发生顺序触发，因此日志可证明“ntdll 先于 kernel32 加载”，也可用于观察某个进程实际加载了哪些模块（含隐藏/非磁盘模块的映像路径）。
- 为什么有用：用户态 API（如 `EnumProcessModules`）只能看到已加载模块列表，且可能被 hook/篡改；内核回调在更底层、按事件实时触发，能记录模块加载的时间顺序与完整路径。
- 边界：回调在 `PASSIVE_LEVEL` 运行，不能做耗时/分页内存操作；`EPROCESS` 偏移随版本变化，应优先用 `PsGetProcessImageFileName` 或按版本适配；驱动需签名/Secure Boot 允许加载；`FullImageName` 对某些内存映射可能为空或特殊。

## 触发条件

- 攻击者/分析者拥有内核驱动加载权限（测试签名模式、已签名驱动、VM 调试环境）。
- 目标 Windows 版本与驱动编译版本匹配（WDK 构建），Secure Boot/模块签名策略允许加载。
- 需要监控的进程/模块已确定，或需要观察系统 DLL 的加载顺序。
- 有内核调试/日志查看手段（WinDbg、DebugView、`DbgPrintEx`）。

## 利用步骤

1. 用 WDK 创建 KMDF/WDM 空驱动，包含 `<ntifs.h>`。
2. `DriverEntry` 中调用 `PsSetLoadImageNotifyRoutine(TestRoutine)`，并设置 `DriverObject->DriverUnload`。
3. 在回调中 `PsLookupProcessByProcessId` 取 EPROCESS，按 `ImageFileName` 过滤目标进程；`DbgPrintEx` 输出 `FullImageName` 与 `ImageInfo->ImageBase`。
4. 卸载回调中 `PsRemoveLoadImageNotifyRoutine(TestRoutine)`；注意 `PsLookupProcessByProcessId` 返回的 EPROCESS 需要 `ObDereferenceObject` 释放（示例为简化省略）。
5. 编译、签名/测试签名，`sc create`/`sc start`（或 OSR Loader 等工具）加载；启动目标进程观察日志顺序。
6. 分析输出：确认 ntdll、kernel32 的先后与路径，识别异常模块/非系统路径加载。
7. 卸载驱动并清理服务；生产环境不要在未授权系统加载。

## PoC

```c
#include <ntifs.h>

#define DebugPrint(...) DbgPrintEx(77, 0, __VA_ARGS__)

static ULONG imageFileNameOffset = 0x450;   // 随 Windows 版本调整，优先用 PsGetProcessImageFileName

VOID TestRoutine(_In_opt_ PUNICODE_STRING FullImageName,
                 _In_ HANDLE ProcessId,
                 _In_ PIMAGE_INFO ImageInfo) {
    PEPROCESS pEprocess = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &pEprocess)))
        return;
    PUCHAR imageFileName = (PUCHAR)((ULONG64)pEprocess + imageFileNameOffset);
    if (_stricmp((const char *)imageFileName, "notepad.exe") == 0) {
        DebugPrint("%wZ  base=%p\n", FullImageName, ImageInfo->ImageBase);
    }
    ObDereferenceObject(pEprocess);
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject) {
    PsRemoveLoadImageNotifyRoutine(TestRoutine);
    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PsSetLoadImageNotifyRoutine(TestRoutine);
    DriverObject->DriverUnload = UnloadDriver;
    return STATUS_SUCCESS;
}
```

```text
预期输出（示例）：
\Device\HarddiskVolume3\Windows\System32\ntdll.dll
\Device\HarddiskVolume3\Windows\System32\kernel32.dll
\Device\HarddiskVolume3\Windows\System32\KernelBase.dll
...
```

## 变体与关联

- 变体：结合 `ImageInfo->SystemModeImage` 区分用户态 DLL 与内核驱动；记录 `ImageBase/ImageSize` 用于后续内存扫描。
- 变体：用 `PsSetCreateProcessNotifyRoutineEx`/`PsSetCreateThreadNotifyRoutine` 做进程/线程维度的互补监控（见关联卡）。
- 变体：EDR 用同一回调检测可疑模块加载（非系统路径、未签名、反射注入的手工映射可能不触发该回调，需其它遥测）。
- 关联：[[code-analysis-reverse-windows-process-notify-callback-analysis]]（进程创建回调数组分析）、[[code-analysis-reverse-windows-thread-notify-callback-analysis]]（线程创建回调分析）、[[pentest-c2-debug-event-load-dll-module-base]]（用户态调试事件获取模块基址，与内核回调互为视角）。

## 检测与防御

- 检测：新加载的未知签名驱动；`PsSetLoadImageNotifyRoutine` 的调用来自非安全厂商模块；驱动加载后大量打印/记录模块事件。
- 防御：启用 Secure Boot/驱动签名强制与 HVCI；只允许受信驱动；监控驱动加载与内核回调注册；对 `\Device\HarddiskVolume*` 之外的模块路径告警。
- 边界：该回调是合法监控机制，攻防双方都可使用；分析时注意偏移/版本适配与 `ObDereferenceObject` 引用计数，避免蓝屏。
