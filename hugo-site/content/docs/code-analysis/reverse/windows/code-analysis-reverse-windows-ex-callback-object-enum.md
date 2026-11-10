---
id: code-analysis-reverse-windows-ex-callback-object-enum
title: 遍历 Windows 执行体回调对象：ExpCallbackListHead、CALLBACK_OBJECT/CALLBACK_REGISTRATION 与分版本 PushLock
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-ex-callback-object-enumeration
tags:
- windows
- kernel
- driver
- callback
- expcallbacklisthead
- anti-hook
- windbg
- edr
- enumeration
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:12:55+08:00'
  notes: 已对照原文全文核对（原文无图片）：ExCreateCallback/ExRegisterCallback/ExNotifyCallback/ExUnregisterCallback 流程、CALLBACK_OBJECT 0x38（tag 'llaC'、ListEntry@0x10、AllowMultipleCallbacks@0x20、ListEntry2@0x28）与 CALLBACK_REGISTRATION 0x30 字段、ExpCallbackListHead/ExpCallbackListLock 双层链表与 SpinLock/PushLock 遍历、Win10 ExAcquirePushLockSharedEx 与 Win7 ExfAcquirePushLockShared 分支均与原文伪代码/结构定义一致。未验证点：原文通过外部 g_info 提供全局地址、未展开定位方法，卡片已标注需符号/特征扫描；PoC 为改写的最小化伪代码，未在驱动环境编译运行；结构偏移随版本变化。原文无版本信息，affected_versions 已 --clear。dedup 报告无 duplicate，最近候选 Cm/Ob/Ps 回调族与 Ex Callback 对象不同。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-ex-callback-object-enum/
draft: false
kb_aliases:
- 执行体回调
- Ex Callback Objects
- CALLBACK_OBJECT
- CALLBACK_REGISTRATION
- ExRegisterCallback
- ExpCallbackListHead
- \Callback 对象目录
- AntiHook EnumExCallback
---

## 一句话结论

Windows 的“执行体回调对象”（Callback Objects，`ExCreateCallback`/`ExRegisterCallback` 一族）把注册信息挂在 `CALLBACK_OBJECT` 的注册链表与内核全局链表 `ExpCallbackListHead` 上；在驱动里按 `ExpCallbackListHead → CALLBACK_OBJECT.ListEntry2 → CALLBACK_OBJECT.ListEntry → CALLBACK_REGISTRATION` 逐层遍历，并分别持有全局 PushLock 与对象 SpinLock，就能枚举系统内所有执行体回调及其回调函数所属驱动（如 `WdFilter.sys`、第三方安全驱动），用于反 Hook/EDR 检查与内核组件行为分析。

## 原理

- **对象与 API**：执行体回调对象是一种内核对象（类型 `ExCallbackObjectType`）。驱动用 `ExCreateCallback(&obj, &attrs, Create, AllowMultipleCallbacks)` 创建或打开，`ExRegisterCallback(obj, fn, ctx)` 注册回调并返回一个注册句柄，`ExNotifyCallback` 触发，`ExUnregisterCallback` 注销。命名对象位于对象目录 `\Callback\` 下，如 `PowerState`、`ProcessorAdd`、`SetSystemTime`、`SeImageVerificationDriverInfo`、`IoSessionNotifications` 等；系统组件与安全驱动通过它们挂钩电源、时间、处理器、镜像校验等事件。
- **CALLBACK_OBJECT（x64 约 0x38 字节，tag 为 `'llaC'`/`0x6c6c6143`）**：
  - `+0x00` Tag；
  - `+0x08` SpinLock（保护本对象的注册链表）；
  - `+0x10` ListEntry：本对象的 `CALLBACK_REGISTRATION` 链表；
  - `+0x20` AllowMultipleCallbacks（为 false 时只允许注册一个回调）；
  - `+0x28` ListEntry2：链接到全局 `ExpCallbackListHead` 的节点。
- **CALLBACK_REGISTRATION（约 0x30 字节）**：
  - `+0x00` ListEntry（挂到 `CALLBACK_OBJECT.ListEntry`）；
  - `+0x10` CallbackObject 指针；
  - `+0x18` CallbackFunction（回调函数地址）；
  - `+0x20` CallbackContext；
  - `+0x28` 计数字段与标志字节。
- **全局链表与锁**：`ExCreateCallback` 创建对象时在 `ExpCallbackListLock`（PushLock）保护下把对象的 `ListEntry2` 插入 `ExpCallbackListHead` 双向链表。因此从该链表可以拿到**所有**对象，包括未命名对象（例如 ALPC/电源相关的内核回调），这是仅查 `\Callback\` 对象目录做不到的。
- **遍历顺序与加锁**：
  1. `KeEnterGuardedRegion`，按系统版本获取共享 PushLock（Windows 10 用 `ExAcquirePushLockSharedEx`，Windows 7 用 `ExfAcquirePushLockShared`），遍历 `ExpCallbackListHead`；
  2. 对每个 `CALLBACK_OBJECT`，用 `CONTAINING_RECORD(iter, CALLBACK_OBJECT, ListEntry2)` 还原对象；
  3. 取对象 `SpinLock`（`KeAcquireSpinLockRaiseToDpc`），遍历其 `ListEntry` 注册链表，用 `CONTAINING_RECORD(iter, CALLBACK_REGISTRATION, ListEntry)` 取节点，读取 `CallbackFunction`/`CallbackContext`；
  4. 释放 SpinLock，继续下一个对象；最后释放 PushLock、`KeLeaveGuardedRegion`。
- **函数归属解析**：对每个 `CallbackFunction` 用 `RtlPcToFileHeader`（或 AuxKlib 相关接口/符号解析）得到所属驱动映像路径，再配合 PDB/导出符号把地址翻译成 `模块!符号`。文章的输出即把回调定位到 `ntoskrnl.exe`、`ACPI.sys`、`tcpip.sys`、`WdFilter.sys`、`360netmon.sys` 等模块，便于判断哪些安全组件在监控什么事件。
- **为什么有价值**：安全软件/反作弊常用这类回调监控系统行为；反 Hook 工具或应急分析需要知道系统里有哪些回调、由谁注册、是否出现未签名/异常驱动的回调。对象目录与全局链表的差异还能暴露被恶意驱动从全局链表摘除（隐藏）的命名对象。
- **限制**：`ExpCallbackListHead`、`ExpCallbackListLock` 不导出符号，文章的代码通过外部 `g_info` 提供地址；实际使用需用符号/特征扫描定位（例如在 `ExCreateCallback` 的插入路径中找 `lea` 全局地址），跨 Windows 版本结构偏移与锁 API 都要重新核对；遍历必须持有正确的锁，否则对象/节点可能被并发注销导致释放后使用。

## 触发条件

- 已能在目标上运行内核代码（测试签名驱动、BYOVD 入口或双机内核调试）。
- 已知目标 Windows 版本的 `ExpCallbackListHead`/`ExpCallbackListLock` 地址（私有符号、特征码扫描或调试器手工定位）。
- `CALLBACK_OBJECT`/`CALLBACK_REGISTRATION` 的字段偏移已按版本核对（结构无公开符号）。
- 目标需要分析的对象确实通过 Ex 回调注册（其他回调族如 `CmRegisterCallback`、`PsSetCreateProcessNotifyRoutine`、`ObRegisterCallbacks` 不在本链表里）。

## 利用步骤

1. 在 WinDbg/符号服务器或特征扫描中定位 `ExpCallbackListHead` 与 `ExpCallbackListLock`；先用 `!object \Callback` 记录命名对象基线。
2. 确认版本对应的共享 PushLock API（Win10 `ExAcquirePushLockSharedEx`，Win7 `ExfAcquirePushLockShared`），用 `MmGetSystemRoutineAddress` 动态取址。
3. 进入受保护区域，取共享锁，环形遍历 `ExpCallbackListHead`。
4. 对每个 `CALLBACK_OBJECT` 取其 SpinLock，遍历注册链表并打印回调函数、上下文、对象名与 tag；对函数地址做模块归属解析。
5. 释放锁后整理输出，重点检查：未签名驱动/临时目录驱动注册的回调、与安全软件已知回调不符的条目、`AllowMultipleCallbacks=false` 但出现多个注册的异常对象。
6. 与 `\Callback` 对象目录对比：目录中存在但全局链表中缺失的对象，可能被恶意代码摘链隐藏；反向差异也要核查。

## PoC

```c
typedef struct _CALLBACK_OBJECT {
    ULONG        Tag;                    /* 'llaC' */
    KSPIN_LOCK   SpinLock;
    LIST_ENTRY   ListEntry;              /* CALLBACK_REGISTRATION 链表 */
    BOOLEAN      AllowMultipleCallbacks;
    LIST_ENTRY   ListEntry2;             /* 挂入 ExpCallbackListHead */
} CALLBACK_OBJECT, *PCALLBACK_OBJECT;

typedef struct _CALLBACK_REGISTRATION {
    LIST_ENTRY       ListEntry;
    PCALLBACK_OBJECT CallbackObject;
    PVOID            CallbackFunction;
    PVOID            CallbackContext;
    ULONG            n;
    BOOLEAN          b;
} CALLBACK_REGISTRATION, *PCALLBACK_REGISTRATION;

void EnumOneObject(PCALLBACK_OBJECT obj, PVOID ctx) {
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&obj->SpinLock);
    for (PLIST_ENTRY it = obj->ListEntry.Flink; it != &obj->ListEntry; it = it->Flink) {
        PCALLBACK_REGISTRATION r =
            CONTAINING_RECORD(it, CALLBACK_REGISTRATION, ListEntry);
        /* 打印 obj、r->CallbackFunction、r->CallbackContext，
           并用 RtlPcToFileHeader 解析回调函数所属模块 */
    }
    KeReleaseSpinLock(&obj->SpinLock, irql);
}

/* 调用方需先定位 ExpCallbackListHead / ExpCallbackListLock，
   并按版本取得 ExAcquirePushLockSharedEx 或 ExfAcquirePushLockShared */
void EnumAllExCallbacks(PLIST_ENTRY head, PVOID pushLock,
                        VOID (*acquire)(PVOID, ULONG),
                        VOID (*release)(PVOID, ULONG), PVOID ctx) {
    KeEnterGuardedRegion();
    acquire(pushLock, 0);
    for (PLIST_ENTRY it = head->Flink; it != head; it = it->Flink) {
        PCALLBACK_OBJECT obj = CONTAINING_RECORD(it, CALLBACK_OBJECT, ListEntry2);
        EnumOneObject(obj, ctx);
    }
    release(pushLock, 0);
    KeLeaveGuardedRegion();
}
```

说明：结构与流程按文章正文/反汇编整理，地址定位与锁函数获取为伪代码占位；结构偏移与锁 API 随 Windows 版本变化，需在目标版本核对后再运行。

## 变体与关联

- **只枚举命名对象**：用 `ExCreateCallback`/`ObReferenceObjectByName` 打开 `\Callback\<Name>` 后直接遍历其注册链表，不需要全局地址，但看不到未命名对象。
- **其他回调族**：注册表回调（`CmpCallback` 链表/`CmUnRegisterCallback`）见 [[code-analysis-reverse-windows-cm-callback-list-enum-unregister]]；进程/线程/镜像通知回调的分析见 [[code-analysis-reverse-windows-process-notify-callback-analysis]]、[[code-analysis-reverse-windows-thread-notify-callback-analysis]]、[[code-analysis-reverse-windows-load-image-notify-callback]]；对象回调见 [[defense-hardening-windows-kernel-process-protection-ob-callback]]。
- **监控系统时间**：驱动可打开 `\Callback\SetSystemTime` 并 `ExRegisterCallback`，在时间被修改时收到通知（IRQL ≤ DISPATCH_LEVEL，回调里不能做阻塞操作）；这既是反作弊/安全监控手法，也可用于检测时间篡改。
- **边界**：拿不到全局地址、目标版本结构偏移不符、遍历未加锁导致竞争崩溃、或回调对象已被恶意代码摘链时，枚举结果不完整。

## 检测与防御

- **检测**：监控驱动加载与内核内存访问，尤其是非签名/临时目录驱动扫描 `ntoskrnl` 全局链表的行为；对比 `\Callback` 目录与回调链表的基线差异；关注对 `ExUnregisterCallback` 的可疑调用与回调函数被 patch 成 `ret` 的情况。
- **防御**：启用驱动签名强制、HVCI、PatchGuard；限制测试签名与 BYOVD 驱动的加载；安全产品对自身回调做完整性校验与恢复；定期采集回调基线用于应急排查。
- **分析用途**：应急响应时用本枚举确认安全软件/恶意驱动在系统事件上的挂钩情况，判断攻击者是否通过注册回调实现持久化监控或阻断。
