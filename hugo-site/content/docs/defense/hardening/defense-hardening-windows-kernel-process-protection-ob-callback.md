---
id: defense-hardening-windows-kernel-process-protection-ob-callback
title: Windows 内核进程保护驱动：ObRegisterCallbacks 剥离句柄危险权限 + 进程创建回调自动保护子进程
type: scenario
domain: defense
path: defense/hardening
technique: windows-kernel-process-protection-ob-callback
tags:
- windows
- kernel-driver
- process-protection
- obregistercallbacks
- handle-access
- anti-kill
- edr
- hardening
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V234
  verified_at: '2026-11-07T09:05:25+08:00'
  notes: 已对照 18733 原文与全部 4 张图片核对：ObRegisterCallbacks 进程/线程预操作回调、PROTECT_ACCESS_MASK/THREAD_PROTECT_MASK、PsSetCreateProcessNotifyRoutineEx 子进程继承、设备 \Device\saogang 与 \DosDevices\saogang、IOCTL_ADD_PID/REMOVE_PID/ADD_NAME/SET_ALLOWPID、KernelHandle 放行边界及管理员 taskkill /f /pid 2020/404/8392 均返回拒绝访问均与源码/截图一致；驱动代码为演示性质、未编译加载。dedup 候选 BYOVD/PPL、load-image 回调、KiSystemCall64、进程通知回调分析均为不同技术，非同一卡。
url: /docs/defense/hardening/defense-hardening-windows-kernel-process-protection-ob-callback/
draft: false
kb_aliases:
- 内核级进程保护
- ObRegisterCallbacks 进程保护
- 剥离 PROCESS_TERMINATE
- taskkill 拒绝访问
- PsSetCreateProcessNotifyRoutineEx 子进程保护
- SAOGANG 驱动
---

## 一句话结论

加载一个内核驱动，在 `ObRegisterCallbacks` 的进程/线程句柄预操作回调里对受保护 PID 清除 `PROCESS_TERMINATE`、`PROCESS_CREATE_THREAD`、`PROCESS_VM_WRITE`、`PROCESS_SUSPEND_RESUME` 等危险权限，并用 `PsSetCreateProcessNotifyRoutineEx` 把受保护进程的子进程自动加入保护列表；此后即使管理员执行 `taskkill /f /pid <受保护PID>`，`OpenProcess(PROCESS_TERMINATE)` 也拿不到终止权限，`TerminateProcess` 返回“拒绝访问”。

## 原理

- **句柄是权限载体**：用户态不能直接操作 `EPROCESS`，必须通过 `OpenProcess`/`OpenThread` 获得的句柄；句柄的 `DesiredAccess` 决定能做什么。`taskkill /f` 的路径是 `OpenProcess(PROCESS_TERMINATE, ...)` → `TerminateProcess`；只要前一步拿不到 `PROCESS_TERMINATE`，后一步必然失败。
- **Ob 回调拦截**：驱动通过 `ObRegisterCallbacks` 注册 `PsProcessType`/`PsThreadType` 的 `OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE` 预操作回调；在 `POB_PRE_OPERATION_INFORMATION` 中判断目标 PID 是否在保护列表，若是则：
  - CREATE：`Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;`
  - DUPLICATE：`Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;`
  回调返回 `OB_PREOP_SUCCESS`，内核继续创建句柄，但危险权限已被剥离。
- **权限掩码**：进程侧包含 `PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION`；线程侧包含 `THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION | THREAD_SET_LIMITED_INFORMATION`。这样不仅阻止终止，也阻止远程线程注入、内存写入、挂起/恢复等后续操作。
- **子进程自动保护**：`PsSetCreateProcessNotifyRoutineEx` 注册进程创建/退出回调；新进程创建时 `CreateInfo` 非空，若 `CreateInfo->CreatingThreadId.UniqueProcess`（父进程 PID）在保护列表，则把子进程 PID 加入保护列表。这对浏览器多进程、服务拉起子进程等场景有效。
- **控制接口**：驱动创建 `\Device\saogang` 与 `\DosDevices\saogang` 符号链接，用户态用 `CreateFile(L"\\\\.\\saogang")` 打开，通过 `DeviceIoControl` 发送 `IOCTL_SAOGANG_ADD_PID`、`REMOVE_PID`、`ADD_NAME`、`SET_ALLOWPID` 等命令；全局列表用 `KSPIN_LOCK` 保护。
- **为什么管理员也杀不掉**：管理员权限只影响 `OpenProcess` 的常规安全检查；Ob 预操作回调在句柄创建前运行，仍会剥离 `PROCESS_TERMINATE`。原文截图显示管理员 `taskkill /f /pid 2020/404/8392` 均返回“拒绝访问”。
- **边界**：`Info->KernelHandle` 为真时回调直接放行（内核句柄）；拥有内核读写/驱动加载能力的攻击者可以绕过；驱动只覆盖其掩码内的访问位，其他终止路径（如内核态直接调用、受保护进程以外的句柄复制）不受控；驱动必须签名/测试签名加载。

## 触发条件

- 目标 Windows 允许加载内核驱动（测试签名模式、已签名驱动或存在 BYOVD 入口）。
- 驱动成功注册 Ob 回调与进程通知回调，保护开关开启。
- 受保护进程的 PID 或进程名被加入列表（或由父进程自动继承）。
- 用户态客户端能打开 `\\.\saogang` 并发送 IOCTL。
- 攻击者使用 `taskkill /f`、任务管理器结束任务、`Stop-Process -Force` 等常规路径尝试终止。

## 利用步骤

1. 编写/加载驱动：`IoCreateDevice` + `IoCreateSymbolicLink` 创建设备，注册 `IRP_MJ_CREATE`/`IRP_MJ_DEVICE_CONTROL` 分发函数。
2. 在 `DriverEntry` 中构造 `OB_OPERATION_REGISTRATION` 数组并调用 `ObRegisterCallbacks`；注册 `PsSetCreateProcessNotifyRoutineEx`。
3. 在 `OnPreOpenProcess`/`OnPreOpenThread` 中判断目标 PID/进程名是否受保护，命中则清除 `DesiredAccess` 中的危险位。
4. 用户态客户端打开 `\\.\saogang`，发送 `IOCTL_SAOGANG_ADD_PID`（或 `ADD_NAME`）把目标进程加入保护列表。
5. 以管理员执行 `taskkill /f /pid <PID>` 验证返回“拒绝访问”；任务管理器结束任务同样失败。
6. 需要退出保护时发送 `REMOVE_PID`/`DISABLE_PROTECTION`，或卸载驱动（注销回调、删除符号链接/设备）。

## PoC

```c
// 驱动：注册进程/线程句柄回调
OB_OPERATION_REGISTRATION ops[] = {
    { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, OnPreOpenProcess, NULL },
    { PsThreadType,  OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, OnPreOpenThread,  NULL },
};
OB_CALLBACK_REGISTRATION reg = {
    OB_FLT_REGISTRATION_VERSION, 2, RTL_CONSTANT_STRING(L"SAOGANG_12345.6171"), NULL, ops
};
ObRegisterCallbacks(&reg, &g_RegHandle);
PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);

// 预操作回调：剥离危险权限
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID ctx, POB_PRE_OPERATION_INFORMATION Info) {
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;
    ULONG pid = HandleToULong(PsGetProcessId((PEPROCESS)Info->Object));
    if (!IsPidProtected(pid)) return OB_PREOP_SUCCESS;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;
    else
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;
    return OB_PREOP_SUCCESS;
}

// 进程创建回调：受保护父进程的子进程自动加入
VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (!CreateInfo) return;
    ULONG parent = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
    if (IsPidProtected(parent)) AddProtectedPid(HandleToULong(ProcessId), NULL);
}
```

```cpp
// 用户态：打开设备并下发 IOCTL
HANDLE h = CreateFile(L"\\\\.\\saogang", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, 0, NULL);
DWORD pid = 8392, ret = 0;
DeviceIoControl(h, IOCTL_SAOGANG_ADD_PID, &pid, sizeof(pid), NULL, 0, &ret, NULL);
```

## 变体与关联

- **保护目标变体**：按 PID、进程名精确/模糊匹配、父进程继承；也可只保护特定线程或只剥离 `TERMINATE`。
- **实现变体**：`PsSetCreateProcessNotifyRoutineEx` 之外还可用 `PsSetLoadImageNotifyRoutine`、ETW/ minifilter；用户态自保护可用 PPL（Protected Process Light）或服务恢复策略。
- **攻防双用**：同一技术在 EDR/杀软中用于自我保护，在恶意软件中用于反终止/反卸载；攻击者也可用 BYOVD 驱动从内核直接 `ZwTerminateProcess` 绕过 Ob 回调。
- **关联**：[[pentest-privilege-escalation-byovd-zwterminateprocess-ppl-edr-kill]]（BYOVD 白驱动强杀 PPL）、[[code-analysis-reverse-windows-process-notify-callback-analysis]]（WinDbg 枚举进程创建回调）、[[defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove]]（另一类内核/运行时保护与移除对抗）。

## 检测与防御

- **检测**：监控驱动加载与 `ObRegisterCallbacks`/`PsSetCreateProcessNotifyRoutineEx` 的调用；枚举设备对象/符号链接（如 `\\.\saogang`）与不明 IOCTL 接口；对“taskkill 被拒绝访问但进程仍存活”的告警做驱动排查。
- **防御**：启用驱动签名强制、HVCI/内核隔离；限制管理员加载未签名驱动；使用 PPL/ELAM 保护关键安全进程；对 EDR 自身做完整性校验。
- **边界**：该驱动不是对抗内核级攻击者的安全边界；拥有内核权限的攻击者可绕过 Ob 回调或直接卸载驱动。生产环境应结合签名验证、IOCTL 调用者校验（不要只依赖 `ValidateCallerAccess` 的简化检查）和最小权限原则。
- **注意**：原文代码为演示性质，`ValidateCallerAccess`、`GetProcessNameByPid` 等实现被简化；实际部署需补全调用者鉴权、对象引用计数与卸载同步，避免引入新的内核攻击面。
