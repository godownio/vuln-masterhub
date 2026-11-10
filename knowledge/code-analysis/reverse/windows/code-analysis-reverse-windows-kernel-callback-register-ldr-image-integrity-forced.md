---
id: code-analysis-reverse-windows-kernel-callback-register-ldr-image-integrity-forced
title: 注册内核回调被 0xc0000022 拒绝：置 LDR_DATA_TABLE_ENTRY->Flags |= 0x20（LDRP_IMAGE_INTEGRITY_FORCED）让 MmVerifyCallbackFunction 通过
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ldr-image-integrity-forced-mmverifycallbackfunction-callback-register
aliases:
- MmVerifyCallbackFunction
- LDRP_IMAGE_INTEGRITY_FORCED
- Ldr->Flags |= 0x20
- PsSetCreateProcessNotifyRoutineEx 返回 0xc0000022
- ObRegisterCallbacks 0xc0000022
- 回调注册失败 STATUS_ACCESS_DENIED
- DriverSection Flags
- 内核回调注册条件
tags:
- windows
- kernel-driver
- callback
- process-notify
- obregistercallbacks
- image-integrity
- hvci
- rootkit
- bypass
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:25:53+08:00'
  notes: 已对照原文核对；本次核对未读取图片；PsSetCreateProcessNotifyRoutine 与 ...Ex 内部都调用 PspSetCreateProcessNotifyRoutine（第三参数不同）、注册路径经 MmVerifyCallbackFunction 校验 LDR_DATA_TABLE_ENTRY.Flags 的 0x20（LDRP_IMAGE_INTEGRITY_FORCED）、以及 DriverObject->DriverSection 的 Flags 按位或 0x20 后 Ex 回调与 ObRegisterCallbacks 均能注册成功（原文调试为 0xc0000022 即 STATUS_ACCESS_DENIED），均与正文一致；OBJECT_TYPE.TypeInfo.ObjectTypeFlags.SupportsObjectCallbacks 清零使 CallbackList 失效、以及 OB_OPERATION_REGISTRATION/OB_CALLBACK_REGISTRATION 各字段（Version=ObGetFilterVersion、Altitude、PreOperation）也与原文代码一致。未验证点：未加载/执行任何驱动；反汇编与调试输出截图未读图核对；LDR_DATA_TABLE_ENTRY.Flags 偏移随版本变化已在卡内注明；原文无版本区间，未设 affected_versions。
---

## 一句话结论

`PsSetCreateProcessNotifyRoutineEx` 与 `ObRegisterCallbacks` 在注册前都会调 `MmVerifyCallbackFunction` 检查「回调函数所在的驱动映像是否被标记为需要完整性校验」；检查不过就返回 `0xc0000022`（`STATUS_ACCESS_DENIED`），表现为「驱动加载成功、回调一行都不打印」。判断依据是驱动 `DriverObject->DriverSection` 指向的 `LDR_DATA_TABLE_ENTRY.Flags` 是否含 `LDRP_IMAGE_INTEGRITY_FORCED(0x20)`，因此在 `DriverEntry` 里先 `((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection)->Flags |= 0x20;` 再注册，回调即可正常工作——这正是「驱动必须带 HVCI/CI 签名标记才能注册内核回调」这条策略在运行期的可绕过点。

## 原理

- **两条注册路径共用一道校验**：`PsSetCreateProcessNotifyRoutine`（旧接口）与 `PsSetCreateProcessNotifyRoutineEx`（新接口）内部都调 `PspSetCreateProcessNotifyRoutine`，差别只是第三个参数（Ex 走一条会做额外校验的分支）；`ObRegisterCallbacks` 也调同一个 `MmVerifyCallbackFunction`。所以「旧接口能注册、Ex 接口静默失败」这一现象本身就指向该校验，而不是 API 用法错误。
- **校验的是什么**：`MmVerifyCallbackFunction(address)` 取出该地址所属驱动映像的 `LDR_DATA_TABLE_ENTRY`，读其 `Flags`；若 `LDRP_IMAGE_INTEGRITY_FORCED` 位置位则放行。这个位由内核在「以 HVCI/CI 策略强制完整性」方式加载的驱动上设置（安全启动 + 驱动签名 + HVCI 环境下的正常驱动天然带位），未签名/测试签名驱动的该位为 0，于是 `ObRegisterCallbacks` 直接返回 `STATUS_ACCESS_DENIED(0xc0000022)`。
- **为什么改 Flags 有效**：`MmVerifyCallbackFunction` 只读内存中的这个标志位、不做二次核验（不重算映像哈希、不查证书链）；而 `DriverSection` 是 `DriverObject` 里的公开字段，驱动自己就能拿到并改写。把位补上，校验即通过。这也说明它是一个「策略标记」而非「安全边界」。
- **为什么 Ex 接口比旧接口更值钱**：`PsSetCreateProcessNotifyRoutineEx` 的回调带 `PPS_CREATE_NOTIFY_INFO`，能拿到 `ImageFileName`、`CommandLine`、`FileObject`，并且**可以通过 `CreateInfo->CreationStatus` 拒绝进程创建**（EDR/进程保护的基础能力）；旧接口只有 PID 与 create/remove，不能拦截。因此「想用 Ex 但被拒」是实战中最常见的卡点。
- **对象回调的同类门槛**：`ObRegisterCallbacks` 通过后，回调才能对 `PsProcessType`/`PsThreadType` 的句柄创建/复制做预操作（改 `DesiredAccess`）；被拒时表现为「驱动 loaded、`DbgPrint` 无输出」，调试器里能看到返回 0xc0000022。
- **另一个相关的能力位**：`OBJECT_TYPE.TypeInfo.ObjectTypeFlags.SupportsObjectCallbacks` 决定 `OBJECT_TYPE.CallbackList`（老式 `ObRegisterCallbacks` 之外的 per-type 回调链）是否生效；把该位清零可以让依赖 `CallbackList` 的保护驱动失效——与「补 0x20 让自己能注册」正好是一对攻防操作。

## 触发条件

- 自写/修改的内核驱动未以「强制完整性」方式加载（测试签名、未签名、或关闭 HVCI 的环境下自行加载），因此 `Flags` 中缺 `0x20`。
- 驱动需要注册 `PsSetCreateProcessNotifyRoutineEx`、`PsSetCreateThreadNotifyRoutine` 或 `ObRegisterCallbacks`，且运行在会执行 `MmVerifyCallbackFunction` 的 Windows 版本上。
- 能在 `DriverEntry` 早期拿到 `DriverObject->DriverSection`（该字段在驱动加载时已由内核填好）。
- 具备内核代码执行能力（否则无从改位）；`LDR_DATA_TABLE_ENTRY.Flags` 的偏移随版本变化，需按 `dt nt!_LDR_DATA_TABLE_ENTRY` 核对。

## 利用步骤

1. 先只注册回调（不补位），在调试器里看返回值：`PsSetCreateProcessNotifyRoutineEx` / `ObRegisterCallbacks` 返回 `0xc0000022`，且回调从不触发——确认是校验问题而不是签名/参数问题。
2. 在 `DriverEntry` 最前面补位：
   ```c
   PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
   ldr->Flags |= 0x20;   /* LDRP_IMAGE_INTEGRITY_FORCED */
   ```
3. 再注册回调（Ex 版本 / Ob 版本），确认返回 `STATUS_SUCCESS` 且 `DbgPrint`/调试输出出现。
4. 卸载时正确注销：`PsSetCreateProcessNotifyRoutineEx(routine, TRUE)`、`ObUnRegisterCallbacks(RegistrationHandle)`；`PsSetLoadImageNotifyRoutine` 对应 `PsRemoveLoadImageNotifyRoutine`。
5. 若要停用别人的对象回调（分析保护类驱动时）：定位目标 `OBJECT_TYPE`，把 `TypeInfo.ObjectTypeFlags.SupportsObjectCallbacks` 清 0，`CallbackList` 上的回调即不再被调用（已注册的 `ObRegisterCallbacks` 预操作回调不受影响，二者机制不同）。

## PoC

```c
/* 关键一行：让 MmVerifyCallbackFunction 通过 */
PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
ldr->Flags |= 0x20;                     /* LDRP_IMAGE_INTEGRITY_FORCED */

/* 之后两类回调都能注册成功 */
PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)OnProc, FALSE);

OB_OPERATION_REGISTRATION ops = { 0 };
ops.ObjectType   = *PsProcessType;
ops.Operations   = OB_OPERATION_HANDLE_CREATE;
ops.PreOperation = OnPreOpen;
OB_CALLBACK_REGISTRATION reg = { 0 };
reg.Version = ObGetFilterVersion();
RtlInitUnicodeString(&reg.Altitude, L"114514");
reg.OperationRegistrationCount = 1;
reg.OperationRegistration = &ops;
ObRegisterCallbacks(&reg, &g_Handle);   /* 未补位时返回 0xc0000022 */
```

原文在调试环境中先复现了「Ex 回调无任何输出」，再反汇编比对 `PsSetCreateProcessNotifyRoutine` 与 `...Ex` 都落到 `PspSetCreateProcessNotifyRoutine`（第三参数不同），定位到 `MmVerifyCallbackFunction`，最后用 `Flags |= 0x20` 让两类回调都注册成功并看到回调输出。

## 变体与关联

- **不补位而改策略**：让驱动真正以 HVCI/CI 强制方式加载（正确签名 + 安全启动），位天然存在——这是正规做法，但需要证书与策略配合。
- **关掉校验**：在调试环境直接 patch `MmVerifyCallbackFunction` 返回成功，或 patch `PspSetCreateProcessNotifyRoutine` 跳过分支；适合分析，不适合持久化（HVCI 下内核代码只读）。
- **对象回调的停用**：清 `SupportsObjectCallbacks` 位（原文用 `OBCALL.sys` 保护 calc.exe，改位后保护失效）；这是对「老式 per-type 回调」的绕过，与 `ObRegisterCallbacks` 的预操作回调是两套机制。
- **回调本身的应用**：进程/线程回调做监控与拦截（[[defense-hardening-windows-kernel-process-protection-ob-callback]]）、加载映像回调做模块监控与「阻止驱动加载」（同批「load image notify 改入口点 ret 阻止驱动加载」卡）、注册表回调枚举与反注册（[[code-analysis-reverse-windows-cm-callback-list-enum-unregister]]）。
- **回调数组的取证**：在 WinDbg 里枚举 `PspCreateProcessNotifyRoutine`/`PspCreateThreadNotifyRoutine` 数组可看到实际注册者（[[code-analysis-reverse-windows-process-notify-callback-analysis]]、[[code-analysis-reverse-windows-thread-notify-callback-analysis]]）。

## 检测与防御

- **检测**：驱动中出现对 `DriverSection` 的写入（尤其写 `Flags |= 0x20`）是典型「伪装完整性标记」行为；可结合 HVCI/CI 日志核对「该驱动实际签名状态」与「内存中 Flags」是否一致，不一致即高度可疑。`ObRegisterCallbacks`/`PsSetCreateProcessNotifyRoutineEx` 的调用者若不是已知安全产品，也应告警。
- **防御**：启用 HVCI + 驱动签名强制 + 安全启动，使 `LDRP_IMAGE_INTEGRITY_FORCED` 与真实签名状态绑定；用 PatchGuard/内核代码完整性保护 `LDR_DATA_TABLE_ENTRY` 与 `OBJECT_TYPE` 的关键位不被改写；对非 PPL 驱动调用回调注册 API 做白名单。
- **边界**：本技巧只是「通过一道策略校验」，不改变驱动本身的签名状态；在开启 HVCI 且 PatchGuard 完整的环境里，改 `Flags` 可能触发完整性检查。原文为教学性质的内核实验，未在真实防护环境验证副作用。
