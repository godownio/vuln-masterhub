---
id: code-analysis-reverse-windows-thread-notify-callback-analysis
title: WinDbg 枚举 PspCreateThreadNotifyRoutine：杀软线程创建回调与注入检测点
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: kernel-thread-notify-callback-analysis
tags:
- reverse-engineering
- windows
- kernel
- windbg
- notify-routine
- thread-injection
- edr
- defender
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:53:43+08:00'
  notes: 已对照原文核对：PspSetCreateThreadNotifyRoutine 的 ExAllocateCallBack、PspCreateThreadNotifyRoutine 数组、cmp ebx,40h、PspNotifyEnableMask bit3，以及 5 个回调（WdFilter×2、mmcss、KslD×2）、安装火绒重启后 sysdiag+0xcc50、KslD!tk::COSCallback::CreateThreadNotifyRoutineEx 的 [rdi+228h]/[rdi+230h]/_guard_dispatch_icall 遍历均与正文一致。该节无独立截图，SEC_IMAGE 检查为作者推测，卡内已标 medium；无版本区间。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-thread-notify-callback-analysis/
draft: false
kb_aliases:
- PspCreateThreadNotifyRoutine
- 线程创建回调
- MpCreateThreadNotifyRoutineEx
- KslD COSCallback
- sysdiag 线程回调
- 内核线程监控
---

## 一句话结论

`nt!PspCreateThreadNotifyRoutine` 数组保存了所有线程创建通知回调；在 WinDbg 中枚举该数组可看到 Defender 的 `MpCreateThreadNotifyRoutine`/`MpCreateThreadNotifyRoutineEx` 以及第三方驱动（如 `KslD!tk::COSCallback::*`、火绒 `sysdiag+0xcc50`）都订阅了线程创建。反汇编这些回调可读出检测维度：System 进程（PID 4）例外、跨进程创建者 PID 比对、起始地址是否来自 `SEC_IMAGE` 映射；这也是 `VirtualAlloc` + `CreateRemoteThread` 容易被识破的原因。

## 原理

- `PsSetCreateThreadNotifyRoutine(Ex)` 注册时分配回调块并插入 `PspCreateThreadNotifyRoutine` 数组；注册代码会用 `lea rcx,[nt!PspCreateThreadNotifyRoutine]` 定位数组，以 `cmp ebx,40h` 遍历 64 个槽位，并通过 `PspNotifyEnableMask` 的 bit 3 打开线程通知。
- 数组表项与进程回调相同，是带低位标志的编码指针；清低 4 位后 `dps <addr> L2`，第二个 qword（+8）即回调函数。文章环境初始有 5 个非零项：`WdFilter!MpCreateThreadNotifyRoutine`、`WdFilter!MpCreateThreadNotifyRoutineEx`、`mmcss!CiThreadNotification`、`KslD!tk::COSCallback::CreateThreadNotifyRoutine`、`KslD!tk::COSCallback::CreateThreadNotifyRoutineEx`。
- `MpCreateThreadNotifyRoutine` 的检查点：`cmp r12d,4` 说明目标进程为 System（PID 4）时直接放行；`PsGetCurrentProcessId` 取发起者 PID 后与目标 PID 比较（`cmp r15,r12; setne`），用于区分本地线程创建与跨进程远程创建；`PsIsSystemThread` 另外判断系统线程。
- `MpCreateThreadNotifyRoutineEx` 能拿到 `PS_CREATE_THREAD_NOTIFY_ROUTINE_EX`（含线程初始栈与起始地址）；文章判断它会检查 `StartAddress` 是否指向 `SEC_IMAGE` 映射，若只是 `VirtualAlloc` 出来的私有内存再 `CreateRemoteThread`，会被识别（该点为原文分析，未见对应反汇编片段）。
- 第三方 AV 也使用同一机制：安装火绒并重启后，数组中新增 `sysdiag+0xcc50` 回调；重启后可观察到 `KslD!tk::COSCallback::CreateThreadNotifyRoutineEx`，其实现遍历内部回调列表（`[rdi+228h]` 计数、`[rdi+230h]` 数组）并通过 `_guard_dispatch_icall` 逐个调用。说明线程创建是主流杀软共同的监控点。

## 触发条件

- 已通过双机内核调试连接目标 Windows，并加载 `nt`、`WdFilter` 及第三方驱动符号（无符号时可用 `ln`/基址+偏移）。
- 目标机加载了注册线程创建回调的 AV/EDR 驱动；安装/更新安全产品后通常需要重启回调才生效。
- 关注的是内核态线程创建路径；用户态注入手法是否最终触发这些回调，取决于其是否调用 `NtCreateThreadEx`/`PsCreateSystemThread` 等内核路径。
- 数组布局、回调地址随 Windows 与产品版本变化。

## 利用步骤

1. 查看注册函数确认数组位置与槽位数：
   ```text
   kd> u nt!PsSetCreateThreadNotifyRoutine L30
   ```
   关键指令：`call nt!ExAllocateCallBack`、`lea rcx,[nt!PspCreateThreadNotifyRoutine]`、`cmp ebx,40h`、`lock inc dword ptr [nt!PspCreateThreadNotifyRoutineCount]`、`lock bts dword ptr [nt!PspNotifyEnableMask],3`。
2. 读取数组：
   ```text
   kd> dq nt!PspCreateThreadNotifyRoutine L10
   ```
   文章环境显示 5 个非零表项。
3. 对每个表项清低 4 位后解引用：
   ```text
   kd> dps ffff8283`48008580 L2
   ffff8283`48008580  00000000`00000020
   ffff8283`48008588  fffff80a`83aaf690 WdFilter!MpCreateThreadNotifyRoutine
   ```
4. 反汇编 Defender 的两个线程回调，定位检查逻辑：
   ```text
   kd> u WdFilter!MpCreateThreadNotifyRoutine L50
   kd> u WdFilter!MpCreateThreadNotifyRoutineEx
   ```
   关注 `cmp r12d,4`（System PID 4 放行）、`PsGetCurrentProcessId` 与 `cmp r15,r12; setne`（远程/本地判定）、`PsIsSystemThread`。
5. 安装/更新第三方 AV 后重启，再次 `dq`/`dps` 对比数组，新增表项即新注册的线程回调；对 `sysdiag+0xcc50` 或 `KslD!tk::COSCallback::CreateThreadNotifyRoutineEx` 下断/反汇编，观察其内部回调列表遍历。
6. 结合 `PspNotifyEnableMask` 的 bit 3 判断线程通知是否全局启用；结合回调地址的驱动模块归属判断由哪个产品注册。

## PoC

```text
kd> u nt!PsSetCreateThreadNotifyRoutine L30
kd> dq nt!PspCreateThreadNotifyRoutine L10
kd> dps ffff8283`48008580 L2
kd> dps ffff8283`480086d0 L2
kd> dps ffff8283`487a43f0 L2
kd> dps ffff8283`487a9b20 L2
kd> dps ffff8283`487a9bb0 L2
kd> u WdFilter!MpCreateThreadNotifyRoutine L50
kd> u WdFilter!MpCreateThreadNotifyRoutineEx
kd> u KslD!tk::COSCallback::CreateThreadNotifyRoutineEx L50
```

```text
# 关键反汇编片段（原文）
fffff80a`83aaf6d8  cmp r12d,4                 ; 目标进程 PID == 4（System）则跳过
fffff80a`83aaf6e2  mov rcx,qword ptr gs:[188h]
fffff80a`83aaf6eb  call qword ptr [WdFilter!_imp_PsIsSystemThread]
fffff80a`83aaf707  call nt!PsGetCurrentProcessId
fffff80a`83aaf722  cmp r15,r12               ; 发起者 PID vs 目标 PID
fffff80a`83aaf72e  setne byte ptr [rsp+30h]  ; 跨进程创建标志
```

## 变体与关联

- 变体：不同 AV/EDR 注册的回调数量与函数名不同；新装/升级安全产品后通常要重启，数组才会出现新回调（文章观察到的现象）。
- 变体：除线程创建外，进程创建、镜像加载、对象句柄操作也各有回调入口，可沿用相同枚举流程，见进程回调卡。
- 边界：文章未给出绕过这些检查的 PoC；“`StartAddress` 必须为 `SEC_IMAGE`”“VirtualAlloc+CreateRemoteThread 会被识破”是作者基于函数行为的判断，未展示对应反汇编或实测拦截日志，按 medium 置信度保留。
- 关联：[[code-analysis-reverse-windows-kernel-debugging-vmware-windbg]]（调试环境）、[[code-analysis-reverse-windows-process-notify-callback-analysis]]（进程创建回调）、[[pentest-c2-shellcode-loader-rx-sleep-etw-encryption]]、[[pentest-c2-windows-process-hollowing-pe-injection]]（与线程/进程注入相关的规避背景）。

## 检测与防御

- 检测（防御方视角）：线程创建通知回调是 EDR 检测注入的核心机制；应监控 `PspCreateThreadNotifyRoutine` 数组是否被摘除/篡改，以及 `PspNotifyEnableMask` 的 bit 3 是否被清零；安全产品回调缺失是内核级对抗的强信号。
- 检测（攻击方视角/审计）：跨进程创建（发起者 PID ≠ 目标 PID）会被重点检查；System 进程 PID 4 是明确例外；起始地址不是镜像映射的线程更容易触发判定。
- 加固：启用驱动签名与 PatchGuard/内核完整性保护；限制内核调试与驱动加载；监控新注册的线程创建回调及其驱动来源。
