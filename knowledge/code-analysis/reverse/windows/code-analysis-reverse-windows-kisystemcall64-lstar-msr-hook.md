---
id: code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook
title: KiSystemCall64 系统调用钩子：重写 IA32_LSTAR MSR + 自建伪造 SSDT/Shadow SSDT 跳板
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-kisystemcall64-lstar-msr-hook
aliases:
- KiSystemCall64 hook
- LSTAR MSR Hook
- IA32_LSTAR 0xC0000082
- SSDT Hook
- Shadow SSDT Hook
- 系统调用拦截
- 内核钩子
- KKiSystemCall.sys
tags:
- windows
- kernel
- driver
- hook
- syscall
- lstar
- ssdt
- rootkit
- reverse-engineering
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T23:16:47+08:00'
  notes: 已对照原文与5张图核对：LSTAR MSR 0xC0000082、KiSystemCall64 现场/分发/参数复制、0x13000 布局、E8/FF15 重定位、伪造 SSDT/Shadow SSDT 跳板与 RVA 计算、NtTerminateProcess 索引41、多 CPU 写 LSTAR 均与原文一致；KMD Manager 加载 KKiSystemCall.sys、PC Hunter 报 Int2e/Sysenter 钩子、任务管理器结束 calc.exe 拒绝访问与截图一致。原文为节选代码，未提供完整可编译驱动，卡片已注明，未复跑。
---

## 一句话结论

x64 Windows 的用户态 `syscall` 会跳转到 `IA32_LSTAR`（MSR 0xC0000082）保存的 `KiSystemCall64`；驱动可以复制并重定位 `KiSystemCall64` 的代码、伪造 SSDT 与 Shadow SSDT 的 RVA 表和服务跳板，然后在每个 CPU 上把 LSTAR 改写为副本地址，从而拦截所有系统调用并在函数级挂钩（例如让 `NtTerminateProcess` 拒绝结束受保护进程）。

## 原理

- **系统调用入口**：用户态执行 `syscall` 时，CPU 硬件把返回地址存入 RCX、RFLAGS 存入 R11，并从 `IA32_LSTAR` MSR（0xC0000082）取出 `KiSystemCall64` 地址，切换到 Ring 0 与内核栈。改 LSTAR 就改掉了所有系统调用的统一入口。
- **KiSystemCall64 现场**：入口先 `swapgs` 切到 KPCR，把用户 RSP 存到 `KPCR+0x10`，从 `KPCR+0x1A8` 取内核栈；随后压入用户 SS（0x2B）、用户 RSP、RFLAGS、用户 CS（0x33）、返回地址，构造 `_KTRAP_FRAME`，保存非易失寄存器。
- **服务分发**：`KiSystemServiceStart` 用 `eax` 的系统调用号选择服务表：高位区分普通 SSDT 与 Shadow SSDT（GUI 服务），`eax & 0xFFF` 是服务索引；服务地址按 `ServiceTableBase + (RVA >> 4)` 计算（RVA 低 4 位保留）。参数大小从 `ArgumentTableBase` 取，用 `rep movsq` 从用户栈复制到内核栈。
- **钩子总体设计**：不能简单在 `KiSystemCall64` 头部写 jump（会破坏现场），而是把整段函数复制到新分配的非分页内存，修复其中的相对 call/jmp 与绝对地址引用，再让 LSTAR 指向副本；副本内部对 SSDT 的引用被重定向到伪造表。
- **内存布局**：一次分配约 0x13000 字节，分区放置原始代码副本、伪造的描述符表结构、地址指针数组、伪造 SSDT RVA 表、SSDT 跳板、SSDT 函数地址数组、伪造 Shadow SSDT RVA 表、Shadow 跳板与 Shadow 函数地址数组。
- **重定位**：扫描副本中的 `E8`（call rel32）与 `FF 15`（call qword ptr [rip+disp]），按原目标计算新偏移；把 `lea r10, [KeServiceDescriptorTable]`（`4C 8D 15`）改成 `jmp qword ptr [__Address]`（`FF 25`），使副本读取伪造表。
- **伪造 SSDT**：复制原表项，对每个服务计算原函数地址 `base + (RVA >> 4)` 存入函数指针数组；需要挂钩的索引（示例为 41，`NtTerminateProcess`）替换为自定义函数；为每个服务生成 6 字节跳板 `FF 25 XX XX XX XX`（jmp qword ptr [函数指针数组+index*8]），再把新 RVA 写回伪造表：`NewRVA = ((Trampoline - FakeBase) << 4) | (OriginalRVA & 0xF)`。修改函数指针数组即可动态换钩子。
- **Shadow SSDT**：win32k 的 GUI 服务位于会话空间，构造 Shadow 表前必须 `KeStackAttachProcess` 附加到 GUI 进程上下文，才能解析并复制相关地址。
- **多处理器安装**：对每个 CPU 执行 `KeSetSystemAffinityThread(1<<i)` → `__writemsr(0xC0000082, FakeKiSystemCall64)` → `KeRevertToUserAffinityThread()`，保证所有核心的 LSTAR 一致；卸载时反向恢复原地址并释放内存。
- **为什么能拦住进程结束**：挂钩 `NtTerminateProcess` 后，任务管理器结束进程会先进入钩子；钩子对受保护 PID 返回 `STATUS_ACCESS_DENIED`，不调用原函数，用户看到“拒绝访问”。

## 触发条件

- 攻击者/安全软件能在目标 Windows x64 上加载内核驱动（测试签名、已签名驱动、BYOVD 或被利用的驱动加载漏洞）。
- 驱动可读写 MSR（Ring 0）并分配非分页池，具备定位 `KeServiceDescriptorTable`/`KeServiceDescriptorTableShadow` 的能力。
- 目标未启用会阻止 MSR/SSDT 修改的强完整性保护，或攻击者已绕过相关保护（原文未讨论 PatchGuard/驱动签名等前置条件）。
- 需要挂钩的系统服务在 SSDT 或 Shadow SSDT 中，且调用路径经过 `KiSystemCall64`。
- 演示环境为 Windows 7 7601 x64 双机调试；系统调用反汇编示例取自 Windows 10 21H2。

## 利用步骤

1. 读取 `__readmsr(0xC0000082)` 取得原始 `KiSystemCall64` 地址，扫描函数边界（如查找 `E9` 跳转）确定需要复制的长度。
2. 分配 0x13000 字节非分页内存，按布局放置代码副本、伪造描述符表、RVA 表、跳板与函数指针数组。
3. 复制原始代码并修复相对 call/jmp 与 SSDT 引用；把 `lea r10, [KeServiceDescriptorTable]` 重定向到伪造表指针。
4. 构造伪造 SSDT：为每个服务生成跳板并写回新 RVA；在函数指针数组中把目标服务（如索引 41 `NtTerminateProcess`）替换为钩子函数。
5. 如需 GUI 服务，附加到 GUI 进程后构造 Shadow SSDT。
6. 遍历所有 CPU，设置亲和后写入 LSTAR 指向副本；恢复亲和生产环境。
7. 加载驱动（原文用 KMD Manager 加载 `KKiSystemCall.sys`），验证钩子：PC Hunter 检测到 Int2e/Sysenter 钩子（未知模块地址 0xFFFFFA80614F2000），任务管理器结束 calc.exe 返回“拒绝访问”。
8. 卸载时在所有 CPU 恢复原始 LSTAR 并释放池内存。

## PoC

安装钩子的核心片段（原文节选，非完整可编译驱动）：

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
    DriverObject->DriverUnload = DriverUnload;

    __FakeKiSystemCall64 = ReloadKiSystemCall64();
    if (__FakeKiSystemCall64) {
        KiSystemCall64 = __readmsr(0xC0000082);

        for (ULONG i = 0; i < KeNumberProcessors; i++) {
            KeSetSystemAffinityThread((KAFFINITY)((ULONG64)1 << i));
            __writemsr(0xC0000082, __FakeKiSystemCall64);
            KeRevertToUserAffinityThread();
        }
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}
```

服务地址与跳板计算：

```c
ULONG_PTR OriginalFunction = (ULONG_PTR)OriginalTable->ServiceTableBase
                           + (OriginalRVA >> 4);
__FakeSsdtService[i] = OriginalFunction;

if (i == 41) { // NtTerminateProcess
    __NtTerminateProcess = (LPFN_TERMINATEPROCESS)__FakeSsdtService[i];
    __FakeSsdtService[i] = (ULONG_PTR)FakeNtTerminateProcess;
}

BuildTrampoline(__SsdtTrampoline, &__FakeSsdtService[i]);
ULONG NewRVA = (ULONG)((__SsdtTrampoline - __FakeServiceTableBase) << 4)
             | (OriginalRVA & 0xF);
__FakeServiceTableBase[i] = NewRVA;
__SsdtTrampoline += 6;
```

钩子函数：

```c
NTSTATUS FakeNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    DbgPrint("NtTerminateProcess called: PID=%d, Status=0x%X\n",
             PsGetProcessId(ProcessHandle), ExitStatus);

    if (IsProtectedProcess(ProcessHandle)) {
        return STATUS_ACCESS_DENIED;
    }
    return __NtTerminateProcess(ProcessHandle, ExitStatus);
}
```

检测 LSTAR/SSDT 是否被改：

```c
BOOLEAN IsKiSystemCall64Hooked()
{
    ULONG_PTR CurrentLstar = __readmsr(0xC0000082);
    ULONG_PTR OriginalLstar = GetOriginalKiSystemCall64Address();
    return CurrentLstar != OriginalLstar;
}

BOOLEAN IsSSDTHooked()
{
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = KeServiceDescriptorTable;
    if ((ULONG_PTR)ssdt->ServiceTableBase < (ULONG_PTR)ntoskrnlBase ||
        (ULONG_PTR)ssdt->ServiceTableBase > (ULONG_PTR)ntoskrnlEnd) {
        return TRUE;
    }
    return FALSE;
}
```

## 变体与关联

- 只改 LSTAR 指向一个简单 jmp 会在入口现场未建立时破坏栈/GS，实际实现必须复制并重定位完整入口代码；文章采用整段复制 + 伪造 SSDT 的方式。
- 可以不挂钩所有服务，只在伪造 SSDT 中替换目标索引；函数指针数组可运行时修改，便于动态开关。
- Shadow SSDT 的 GUI 服务需要会话空间上下文，必须附加到 GUI 进程；普通 SSDT 服务不需要。
- 同类 Windows 内核 hook 技术：IAT Hook、inline hook、SSDT hook；本文是更底层的 syscall 入口 hook，能覆盖所有经过 `KiSystemCall64` 的调用。
- 关联：[[code-analysis-reverse-windows-iat-hook-install-messagebox]]（用户态 IAT Hook）、[[code-analysis-reverse-windows-api-hook-hidden-aes-branch]]（inline hook）。
- 关联：[[code-analysis-reverse-windows-kernel-debugging-vmware-windbg]]（本文调试所用的双机内核调试环境）。

## 检测与防御

- 读取 `IA32_LSTAR`（0xC0000082）并与 `nt!KiSystemCall64` 的已知地址比较；LSTAR 指向非 ntoskrnl 模块范围即可疑。
- 校验 `KeServiceDescriptorTable`/`KeServiceDescriptorTableShadow` 的 `ServiceTableBase` 是否位于 ntoskrnl 映像范围内，检查 RVA 表与函数指针是否指向未知模块。
- 使用 PC Hunter 等工具检查 Int2e/Sysenter/SSDT/Shadow SSDT 钩子；原文演示中 PC Hunter 报告“Int2e/Sysenter钩子 0xFFFFFA80614F2000（未知模块）”。
- 启用 PatchGuard/驱动签名/内核完整性保护，限制未签名驱动加载；监控对 MSR 0xC0000082 的写入与异常非分页池分配。
- 监控 `NtTerminateProcess` 等敏感服务返回 `STATUS_ACCESS_DENIED` 而进程仍存活的异常行为；关联驱动加载日志与未知模块地址。
