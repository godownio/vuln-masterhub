---
id: code-analysis-reverse-windows-arm64-ssdt-compactoffset-trampoline-hook
title: Windows on ARM64 SSDT Hook：KiServiceTable CompactOffset 编解码 + ADRP/ADD/BR trampoline 改系统调用分派
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: arm64-ssdt-compactoffset-trampoline-hook
aliases:
- ARM64 SSDT Hook
- Windows on ARM Rootkit
- KiServiceTable
- CompactOffset
- KeServiceDescriptorTable
- ARM64 trampoline
- adrp add br
- WoA rootkit
tags:
- reverse
- windows
- arm64
- rootkit
- ssdt
- kernel
- hook
- trampoline
- code-cave
- mdl
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:57:08+08:00'
  notes: 已对照原文与6图核对（图04 KiServiceTable CompactOffset分派、图06 trampoline/Code Cave）；CompactOffset解码 table+(off>>>4)与编码16*(target-table)、Code Cave两NOP+0可逆性校验、MDL SuperCopyMemory写只读页均与原文代码一致；与x86 SSDT卡（指针表项+CR0.WP）机制不同；原文为Windows 11 on ARM64研究且调试模式关闭PatchGuard/DSE/SecureBoot、hook成功未截图，confidence=medium如实；无受影响版本区间；PoC未编译运行
---

## 一句话结论

与 x86 的 SSDT 直接存函数指针不同，Windows on ARM64 的 `KiServiceTable` 为每个系统调用存一个 32 位 **CompactOffset**，解析公式是 `handler = KiServiceTable + (CompactOffset >>> 4)`；把它按逆向公式 `CompactOffset = (UINT32)(16 * (target - KiServiceTable))` 编码成目标地址（必须靠近 `KiServiceTable` 才能编码），覆盖对应 syscall 索引的 DWORD，就能把该系统调用重定向到自己的 hook 代码。由于 ARM64 没有可加载 64 位绝对地址的 JMP，跳转要用 `adrp/add/br` 三条指令组成的 trampoline；hook 代码放在内核模块中搜索到的 Code Cave（两个 NOP 开头、后跟 0）里，最后再 trampoline 跳回原处理函数。改只读的内核表还要绕过写保护：ARM64 上 CR0.WP 手法无效，可用 MDL（`IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache`）映射成可写后拷贝。

## 原理

- **ARM64 系统调用链**：用户态 `Nt*` API（如 `NtReadFile`）进入 `ntdll!Zw*`，后者用 `SVC`（示例 `SVC 0x55`）从 EL0 陷入 EL1；`VBAR_EL1` 指向 `KiArm64ExceptionVectors`（每项 0x80 字节），偏移 0x200/0x400 分别是 `KiKernelExceptionHandler`/`KiUserExceptionHandler`，最终到 `KiSystemService/KiSystemServiceException`，再按 syscall 号查 `KiServiceTable` 分派到 `ntoskrnl!Nt*`。
- **SSDT/KiServiceTable 定位**：`KiServiceTable` 是未导出符号，可从 `KeServiceDescriptorTable`/`KeServiceDescriptorTableShadow` 的第一个 QWORD 解引用拿到表指针；`SystemServiceTable` 结构含 `ServiceTable`、`CounterTable`、`ServiceLimit`、`ArgumentTable`。
- **CompactOffset 编解码**：ARM64 表项不是指针而是 DWORD 偏移。解码 `target = KiServiceTable + (dwo(KiServiceTable + index*4) >>> 4)`；编码 `offset = (UINT32)(16 * (target - KiServiceTable))`。因此 hook 目标必须位于 `KiServiceTable` 之后且距离可被 16 编码表达，否则偏移无法正确解析——这是找 Code Cave 的硬约束。
- **ARM64 trampoline**：`adrp xip0, #页对齐地址` 计算相对当前 PC 的页地址，`add xip0, xip0, #低 12 位` 补齐页内偏移，`br xip0` 无条件跳转（原文示例跳 `0xfffff8016bd93214`）。`adrp` 的寻址范围约 ±4GB，Code Cave 必须落在可达范围内。
- **Code Cave 搜索与可逆性验证**：在内核所有模块中扫描“两个 NOP（ARM64 NOP = `0xd503201f`，两个为 8 字节）+ 后续全 0”的区域；候选地址先用编码公式算出 CompactOffset，再用解码公式回代，只有 `cave == KiServiceTable + (offset >>> 4)` 的候选才能用作 SSDT 目标（`SearchCodeCave`/`CalculateServiceTableEntry`）。
- **写只读内存**：SSDT 位于只读页。x86 可用清 `CR0.WP`（bit 16）写；ARM64 上作者未找到等价的寄存器和位，改用 MDL：`IoAllocateMdl` → `MmBuildMdlForNonPagedPool` → `MmMapLockedPagesSpecifyCache(MmWriteCombined)` 得到同一物理页的可写映射 → `RtlCopyMemory` → `MmUnmapLockedPages`/`IoFreeMdl`（`SuperCopyMemory`）；写入时提高 IRQL 到 DPC 级别减少并发干扰。
- **Hook 流程**：解码目标 syscall 的 CompactOffset → 计算 Code Cave → 在 cave 写 hook 代码（保存/检查参数、执行恶意逻辑）→ 用 `adrp/add/br` 跳回原 `Nt*` 处理函数 → 把 SSDT 表项改成指向 cave 的 CompactOffset。之后所有该 syscall 都会经过 hook。
- **限制**：PatchGuard/KPP 会检测 SSDT 修改并在约 15–30 分钟内蓝屏（原文在调试模式下关闭 PatchGuard/DSE/Secure Boot，未做绕过）；HVCI/内核完整性可能阻止写只读页；不同 Windows 版本的表布局/符号需重新核对。

## 触发条件

- Windows 11 on ARM64（AArch64）目标，已能加载/运行 Ring0 驱动；研究环境关闭 PatchGuard、驱动签名强制与 Secure Boot（或具备对应绕过）。
- 已知 `KiServiceTable` 地址（符号或 `KeServiceDescriptorTable` 解引用），目标 syscall 索引与期望的 `Nt*` 处理函数已知。
- 存在满足 CompactOffset 编码约束的 Code Cave（在 `KiServiceTable` 之后、距离可编码、adrp ±4GB 可达）。
- 能写只读内核内存（MDL 手法）并能承受 PatchGuard/HVCI 的检测窗口。

## 利用步骤

1. 在调试器（kd/WinDbg）确认 `nt!KiServiceTable`、`KeServiceDescriptorTable` 与目标 syscall 索引；用 `u nt!KiServiceTable + (dwo(nt!KiServiceTable + <idx>*4) >>> 4)` 验证解码公式（原文示例 idx=0x47 解到 `NtAddAtom`）。
2. 选目标 syscall（如文件/注册表/进程枚举相关），确定其原始 `Nt*` 处理函数地址。
3. 用 `SearchCodeCave` 在已加载模块中搜索“两个 NOP + 0”模式，并用编码/解码公式验证候选可逆。
4. 在 Code Cave 中写 hook 代码：保存寄存器/参数，执行恶意逻辑，末尾用 `adrp/add/br` 跳回原处理函数（或原函数被覆盖后的续接点）。
5. 用 `CalculateServiceTableEntry(cave)` 算出 CompactOffset，再用 `SuperCopyMemory`（MDL 写只读页）覆盖 `KiServiceTable + idx*4` 的 DWORD。
6. 触发对应系统调用验证 hook 生效；调试模式下观察 `u` 反汇编确认表项解码到 cave。
7. 卸载时恢复原始 DWORD/原 hook 字节，避免 PatchGuard/崩溃。

## PoC

原文关键代码（节选，未在本机编译运行）：

```c
UINT32 CalculateServiceTableEntry(ULONGLONG codeCave)
{
    return (UINT32)(16 * (codeCave - g_KiServiceTable));
}

ULONGLONG SearchCodeCave(ULONGLONG pStartSearchAddress, ULONGLONG value, ULONGLONG size)
{
    UINT64 pEndSearchAddress = pStartSearchAddress + size;
    while (pStartSearchAddress++ && pStartSearchAddress < pEndSearchAddress - 8) {
        if (MmIsAddressValid((PVOID)pStartSearchAddress) &&
            MmIsAddressValid((PVOID)(pStartSearchAddress + 0x8)) &&
            MmIsAddressValid((PVOID)(pStartSearchAddress + 0x10)) &&
            MmIsAddressValid((PVOID)(pStartSearchAddress + 0x18))) {
            if (*(PUINT64)(pStartSearchAddress) == value &&   // 0xd503201fd503201f = 两个 NOP
                *(PUINT64)(pStartSearchAddress + 0x8) == 0x0 &&
                *(PUINT64)(pStartSearchAddress + 0x10) == 0x0) {
                if (pStartSearchAddress == (g_KiServiceTable + (CalculateServiceTableEntry(pStartSearchAddress) >> 4)))
                    return pStartSearchAddress;               // 可逆，能作 CompactOffset 目标
            }
        }
    }
    return 0;
}

NTSTATUS SuperCopyMemory(VOID UNALIGNED* Destination, CONST VOID UNALIGNED* Source, ULONG Length)
{
    PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
    if (!g_pmdl) return STATUS_UNSUCCESSFUL;
    MmBuildMdlForNonPagedPool(g_pmdl);
    UINT64* Mapped = (UINT64*)MmMapLockedPagesSpecifyCache(g_pmdl, KernelMode, MmWriteCombined, NULL, FALSE, NormalPagePriority);
    if (!Mapped) { IoFreeMdl(g_pmdl); return STATUS_UNSUCCESSFUL; }
    KIRQL kirql = KeRaiseIrqlToDpcLevel();
    RtlCopyMemory(Mapped, &Source, Length);
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) KeLowerIrql(kirql);
    MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
    IoFreeMdl(g_pmdl);
    return STATUS_SUCCESS;
}
```

CompactOffset 解码（WinDbg，原文示例）：

```text
0: kd> u nt!KiServiceTable + (dwo(nt!KiServiceTable + 0x47 * 4) >>> 4)
nt!NtAddAtom:
fffff801`67159cf0 52800003 mov w3,#0
```

## 变体与关联

- **同产品 x86 SSDT Hook**：[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]] 改的是指针型 SSDT 表项并用 `CR0.WP` 清写保护；ARM64 是 CompactOffset 编码 + MDL 写只读页，体系结构/编码方式完全不同。
- **全局 syscall hook**：[[code-analysis-reverse-windows-arm64-kisystemservice-global-syscall-hook]] 直接 patch `KiSystemService` 入口（一处 hook 全部 syscall），本卡是按表项 hook 单个/部分 syscall，补丁位置与粒度不同。
- **x86 KiSystemCall64**：[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]] 重写 `IA32_LSTAR` MSR + 伪造 Shadow SSDT；ARM64 用 `VBAR_EL1`/`SVC` 与 `KiServiceTable`，不是同一机制。
- **ARM64 inline hook 与写保护**：[[mobile-android-kpm-inline-hook-arm64-trampoline-relocation]] 是 Android 内核模块的 ARM64 trampoline/页表改权限；本卡是 Windows on ARM64 SSDT 表项，环境与目标不同。MDL 写只读页的通用做法也见 [[code-analysis-reverse-windows-pte-hook-page-table-isolation-inline-hook]]。
- **检测工具**：原文发布 WOARKD（Windows On ARM Rootkit Detector）扫描 syscall 与内核结构篡改；其思路可作防御参考。

## 检测与防御

- **完整性检测**：遍历 `KiServiceTable` 每个表项，解码后检查目标是否落在 `ntoskrnl`/合法模块的可执行节内、是否等于该索引对应的导出 `Nt*` 函数；发现指向非映像页/Code Cave/未知驱动即为 hook。WOARKD 类工具即做此扫描。
- **缓解措施**：启用 PatchGuard/KPP、DSE、Secure Boot、HVCI 与易受攻击驱动阻止列表；HVCI 可阻止修改只读内核页。限制未签名驱动加载，监控驱动加载与内核内存可写-可执行（W+X）区域。
- **行为检测**：监控 `MmMapLockedPagesSpecifyCache`/`MmBuildMdlForNonPagedPool` 对 `KiServiceTable` 所在页的写入、IRQL 提升 + `RtlCopyMemory` 组合；内核中出现 `adrp/add/br` 三指令跳转模式与两个 NOP 开头的 Code Cave；系统调用行为与预期 `Nt*` 实现不一致。
- **响应**：调试模式下可从干净的 `ntoskrnl` 符号恢复原表项、卸载可疑驱动；生产环境依赖 HVCI/PatchGuard 与重启清理。
