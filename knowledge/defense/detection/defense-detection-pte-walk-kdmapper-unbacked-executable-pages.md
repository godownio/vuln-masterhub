---
id: defense-detection-pte-walk-kdmapper-unbacked-executable-pages
title: PTE Walk 内核页表扫描：从 CR3 逐级遍历发现 Kdmapper 无模块可执行页
type: scenario
domain: defense
path: defense/detection
technique: pte-walk-unbacked-executable-page-detection
aliases:
- PTE Walk
- 页表扫描
- 内核页表遍历
- 无模块驱动检测
- Kdmapper 检测
- CR3 遍历
tags:
- windows
- kernel
- rootkit
- detection
- pte
- page-table
- kdmapper
- memory-scan
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:27:03+08:00'
  notes: 已对照原文与图01/03/08核对：CR3->PML4/PDPT/PD/PT 四级遍历、present 跳过、1GB/2MB 大页处理、扫描前后 diff（FFFFF8C0708F13000 Size 0x1000->0x7000 R:1 W:1 X:1）均一致；模块比对检测判据与 dup-scan related 的 PTE Hook 攻击卡目的不同，保留。未编译/复跑。
---

## 一句话结论

不扫描 248TB 线性地址、也不处理不连续的物理地址，而是从 `CR3` 拿到 PML4 基址后按 x64 四级页表逐级遍历，利用 `present` 位跳过未映射页、识别 1GB/2MB 大页，只枚举真正映射的内核虚拟页；再筛选“可执行但不在任何已加载模块范围内”的页，即可在 1 秒内定位 Kdmapper 手动映射驱动留下的无模块 RWX 页。

## 原理

- **传统扫描的低效**：内核线性地址空间可达 248TB，逐页 `CheckPage` 不可行；物理地址不连续且存在多虚拟地址映射同一物理页，处理复杂且易漏。
- **x64 四级页表**：`CR3` 指向 PML4；线性地址按 `[47:39]` PML4、`[38:30]` PDPT、`[29:21]` PD、`[20:12]` PT、`[11:0]` offset 拆分。每个表项包含 `present`（是否映射）、`write`、`noExecute`、`large_page`、`page_frame_number`（物理页帧号）等位。
- **PTE Walk 的关键优化**：只沿 `present=1` 的表项向下走，未映射的整段地址直接跳过；遇到 `large_page=1` 的 PDPTE（1GB）或 PDE（2MB）直接按大页范围记录，不再遍历下级页表。真实物理内存远小于 248TB，因此遍历量很小。
- **检测判据**：把遍历得到的可执行区间与 `SystemModuleInformation`/`PsLoadedModuleList` 中已加载模块的 `[ImageBase, ImageBase+ImageSize]` 对比；落在模块之外的 `X=1` 页很可能是 Kdmapper 等手动映射的驱动或内核 shellcode。文章对照扫描显示，Kdmapper 映射后某页从 `Size:0x1000` 变为 `Size:0x7000`、`R:1 W:1 X:1`，与已加载模块范围不符。
- **实现要点**：需要把页表物理地址 `Pa` 转换为内核虚拟地址 `Va`（`VaFromPa`）才能读表项；对每个表项用 `MmIsAddressValid` 防无效地址；按起点/终点计算各层索引范围，避免越界。

## 触发条件

- 防守方拥有内核驱动/内核回调能力，能读取 `CR3` 与任意内核虚拟地址。
- 目标为 x64 Windows，使用四级页表（未启用特殊分页模式）。
- Rootkit 采用 Kdmapper 式手动映射（镜像不在已加载模块列表、页表却有可执行映射）；若攻击者做模块踩踏/隐藏可执行位，单靠 PTE Walk 可能漏检。
- 扫描范围与权限允许访问全部内核页表；需处理大页与无效表项。

## 利用步骤

1. 读取 `CR3`，取 `PhysicalAddress << 12` 得到 PML4 物理基址，转换为内核虚拟地址并校验有效。
2. 根据扫描起止地址计算 PML4/PDPT/PD/PT 索引范围；从 PML4 开始逐项检查 `present`。
3. 对 `present` 的 PDPTE：若 `large_page=1`，按 1GB 大页记录 R/W/X 区间；否则取 PDPT 物理地址继续。
4. 对 PDE：若 `large_page=1`，按 2MB 大页记录；否则取 PT 物理地址继续。
5. 对 PTE：`present=1` 时按 4KB 页记录 R/W/X；合并连续同属性区间，输出可执行区间列表。
6. 与已加载模块范围比对，标记 `X=1` 且不在任何模块内的区间；对这些页做进一步内容扫描/特征匹配，确认是否为 Kdmapper 映射镜像。
7. 文章实测：扫描整个内核空间耗时不超过 1 秒，Kdmapper 映射前后 diff 直接显示新增的 RWX 区间。

## PoC

核心遍历骨架（基于文章代码，省略完整边界处理）：

```c
CR3_X64 cr3; cr3.value = __readcr3();
ULONGLONG cr3_pa = cr3.Bits.PhysicalAddress << 12;
PVOID cr3_va = VaFromPa(cr3_pa);

for (ULONG i = pml4_start; i <= pml4_end; ++i) {
    PHARDWARE_PTE_X64 pml4e = (PHARDWARE_PTE_X64)((PUCHAR)cr3_va + i * 8);
    if (!MmIsAddressValid(pml4e) || !pml4e->Bits.present) continue;

    PVOID pdpt_va = VaFromPa(pml4e->Bits.page_frame_number << 12);
    for (ULONG x = pdpt_start; x <= pdpt_end; ++x) {
        PHARDWARE_PTE_X64 pdpte = (PHARDWARE_PTE_X64)((PUCHAR)pdpt_va + x * 8);
        if (!pdpte->Bits.present) continue;
        if (pdpte->Bits.large_page) { AddRange(...1GB...); continue; }

        PVOID pd_va = VaFromPa(pdpte->Bits.page_frame_number << 12);
        for (ULONG y = pd_start; y <= pd_end; ++y) {
            PHARDWARE_PTE_X64 pde = (PHARDWARE_PTE_X64)((PUCHAR)pd_va + y * 8);
            if (!pde->Bits.present) continue;
            if (pde->Bits.large_page) { AddRange(...2MB...); continue; }

            PVOID pt_va = VaFromPa(pde->Bits.page_frame_number << 12);
            for (ULONG z = pt_start; z <= pt_end; ++z) {
                PHARDWARE_PTE_X64 pte = (PHARDWARE_PTE_X64)((PUCHAR)pt_va + z * 8);
                if (!pte->Bits.present) continue;
                AddRange(va, SPAN_PT, /*R*/1, /*W*/pte->Bits.write, /*X*/!pte->Bits.noExecute);
            }
        }
    }
}
```

文章扫描 diff：Kdmapper 映射后新增 `Base:FFFFF8C0708F13000 Size:0x7000 R:1 W:1 X:1`，而模块列表中没有对应模块。

## 变体与关联

- **只扫可执行页**：先过滤 `X=1`，缩小后续内容扫描范围；也可只扫 `RWX` 页作为高置信 IoC。
- **大页处理**：1GB/2MB 大页必须按大页范围记录，否则会漏掉映射在大页里的镜像或重复扫描。
- **模块踩踏对抗**：攻击者把 shellcode 写进合法模块的可执行页时，PTE Walk 看到的页仍在模块范围内，需要结合模块代码完整性校验（磁盘副本/哈希比对）。
- **关联**：[[pentest-privilege-escalation-kdmapper-unsigned-driver-manual-map-trace-cleanup]]（被检测的 Kdmapper 手法）、[[defense-detection-nmi-stack-scan-unbacked-kernel-rootkit]]（NMI 堆栈检测）、[[pentest-c2-module-unhooking-pdata-runtime-function-fnv1a]]（模块代码完整性恢复）。

## 检测与防御

- **部署位置**：作为内核驱动/EDR 的运行时扫描模块，周期性（或按需）执行 PTE Walk；对新增的模块外可执行页告警。
- **性能**：利用 `present` 跳过未映射页、大页直接记录，整内核扫描可达秒级；避免在 NMI/高 IRQL 上下文做重活。
- **误报处理**：HAL、PatchGuard、驱动临时映射页可能不在模块列表内，需要维护白名单/排除范围。
- **组合检测**：PTE Walk 发现可疑页后，再做内容特征扫描、NMI 堆栈关联、驱动加载日志（Sysmon Event 6/7045）与易受攻击驱动阻止列表比对。
- **加固**：启用 HVCI/内存完整性、WDAC 驱动策略，减少可被 Kdmapper 利用的漏洞驱动。
