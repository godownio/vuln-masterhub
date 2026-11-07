---
id: binary-pwn-kernel-self-writing-pipe-arbitrary-rw
title: pipe_buffer 自指与三管道互修：页级 UAF 升级为任意物理页读写
type: scenario
domain: binary
path: binary/pwn/kernel
technique: pipe-buffer-self-writing-arbitrary-physical-rw
tags:
- linux-kernel
- pipe-buffer
- page-level
- uaf
- arbitrary-read-write
- vmemmap
- kaslr
- exploit-primitive
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:10:23+08:00'
  notes: 已对照原文与截图核对：自指pipe_buffer、+0x40找页面struct page、3-4管道互修、SND96/TRD192、vmemmap_base=page&KASLR_MASK、157*0x40找kernel base、CFI不影响数据字段均一致；未验证点：未执行PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-self-writing-pipe-arbitrary-rw/
draft: false
kb_aliases:
- 自写管道
- self-writing pipe
- 三管道任意读写
- pipe_buffer 自指
- pipe_buffer page 指针劫持
- 任意物理页读写
- vmemmap 泄露 KASLR
---

## 一句话结论

页级 UAF 指向的物理页被重分配为其它管道的 `pipe_buffer` 数组后，UAF 管道既能读出 `pipe_buffer.page`（vmemmap 指针）与 `ops`（内核 text 指针），也能改写这些数组；把某条 `pipe_buffer.page` 改成承载数组自身的 `struct page`，该管道就变成“读写自己元数据”的自写管道。再用 3~4 条自写管道互相修补 `offset/len/page`，即可反复校准读写游标，获得稳定的任意物理页读写。

## 原理

- **pipe 的读写语义**：一次 `read()/write()` 的数据来源完全由 `pipe_buffer.page`（物理页的 `struct page *`）、`offset`（页内起点）和 `len`（有效长度）决定。内核在完成 I/O 后会更新 `offset/len`（读推进 offset、写推进 offset/len），所以只改写一次 page 指针只能做一次性读写，第二次就会“跑偏”。
- **页级 UAF 的重分配**：第一阶段让某根管道（victim）的 `pipe_buffer.page` 指向另一根管道（orig）的数据页 P；关闭 orig 后 P 回到 buddy，victim 仍持有 P 的 `struct page` 指针。此时把其它管道通过 `fcntl(F_SETPIPE_SZ)` 调整成小数组（如 3 槽位 × 32 字节 = 96 字节），`kmalloc-cg-*` 会为这些小数组申请新的 slab page，其中一张就落在 P 上。victim 管道读写 P，等价于直接读写一整页 `pipe_buffer` 数组——可以跨多根管道读取/伪造它们的元数据。
- **泄露信息**：从 P 中读出的 `pipe_buffer` 条目包含 `page`（指向该管道数据页的 `struct page`，位于 vmemmap，可据此恢复 vmemmap 基址）与 `ops`（`anon_pipe_buf_ops` 等内核符号，位于内核 text，可据此恢复 kernel base 或直接确认 KASLR 偏移）。`offset/len/flags/private` 也一并泄露。
- **自指（self-writing）**：目标是让某条管道的 `pipe_buffer.page` 指向“承载该 pipe_buffer 数组的那张物理页 P”的 `struct page`。这样这条管道 read/write 的对象就是自己的元数据数组，写 `offset/len` 即修改自己的读写窗口。原文利用相邻 PFN 布局：泄露的 `struct page` 与其后一张页的 `struct page` 相差 0x40，因此对泄露指针做 `page + 0x40`（或在已知 PFN 关系时直接算）即可得到 P 的 `struct page`；随后把伪造条目写进数组，并逐根管道读取首 8 字节，找出 `page` 已等于该值的管道即为新的自写管道。
- **为什么要多个管道**：读/写自写管道会消耗它自己的 `offset/len`，需要另一条管道把它的 `offset/len` 改回可用值；而“修补者”自己也会在写操作中跑偏，所以还需要第三条管道来修补第二条，形成 A 干活、B 修 A、C 修 B 的循环。原文用 4 条自写管道（第 2/3/4 条 + 工作管道）实现这一循环，`arbitrary_read_by_pipe()` 每次先把工作管道的 `page` 设为目标物理页的 `struct page`、`offset=0`、`len=0x1ff8`，再通过第 3/4 条管道把这份伪造条目写回数组，最后从工作管道读取。
- **任意读写**：`pipe_buffer.page` 是 `struct page *`，指向目标物理页的元数据；改它即可让管道读写任意物理页。配合 `page = vmemmap_base + PFN*0x40` 与 `direct map VA = page_offset_base + PA`，可以在内核内存空间中搜索目标 object。原文先令 `vmemmap_base = leaked_page & ~(256MB-1)`（KASLR 粒度 256MB），读 `vmemmap_base + 157*0x40` 附近的指针寻找 kernel text 地址，从而恢复 kernel base；再用当前 `task_struct` 的 `ptraced` 自指针反推 `page_offset_base`。
- **为什么 CFI 不影响**：`CONFIG_CFI_CLANG=y` 保护的是间接函数调用/函数指针，本手法只改 `pipe_buffer.page/offset/len` 这些数据字段，不劫持 `ops`，因此 CFI 不构成阻碍（除非额外启用数据完整性保护）。

## 触发条件

- 已获得页级 UAF：一条管道仍引用已释放的物理页（见 [[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]）。
- 能把该物理页重新分配为 `kmalloc-cg-*` 的 `pipe_buffer` 数组 slab page，并让 UAF 管道覆盖到数组页；需要 `fcntl(F_SETPIPE_SZ)` 可用、`fs.pipe-max-size`/RLIMIT 允许足够大的数组。
- 至少 4 根管道可被控制，能在数组页上读/写多个 `pipe_buffer` 条目；`sizeof(struct pipe_buffer)`、`struct page` 大小与目标内核一致（按版本核对，必要时用 BTF/pahole）。
- 目标内核 vmemmap 基址的 KASLR 粒度为 256MB（常见配置）；内存大小与扫描范围可接受；允许 `vmemmap_base` 扫描与失败重试。
- 需要能区分管道数据（例如每根管道写入唯一标记），以便在数组中定位条目和确认自写管道。

## 利用步骤

1. **释放第一阶段的数据页**：在页级 UAF 已建立后，关闭 orig 管道，使其数据页 P 回到 buddy；确认 victim 管道仍能读写 P。
2. **让数组页覆盖 P**：对其余管道执行 `fcntl(F_SETPIPE_SZ, small_size)`（原文 96 字节数组对应 3 个槽位），使它们的 `pipe->bufs` 小数组从 `kmalloc-cg-*` 申请 slab page，其中一张落在 P；此时 victim 读写 P 就是读写多根管道的 `pipe_buffer` 数组。
3. **泄露 page 与 ops**：调整 victim 的读写偏移，读出数组中某个条目的 32/40 字节，得到 `struct page *page`、`ops`、`offset/len` 等；校验 `page` 落在 vmemmap 区、`ops` 落在内核 text 区。
4. **建立第一条自写管道**：按相邻 PFN 关系把该条目的 `page` 改成承载数组的物理页 P 的 `struct page`（原文 `page + 0x40`，依赖 P 与泄露数据页相邻的布局），写回数组；逐根读取管道首 8 字节，找到返回 `page` 值的管道即为自写管道。
5. **重复建立第 2~4 条自写管道**：释放第二阶段 orig 的数据页并重分配为更小的数组页，用同样的伪造条目把另一条管道指向已知 `struct page`，直到拥有至少 4 条可互相修改的管道。
6. **搭建互修循环**：用 `setup_evil_pipe()` 初始化各管道的伪造条目；`arbitrary_write_by_pipe()` / `arbitrary_read_by_pipe()` 每次通过第 3/4 条管道把“目标页 + offset/len”写回工作管道的条目，再从工作管道执行一次 I/O。
7. **恢复 KASLR 信息**：令 `vmemmap_base = leaked_page & ~(0x10000000-1)`，循环读 `vmemmap_base + 157*0x40` 附近的指针，寻找落在内核 text 区且低 12 位合理的值；失败则按 256MB 步进调整 vmemmap 基址。
8. **定位 task_struct 与提权**：用任意读扫描 vmemmap 页寻找当前进程的 `comm`，由 `ptraced` 自指针反推 `page_offset_base` 与 `task_struct` 地址，再沿 `real_parent` 找 `init_task`，覆写 `cred/real_cred/nsproxy`（详见 [[binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe]]）。

## PoC

```c
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};

struct pipe_buffer info_pipe_buf, evil_2nd_buf, evil_3rd_buf, evil_4th_buf;
char zero_buf[0x1000];

/* 通过自写管道把伪造条目写回数组，使工作管道指向目标 struct page */
ssize_t arbitrary_read_by_pipe(struct page *page_to_read, void *dst) {
    evil_2nd_buf.page   = page_to_read;
    evil_2nd_buf.offset = 0;
    evil_2nd_buf.len    = 0x1ff8;

    write(pipe_fd[self_3rd_pipe_pid][1], &evil_4th_buf, sizeof(evil_4th_buf));
    write(pipe_fd[self_4th_pipe_pid][1], &evil_2nd_buf, sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], zero_buf, TRD_PIPE_BUF_SZ - sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], &evil_3rd_buf, sizeof(evil_3rd_buf));

    return read(pipe_fd[self_2nd_pipe_pid][0], dst, 0xfff);
}

void arbitrary_write_by_pipe(struct page *page_to_write, void *src, size_t len) {
    evil_2nd_buf.page   = page_to_write;
    evil_2nd_buf.offset = 0;
    evil_2nd_buf.len    = 0;

    write(pipe_fd[self_3rd_pipe_pid][1], &evil_4th_buf, sizeof(evil_4th_buf));
    write(pipe_fd[self_4th_pipe_pid][1], &evil_2nd_buf, sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], zero_buf, TRD_PIPE_BUF_SZ - sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], &evil_3rd_buf, sizeof(evil_3rd_buf));

    write(pipe_fd[self_2nd_pipe_pid][1], src, len);
}

/* 由泄露的 struct page 恢复 vmemmap 基址，并扫描 kernel text 指针 */
vmemmap_base = (size_t)info_pipe_buf.page & ~(0x10000000 - 1);
for (;;) {
    rlen = arbitrary_read_by_pipe((struct page *)(vmemmap_base + 157 * 0x40), buf);
    if (buf[0] > KERNEL_BASE && ((buf[0] & 0xfff) < 0x100)) {
        kernel_base = buf[0] & ~0xfff;
        break;
    }
    if (rlen < 0) { vmemmap_base += 0x10000000; break; }
    vmemmap_base -= 0x10000000;
}
```

原文中 `SND_PIPE_BUF_SZ=96`、`TRD_PIPE_BUF_SZ=192`（按 32 字节 `pipe_buffer` 计算槽位数），并依赖相邻 PFN 的 `+0x40` 关系；不同内核的结构体大小、slab 桶和页布局需要重新推导。本卡不执行 PoC。

## 变体与关联

- **两管道变体**：若只需一次读写或能精确控制 offset/len，可省掉第三根管道；但连续读写时状态漂移会导致失败，三管道是稳定性的折中。
- **不同目标对象**：不限于 `pipe_buffer`；任何“整页可被 UAF 管道覆盖、且首字段为 `struct page *` 或其它可控指针”的 slab 数组都可作为自写载体。
- **Dirty Pipe 化**：把 `pipe_buffer.page` 指向 page cache 的 `struct page`、配合 `offset/len` 越界，可改只读文件缓存；但需要处理 `PIPE_BUF_FLAG_CAN_MERGE` 等语义。
- **KASLR 变体**：若目标内存大于文中示例，`vmemmap_base` 的 256MB 对齐假设可能不成立，需要更多候选或从其它泄露恢复；`page_offset_base` 也可通过 `ptraced` 自指针或 direct map 扫描求。
- **关联**：[[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]（前置页级 UAF）、[[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]（页级风水）、[[binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe]]（后续提权）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（另一种任意物理页读写路径）。
- **边界**：本卡是“页级 UAF → 任意物理页读写”的通用升级链，不绑定具体漏洞；需要多次布局与泄露，失败点主要在数组页重分配命中和 `+0x40` 相邻关系。`CONFIG_CFI_CLANG` 不影响，但 KASAN/KFENCE、`init_on_free`、pipe 大小限制会降低可行性。

## 检测与防御

- **消除页级 UAF**：根因仍是页被提前释放后仍被管道引用；修复跨缓存溢出/页释放逻辑，开启 KASAN/KFENCE 在测试环境捕获。
- **限制 pipe 元数据被覆盖**：降低 `fs.pipe-max-size` 与 RLIMIT，使 `F_SETPIPE_SZ` 只能得到小数组，减少可覆盖的数组页价值；限制管道数量与总容量。
- **数据完整性**：`CONFIG_CFI_CLANG` 只保护函数指针，无法阻止本卡；可考虑内核数据完整性/页表隔离/内存加密等更强机制（视平台）。
- **检测**：单进程在短时间内大量创建管道、反复 `F_SETPIPE_SZ`、跨管道读取到 `struct page`/内核指针形态的数据；`pipe_buffer` 字段异常（page 落在 vmemmap、offset/len 越界）；关闭管道后仍访问已释放物理页导致的 UAF 报告。
- **运行环境**：在容器/沙箱中限制 `CAP_SYS_ADMIN`、`unprivileged_userns` 与 pipe 资源；对高风险内核模块（自定义字符设备）做代码审计，避免 0x800 对象末尾一字节写这类入口。
