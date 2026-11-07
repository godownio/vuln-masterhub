---
id: binary-pwn-kernel-buddy-page-spray-packet-tx-ring
title: buddy 页级堆风水：PF_PACKET TX_RING 在用户态批量分配/释放 2^order 连续物理页
type: scenario
domain: binary
path: binary/pwn/kernel
technique: buddy-page-spray-packet-tx-ring
tags:
- linux-kernel
- buddy-system
- page-allocator
- packet-socket
- heap-grooming
- exploit-primitive
- page-level
- af-packet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:10:19+08:00'
  notes: 已对照原文与7张截图核对：PF_PACKET/SOCK_RAW→PACKET_TX_RING→alloc_pg_vec→__get_free_pages(order)、close→free_pg_vec、unshare userns、tp_block_size决定order、噪声吸收与F_SETPIPE_SZ区别均一致；未验证点：未执行PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-buddy-page-spray-packet-tx-ring/
draft: false
kb_aliases:
- PF_PACKET 页喷
- PACKET_TX_RING
- alloc_pg_vec
- __get_free_pages 页喷射
- 页级堆风水
- page-level heap feng shui
- buddy system page spray
- 连续物理页分配
---

## 一句话结论

在允许创建 `AF_PACKET` 套接字的环境里（无 `CAP_NET_RAW` 时通常先建 unprivileged user+net namespace），`setsockopt(PACKET_TX_RING)` 会经 `alloc_pg_vec()` → `alloc_one_pg_vec_page()` → `__get_free_pages(order)` 从 buddy 直接分配 `tp_block_nr` 块 `2^order` 个连续物理页，`close()` 时经 `free_pg_vec()` 整块归还；用户态因此获得按 order 精确“占住/释放”物理页的页级堆风水原语，可把漏洞 kmem_cache 的 slab page 夹到目标 cache 的 slab page 之间。

## 原理

- **分配粒度**：buddy system 以 `2^order` 个连续页为一块管理，同 order 的空闲块挂成链表；低 order 不足时从高 order 拆半。slub 的 `kmem_cache` 在 freelist 和 partial 链表都为空（或刚创建）时会向 buddy 申请新的 slab page，申请大小由对象大小和每页对象数决定。例如 2KB 对象、4KB 页时一页放 2 个，slub 往往一次要 order-3（8 页、32KB）来装 16 个对象。
- **packet ring 调用链**：`socket(AF_PACKET, SOCK_RAW, ...)` 创建 packet socket 后，`setsockopt(SOL_PACKET, PACKET_TX_RING, &req)` 进入 `packet_setsockopt()` 的 `PACKET_TX_RING` 分支 → `packet_set_ring()` → `alloc_pg_vec(req, order)`。`order` 由 `tp_block_size` 决定（块大小必须为页大小整数倍），`alloc_pg_vec()` 先 `kcalloc(tp_block_nr, sizeof(struct pgv), ...)` 建描述数组，再对每个块调用 `alloc_one_pg_vec_page(order)`；后者执行：
  ```c
  gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP | __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY;
  buffer = (char *)__get_free_pages(gfp_flags, order);
  ```
  即绕开 slab，直接向 buddy 要 `2^order` 连续页。
- **为什么能布局**：ring 存活期间这些页被 ring 引用、不会回到 buddy 空闲链表，其他 `kmem_cache` 或页分配者拿不到；`close(socket)` → `packet_release()` → `packet_set_ring(..., 1, ...)` → `free_pg_vec()` 才把整块页归还。先耗尽低 order 页再请求高 order，可让后续请求更接近物理连续；反复“释放一块 → 让目标 cache 取走 → 再释放相邻块”即可控制 slab page 的相邻关系。
- **为什么需要页级相邻**：跨缓存溢出/越界写通常只能越过当前 slab page 的边界一字节或几十字节，只有漏洞 slab page 的下一物理页恰好属于 victim cache 时，越界才会落到 victim 对象上。页级风水把这一关系从“随机”变成“可布置”。
- **噪声来源**：每次创建 packet socket 还会分配 `sock_inode_cache`、dentry、`kmalloc-8` 的 `pgv` 数组等；大量 `setsockopt` 流程也会消耗 buddy 页。因此需要先喷一批 order-0/order-2 页吸收这些噪声，再释放/分配目标 order 的块，否则“物理连续”会被打散。
- **与 `F_SETPIPE_SZ` 的区别**：`fcntl(F_SETPIPE_SZ)` 控制的是 `pipe->bufs` 数组大小及所属 `kmalloc-cg-*` 桶，随后由 slub 间接向 buddy 要 slab page；PF_PACKET ring 则是直接向 buddy 要指定 order 的原始页。两者常配合使用：前者造 victim slab page，后者负责页级排布。

## 触发条件

- 内核启用 `CONFIG_PACKET`，进程能创建 `AF_PACKET`/`SOCK_RAW`；无 `CAP_NET_RAW` 时需要允许 unprivileged user namespace（`unshare(CLONE_NEWUSER|CLONE_NEWNET)` 并写 `uid_map`/`gid_map`）。
- 有一个需要页级布局的内核漏洞或越界原语（跨缓存溢出、页级 UAF、Dirty Pagetable 等）。
- 目标 page allocator 为 buddy + slub，页大小 4KB（常见 x86_64 配置）；目标 cache 的 slab order 与 ring block order 可匹配。
- 有足够内存做页喷射；允许一定的概率失败和重试。

## 利用步骤

1. **准备隔离命名空间**：父进程 `pipe()` 建立命令/回复通道，`fork()` 子进程；子进程执行 `unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET)`，向 `/proc/self/setgroups` 写 `deny`，向 `uid_map`/`gid_map` 写 `0 <原uid> 1`，获得创建 `AF_PACKET` 的权限。
2. **实现页分配/释放命令**：`ALLOC` 命令在子进程创建 socket，设置 `PACKET_VERSION=TPACKET_V1`，构造 `tpacket_req{tp_block_size=<order 对应字节>, tp_block_nr=<块数>, tp_frame_size=..., tp_frame_nr=...}` 并 `setsockopt(PACKET_TX_RING)`；把返回 fd 存入数组。`FREE` 命令 `close(fd)`。
3. **吸收噪声**：先喷射一批 order-0（`tp_block_size=0x1000`）和 order-2（`0x4000`）页，消耗 packet socket 自身产生的 dentry/inode/kmalloc 分配，避免它们插进目标 order 的空闲块。
4. **布置漏洞 slab page**：释放一个 order-3 的 ring 块（8 页），立即分配漏洞对象的独立 `kmem_cache` 对象（2KB×16），让该块成为 vuln 的 slab page；再释放相邻 order-3 块并让 victim cache（如 2KB 的 `pipe_buffer` 数组）取走，从而形成 `[victim slab page][vuln slab page][victim slab page]`。
5. **触发越界/溢出**，读取 victim 对象判断是否命中（例如 pipe 中读出的标记与预期索引不一致）。
6. **回收/重排**：关闭 socket 释放 ring 页，或在下一阶段继续用 `FREE`/`ALLOC` 把指定页让给新的目标 cache，制造页级 UAF 或类型混淆。

## PoC

```c
/* 子进程：unshare 后按命令分配/释放 packet ring 页 */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr) {
    struct tpacket_req req;
    int fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    int version = TPACKET_V1;
    if (fd < 0) return -1;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;          /* 如 0x1000 / 0x4000 / 0x8000，决定 order */
    req.tp_block_nr   = nr;            /* 分配多少块 */
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr   = (size * nr) / req.tp_frame_size;
    if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
        close(fd);
        return -1;
    }
    return fd;                         /* 关闭 fd 即整块归还 buddy */
}

/* 父进程：先吸收噪声，再布置 order-3 页 */
for (int i = 0; i < 0x20; i++) alloc_page(i, 0x1000, 1);          /* order-0 */
for (int i = 0; i < 0x40; i++) alloc_page(0x20 + i, 0x4000, 1);    /* order-2 */
for (int i = 0; i < 0x40; i++) {
    if (i % 19 == 0) free_page(0x20 + i);   /* 吸收 sock_inode_cache 噪声 */
    if (i % 21 == 0) free_page(0x40 + i);   /* 吸收 dentry 噪声 */
    alloc_page(0x60 + i, 0x8000, 1);        /* order-3：8 页连续 */
}
```

原文用 `tp_block_size=0x8000, tp_block_nr=1` 的 order-3 块配合 2KB 对象的独立 `kmem_cache`（16 对象/32KB slab）完成布局；本卡不执行 PoC，具体 order 与噪声比例需按目标内核的对象大小和 slub 参数重新计算。

## 变体与关联

- **PACKET_RX_RING**：同样走 `alloc_pg_vec()`，只是 ring 用于收包；若 TX 路径被限制可尝试 RX 路径。
- **块数与 order**：`tp_block_nr` 控制一次申请多少块，`tp_block_size` 控制每块 order；也可一次申请多个 order-3 块形成大页池。
- **其它页级分配 API**：`io_uring` 的 ring、`mmap` 大页、`sendfile`/`splice` 等也能影响页分配，但 packet ring 的 order 与生命周期最直接、可反复释放。
- **关联**：[[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]（用本原语把 vuln slab page 夹在 pipe_buffer 数组页之间）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（另一种页级利用）、[[binary-pwn-kernel-self-writing-pipe-arbitrary-rw]]（后续把页级 UAF 升级为任意物理页读写）。
- **边界**：本卡只提供“页级布局能力”，不含漏洞本身；unprivileged userns 被禁用、seccomp 拦截 `socket(AF_PACKET)`/`setsockopt` 或内存碎片严重时不可用或成功率下降。

## 检测与防御

- **攻击面收敛**：关闭 unprivileged user namespace（`kernel.unprivileged_userns_clone=0` 或发行版对应开关）、收紧 `CAP_NET_RAW`；容器 seccomp 阻断 `socket(AF_PACKET, SOCK_RAW, ...)`、`setsockopt(PACKET_TX_RING/PACKET_RX_RING)` 和 `unshare(CLONE_NEWUSER|CLONE_NEWNET)`。
- **资源限制**：对进程施加内存 cgroup 限制、限制 packet ring 的最大块数与块大小，降低可喷射的页规模；监控短生命周期的大块 AF_PACKET ring 分配。
- **检测**：审计日志中出现同一进程反复创建/关闭 AF_PACKET socket、`tp_block_nr`/`tp_block_size` 异常大、与业务无关的 ring 分配；结合 KASAN/KFENCE 在测试环境暴露页级越界与 UAF。
- **根治**：修掉具体的越界/off-by-null 漏洞；页级风水只是放大器，漏洞不存在时该原语无法单独提权。
