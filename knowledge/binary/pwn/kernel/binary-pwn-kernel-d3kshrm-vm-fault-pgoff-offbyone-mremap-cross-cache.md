---
id: binary-pwn-kernel-d3kshrm-vm-fault-pgoff-offbyone-mremap-cross-cache
title: 内核模块 vm_fault 用 `pgoff <= page_num` 判界，配合未注册 vm_mremap 的 mremap 扩容，跨缓存接到 pipe_buffer.page 改写只读文件页
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-vm-fault-pgoff-offbyone-mremap-pipe-buffer-page-overwrite
aliases:
- d3kshrm
- D3CTF d3kshrm
- vm_fault pgoff 越界
- pgoff <= page_num off-by-one
- 未注册 vm_mremap
- mremap 扩容绕过范围检查
- pipe_buffer page 跨缓存
- 只读文件页改写
tags:
- pwn
- kernel
- mmap
- vm-fault
- off-by-one
- mremap
- cross-cache
- pipe-buffer
- page-cache
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T09:01:30+08:00'
  notes: 已对照原文核对：22 张图确认 pages 0x88 / lock 0x90 / ref 0x94 / page_num 0x80、mmap 的 (end-start)>>12<=page_num、vm_fault 的 pgoff<=page_num 与 a1[10]=pages[a1[2]]、vm_ops 仅 vm_close/vm_fault（无 vm_mremap）均与卡片一致；img22 显示 Success to change poweroff 并打出 d3ctf flag，链路完整。未验证点：跨缓存风水成功率（原文自述约 10%）未复跑
---

## 一句话结论

题目模块在 `mmap` 时按 `(end-start)>>12 <= page_num` 记录可映射页数，`d3kshrm_vm_fault()` 却用 `if (pgoff <= page_num)` 判界——允许 `pgoff == page_num` 这一格；又因为 `vm_operations_struct` 只注册了 `vm_close`/`vm_fault`、没有 `vm_mremap`，用户可以先 `mmap(MAX_PGSIZE)` 再 `mremap` 扩一页，访问新增页时内核把 `pgoff=0x200` 交给 `vm_fault`，读到 `pages[0x200]`（数组后一格的越界指针）。用 USMA + pipe_buffer 跨缓存把该位置摆成 `pipe_buffer.page`，就能把 `/sbin/poweroff` 的 page cache 映射进用户态并直接改写。

## 原理

- **对象与数组是两套分配器**：`add` 用 `kmalloc_cache_noprof(kmalloc_caches[2], ..., 0xA0)` 拿 `ChunkManager`（实际 0xC0 桶，未隔离），`pages` 则从专用 `d3kshrm_pages_cachep` 拿 0x1000；两者不共享 slab，因此后面可以做跨缓存（cross-cache）。
- **mmap 的检查**：`if ((vma_end - vma_start) >> 12 <= chunk->page_num)` 通过后设置 `vma->vm_ops = d3kshrm_vm_ops`、`vma->vm_private_data = ChunkManager`，并 `ref++`。也就是说 VMA 的合法页数**在 mmap 时就固化**了。
- **缺 `vm_mremap` 的后果**：`mremap()` 正常会调用 `vma->vm_ops->mremap` 做范围校验；该模块没注册，`mremap` 直接完成 VMA 扩容，不回头核对 `page_num`。于是 VMA 变成了 `page_num+1` 页，而 `ChunkManager` 仍只准备了 `page_num` 个 page 指针。
- **vm_fault 的判界错误**：`v2 = a1[2]` 是 fault 地址相对 VMA 起点的页偏移（pgoff），代码写的是
  ```c
  if (v2 <= v1->page_num) {
      v4 = (struct page *)v1->pages[v2];
      ...
      _InterlockedIncrement((volatile signed __int32 *)v4 + 0xD);  /* page->_refcount */
      a1[10] = v1->pages[a1[2]];                                   /* vmf->page = pages[pgoff] */
      v3 = 0;
  }
  ```
  `<=` 使 `pgoff == page_num` 也被放行，而 `pages` 只有 `page_num` 项（下标 0..page_num-1），`pages[page_num]` 恰好是数组后一格——越界读一个 8 字节指针，且该指针会被当作 `struct page *` 做 `_refcount++` 并交给 `vmf->page`，于是用户拿到“该指针所指物理页”的映射。
- **为什么要跨缓存**：`pages` 数组来自身份固定的 `kmem_cache`，第 0x200 项落在数组末尾之后；只要让紧随其后的物理页属于 pipe_buffer 数组（`pipe_buffer` 元素含 `struct page *page`），`pages[0x200]` 就会读到某个 pipe 持有的页指针，而这个页正是 `splice()` 从 `/sbin/poweroff` 读进来的 page cache 页。
- **为什么最终是写只读文件**：`vmf->page` 被装进用户 PTE 后，用户对该地址的写直接落到 page cache（脏页），绕过文件权限位；随后执行/读取 `/sbin/poweroff` 拿到的就是被改写的内容，实现“只读文件写”。
- **跨缓存落地细节**：USMA 用 `AF_PACKET` + `TPACKET_V3`，`tp_block_nr=0x40`、`tp_block_size=0x1000` 得到 0x40*0x1000 的连续页；关 socket、`munmap` 隔块释放形成空洞。slub 从伙伴系统取新 slab 有最小 order（原文实测约 0xa 页），所以必须造 0x40*0x1000 的大洞才能让 `d3kshrm_pages_cachep` 的 slab 落进去；随后 `pipe_buffer` 喷射（`fcntl(F_SETPIPE_SZ)` + `splice(poweroff)`）占据 `pages` 之后的页。

## 触发条件

- 模块提供“用户态可控页指针数组 + mmap → vm_fault 取数组项当 page”的语义，且判界写成 `<=`。
- `vm_operations_struct` 未注册 `vm_mremap`（或注册了但不校验扩容后的页数），使用户能把 VMA 扩到 `page_num+1` 页。
- 能从进程上下文分配 0x1000 的 `pipe_buffer` 数组并让它落在 `pages` 数组之后（需要可控的页级空洞，通常 >0xa 页的连续释放）。
- 能 `splice()` 打开目标只读文件（如 `/sbin/poweroff`、`/etc/passwd`）拿到 page cache 页。
- CTF 环境一般允许 `unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET)` 获得 `CAP_NET_RAW` 做 USMA 喷射。

## 利用步骤

1. 打开 `/proc/d3kshrm`，`add` 一个 `page_num=0x200`（最大）的 ChunkManager。
2. `mmap(addr, MAX_PGSIZE=0x200*0x1000, MAP_SHARED)`，再 `mremap(addr, MAX_PGSIZE, MAX_PGSIZE+0x1000, MREMAP_MAYMOVE)` 扩一页——因无 `vm_mremap`，扩容成功。
3. 堆风水：用 USMA（`AF_PACKET`/`TPACKET_V3`，`block_nr=0x40`）造 0x40*0x1000 连续页，关闭 socket 并隔块 `munmap` 形成空洞；再 `add` 若干 `page_num=0x200` 的 ChunkManager 触发 `d3kshrm_pages_cachep` 新 slab 落入空洞。
4. 喷射 `pipe_buffer`：`pipe()` + `fcntl(F_SETPIPE_SZ, 0x40*0x1000)` + `splice(pwfd, &off, pipe_w, NULL, 1/0x1000, 0)`，让 pipe 数组排在 `pages` 之后。
5. 逐个 `bind(idx)` + `mmap(0xdead000000, MAX_PGSIZE)` + `mremap` 扩容，读 `*(uint64_t*)(addr+MAX_PGSIZE)`，若等于 ELF 头 `0x3010102464c457f` 说明命中了 `/sbin/poweroff` 的第一页。
6. 直接 `memcpy(addr+MAX_PGSIZE, orw_elfcode, ...)` 覆盖为读取 `/flag` 的 ELF，执行 `/sbin/poweroff` 拿 flag；失败则 `munmap` 后换下一个 idx（原文成功率约 10%）。

## PoC

```c
kadd(fd, 3);                                  /* 或 0x200，视风水需要 */
uint64_t a = mmap(0xdead000000, 0x200000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
a = mremap(a, 0x200000, 0x201000, MREMAP_MAYMOVE);   /* 无 vm_mremap → 扩容成功 */
if (*(uint64_t*)(a + 0x200000) == 0x3010102464c457f)  /* 命中 poweroff 首页 */
    memcpy(a + 0x200000, orw_elfcode, sizeof(orw_elfcode));
```

要点：`0x200000` 是 `page_num=0x200` 对应的 0x200 页；`+0x200000` 这一页的 `pgoff=0x200`，正好命中 `pgoff <= page_num` 的越界格。原文完整 exp 含 USMA/pipe_buffer 风水与多 idx 重试，本条不重复贴全量代码。

## 变体与关联

- **同题另一条链**：[[binary-pwn-kernel-d3kshrm-vm-close-refcount-uaf-page-table-hijack]]（`vm_close` 重复减引用 → ChunkManager UAF → 伪造 pages 表），两条链共用“ChunkManager 的 pages 指针被当成 page 表”的利用面，但一条是 pgoff 越界读、一条是 UAF 后伪造，根因不同。
- **判界变体**：`<=`/`<` 写反是 mmap 类驱动的常见 off-by-one；若 `page_num` 可被用户改大，同样能越界。
- **mremap 变体**：即使注册了 `vm_mremap`，若只校验“新长度不小于旧长度”而不校验 `pgoff < page_num`，仍可越界；`MREMAP_FIXED`、`mremap` 收缩后再扩张也可用来制造越界 pgoff。
- **跨缓存变体**：USMA（packet rx ring）可用 `setsockopt(PACKET_RX_RING)` 的 `tp_block_size=0x1000` 造页；pipe_buffer 也可换成 `msg_msg`、`sk_buff` 等含 `struct page *` 的结构。
- **关联技巧**：[[binary-pwn-kernel-write-size-growth-seek-oob-physical-scan]]（同为“按用户可控偏移访问 page”）、[[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]（pipe_buffer 页级利用）。

## 检测与防御

- **代码修复**：`vm_fault` 判界改为 `pgoff < page_num`；注册 `vm_mremap` 并在扩容时校验 `new_pages <= page_num`；`mmap` 时把页数固化到 VMA 私有结构而不是每次信任传入长度。
- **加固**：`pages` 数组使用 `struct page *` 的 `kvmalloc` + 显式长度校验，所有下标统一走 `array_index_nospec`/边界宏；对 `vm_ops` 做完整性检查（缺 `mremap` 时不允许扩容）。
- **检测**：模块 mmap 区域出现 `pgoff == page_num` 的 fault；同一 VMA 先 `mmap` 后 `mremap(+0x1000)` 再访问末页的模式；`/sbin/poweroff` 等只读文件的 page cache 被写脏（`/proc/kpageflags` 脏页、文件校验和变化）；AF_PACKET ring 大量创建/关闭 + pipe 大量 `splice` 的典型跨缓存风水。
