---
id: binary-pwn-kernel-d3kshrm-vm-close-refcount-uaf-page-table-hijack
title: vm_close 每次 munmap 都无条件减引用：拆分 munmap 把 ChunkManager 引用多减一次造成 UAF，再用 USMA 伪造成 page 表劫持 vm_fault
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-vm-close-refcount-overdecrement-chunkmanager-uaf-fake-page-table
aliases:
- d3kshrm
- D3CTF d3kshrm
- vm_close 引用计数多减
- munmap 拆分触发两次 vm_close
- ChunkManager UAF
- USMA 伪造 pages 表
- 伪造 page 表映射任意页
tags:
- pwn
- kernel
- mmap
- vm-close
- refcount
- uaf
- cross-cache
- packet-ring
- page-table
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T09:01:32+08:00'
  notes: 已对照原文核对：img11/13 确认 vm_close 先 _InterlockedDecrement(ref) 再做 owner 比对、img08 确认 dele 仅在 ref==0 时 kfree；拆分 munmap 触发两次 close 的多减一逻辑与原文一致；img15 显示人工输入 page 地址 0xffffea00000dba00 后打出 d3ctf flag，非纯理论链。保留理由：缺的是 struct page* 泄露这一前提（原文自述 KASLR 开启时难以利用），final harm 已由截图证明，非仅原语。未验证点：无自动 leak，exp 非自包含；标题 page-table 实指伪造 pages 指针数组，措辞易误解
---

## 一句话结论

模块的 `d3kshrm_vm_close()` 每次被调用都会对本 VMA 的 `ChunkManager` 无条件 `_InterlockedDecrement(&chunk->ref)`；用户把一块 `0x3000` 的 mmap 拆成两次 `munmap(addr,0x1000)`、`munmap(addr+0x1000,0x1000)`，会触发两次 `vm_close`，引用计数比实际映射少减 1，随后 `dele` 就能在 VMA 仍持有指针时释放 `ChunkManager`，形成 UAF；用 USMA（AF_PACKET ring）占住这个 0xC0 空洞后，`vm_fault` 会把攻击者布置在 ring 缓冲区里的假 `pages` 表当成真实 page 指针数组，从而映射任意物理页。

## 原理

- **正常引用模型**：`bind` 把 `d3kshrm_arr[idx]` 挂到 `file->private_data` 并 `ref++`；`mmap` 时也给 `ChunkManager` `ref++` 并把指针存进 `vma->vm_private_data`；`vm_close`（`munmap` 触发）负责 `ref--`。只有 `ref` 归零，`dele` 才真正 `kfree(ChunkManager)` 并 `kmem_cache_free(pages)`。
- **缺陷 1：vm_close 无限定减引用**：
  ```c
  v2 = *(struct ChunkManager **)(vma + 0x88);   /* vm_private_data */
  raw_spin_lock(&v2->lock);
  v6 = *(_DWORD *)(__readgsqword(...) + 0x590); /* 当前 cpu */
  _InterlockedDecrement(&v2->ref);              /* 无条件减 */
  ... 再拿 cpu 去比对 owner[0..n]，只决定返回值 ...
  ```
  减引用发生在 owner 校验之前、且不看“这个 VMA 是否只关闭一次”，也没有“vm_close 只允许一次”的标记。
- **缺陷 2：munmap 可以按 VMA 拆分**：`munmap` 按“被解除映射的区间”遍历 VMA 并调用 `vm_ops->close`。对 `mmap(len=0x3000)` 得到的单个 VMA，先 `munmap(addr,0x1000)`（VMA 被切成 `[0,0x1000)` 与 `[0x1000,0x3000)`，后者 close 一次）再 `munmap(addr+0x1000,0x1000)`（再 close 一次），两次 close 只对应一次 mmap 的 `ref++`，净多减 1。
- **为什么能 UAF**：`ref` 被多减后提前归零（或低于真实引用数），`dele` 通过 `if (!chunk->ref)` 判定“无人引用”，执行 `_free_pages(pages[i])`、`kmem_cache_free(pages)`、`kfree(chunk)`；而 `mmap` 留下的 VMA 仍保存 `vm_private_data = chunk`，之后任何 fault/close 都会解引用已释放内存。
- **为什么 vm_fault 可被劫持**：
  ```c
  v1 = *(struct ChunkManager **)(vma + 0x88);
  raw_spin_lock(&v1->lock);
  v2 = vma[2];                       /* pgoff */
  if (v2 <= v1->page_num) {
      v4 = v1->pages[v2];            /* 取“page 指针” */
      ... _InterlockedIncrement(v4 + 0xD);   /* page->_refcount++ */
      vmf->page = v1->pages[v2];     /* 直接返回给内核装 PTE */
  }
  ```
  只要伪造对象在 `0x88` 处给出一个可控缓冲区地址、`0x90` 处 `lock` 为 0（`raw_spin_lock` 对 0 可正常加锁）、`0x80` 处 `page_num` 足够大，`vm_fault` 就会把该缓冲区第 `pgoff` 项当作 `struct page *`，`vmf->page` 即该指针指向的物理页——任意页映射。
- **为什么用 USMA 占位**：`ChunkManager` 是 0xC0 桶（`kmalloc-192`），AF_PACKET `TPACKET_V3` 的 ring 会分配一个 0xC0 左右的管理结构体，其中 `0x88` 指向 mmap 出来的 ring 缓冲区（用户可写）、`0x90` 为 0；申请 `0x12*0x1000` 的 rx 缓冲区即可稳定得到该布局，再用 `mmap` 把 ring 映射进用户态，就能在 `+0x1000*0x11+0x10` 等位置写入任意 page 指针。
- **本文的局限**：原文没找到 leak `struct page *` 的方法，exp 里由人工输入 `page` 地址（示例 `0xffffea00000dba00`），属于“有 leak 即可打通”的半成链；在 KASLR 关闭或另有 page 指针泄露时可直接使用。

## 触发条件

- 模块 `mmap` 时给 `ChunkManager` 加引用、`vm_close` 无条件减引用，且没有“每个 VMA 只 close 一次”的保护。
- 用户能把一块映射拆成多次 `munmap`（任何非 `MAP_FIXED` 连续映射都满足），从而多次触发 `vm_close`。
- `dele` 的释放条件只看 `ref`，没有额外的 VMA 活跃计数；`ChunkManager` 落在未隔离的 0xC0 桶（可与其它对象互换）。
- 能通过 USMA（`AF_PACKET` + `TPACKET_V3`，需要 `CAP_NET_RAW`，通常靠 `unshare(CLONE_NEWUSER|CLONE_NEWNET)` 获得）制造 0xC0 占位对象并拿到其可控缓冲区地址。
- 需要知道目标 `struct page *` 的地址（或能通过其它途径泄露/爆破 vmemmap 基址），否则只能打半链；`splice()` 一个只读文件可把该文件的 page cache 页指针放进 pipe，但本文未用它取页地址。

## 利用步骤

1. `open("/proc/d3kshrm")`，`add(3)` 创建一个 3 页的 `ChunkManager`，`bind(0)` 让 fd 持有一份引用。
2. `mmap(0xdeadbef000, 0x3000, MAP_SHARED)`，然后 `munmap(addr,0x1000)`、`munmap(addr+0x1000,0x1000)`——两次 `vm_close` 让 `ref` 多减 1。
3. `dele(0)` 释放 `ChunkManager`（`kfree` 0xC0 块 + 释放 pages 数组），VMA 里的 `vm_private_data` 成为悬空指针。
4. USMA 占位：`socket(AF_PACKET, SOCK_RAW)` + `PACKET_VERSION=TPACKET_V3` + `PACKET_RX_RING`（`tp_block_nr=0x90/8`、`tp_block_size=0x1000`），喷射 0x80 个，命中的那个 0xC0 结构体覆盖被释放的 `ChunkManager`。
5. 对每个 ring `mmap(0x12*0x1000)`，在 `+0x1000*0x11+0x10` 处写入目标 `struct page *`（假 `pages` 表项）。
6. 访问原 VMA 的 `addr+0x2000`，`vm_fault` 经假 `ChunkManager` 取到假 `pages` 表项，把该 page 映射进用户态；读 `addr+0x2000` 校验是否为目标文件首页（ELF 头 `0x3010102464c457f`）后直接改写（原文覆盖 `/sbin/poweroff` 为读 flag 的 ELF）。

## PoC

```c
kadd(fd, 3); kbind(fd, 0);
uint64_t addr = mmap(0xdeadbef000, 0x3000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
munmap(addr, 0x1000);
munmap(addr + 0x1000, 0x1000);      /* 第二次 vm_close → ref 多减 1 */
kdele(fd, 0);                        /* ChunkManager 被释放，VMA 仍指向它 */
spray_rx_ring(0x80);                 /* USMA 占位 0xC0 */
/* 在 ring 缓冲区写入目标 struct page *，再 fault addr+0x2000 */
```

半成点：原文 `scanf("%p", &page)` 由人工提供 `struct page *`（示例 `0xffffea00000dba00`），没有自动 leak；本条未在本地复跑。

## 变体与关联

- **同题另一条链**：[[binary-pwn-kernel-d3kshrm-vm-fault-pgoff-offbyone-mremap-cross-cache]]（`pgoff == page_num` 越界 + 未注册 `vm_mremap` + pipe_buffer 跨缓存），不需要 UAF，但需要精心风水；本条用引用计数 bug 得到更直接的“伪造 page 表”。
- **引用计数变体**：不只 `munmap` 拆分，`fork()` 复制 VMA、`mremap` 搬移、`mprotect` 拆 VMA 都可能让 `vm_close` 多调一次；审计时看 `vm_ops->close` 是否幂等。
- **占位对象变体**：0xC0 桶可用 `msg_msg`、`setxattr`、`sendmsg` 的辅助缓冲区等替代 AF_PACKET ring，只要能在 `0x88` 放出可控指针、`0x90` 放 0。
- **关联技巧**：[[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]、[[binary-pwn-kernel-sock-refcount-race-lock-sock-double-free]]（引用计数类 UAF 的通用打法）。

## 检测与防御

- **代码修复**：`vm_close` 只在“本 VMA 确实持有一份引用”时减引用——用 `vm_private_data` 置 NULL 做幂等标记，或改为 `refcount_t` 并检查 `refcount_dec_and_test` 的返回值；`dele` 的释放条件改成“ref==0 且无活跃 VMA”。
- **加固**：`mmap` 时给 VMA 单独保存引用计数，`close` 与 `open` 严格配对；`pages` 指针在使用前校验是否落在 `d3kshrm_pages_cachep` 的合法对象内（如 `virt_to_slab` 校验）。
- **检测**：同一 fd 上对同一映射区间多次 `munmap` 的拆分模式；`vm_close` 调用次数大于 `mmap` 次数；USMA ring 大量创建 + 同尺寸 0xC0 对象被释放的时间相关性；模块日志出现“Unable to find specific owner ... when releasing ref”告警（原文非预期 exp 触发过该告警）。
