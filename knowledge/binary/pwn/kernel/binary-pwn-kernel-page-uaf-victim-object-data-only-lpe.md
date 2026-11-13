---
id: binary-pwn-kernel-page-uaf-victim-object-data-only-lpe
title: 页级 UAF 重分配为 victim 对象 slab：整页读写同一 cache 的全部结构体，改 file->f_mode/f_mapping 等数据字段做 data-only 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: page-uaf-victim-object-data-only-lpe
aliases:
- Page UAF 提权
- 页级 UAF data-only
- victim object 整页读写
- file->f_mode 改写
- file->f_mapping 改写
- bridge object
- object 挖掘
- 无地址泄露内核提权
tags:
- linux-kernel
- page-level
- uaf
- data-only
- cfi-bypass
- pipe-buffer
- file-struct
- victim-object
- bridge-object
- lpe
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:22:51+08:00'
  notes: 已对照30张幻灯片核对：OOB部分改写pipe_buffer->page低字节→两管道同页(3/4概率)→close一根pipe经pipe_release/__free_page释放4KB→另一pipe读写UAF页→堆喷victim对象经new_slab占据页→整页读写→data-only改file->f_mode/f_mapping、pipe_buffer->flags；优势（稳定/无leak/版本无关/绕CFI/绕cache隔离）、bridge/victim object挖掘、CVE-2021-22555 no-leak page-UAF改/etc/passwd演示、CONFIG_RANDOM_KMALLOC_CACHES影响均与图18-28一致。与既有 page-level-uaf 原语卡、self-writing-pipe 卡为上下游但不同升级路径，非重复。未验证点：原文无完整exp，演示输出为截图转写，字段偏移需按目标内核核对；原文未给版本区间，affected_versions 保持 null。
---

## 一句话结论

页级 UAF（一根 pipe 仍引用已释放的 4KB 物理页）可以把该页通过 `new_slab()` 重新分配为任意 victim 对象 cache 的 slab page：大量创建 victim 结构体促使其 cache 申请新 slab 并占住这张 UAF 页后，UAF pipe 就能整页读写同一 slab 上的所有 victim 对象，只需改写 `file->f_mode`/`file->f_mapping`、`pipe_buffer->flags` 等数据字段即可完成 data-only 提权（如把只读打开的 `/etc/passwd` 改成可写并替换 root 密码哈希）——不需要泄露内核地址、不依赖 gadget/ROP 与内核小版本、绕过 CFI 和 cache 隔离。

## 原理

- **起点：页级 UAF**：先用“OOB 部分改写 pipe_buffer->page 低字节 → 两根 pipe 指向同一物理页 → 关闭其中一根”的方法得到页级 UAF（原语与 3/4 概率、vmemmap 0x40 步进等细节见 [[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]）。本卡的起点是：该 4KB 页已释放，但另一根 pipe 仍能按 `page/offset/len` 读写它。
- **为什么能跨 cache 接管 victim 对象**：内核的 cache 隔离是“对象级”的——不同结构体从不同 `kmem_cache` 分配，避免同缓存内类型混淆。但所有 slab page 最终都来自 buddy 页分配器；当任意 cache 需要新的 slab 时，`new_slab()` 从 buddy 申请 order-N 页，刚释放的 UAF 页就在空闲链表中，会被 victim cache 取走并切成该 cache 的对象数组。页级操作绕开了 cache 粒度，因此不受专用 cache 隔离限制（这也是它相对跨缓存利用更稳的原因）。
- **“整页读写”等于“全 cache 读写”**：UAF pipe 的 read/write 直接以物理页为对象，覆盖整张 4KB 页；该页此时是 victim cache 的一个 slab，排列着 N 个 victim 结构体，于是 pipe 的每次读写可以观察并修改这一页内所有对象，等价于获得了该 victim cache 的完全读写原语。
- **data-only 攻击为什么能提权**：不提权靠劫持函数指针，而是改“安全判定的数据字段”。典型目标（文中列出）：
  - `file->f_mode`：文件描述符的读写模式；把只读 fd 的 `f_mode` 加上 `FMODE_WRITE`，就能通过该 fd 向原本只读打开的文件写入。
  - `file->f_mapping`：文件地址空间映射；改写它可影响读写落到哪个页缓存。
  - `pipe_buffer->flags`：管道缓冲区标志，影响管道读写/合并行为。
  - 由于不碰函数指针，`CONFIG_CFI_CLANG` 不构成阻碍。
- **无地址泄露/版本无关的边界**：“不需要 leak”指不需要内核基址与堆地址（没有 ROP、没有 KASLR 泄露）；但仍需知道 victim 结构体的字段偏移（可用目标内核的 BTF/pahole 离线获得），所以并非完全免适配，只是不依赖 gadget 偏移与运行时布局。
- **对象挖掘（object mining）**：页级 UAF 的利用需要两类对象：
  - Bridge object（人工选择）：自身含 `struct page *` 字段、能跨 syscall 存活，让少量 OOB 字节改写就能改变“指向哪一页”。文中列出的候选包括 `pipe_buffer->page`、`bio_vec->bv_page`、`sock->sk_frag.page`、`xfrm_state->xfrag->page`、`pipe_inode_info->tmp_page`、`lbuf->l_page` 等；`Userfaultfd`/`FUSE` 可以在前后拷贝过程中延长竞争窗口，便于在窗口内改掉 `*page`。
  - Victim object（自动筛选）：页被重分配后，改写其某个字段就能形成 data-only 危害的对象（`struct file` 的 `f_mode`/`f_mapping`、`pipe_buffer` 的 `flags` 等）；可通过代码插桩自动化评估可利用性。
- **实战演示**：在 CVE-2021-22555 上实现“no leak page-UAF”：创建空洞、触发 off-by-null、找到两根 pipe（0x79/0x7a）、拿到其中一根的 `pipe->page` UAF，堆喷 passwd 文件的 `struct file`，编辑 `pwd.bck`、设置 root 密码为指定值并写回，最终 `/etc/passwd` 被成功修改。
- **优势总结**：① 利用稳定，不需要复杂的内核堆风水；② 某些情况下全程不需要地址泄露；③ 不依赖具体内核小版本（无 gadget/偏移硬编码）；④ data-only 绕过 CFI；⑤ 在页级操作，绕过 cache 隔离（不需要 cross-cache 的复杂页回收）。

## 触发条件

- 已获得页级 UAF：存在一根 pipe 仍引用已释放的 4KB 物理页（来源可以是任意能把对象 UAF/Double Free 转成 pipe 页 UAF 的漏洞）；
- 能通过大量创建 victim 对象触发其 `kmem_cache` 的 `new_slab()`，把 UAF 页重新分配为该 cache 的 slab 页；
- 已知目标内核 victim 结构体的字段布局（BTF/pahole/源码），能定位并改写目标数据字段；
- 能对 victim 对象执行有意义的操作（如对只读 fd 写入、关闭 pipe 触发 flags 相关行为）；
- 目标为 4KB 页；目标未启用阻断页级复用的保护（页级隔离、强化 data 完整性等）。

## 利用步骤

1. 按 [[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]] 的方法制造页级 UAF：让 victim pipe 的 `pipe_buffer.page` 指向已由另一根 pipe 释放的物理页 P。
2. 选定 victim 对象与目标效果（例：把 `/etc/passwd` 复制为可写的 `pwd.bck`，再以只读方式打开目标文件产生 `struct file`；或准备 pipe 数组等）。
3. 大量创建/打开 victim 对象，促使其 cache 调用 `new_slab()`；UAF 页 P 被 buddy 分配给该 cache 后，页内出现多个 victim 结构体。
4. 通过 UAF pipe 读整页内容，按已知字段模式（指针、文件路径字符串、`f_mode` 等）识别 victim 对象及其在页内的偏移。
5. 通过 UAF pipe 写目标字段：如 `f_mode |= FMODE_WRITE`，或改写 `f_mapping` 指向目标页缓存；写完确认其它字段未被破坏（否则对象会崩溃）。
6. 通过 victim 对象的正常语义触发效果：向现在可写的 fd 写入篡改后的 `/etc/passwd`（替换 root 密码哈希），或按目标字段语义操作；验证提权/越权结果。
7. 清理堆布局与临时文件，避免留下崩溃/取证痕迹（防御方则重点检测此类行为）。

## PoC

原文为会议幻灯片，未给可执行 exp；演示输出与思路如下（伪代码）：

```c
// 1) 页级 UAF（见原语卡）：victim_pipe 的 pipe_buffer.page 指向已释放页 P
// 2) 打开目标文件（只读）产生 struct file，并大量重复以触发 filp cache new_slab
int fd = open("/etc/passwd", O_RDONLY);
for (int i = 0; i < N; i++) open("/etc/passwd", O_RDONLY);   // 让 P 被 filp cache 占用

// 3) 用 UAF pipe 读 P，扫描页内 struct file（f_mode 等字段），定位目标对象
// 4) 改写 f_mode |= FMODE_WRITE（偏移按目标内核 BTF 确定）
// 5) 通过 fd 写回篡改后的内容（如替换 root 密码哈希）
```

```text
# 幻灯片实战演示（CVE-2021-22555，无地址泄露的 page-UAF）
[+] CVE-2021-22555 no leak page-uaf.
[*] Create hole.
[*] Trigger off by null
[*] Found the two pipe 0x79 and 0x7a
[*] UAF one of the pipe->page.
[*] Spray passwd file...
creating the pwd.bck...
setting root password to "..."...
[*] finally: edit the pwd file
Write Success:17 [*]Now the pwd is:
root:$1$...:0:0:test:/root:/bin/sh
```

以上为按幻灯片步骤与输出整理的方法骨架，未在本机复现；字段偏移与结构体布局需按目标内核核对。

## 变体与关联

- 变体：victim 对象换成 `pipe_buffer` 数组时，可用整页读写改 `pipe_buffer.page/offset/len` 构造自写管道，进而升级为任意物理页读写，见 [[binary-pwn-kernel-self-writing-pipe-arbitrary-rw]]。
- 变体：victim 对象换成含函数指针的结构体时，可回到传统控制流劫持，但受 CFI 限制；data-only 字段（`f_mode`/`f_mapping`/`flags`）是 CFI 环境下的优先选择。
- 关联：[[binary-pwn-kernel-cross-cache-uaf-cred-jar-clone-lpe]]（跨缓存回收 cred 的另一种提权路线）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（页表级复用）、[[binary-pwn-kernel-cve-2021-22555-msg-msg-oob-double-free-pipe-ops-rop]]（本卡前身：把 CVE-2021-22555 从 ROP 路线切到 page-UAF 路线）。
- 边界与未来：`CONFIG_RANDOM_KMALLOC_CACHES=y`（华为云提交的上游 patch）把每个 kmalloc cache 按“启动随机种子 + 调用者地址”拆成 16 个，传统堆喷基本失效；应对只能走 cross-cache（cache 隔离不含页级隔离，UAF/Double Free 仍可用）或页风水让两个被隔离的 cache 在虚拟地址上连续（OOB），但难度与步骤大幅增加、成功率下降。该配置目前主要影响“从 UAF 到可控对象”的回收，不改变页级 UAF 本身的原理。

## 检测与防御

- 修复根漏洞：消除产生页级 UAF 的 OOB/UAF（边界检查、引用计数），页级利用只是放大器，源头仍是内存破坏漏洞。
- 检测：KASAN/KFENCE 对 page UAF 与 slab 越界有直接报告；进程短时间内大量创建 pipe 并反复 `F_SETPIPE_SZ`、大量打开同一文件、管道读到跨管道数据、关闭 pipe 后仍访问其数据页导致异常，都是可疑信号。
- 防御：降低 `fs.pipe-max-size`、限制 pipe 数量与消息队列资源；启用 SLAB_FREELIST_HARDENED/RANDOM；测试环境开 KASAN/KFENCE；对 `CONFIG_STATIC_USERMODEHELPER=y`（防 modprobe_path 路线）和厂商页表保护保持关注。
- 加固：`CONFIG_RANDOM_KMALLOC_CACHES` 可显著提高堆喷/回收难度；对敏感对象（文件、凭据、页表）考虑页级隔离与数据完整性校验；Android 厂商对 creds/page table 的额外保护也属于同一方向。
- 监控：`/etc/passwd`、`/etc/shadow` 等关键文件的异常写入（data-only 攻击最终要落到有语义的操作），以及只读文件描述符出现写行为。
