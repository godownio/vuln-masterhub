---
id: binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack
title: glibc 2.39 tcache safe-linking fd 泄露栈：绕过 environ 的 0x10 对齐限制并把 chunk 分配到栈上
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-safe-linking-stack-leak
aliases:
- tcache fd 泄露栈
- safe-linking 双重异或
- 2.39 栈地址对齐
- chunk 分配到栈
- tcache poisoning 栈
- _exit 无 IO 泄露
tags:
- pwn
- heap
- tcache
- safe-linking
- stack-leak
- glibc-2.39
- tcache-poisoning
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T14:15:14+08:00'
  notes: 已对照原文 ez_jail 全文与图 13-15 核对：_exit 不走 IO、tcache fd 双重异或泄栈、2.39 0x10 对齐避开未对齐 environ、libc+0x2046e0 处存放栈指针、偏移 0x130、毒化到栈上写 system 均与 EXP 一致；已修正卡片把 libc+0x2046e0 误称为栈地址的表述（应为 libc 中存放栈指针的对齐地址）；未在本机复跑
---

## 一句话结论

当程序用 `_exit` 且自带 `write` 版 puts/printf、无法走 stdout/IO 泄露时，可以利用 tcache 的 safe-linking fd 做栈地址泄露：把 UAF 堆块的 fd 伪造成“对齐后的 libc 目标 ^ (chunk>>12)”（目标地址处存放栈指针），经过分配/释放链的双重异或还原出该栈指针；因为 glibc 2.39 要求 chunk 地址 0x10 对齐，需避开未对齐的 `environ` 变量位置，选它附近一个存放栈指针的对齐地址，再把读出的栈指针用于第二次毒化，把 chunk 直接分配到栈上写 `system("/bin/sh")`。

## 原理

- **IO 泄露路径被堵**：程序使用 `_exit` 退出，不会刷新 stdio 缓冲区；虽然自定义 `puts/printf` 内部调用 `write`，但打 stdout 的 FSOP/`_IO_write_base` 路线走不通，需要另找泄露源。
- **safe-linking 公式**：glibc 2.32+ 的 tcache/fastbin fd 存的是 `next ^ (chunk_addr >> 12)`。如果攻击者知道当前 chunk 地址，就能从 fd 还原 `next`；反过来，知道 `next` 也能算出应写入的 fd。
- **把栈指针塞进 fd**：先制造 UAF，把一个已释放 chunk 的 fd 改写成 `read_target ^ (chunk_addr >> 12)`（`read_target` 是 libc 中一个 0x10 对齐、存放栈指针的地址）；随后分配/释放同尺寸 chunk 时，分配器会把该“next”值按 safe-linking 再编码写入另一个块或 tcache bin。读取那个块的 fd，再与相关 chunk 地址异或两次，即可恢复 `read_target` 处存放的栈指针。
- **2.39 的 0x10 对齐限制**：tcache 分配要求目标 chunk 地址 0x10 对齐；`environ` 变量所在地址或它指向的栈值未必满足对齐/布局要求，直接用作分配目标会失败。需要选 libc 中 `environ` 附近一个 0x10 对齐、存放栈指针的地址（如 `libc+0x2046e0`），该栈指针与栈上返回地址的偏移在固定环境下是常数。
- **把 chunk 开到栈上**：再次毒化 tcache fd 为 `(stack_addr-0x8) ^ (chunk>>12)`，让下一次同尺寸分配返回栈上的目标地址；在栈上写入 `/bin/sh`、`pop rdi; ret` 与 `system` 地址，或把返回地址改成 one_gadget，触发即得 shell。
- **前提**：需要能 show 已释放/重叠 chunk 的内容（UAF 读），以及至少一次同尺寸 tcache 分配来消费被篡改的 fd。

## 触发条件

- 目标为 glibc 2.39 x86-64，存在 tcache UAF 或可读已释放 chunk 的 show 功能。
- 程序无可用 stdout/IO 泄露，但能通过 show 读取堆块 fd。
- 已泄露 libc 基址与堆基址（unsorted bin + tcache fd 均可）。
- 目标栈地址与某个返回地址偏移固定（关闭 ASLR 或已知环境）。
- 能进行 tcache 毒化并把 chunk 分配到栈（栈地址需 0x10 对齐）。

## 利用步骤

1. 用 unsorted bin 泄露 libc 基址；用 tcache fd 或堆指针泄露堆基址。
2. 准备 7 个左右同尺寸 tcache 块，制造 UAF：释放一个块后仍保留 show 索引。
3. 计算 0x10 对齐的 libc 读取目标：`read_target = libc_base + 0x2046e0`（示例，environ 附近、存放栈指针的地址），确认其地址 0x10 对齐；不要直接把未对齐的 `environ` 变量位置作为分配目标。
4. 用一次大块溢出/编辑改写 UAF 块的 fd 为 `read_target ^ (chunk_addr >> 12)`。
5. 分配同尺寸块消费该 fd，再释放/展示相关块，读取被 safe-linking 编码后的值。
6. 对读到的值依次异或 `(heap_chunk >> 12)` 与 `(read_target >> 12)`，恢复 `read_target` 处存放的栈指针，再减去固定偏移得到返回地址位置。
7. 再次毒化 tcache fd 为 `(stack_addr-0x8) ^ (chunk>>12)`，分配 chunk 到栈；写入 `/bin/sh` 与 `system` 的 ROP 或 one_gadget。
8. 触发返回/退出，拿到 shell。

## PoC

关键步骤骨架（偏移按目标 libc/环境调整；原文 EXP 已打通）：

```python
# 伪造 UAF 块 fd，指向 libc 中存放栈指针的对齐地址
add(0, 0x460, b'a'*0x438 + p64(0x411)
    + p64((heap_chunk >> 12) ^ (libc_base + 0x2046e0)) + p64(0))
add(1, 0x400, b'/bin/sh\x00')
add(2, 0x400, b'/bin/sh\x00')
delete(8)          # 让带栈指针的 fd 进入 tcache
show(8)
raw = u64(p.recv(6).ljust(8, b'\x00'))
stack_leak = raw ^ (heap_chunk >> 12) ^ ((libc_base + 0x2046e0) >> 12)
stack_leak -= 0x130

# 再毒化到栈上，分配 chunk 写 ROP
add(0, 0x460, b'a'*0x438 + p64(0x411)
    + p64((heap_chunk2 >> 12) ^ (stack_leak - 0x8)) + p64(0))
add(1, 0x400, b'/bin/sh\x00')
add(0x10, 0x400, b'/bin/sh\x00' + p64(pop_rdi) + p64(stack_leak-0x8) + p64(system))
```

## 变体与关联

- 变体：若 `environ` 可对齐（不同 libc 布局），可直接用 `environ` 泄露；若无法 show，可改用 tcache stashing unlink 或 largebin attack 把栈指针写入可读结构。
- 变体：把最终目标从栈返回地址改为 `__free_hook`（2.39 已移除）或 `_IO_list_all`，需按版本调整。
- 关联：[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（同页 tcache 双 free 自异或恢复堆地址）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄露栈 + 栈上 ROP）、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（tcache 毒化改 GOT）。

## 检测与防御

- 防御：升级 glibc 并使用 tcache key/double-free 检查；对 show 已释放块、负数索引、悬空指针做校验；开启 Full RELRO/PIE/Canary。
- 检测：监控 tcache fd 中出现非堆范围值、同一块被反复 free/show、以及分配到栈地址的异常 malloc 返回。
- 分析：2.39 下所有 chunk 目标必须 0x10 对齐；先确认 `environ` 的实际值与附近对齐地址的偏移，再用 safe-linking 公式双向验算。
- 该场景为 CTF/授权测试利用；生产环境不要仅依赖 `_exit` 或关闭 IO 作为防护。
