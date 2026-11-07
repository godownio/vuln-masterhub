---
id: binary-pwn-stack-bss-pivot-write-gadget-chunked-orw
title: 无输出函数 + 0x20 短读的 BSS 栈迁移：借 _libc_start_main 内 write gadget 泄 libc 并反复 _start 分块写 ORW
type: scenario
domain: binary
path: binary/pwn/stack
technique: bss-pivot-write-gadget-chunked-rop
aliases:
- 无输出函数 pwn
- BSS 栈迁移分块 ROP
- write gadget 泄露 libc
- 反复 _start 续写 ROP
- seccomp ORW 短读
- glibc 2.39 rdx 控制
tags:
- pwn
- stack-pivot
- bss
- no-output
- write-gadget
- libc-leak
- seccomp
- orw
- chunked-rop
- glibc-2.39
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T13:34:14+08:00'
  notes: 已对照原文 2025N1CTF Nothing 全文与 24 张图核对：0x20 短读无输出、leave;ret 迁 BSS、_start/main 逐格下移、_libc_start_main+139 附近 write gadget（偏移 0x2a360）、add edx,eax 控 rdx、分块 ORW 均一致；EXP 未在本机复跑
---

## 一句话结论

当题目没有 `write/puts/printf`、每次只读 0x20 字节且开了 seccomp 时，可以先用 `leave; ret` 把 rbp 迁到 BSS，把 `_start/main` 当作可重复调用的“读入 gadget”，再部分覆盖栈上已有的 `_libc_start_main` 返回地址到其附近的 `write(1, ...)` gadget 泄露 libc；随后每轮向 BSS 写 4 个 qword 并回到 `_start`，即可分块拼出任意长度的 open/read/write ROP 链。

## 原理

- **入口限制**：目标 main 只有 `read(0, buf, 0x20)`，缓冲区仅 8 字节，没有输出函数；读取长度刚好覆盖 8 字节 buf、8 字节 saved rbx、8 字节 saved rbp 和 8 字节返回地址，足以做一次 `leave; ret` 栈迁移。
- **迁移到 BSS**：把 saved rbp 改为 BSS 高地址（如 `0x404a00+8`），返回地址改为 main 中 `read` 调用附近的地址；main 的 `pop rbp; ret` 后 rbp 指向 BSS，下一次 `leave; ret` 即把 rsp 切到 BSS 预置链上。BSS 地址固定（非 PIE），每次运行栈位置一致。
- **把 _start/main 当读入 gadget**：`_start` 会重新走 libc 启动流程并再次调用 main；每次 main 的 `push rbp/push rbx` 与 `pop` 数量不完全对称，调用一次后栈帧向下移动 8 字节。预先在 BSS 填满 `start` 地址，就能像“毛毛虫”一样逐格下移，每格获得一次 0x20 字节的任意写。
- **泄露 libc**：`__libc_start_main` 在调用 main 前会把自身的返回地址（`_libc_start_main+139`）留在栈上，该地址属于 libc。把栈上这个返回地址的低 2 字节部分覆盖为同函数附近的 `mov edx,1; lea rsi,[rip+...]; jmp write` gadget，程序在下一次返回时执行 `write(1, ...)`，把栈上残留的 libc 指针打印出来；接收 6 字节即可算 libc 基址。
- **分块写 ROP**：每轮 `start` 只允许写 0x20 字节，但可以把 4 个 qword 追加到 BSS 的 ROP 缓冲区（如 `0x404c00+0x20*n`），然后返回 `start` 继续下一轮；重复若干次即可构造任意长链，不受单次读长度限制。
- **glibc 2.39 的 rdx 控制**：2.39 中常用的 `pop rdx` gadget 稀少，样本使用 `add edx, eax ; mov rax, rdx ; pop rbx ; ret`：先把 `rax` 设为想要的长度（如 0x50），`edx` 加上 `eax` 得到长度，同时 `rax=rdx`；再配合 `pop rdi/pop rsi` 与 `syscall` 完成 open/read/write。
- **最终危害**：在 seccomp 只允许 open/read/write 的沙箱里读取 flag 并写回 stdout，完成 CTF 目标。

## 触发条件

- 目标为非 PIE 的 x86-64 程序，BSS 地址固定；main 存在可覆盖 saved rbp/返回地址的短读栈溢出。
- 二进制没有可用的输出函数，但 libc 已加载且栈上保留 `_libc_start_main` 返回地址。
- 程序可被重复启动（`_start` 可再次进入 main），且每次调用栈帧有固定偏移，允许逐格写入。
- 目标开启 seccomp 且只允许 open/read/write 等有限 syscall，不能直接 `system`。
- 需要可控 rdx 的 gadget；glibc 2.39 下可用 `add edx, eax; mov rax, rdx; pop rbx; ret` 一类组合。

## 利用步骤

1. 第一次发送 `b'a'*8 + p64(0x111) + p64(bss+8) + p64(main_read_addr)`：覆盖 saved rbx/rbp/返回地址，让 main 的 `pop rbp; ret` 把 rbp 指向 BSS。
2. 在 BSS 预置 `start` 地址（如 `p64(start)*4`），使后续 `leave; ret` 落到 `_start`，并把栈帧固定在 BSS 上。
3. 通过一次任意写把 BSS 上的 `0x4049a0` 填成 `start`，接住程序流；再构造 `write` 前的寄存器布局（rdi/rsi/rdx 与返回地址）。
4. 定位栈上 `_libc_start_main+139` 的返回地址，发送 `p64(main)*3 + b'\x60\xa3'` 之类 payload 部分覆盖低 2 字节，跳到 libc 内的 `write(1, ...)` gadget；接收 6 字节 libc 指针并计算基址。
5. 解析 libc 中 `pop rdi`、`pop rsi`、`add edx,eax; mov rax,rdx; pop rbx; ret`、`syscall`、`open64/read/write` 地址。
6. 每轮写 4 个 qword 到 `0x404c00+offset`，返回 `start`；按 open("/flag") → read(3, buf, 0x50) → write(1, buf, 0x50) 的顺序拼链。
7. 最后一轮把栈迁到 ROP 缓冲区并触发链，读取 flag。

## PoC

关键 payload 骨架（地址按目标调整，未在本机复跑）：

```python
start = 0x401090
bss   = 0x404a00

# 1) 迁移 rbp 到 BSS，并回到 main 的 read 附近
p.send(b'a'*8 + p64(0x111) + p64(bss+8) + p64(0x40129C))
p.send(p64(start)*4)

# 2) 预置返回地址与 write 参数
p.send(b'deadbeef' + p64(bss) + p64(bss) + p64(0x401286))

# 3) 部分覆盖 _libc_start_main 返回地址，跳到 write gadget 泄 libc
p.send(p64(main)*3 + b'\x60\xa3')
p.recv(0x18)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x2a360

# 4) 分块写 ORW 链：每轮 4 个 qword，回到 start
#    open('/flag',0) -> read(3,0x404e00,0x50) -> write(1,0x404e00,0x50)
```

## 变体与关联

- 变体：若没有 `_libc_start_main` 返回地址可部分覆盖，可用 `ret2csu` 或其它 `write@plt` 调用泄露 GOT。
- 变体：把 `_start` 换成 main 本身或其它可重复调用的读入函数，只要栈帧每次有固定偏移。
- 变体：把分块写目标换成 `__free_hook`/`__malloc_hook` 或返回地址，直接写一条短链。
- 关联：[[binary-pwn-stack-pivot-leave-ret-bss]]（基础 BSS 栈迁移）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（两阶段写 BSS 后 system）、[[binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop]]（可控 rbp 逐轮任意写与分块 ROP）。

## 检测与防御

- 该场景为 CTF/授权测试利用；防御方应开启 PIE + Full RELRO + Canary，减少固定 BSS 与可直接覆盖的返回地址。
- 部署 seccomp 时同时限制 `write` 并不能阻止 ORW 泄露 flag；应配合隐藏 flag、限制 open 路径或使用独立沙箱。
- 监控进程反复从 `_start` 重启、栈指针长期落在 BSS、以及 `write` 调用方位于 libc 内部非正常偏移的行为。
- 对二进制做栈保护与影子栈（CET shadow stack）可阻断 `leave; ret` 迁移与返回地址覆盖。
