---
id: binary-pwn-stack-ret2libc
title: ret2libc 绕过 NX
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2libc
aliases: [ret2libc, 返回 libc]
tags: [pwn, stack, rop, ret2libc, nx]
cve: []
severity: high
confidence: high
status: draft
created: 2026-11-04
updated: 2026-11-04
---

## 一句话结论

当栈可溢出但 NX 开启、二进制中没有现成 `system("/bin/sh")` 时，泄漏 libc 基址后返回到 libc 中的 `system` 并布置参数字符串即可 getshell。

## 原理

NX 只禁止执行栈上的 shellcode，不禁止跳转到已映射的可执行段。libc 中同时存在 `system` 与 `/bin/sh` 字符串，知道 libc 版本与基址后即可计算两者地址。常见做法先用 `puts`/`write` 泄漏 GOT 中的 libc 函数地址，再二次溢出返回 `system`。

## 触发条件

- 存在栈溢出且可控制返回地址；
- 有可用的泄漏原语（`puts`/`write`/`printf`）；
- 已知目标 libc 版本或可在线匹配。

## 利用步骤

1. 计算溢出偏移；
2. 第一次溢出调用 `puts(puts@got)` 泄漏地址，再返回 `main`；
3. 用泄漏地址减去 libc 符号偏移，得到基址；
4. 第二次溢出布置 `pop rdi; ret` + `/bin/sh` + `system`；
5. 获取 shell。

## PoC

```python
payload1 = b"A"*offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
# 解析泄漏 -> libc_base
payload2 = b"A"*offset + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
```

## 变体与关联

- 变体：`one_gadget`、`ret2csu`、SROP；
- 关联：ASLR 泄漏、GOT 覆写。

## 检测与防御

- 检测：崩溃栈中的 libc 地址与 ROP 链；
- 防御：Full RELRO、PIE、Canary、ASLR、CFI。
