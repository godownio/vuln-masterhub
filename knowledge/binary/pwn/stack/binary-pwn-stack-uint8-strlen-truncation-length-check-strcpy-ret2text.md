---
id: binary-pwn-stack-uint8-strlen-truncation-length-check-strcpy-ret2text
title: 长度检查变量为 unsigned __int8：strlen(260) 截断成 4 绕过 3-8 限制，strcpy 仍按全量复制溢出栈 ret2text
type: scenario
domain: binary
path: binary/pwn/stack
technique: uint8-strlen-truncation-length-check-bypass-strcpy-overflow
aliases:
- int_overflow
- unsigned __int8 长度截断
- strlen 截断绕过
- 260 截断为 4
- 长度检查绕过 strcpy
- 整数截断 ret2text
tags:
- pwn
- stack
- integer-truncation
- uint8
- strlen
- strcpy
- ret2text
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V688
  verified_at: '2026-11-13T16:18:19+08:00'
  notes: 已对照原文与14张图核对：checksec(图04 No PIE/No canary/NX)、图05 栈差0xffffce80-0xffffce6c=0x14 再+4=24、图07 unsigned __int8 v3、图06 payload b'a'*0x14+b'a'*4+p32(0x0804868B) 后 ljust(260)、260&0xff=4 通过 3<len<=8、图09 flag 成功；未验证点：未本机复跑 PoC
---

## 一句话结论

口令校验把 `strlen(s)` 存入 `unsigned __int8` 后再与 `3 < len <= 8` 比较：输入 260 字节时 strlen=260，截断成 8 位后等于 4，检查通过；但真正复制用的 `strcpy(dest, s)` 仍按原始字符串长度复制 260 字节到 11 字节栈缓冲区，覆盖返回地址。无 PIE/Canary 时直接 ret2text 跳到后门 `system("cat flag")`。

## 原理

- **检查值与被使用值不一致（整数截断）**：`check_passwd` 中
  ```c
  unsigned __int8 v3;
  v3 = strlen(s);
  if (v3 <= 3u || v3 > 8u) { reject; }
  else { strcpy(dest, s); }   // dest[11]
  ```
  `strlen` 返回 `size_t`，赋给 8 位无符号变量时只保留低 8 位（即长度 mod 256）。长度 260（0x104）→ 低 8 位 4，落在 4..8 区间，检查通过；长度 259→3（不通过）、261→5（通过）等同理。
- **为什么仍溢出**：通过检查后执行 `strcpy(dest, s)`，`strcpy` 以 `\0` 为界复制**完整**输入，260 字节远超 `dest[11]`，依次覆盖相邻局部变量、saved ebp 与返回地址。若长度检查本身用 `strlen` 的返回值做 `memcpy` 长度，就不会溢出；漏洞点正是“检查用截断值、操作用原值”。
- **为什么能直接 ret2text**：原文目标为 32 位、No PIE（0x8048000）、No canary、NX 开启；二进制自带 `what_is_this()`（`system("cat flag")`），返回地址覆盖为该后门地址即可读 flag，无需 libc 泄露。
- **payload 长度为何是 260**：既满足“低 8 位在 4..8”，又能覆盖到返回地址；原文按 `0x14` 填充 + 4 字节对齐 + `p32(backdoor)`，再把总长补齐到 260（`.ljust(260, b'a')`），保证 `strlen` 截断后仍通过检查。
- **同类变体**：任何“把长度/索引存入更窄整型后再做范围检查或分配”的代码都可能出现该模式（uint8/uint16/signed char 截断），典型还有 `abs(INT_MIN)`、有符号→无符号放大、低字节检查等。

## 触发条件

- 32 位（或其它架构）ELF，存在把长度存入 `unsigned __int8`/`uint16_t` 后再做范围检查、随后用原字符串/原长度做拷贝的代码。
- 拷贝操作（`strcpy`/`strcat`/循环）不受检查值约束，能写入超过目标缓冲区。
- 目标无 PIE/Canary（或已具备对应绕过），且存在后门函数/可用 ROP 目标；NX 不影响 ret2text。
- 输入通道允许一次发送超过 255 字节（如 `read(0, buf, 0x199)`）。

## 利用步骤

1. 反汇编定位检查函数：确认长度变量类型为 `unsigned __int8`、检查区间与后续 `strcpy` 的目标缓冲区大小和栈偏移（原文 dest[11]，填充 0x14 + 4 字节对齐）。
2. 选择通过截断的长度：如 260（0x104 → 4）、261（→5）……并按需保证总长足够覆盖返回地址。
3. 构造 payload：填充到返回地址 + 后门地址，尾部补齐到所选长度（原文 `ljust(260, b'a')`）。
4. 通过 username/passwd 交互发送，触发 `strcpy` 溢出，函数返回跳到后门读取 flag。
5. 若失败：核对长度变量的实际位宽与检查顺序（编译器可能用 `movzx` 截断）、目标是否 PIE/Canary、拷贝函数是否真的使用原字符串。

## PoC

```python
from pwn import *

context(arch='i386', log_level='debug')
p = remote('target', 59290)
backdoor = 0x0804868B

p.recvuntil('Your choice:')
p.send('1')
p.recv()
p.send('evil')

payload  = b'a' * 0x14 + b'a' * 4 + p32(backdoor)   # 覆盖 dest -> saved ebp -> ret
payload  = payload.ljust(260, b'a')                 # 260 & 0xff = 4，绕过 3 < len <= 8
p.recvuntil('Please input your passwd:')
p.send(payload)
p.interactive()
```

## 变体与关联

- **同族截断**：[[binary-pwn-stack-negative-one-length-uint8-truncation-oob-copy]]（uint8 把 -1 截断成 255 导致 256 字节越界拷贝）、[[binary-pwn-stack-tlv-length-low-byte-check-memcpy-overflow]]（低字节检查、全长度 memcpy）、[[binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow]]（abs(INT_MIN) 负余数绕过）；本卡是“长度值本身被截断后与区间比较、拷贝仍用原串”的版本。
- **有符号/无符号放大**：见 [[ctf-pwn-signed-length-unsigned-param-amplify-password-blank-ret2libc]]（负数通过有符号检查、无符号形参放大长度）。
- **无后门变体**：无 PIE 时可 ret2plt 泄 libc 后 ret2libc；有 Canary 时需先泄露 canary；PIE 时需先泄代码基址。
- **边界**：若检查与拷贝都使用截断后的长度、或拷贝前按实际长度二次校验，则链不成立。

## 检测与防御

- **代码审计**：检查长度变量类型是否足够宽（用 `size_t`）、比较是否与拷贝长度一致；任何 `unsigned char/short` 存长度后做范围判断的代码都应按整数截断风险审计。
- **加固**：拷贝使用 `strncpy`/`snprintf`/`memcpy` 并显式限制为目标缓冲区大小；开启 `-fstack-protector-strong`、PIE、NX、Full RELRO；移除调试后门函数。
- **检测**：二进制的检查函数中出现 `movzx`/窄类型长度与 `strcpy` 组合；请求/输入长度恰好为 256 的倍数加小值（如 260）且随后触发崩溃/跳转。
- **响应**：崩溃现场若返回地址指向二进制内非调用点（如 system/cat flag 后门），按整数截断绕过栈溢出处置。
