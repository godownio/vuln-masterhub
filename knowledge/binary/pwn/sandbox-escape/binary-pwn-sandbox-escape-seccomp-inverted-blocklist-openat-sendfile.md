---
id: binary-pwn-sandbox-escape-seccomp-inverted-blocklist-openat-sendfile
title: seccomp 过滤器写成黑名单：只 kill open/read/write/execve，换 openat+sendfile 读 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: seccomp-inverted-blocklist-openat-sendfile
aliases:
- seccomp 写反
- seccomp 黑名单
- openat sendfile 读 flag
- 过滤 execve 之外的 syscall
- KILL_PROCESS 分支错位
tags:
- pwn
- seccomp
- sandbox
- shellcode
- openat
- sendfile
- syscall
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:51:22+08:00'
  notes: 已对照原文核对；seccomp-tools dump 逐行与卡内一致（read/write/open/readv/writev/execve/execveat 命中跳 0013 return KILL_PROCESS，0012 默认 return ALLOW，arch/sysno 异常走 0014 KILL），openat(257)+sendfile(40)+AT_FDCWD(-100) 参数正确；本次核对未读取图片，字母数字 payload 实际回显、以及与既有 seccomp 卡（openat2+pipe+splice、ORW 缺 read 用 sendfile）的边界属作者判定，本会话未复跑
---

## 一句话结论

BPF 过滤器本该写成「只放行白名单」，一旦写反成黑名单——把 `read`/`write`/`open`/`readv`/`writev`/`execve`/`execveat` 这些**常用**调用直接 `KILL_PROCESS`、其余全部 `ALLOW`——那么「不能 open/read/write」的直觉就失效了：改用没被点名的 `openat` + `sendfile` 同样能打开并读出 flag，而 `execve` 被禁只意味着拿不到交互 shell，并不影响读文件。

## 原理

- **seccomp-BPF 的两条分支**：加载的过滤器在每条规则上跳转到「允许」或「杀死」两个 `return`。写白名单时是「命中白名单 → ALLOW，其余 → KILL」；本例反了：命中一小撮常见调用 → `KILL_PROCESS`，落到默认分支 → `ALLOW`。
- **黑名单天然漏项**：`open` 被禁，`openat` 没被禁；`read`/`write` 被禁，`sendfile`（内核态直接在两个 fd 之间搬数据）没被禁；`readv`/`writev` 被禁，`pread64`/`pwrite64`/`splice` 也没被禁。只要漏掉一个能把文件内容送到 stdout 的调用，读 flag 的链就成立。
- **openat 与 open 的差异**：`openat(AT_FDCWD=-100, path, flags)` 只是多一个目录 fd 参数，语义等价于 `open`；`AT_FDCWD` 表示相对当前工作目录解析，所以直接给 `-100` 即可。
- **sendfile 替代 read+write**：`sendfile(out_fd=1, in_fd=打开的文件 fd, offset=0, count=0x100)` 在内核里把文件内容写进 stdout，一次调用同时完成「读」和「写」，绕开 `read`/`write` 两个被杀掉的调用。
- **对利用的影响**：这类过滤器不阻止代码执行本身，只限制「执行后能做什么」。所以攻击者不需要 ROP 提权或逃逸，只要换系统调用组合；反之若过滤器确实是白名单（只放行 open/read/write），才是必须把功能压进那几个调用的场景。
- **注意 `ARCH` 与 `sys_number` 的检查顺序**：读过滤器时先看 `A = arch` 与 `A = sys_number` 两处加载，再逐条看 `if (A == xxx) goto <kill>` 的 JT/JF 落点——判断是白名单还是黑名单，关键是看「不匹配任何规则时」落到哪个 `return`。

## 触发条件

- 目标程序把用户输入拷进可执行内存并跳转（CTF 常见 RWX shellcode 题），或可通过漏洞控制执行流后执行系统调用。
- seccomp 过滤器是「黑名单式」实现：只对少数 syscall 返回 `KILL`，默认分支 `ALLOW`。
- 目标文件（flag）对进程可读，且存在一个未被禁用的 syscall 组合能完成「打开 + 输出」。
- 输入对 shellcode 的字符集/长度有限制时，需要先解决编码（如字母数字 shellcode）。

## 利用步骤

1. 用 `seccomp-tools dump ./chal`（或 `seccomp-tools dump -c <pid>`）导出 BPF：确认每个 `if (A == <sysno>)` 后面跟随的是 `return KILL` 还是 `ALLOW`，并看最后一行默认 `return` 是哪个。
2. 判定为黑名单后，列出「被杀掉」的调用集合，再在该集合的补集里找读文件原语：`openat`+`sendfile`、`openat`+`splice`、`openat`+`writev`、`stat`+`mmap`+`write` 等。
3. 写 shellcode：把文件路径压栈 → `openat(-100, path, 0)` → `sendfile(1, fd, 0, 0x100)`；注意返回值检查（`openat` 返回 fd 在 `rax`，`sendfile` 需要 `rdi=1`、`rsi=fd`）。
4. 若输入对字节集有要求（只允许字母数字/可见字符），用 ALPHA3/AE64 编码整段 shellcode，并确认跳转时基址寄存器指向缓冲区。
5. 发送 payload，读取从 stdout 返回的 flag；若进程被杀，用 `strace`/`seccomp-tools` 复查是否误用了被禁调用。
6. 若确实需要 shell 而 `execve` 被禁：改为 `openat` 读 `/bin/sh` 到内存 + 反射式加载，或直接读目标文件（多数 CTF 场景读 flag 即可）。

## PoC

```asm
; openat(AT_FDCWD, "/flag", 0) + sendfile(1, fd, 0, 0x100)
; 文件路径由 pwntools shellcraft 或手写压栈得到
mov rax, 0x67616c662f       ; "/flag" 的小端写法（示例）
push rax
mov rdi, -100               ; AT_FDCWD
mov rsi, rsp                ; path
xor edx, edx                ; flags = O_RDONLY
mov rax, 257                ; SYS_openat
syscall

mov rdi, 1                  ; stdout
mov rsi, rax                ; 刚打开的 fd
xor rdx, rdx                ; offset = 0
mov r10, 0x100              ; count
mov rax, 40                 ; SYS_sendfile
syscall
```

```bash
# 判定过滤器类型
seccomp-tools dump ./pwn
# 关键读法：命中 read/write/open/execve 的那几条 if 落到 return KILL_PROCESS(0x80000000)，
# 其余（包括 openat/sendfile）落到默认 return ALLOW(0x7fff0000)
```

原文的过滤器逐条为：`read`(0)、`write`(1)、`open`(2)、`readv`(0x13)、`writev`(0x14)、`execve`(0x3b)、`execveat`(0x142) 命中即 `KILL_PROCESS`，其余 `ALLOW`；因此 `openat`(0x101)+`sendfile`(0x28) 完全可用。

## 变体与关联

- **变体（黑名单的其他漏项）**：被杀 `read`/`write` 时用 `pread64`/`pwrite64`、`splice`、`copy_file_range`、`sendfile`；被杀 `open` 时用 `openat`/`openat2`/`creat`；被杀 `mmap` 时用 `read` 到栈缓冲；被杀 `execve` 时用 `execveat`（若未禁）或 `uselib`/`finit_module`。
- **反向思路**：若过滤器是真正的白名单（只放行少数调用），则必须把整个利用压进这几个调用，常见套路是 `open/read/write` 的 ORW shellcode；两者判断方法一致，都是先看默认分支。
- 关联：`binary/pwn/sandbox-escape` 下「ALPHA3 可见字符 shellcode + ORW」「最小 shellcode 字节预算」卡（解决编码与长度约束）；`binary/pwn/sandbox-escape` 下其他 seccomp 相关卡。
- 边界：若默认分支是 `KILL`（真白名单）本卡不适用；`sendfile` 对某些文件系统/管道不支持时需退回 `read`+`write`；若过滤器还限制参数（如只允许特定 fd、`flags` 必须为 0），需按规则微调。

## 检测与防御

- 检测（防守视角）：审计自研 seccomp 规则时，检查是否存在「命中即杀、默认放行」的黑名单写法——这等价于几乎不做限制；用 `seccomp-tools`/`bpftool` 导出规则，确认默认 `return` 是 `KILL`；对容器/服务进程抽样验证若干敏感 syscall 是否真的被拦（例如 `openat`、`sendfile`、`socket`）。
- 防御：seccomp 一律用白名单（默认 `KILL`，只放行业务必需的 syscall），并用 `SCMP_ACT_ERRNO` 而非仅 `KILL` 以便观测；对「读文件 + 网络」这类组合调用单独收紧（如额外限制 `openat` 的路径参数需要 `seccomp` 无法表达时用 LSM/AppArmor 补足）；定期用工具回归验证规则确实生效。
