---
id: binary-pwn-stack-arm32-ret2win-backdoor-qemu
title: ARM32 栈溢出 ret2win：0x24 填充覆盖保存的 LR，直跳后门函数 getshell/读 flag
type: scenario
domain: binary
path: binary/pwn/stack
technique: arm32-ret2win-overwrite-lr-backdoor
aliases:
- ARM ret2win
- ARM32 ret2text
- ROP Emporium ret2win ARM
- qemu-arm ret2win
- pop {fp, pc}
- ARM 栈溢出后门函数
tags:
- pwn
- arm
- arm32
- ret2win
- ret2text
- stack-overflow
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
  verified_at: '2026-11-12T21:52:58+08:00'
  notes: 已对照原文全文与33张图核对：图01 checksec arm-32-little/No canary/No PIE(0x10000)/NX enabled；图02-04 main 与 pwnme(buf 32字节, read 56)及 ret2win()->system(/bin/cat flag.txt)；图05/09/10 disasm 确认 push {fp,lr}/sub sp,sp,#0x20/尾声 sub sp,fp,#4;pop {fp,pc}，saved fp 在0xffffef080、saved LR 在0xffffef084，偏移0x24；图06 gdb-multiarch set architecture arm/target remote；图12-14 实测 payload 0x24个a+p32(0x105EC) 返回 Well done 与 flag_is_not_here，与卡内 PoC 一致。typo 部分（图15-25）按 worker 判定并入既有 ARM32 ret2libc 卡，核对偏移112/gadget 0x20904/bin_sh 0x6c384/system 0x10BA8 与既有卡一致，未建新卡成立。CTF 题无 affected_versions/CVE。dedup：与 x86 ret2win 卡架构/返回地址载体不同，与 ARM32 ret2libc 卡无需参数 gadget 的触发条件不同，非同一链，保留。
---

## 一句话结论

ARM32 程序若存在栈溢出且二进制内有现成的后门函数（如 `ret2win()` 直接 `system("/bin/cat flag.txt")`），只需用 `缓冲区长度 + saved fp` 的填充覆盖保存的 `LR`，函数尾声 `pop {fp, pc}` 把攻击者填的地址装入 `pc`，即可直接跳到后门函数；整个过程不需要任何 `system`/`/bin/sh` 地址泄露或 ROP gadget 拼装。

## 原理

- **ARM32 调用约定**：前 4 个参数放在 `r0`–`r3`，返回值在 `r0`；`bl` 指令相当于 x86 的 `call`，把返回地址写入 `LR`（`r14`）；`pc` 相当于 `rip`，`sp` 是栈顶，`fp`（`r11`）类似 `rbp`。
- **函数序言/尾声**：本例 `pwnme` 序言为 `push {fp, lr}`、`add fp, sp, #4`、`sub sp, sp, #0x20`，缓冲区 32 字节；尾声 `sub sp, fp, #4; pop {fp, pc}`。`pop {fp, pc}` 先从栈上恢复 `fp`，再把下一个字直接装入 `pc`——即返回地址就在栈上 `saved fp` 之后。
- **溢出偏移**：缓冲区 32 字节 + saved fp 4 字节 = 0x24，因此 payload = `'a' * 0x24 + p32(后门地址)`；程序无 canary、无 PIE，后门地址可直接从反汇编取得。
- **为什么不需要参数 gadget**：后门函数自身以固定参数调用 `system("/bin/cat flag.txt")`，攻击者只是改变控制流，不需要在跳转前设置 `r0`；这是 ret2win 与 ret2libc 的本质区别。
- **QEMU 用户态运行**：`qemu-arm -L /usr/arm-linux-gnueabi ./pwn` 用交叉 libc 跑 ARM32 ELF；调试时加 `-g 1234`，再用 `gdb-multiarch` 执行 `set architecture arm`、`target remote localhost:1234`。异架构调试建议直接下断点跑到目标函数，避免单步陷入 qemu 内部。

## 触发条件

- ARM32（`arm-32-little`）ELF，存在可覆盖保存 `LR` 的栈溢出（本例 `read(0, buf, 56)` 写入 32 字节缓冲区）。
- 程序未开栈 canary（或可绕过），且无 PIE（或已泄露基址）。
- 二进制内存在后门/win 函数，其行为直接给 shell 或输出 flag。
- 本地有 `qemu-arm` 与对应 `libc6-arm` 交叉库（`-L` 指定 sysroot）。

## 利用步骤

1. `checksec`/`file` 确认架构、NX、PIE、canary；`readelf -h` 看入口。
2. 反汇编定位溢出函数与缓冲区到 saved `LR` 的偏移（本例序言 `push {fp, lr}` + `sub sp, sp, #0x20`，偏移 0x24）。
3. 反汇编定位后门函数地址（本例 `ret2win` 内直接 `system("/bin/cat flag.txt")`）。
4. 构造 `b'a' * 0x24 + p32(backdoor_addr)`，通过程序的 `read` 发送。
5. 若调试：`qemu-arm -g 1234 ./pwn` + `gdb-multiarch`，在 `pop {fp, pc}` 处确认 `sp`/`pc` 变为payload 中的后门地址。
6. 触发后门，读取输出。

## PoC

```python
from pwn import *

context(arch='arm', os='linux', log_level='debug')
p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi", "./pwn"])
# 调试：process(["qemu-arm","-L","/usr/arm-linux-gnueabi","-g","1234","./pwn"])

backdoor = 0x000105EC          # ret2win() -> system("/bin/cat flag.txt")
payload  = b"a" * 0x24 + p32(backdoor)
p.sendafter(b'>', payload)
p.interactive()
```

```text
# gdb-multiarch 侧
set architecture arm
target remote localhost:1234
# 在 pop {fp, pc} / ret2win 入口下断点，确认 pc 被覆盖为 backdoor
```

## 变体与关联

- 需要调用非后门函数（如 `system("/bin/sh")` 位于 libc）时，必须用 `pop {r0, r4, pc}` 一类 gadget 先设置 `r0`，见 [[binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static]]。
- 无直控 `r0` gadget 时可用组合 gadget，见 [[binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3]]。
- x86 对应基础形态见 [[binary-pwn-stack-32bit-gets-ret2win-backdoor]]、[[binary-pwn-stack-ret2text-win-plus-one-align]]；ARM 的差异只在寄存器/返回地址载体（`LR`/`pc`）与偏移计算。
- 异构架构 QEMU/gdb-multiarch 环境搭建的通用步骤见 [[code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch]]。
- 若目标开启 NX 不影响本场景（不执行栈）；开启 PIE 时需要先泄露代码基址。

## 检测与防御

- 防御：开启栈 canary、PIE 与全 RELRO；移除或收敛二进制中的后门/调试函数；编译时避免危险 `read` 长度。
- 检测：CTF 之外关注崩溃现场 `pc` 指向非调用路径的函数入口、`sp` 恢复异常；ARM 程序出现 `pc` 直接落到含 `system` 调用的函数。
- 缓解：BTI/PAC（ARMv8.5+）可提高控制流劫持门槛；对 qemu 仿真环境仅用于分析，不作为生产防御。
