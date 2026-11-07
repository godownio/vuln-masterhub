---
id: ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget
title: 自定义 VM 指令集 pwn：用 VM 内存读写改 GOT，exit 重启 + malloc one_gadget
type: scenario
domain: ctf
path: ctf/pwn
technique: custom-vm-opcode-native-memory-got-restart-onegadget
aliases:
- vvmm
- mvmps
- VM 指令集 pwn
- 虚拟机任意读写
- VM 改 GOT
- exit GOT 重启
- malloc one_gadget
tags:
- pwn
- vm
- bytecode
- virtual-machine
- got-hijack
- one-gadget
- libc-leak
- restart
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:08+08:00'
  notes: 已对照原文指令编码、EXP 与调试记录核对；原文未展示最终 flag；PoC 未复跑。
---

## 一句话结论

当自定义 VM 的指令集直接暴露“按寄存器读写宿主内存”“加减栈指针”“压栈/出栈”等原语且不做地址沙箱时，攻击者可以像写汇编一样用 VM 字节码实现宿主任意读写：读 GOT 泄露 libc，写 `exit@GOT` 为重启地址获得无限次尝试，再把 `malloc@GOT` 改成 one_gadget，最后触发 malloc 完成 RCE。

## 原理

- **指令编码**：每条指令最低 2 位是类型（0–3），高 6 位是 opcode；类型 0 后跟 24 位操作数，类型 1 后跟 8 位操作数，类型 2 后跟两个 8 位寄存器号，类型 3 后跟 8 位寄存器号 + 32 位立即数。用 `code()` 构造器可精确拼出任意指令。
- **栈指针原语**：类型 0 的 opcode 36 执行 `SP -= 4 * operand1`，opcode 37 执行 `SP += 4 * operand1`；类型 1 的 opcode 31 把寄存器压栈、32 从栈弹出到寄存器。它们让攻击者可以移动 VM 的栈指针到任意相对位置，读写宿主栈上的返回地址/局部变量。
- **内存读写原语**：类型 2 的 opcode 12/17 以及类型 0 的 opcode 51 会以寄存器中的值作为地址/偏移访问宿主内存；opcode 51 调用 `sub_4014AF`（读写封装），配合类型 3 的 opcode 3（`reg = imm32`）可以设置 fd、buf、len 等参数，实现对任意地址的读/写。
- **GOT 劫持**：二进制 Partial RELRO、No PIE，GOT 可写；先用 VM 的内存读/写包装读取 `puts@GOT`/`read@GOT`，减去 libc 偏移得到 libc 基址；再把 `exit@GOT` 写成 `0x401030`（`main`/重启入口）或等价地址，使程序退出后重新开始，获得无限次字节码执行机会；最后把 `malloc@GOT` 写成 one_gadget，触发一次 `malloc`。
- **为什么可行**：VM 只把字节码当“数据”解释，但它的指令语义直接操作宿主地址空间；没有把寄存器/操作数限制在 VM 自己的缓冲区，也没有对 GOT/栈地址做范围检查。对 VM 而言这些是正常指令，对宿主而言就是任意读写。
- **调试要点**：VM 栈/寄存器布局与普通汇编不同，`code(0,36,operand)` 的实际减栈是 `4*operand`（不是 operand）；`code(0,37,...)` 同理。先用无害的寄存器赋值/压栈指令验证 `code()` 编码正确，再用内存读写回读确认落点，避免把地址写偏导致流程崩溃。
- **前置条件**：VM 暴露内存读写/栈指针指令；宿主 GOT 可写或存在其他可写函数指针；能泄露 libc；能重启或重复执行以修正失败尝试；最终有 one_gadget/system 可用。

## 触发条件

- 目标提供自定义字节码/VM 解释器，指令集中包含按寄存器/立即数访问宿主内存、修改栈指针、push/pop 等能力。
- VM 没有把内存访问限制在沙箱缓冲区，或边界检查可被寄存器值/偏移绕过。
- 宿主二进制 Partial RELRO/No PIE（或可泄露基址），GOT/函数指针可写。
- VM 执行结束后仍回到可再次提交字节码的循环，或可通过 `exit@GOT`/`main` 重启。
- 目标 libc 有可用 one_gadget，或能通过 `system` + `/bin/sh` 构造命令执行。

## 利用步骤

1. 逆向 opcode 表与指令编码，写 `code(type, opcode, op1, op2)` 构造器；用寄存器赋值、压栈、出栈指令验证编码与 VM 栈方向。
2. 用类型 0 的 36/37 调整 SP 到目标栈槽，用类型 1 的 31/32 在寄存器与栈之间搬运地址/值。
3. 用类型 3 的 opcode 3 设置 fd/buf/len 等寄存器，用 opcode 51（或类型 2 的 12/17）读写 GOT，先读 `puts@GOT` 泄露 libc。
4. 计算 libc 基址、`system`、one_gadget；把 `exit@GOT` 写成 `main`/重启地址，使程序退出后重新进入 VM，获得多次尝试。
5. 把 `malloc@GOT` 写成 one_gadget；构造一次 `malloc` 调用（或让后续代码自然触发），满足 one_gadget 约束后获得 shell。
6. 若 one_gadget 约束不满足，改为把 `malloc@GOT` 写成 `system`，并把 `/bin/sh` 放到 `rdi` 指向的地址；或用 VM 写栈返回地址做 ROP。

## PoC

指令构造器（按题目编码）：

```python
def code(op_type, opcode_high=0, operand1=0, operand2=0):
    opcode_high &= 0x3F
    if op_type == 0:
        opcode = (opcode_high << 2) | 0
        return bytes([opcode, (operand1 >> 16) & 0xFF,
                      (operand1 >> 8) & 0xFF, operand1 & 0xFF])
    if op_type == 1:
        opcode = (opcode_high << 2) | 1
        return bytes([opcode, operand1 & 0xFF])
    if op_type == 2:
        opcode = (opcode_high << 2) | 2
        return bytes([opcode, operand1 & 0xFF, operand2 & 0xFF])
    opcode = (opcode_high << 2) | 3
    return bytes([opcode, operand1 & 0xFF,
                  operand2 & 0xFF, (operand2 >> 8) & 0xFF,
                  (operand2 >> 16) & 0xFF, (operand2 >> 24) & 0xFF])
```

关键链骨架（地址按目标调整）：

```python
payload  = code(3, 3, 0, 0x123456)          # 寄存器赋值，验证编码
payload += code(0, 36, 0x100) * 4           # SP -= 0x400
payload += code(0, 36, 0x20)                # SP -= 0x80

payload += code(3, 3, 0, 1)                 # fd = 1 / 0
payload += code(3, 3, 1, puts_got)          # buf = puts@GOT
payload += code(3, 3, 2, 8)                 # len = 8
payload += code(0, 51, 1)                   # 读写封装：泄露 puts
# ... 计算 libc，构造 exit@GOT=main、malloc@GOT=one_gadget 的写指令 ...
payload += code(1, 31, 1)                   # push 目标地址/值
```

## 变体与关联

- 变体：VM 指令集暴露 `mem[reg]`/`mem[reg+imm]` 读写、`push/pop`、`SP += imm` 等任意组合；有的 VM 用 8 位有符号偏移，可负向写相邻全局变量（见关联卡）。
- 变体：Full RELRO 下 GOT 不可写，可改栈返回地址、`__free_hook`/`__malloc_hook`（旧 glibc）、`_IO_list_all`/FSOP；有 PIE 时先泄露代码基址。
- 变体：无 one_gadget 时把 `malloc@GOT` 改成 `system`，用 VM 写 `/bin/sh` 到 `rdi` 指向的缓冲区；或用 `setcontext`/`longjmp` 做栈迁移。
- 关联：[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（VM 8 位有符号偏移越界写全局命令缓冲区）、[[ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop]]（VM 边界字段与真实缓冲尺寸脱钩）、[[binary-pwn-format-string-malloc-hook-one-gadget]]（one_gadget/GOT 劫持基础）。
- 边界：VM 把内存访问严格限制在自身缓冲区、GOT 只读、无 libc 泄露、one_gadget 约束不满足、或无法重启/重复执行时，本链失效或需要改走其他原语。

## 检测与防御

- VM 内存访问必须锚定自身分配的缓冲区，禁止用寄存器/立即数直接寻址宿主地址；对偏移、长度、寄存器号、栈深度做上下界与整数溢出检查。
- 不要把 GOT/函数指针暴露在 VM 可写范围；开启 Full RELRO、PIE、Canary、CET；VM 进程以低权限运行并配 seccomp/AppArmor。
- 限制 VM 指令集：去掉不必要的宿主内存读写、栈指针任意加减、任意 push/pop；只暴露纯计算与受限 I/O。
- 不向 VM 暴露 one_gadget 可利用的 libc 版本/地址；敏感函数（`malloc`/`free`/`exit`）做完整性校验或改用静态分发。
- 检测：字节码中出现大量 36/37 栈指针调整、51 内存操作、读写 GOT 地址；VM 进程在退出后重新进入 main；`malloc`/`exit` GOT 被改写；one_gadget 特征或异常 shell 子进程。
