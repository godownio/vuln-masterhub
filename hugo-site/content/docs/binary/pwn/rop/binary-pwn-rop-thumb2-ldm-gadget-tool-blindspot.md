---
id: binary-pwn-rop-thumb2-ldm-gadget-tool-blindspot
title: Thumb2 的 ldm.w gadget 是 ROP 工具盲区：ROPgadget 需 --align 2 才能检出，ropper/xrop 直接漏报
type: scenario
domain: binary
path: binary/pwn/rop
technique: thumb2-ldm-gadget-tooling-blindspot
tags:
- pwn
- rop
- arm
- thumb2
- gadget
- tooling
- firmware
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:51:16+08:00'
  notes: 已对照原文第十节与工具输出核对：ROPgadget默认在4字节对齐下漏报0x10066的ldm、--align 2检出但按ARM语义标注、ropper -a ARMTHUMB为0 gadgets、xrop -b16/-b32均未检出；示例机器码e8 94 eb ff、ARMv8中ldm写sp不可预测但目标设备实测正常的表述均与原文一致。纯分析技巧，无组件版本。未在本机复跑工具（无原文样本二进制）。
url: /docs/binary/pwn/rop/binary-pwn-rop-thumb2-ldm-gadget-tool-blindspot/
draft: false
kb_aliases:
- Thumb2 ldm gadget
- ldm.w 栈转储
- ROPgadget align 2
- ARM ROP 工具盲区
- Thumb2 gadget 检测
- ldm 多寄存器加载
---

## 一句话结论

ARM 固件里的 `ldm`（load multiple）可以一次把多个寄存器连同 sp/pc 从内存加载，是理想的 ROP 切换 gadget；但 Thumb2 版本的 `ldm.w` 起始地址只需 2 字节对齐（不必 4 字节对齐），ROPgadget 默认只认 4 字节对齐的 ldm、`--align 2` 时又会把它误标为 ARM 指令，ropper 根本不把 ldm 当作 gadget 结束点，xrop 虽支持 Thumb2 解码却仍可能漏报——只靠现成工具会在 ARM 目标上错过关键 gadget。

## 原理

- **ARM 指令集差异**：ARM 指令 4 字节；Thumb 指令 2 字节（代码密度高但功能受限，Thumb 的 `ldm` 不能设置 pc）；Thumb2 是 Thumb 的扩展，指令仍以 2 字节为单位，4 字节的 Thumb2 指令可以出现在 2 的倍数（非 4 的倍数）地址上。`ldm.w` 属于 Thumb2，可以加载大量寄存器并直接写 sp/pc。
- **为什么工具会漏**：ROP gadget 搜索器通常先找“有趣的结束指令”（如 ldm/pop），再向前反汇编确定 gadget 起点。ROPgadget 只在 ldm 起始地址是 4 的倍数时才认为它是合法 ARM/Thumb2 指令；目标 gadget 在 2 的倍数地址上，默认扫描不到。加 `--align 2` 后能检出，但工具会把这条 Thumb2 指令按 ARM 语义标注（输出形如 `ldm r4, {...}` 而非 `ldm.w`），需要人工按 Thumb 模式核对。
- **ropper/xrop 的行为**：ropper 不把多重加载（ldm）当作可能的链结束点，输出 0 gadget；xrop 基于 bfd libopcodes，理论上支持 Thumb/Thumb2 解码，但在测试二进制中仍未能检出该 gadget。即使都以 `-a ARM`/`-a ARMTHUMB` 指定架构也无法得到正确结果。
- **目标环境特例**：ARMv8 架构参考手册指出最新 ISA 中 `ldm` 设置 sp 属不可预测行为；但在实际目标设备上执行正常、栈被正确转储。做 gadget 假设时要以目标 CPU/固件实测为准。
- **实际用途**：在 TEE/固件等 ARM32 目标中，`ldm.w ip, {...sp, pc}` 可以把一个数据指针（如 GOT 项）当栈转储，一次性设置寄存器、sp 与 pc，配合前一步的任意读写即可完成栈切换与 ROP 启动。

## 触发条件

- 目标为 ARM32/Thumb2 固件或库，需要构造 ROP/JOP 链且缺少常规 pop 系列 gadget。
- 使用 ROPgadget/ropper/xrop 等工具做 gadget 搜索。
- 已能控制某个寄存器指向受控数据（如 r12/ip 指向 GOT 表项或栈上数据）。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 确认目标使用 Thumb/Thumb2（函数指针最低位为 1、代码中 `bx`/`blx` 带状态切换、IDA 显示 thumb 标记）。
2. 用 ROPgadget 分别跑默认与 `--align 2`，对比输出；对 `--align 2` 新增的 ldm/pop 类指令逐条人工反汇编确认（capstone/objdump 指定 Thumb 模式）。
3. 用 ropper/xrop 交叉验证，但不要以它们的“0 gadgets”为结论——它们可能漏报。
4. 直接在二进制中搜索 `ldm` 编码（如 Thumb2 的 `e8 9x` 前缀），用 IDA/capstone 按 Thumb 解码确认寄存器列表与语义。
5. 选取能写 sp/pc 的 `ldm.w`（如 `ldm.w ip, {..., sp, pc}`），把受控指针指向布置好的寄存器值数组，构造栈切换/ROP 启动。
6. 在模拟器或设备上实测（尤其 `ldm` 写 sp 在 ARMv8 上的行为差异），验证后固化 gadget 地址。

## PoC

```python
# 示例机器码（Thumb2 ldm）
# e8 94 eb ff  ->  ldm.w r4, {...}（按 Thumb 模式解码）
# 关键点：指令位于 2 字节对齐地址（如 0x10066），不是 4 的倍数
```

```text
# ROPgadget 默认：漏报
0x0001005c : bx r0
# ROPgadget --align 2：检出（但按 ARM 语义标注）
0x00010066 : ldm r4, {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, fp, sp, lr, pc}
# ropper -a ARMTHUMB：0 gadgets found（漏报）
# xrop -b 16 -r arm：未检出该 ldm（漏报）
```

```text
# 典型利用形态（TEE 驱动场景）
r12 -> .got 中的函数指针项
ldm.w ip, {r0, r1, r3, r4, r5, r6, r8, sb, fp, ip, sp, pc}
# 从 r12 指向处批量加载：设置寄存器、sp、pc -> 进入 ROP 链
```

## 变体与关联

- 变体：其他 Thumb2 多寄存器指令（`ldmia.w`、带写回的 `ldmdb`）同样容易被工具漏报；搜索时按编码前缀而非工具输出。
- 变体：ARM 模式下的 ldm 也有“以 4 字节对齐”限制，但 Thumb2 的 2 字节对齐让工具更容易漏。
- 变体：没有 ldm 时可用 `pop {..., pc}` 的 Thumb2 变体或 `bx`/`blx` 间接跳转组成 JOP 链。
- 关联：[[binary-pwn-stack-teegris-keymst-rsa-pubexp-overflow-secure-world-rop]]（用 ldm.w 切换第二段 ROP）、[[binary-pwn-format-string-teegris-stst-driver-arbitrary-rw-custom-printf-rce]]（用 ldm.w ip 从 GOT 转储启动 ROP）、[[code-analysis-reverse-firmware-samsung-sboot-arm64-exception-vector-extract]]（同类 ARM 固件逆向）。

## 检测与防御

- 检测：二进制加固评估时用多工具交叉扫描并人工复核 Thumb2 gadget；攻击面评估报告应包含“非常规 gadget”清单。
- 防御：编译时开启 CFI/BTI（ARMv8.5）/PAC；减少可被用作 ldm 基址的敏感指针（如 .got 中的内部函数指针）；库尽量不导出可用作间接跳转的指令序列；ASLR 增加 gadget 地址不确定性。
- 说明：本文是 ARM/Thumb2 ROP gadget 检测的工具盲区与人工核对方法，severity low（分析技巧）；仅用于授权测试与自有设备研究。
