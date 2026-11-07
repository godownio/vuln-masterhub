---
id: ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx
title: 自定义 VMC2 寄存器虚拟机逆向：从 handler 抠精确 ISA + 逐轮可逆 ARX 求逆（字节内存/8 位 rotate/STAGE S-box/非零初值）
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-vm-handler-isa-extraction-invertible-arx-inversion
tags:
- ctf
- reverse
- vm
- bytecode
- isa
- arx
- substitution
- differential
- x86-64
- invertible
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:55:54+08:00'
  notes: 已对照原文核对；VMC2 字节内存/8 位 rotate/STAGE/非零初值、8 轮 31 字节求逆与 steps/pc/acc 差分验证一致；PoC 未复跑
url: /docs/ctf/reverse/ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx/
draft: false
kb_aliases:
- VVMM
- VMC2
- 自定义寄存器虚拟机
- VM 执行器逆向
- ISA 语义抠取
- 逐轮求逆 ARX
- STAGE S-box
- 非零内存初值
- VM 差分验证
---

## 一句话结论

面对自带反汇编器/调试报告的 VMC2 自定义寄存器 VM，先用 `--disasm` 拿到完整指令流、再用 x86-64 执行器 handler 逐个确认精确语义，重点纠正“字节内存、`ROLI/RORI` 只转低 8 位、`STAGE` 是带 murmur 哈希的 8 位代换、内存初值不是 0 而是固定模式”这些反直觉点；程序本质是 1 段逐字节装载/置换 + 7 轮 31 字节就地 ARX，每轮每个字节在相邻字节已知时都是双射，于是可以从 31 个比较常量逐轮暴力反解，最后用模拟器与原程序的 `steps/pc/acc/zero` 差分闭环。

## 原理

- **先拿指令流，再从 handler 定语义**：`--disasm` 直接输出 2462 条指令与 opcode 名称；执行器在 `0x140003480`，按 `opcode` 查相对偏移跳表 `0x140006580` 分发。反编译/汇编 handler 可以确认每个助记符的真实行为，避免按“常规 VM”猜测。
- **指令格式**：`opcode(1) | rd(1) | rs(1) | 保留(1) | imm32(4)`，共 8 字节；寄存器 `regs[8]` 为 u32，内存 `mem[128]` 是字节数组，下标 `imm & 0x7f`。`pc` 是字节偏移，`JNZ/JMP` 的 `imm` 是指令条数偏移，`target = pc + 8 + imm*8`。
- **三个最容易猜错的语义**：
  - `ROLI/RORI` 只对低 8 位做 `rol/ror`，高 24 位原样保留（汇编里是 `rol al,cl` 后再拼回高 24 位），不是 32 位旋转。
  - `STM` 只把寄存器低字节写入内存，`LDM` 按字节零扩展读出；因此每轮输出完全由 31 个字节决定。
  - `STAGE`（opcode 0x30）不是简单查表，而是用 `imm` 算一个 murmur3 finalizer 风格的哈希，再对低字节做异或/8 位循环移位/加常量/再异或，等价于一张随 `imm` 变化的 8 位 S-box；固定 `imm` 时它是 256 字节上的双射。
- **内存初值不是 0**：执行器先把 128 字节清零，随后用 SIMD 循环重写成 `mem[j] = (uint8_t)(((49*j + 0x17) & 0xff) ^ 0xa5)`；`mem[31..127]` 从不被 `STM` 写，后续轮次读到 `mem[i+7]` 越界时用的就是这些固定模式。按全 0 建模会得到“自洽但错误”的模拟器。
- **程序结构**：第 1 段对每个字节做 `reg = input[i]; reg ^= k1[i]; reg += k2[i]; reg = rol8(reg,k3[i]); reg = stage_op(i,reg); mem[i]=reg`；第 2–8 轮对 `i=0..30` 就地更新：`a=mem[i]`、`b=mem[i+1]`（越界取 `mem[31]`）、`c=mem[i+7]`（越界取固定模式），`t=rol8((a+b)^c, rot[r][i])`、`s=stage_op(base[r]+i,t)`、`mem[i]=s+add[r][i]`；尾部逐字节与 31 个常量比较。
- **可逆性**：块 `i` 只读 `mem[i]`、`mem[i+1]`、`mem[i+7]`。因为按下标递增就地写回，`j>i` 的读取发生在它们被更新之前（本轮输入），`j<i` 的读取读到本轮已更新的值（等于已知目标状态）。固定其它字节时，映射 `mem[i] -> out[i]` 是 256 个字节上的双射，可以暴力 `v=0..255` 找到唯一解。
- **逐轮求逆**：令 `state = 目标常量[0..30]`；对 `r=8..2`、轮内 `i=30..0`，用已知的 `mem[i+1]`/`mem[i+7]` 和已反推的 `out[j]` 暴力解出 `pre[i]`；7 轮反完得到第 1 段之后的 31 字节，再逐字节反解第 1 段（xor/add/rol8/stage 全是双射）。
- **差分验证**：`--run` 打印 `steps/pc/acc/zero`，其中 `acc` 是停机瞬间 `regs[0]&0xff`，等价于把 8 轮变换的中间状态也校准了。用同一个输入比较模拟器与原程序的四个值，逐位一致后再求逆；最后用 `--check` 接受闭环。
- **干扰项**：`--bof` 是独立小实验：512 字节读进 0x30 栈缓冲，校验和只覆盖前 ≤48 字节，分支只打印一行提示，没有 win 函数或隐藏字符串；不要把它当成主利用。

## 触发条件

- 目标是一个自定义字节码/寄存器 VM（本例题为 PE32+ x86-64，自带 `--disasm/--run/--check` 等模式）。
- 能定位执行器与 opcode 跳表，或至少能拿到完整反汇编；VM 程序对输入做多轮变换后与常量比较。
- 变换在“已知相邻字节”时对当前字节是双射，允许逐字节暴力反解；否则需要 SMT/爆破或其它方法。
- 有原程序或高保真模拟器可做差分验证，能观察到 `steps/pc/acc/zero` 等中间信号。

## 利用步骤

1. 运行 `--layout`/`--help`/`--disasm`，记录 VM 容器格式、指令条数、寄存器/内存大小、轮数，导出完整指令流。
2. 用字符串交叉引用和跳表定位执行器（本题 `0x140003480`），逐个 handler 确认 ISA：寄存器宽度、内存元素宽度、rotate 宽度、`STAGE` 代换、内存初值、跳转语义。
3. 写模拟器，先按“常规 VM”假设实现，再用 `--run` 的 `steps/pc/acc/zero` 对随机输入做差分；定位并修正所有不一致点（本题是字节内存、8 位 rotate、STAGE、非零初值）。
4. 从尾部 31 个比较常量开始，按 `r=8..2`、`i=30..0` 逐块暴力 `v=0..255` 反解；越界下标用固定内存模式。
5. 反完 7 轮后逐字节反解第 1 段的 `xor/add/rol8/stage`，得到 31 字节候选。
6. 用模拟器正向跑一遍，比较每轮 `STM idx=30` 的快照与反推结果；原程序 `--check` 接受即闭环。

## PoC

求逆核心（按原题 31 字节布局；`exec_block` 为模拟器单块执行，`PATTERN` 为固定内存模式）：

```python
def invert_round(r, out_state):
    pre = [None] * 31
    for bi in range(30, -1, -1):
        lo, hi = block_range(r, bi)   # 块 bi 的指令区间
        def memget(j):
            if j >= 31:  return PATTERN[j]     # 越界固定模式
            if j <  bi:  return out_state[j]   # 本轮已写回
            if j >  bi:  return pre[j]         # 本轮尚未写回
            return pre[bi]
        cand = [v for v in range(256)
                if exec_block(lo, hi, memget_with(v)) == out_state[bi]]
        assert len(cand) == 1
        pre[bi] = cand[0]
    return pre

state = TARGET[:]
for r in range(7, 0, -1):        # 第 8..2 轮
    state = invert_round(r, state)
inp = invert_round1(state)       # 第 1 段逐字节反解
```

原文实测结果为 `flag{J1nxI_i5_4_6eautiful_g1rl}`，`--check` 返回 `accepted`；该 PoC 未在本库复跑。

## 变体与关联

- **ISA 变体**：字节/字内存、32 位或 8 位 rotate、带哈希的 S-box、非线性加法/乘法、非零初值；核心是先确认语义再写模拟器。
- **求逆变体**：若映射不是逐字节双射，可尝试逐轮整体 SMT、差分攻击、符号执行或已知明文分段爆破。
- **验证变体**：`steps/pc/acc/zero/halt`、每轮快照、`--check` 接受、输出长度/格式；差分信号越细，越容易定位语义错误。
- **关联卡片**：[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（字节码 VM 的有符号偏移越界写，属于 Pwn 侧）、[[ctf-reverse-apk-knapsack-chacha20-vault]]（APK 加密归档逆向）。

## 检测与防御

- **对逆向方**：不要按“常规 VM”假设语义；所有 rotate/内存宽度/初值/代换都要从 handler 确认；先用差分把模拟器校准，再求逆，避免在错误模型上得到“自洽但错误”的序列。
- **对 VM 保护方**：增加语义反直觉点（字节内存、窄 rotate、哈希 S-box、非零初值）只能提高人工分析成本；真正的强度应来自密钥化代换、轮密钥与输入相关的非线性，以及抗差分的中间状态隐藏。
- **对题目设计方**：`--bof` 这类干扰项应与主逻辑隔离，避免选手误把溢出分支当主利用；关键比较常量不要直接以明文数组暴露。
