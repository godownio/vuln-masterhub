---
id: code-analysis-reverse-obfuscation-ollvm-triton-ast-ai-z3-mba
title: Triton 符号执行 + AI/Z3 化简 OLLVM MBA 混淆：从基本块 AST 还原 hash 算法
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ollvm-triton-ast-ai-z3-mba-deobfuscation
aliases:
- Triton OLLVM
- MBA 化简
- Mixed Boolean-Arithmetic
- SMT-LIB2 AST
- hacklu-2021-ollvm
- 符号执行去混淆
- Z3 位向量求解
tags:
- reverse
- obfuscation
- ollvm
- triton
- symbolic-execution
- z3
- smt
- mba
- ai-assisted
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T22:52:07+08:00'
  notes: 已对照原文及7张截图核对：22块JMP RAX分发、some_table状态、Triton symbolic R15/RBP AST、DeepSeek+Z3化简、8个64位hash反解、Z3算术右移坑均一致；修正PoC中XOR恒等式的常数（C1=0xcd921463a266a514，候选0x326deb9c5d995aeb）及反解示例为单步解table22，原文未给可执行完整脚本
---

## 一句话结论

OLLVM 把算法拆成大量以 `JMP RAX` 串联的基本块，中间状态放在 `some_table` 数组里；用 Triton 对每个基本块做符号执行，把输入寄存器符号化后取出输出寄存器的 AST（SMT-LIB2），再用 Z3 做等价性验证/数值采样，并用 AI 辅助猜测 MBA 恒等式，可以把每块化简成 `+ / ^ / << / >> / & / *` 的简单表达式；最后按调用链重建完整算法，用 Z3 位向量反解 8 个 64 位 hash，恢复原始输入。

## 原理

- **控制流混淆**：程序用函数指针表 `PTR_FUN_0067a050[index]` 分发到各基本块，块尾用 `JMP RAX` 跳到下一块；`some_table` 保存索引、输入、输出和常数，每个块形如“读 `some_table` 输入 → 计算 → 写 `some_table` 输出 → 跳下一块”。手工看反编译会陷入大量伪变量，但数据流本质是一个多步 hash。
- **符号执行提取语义**：Triton 加载 ELF 后，在块入口把输入寄存器/内存符号化（示例符号化 `R15`，并把固定的 `some_table[1]=2` 直接写成具体值），逐条 `processing` 指令到块出口，取 `ctx.getRegisterAst(rbp)` 得到输出 AST；`ctx.simplify(ast, True)` 会先用内置 Z3 化简，输出 SMT-LIB2 表达式。
- **MBA 表达式**：OLLVM 的指令替换用 Mixed Boolean-Arithmetic 恒等式，把简单运算扩展成大量 `bvnot/bvor/bvand/bvxor/bvshl/bvashr` 与 `extract/concat` 的组合。很多看似吓人的 `extract` 串等价于“与某个掩码 XOR”；例如 `(bvxor (bvxor 0xFFFFFFFFFFFFFFFF x) C)` 等价于 `(bvxor (bvnot x) C)`，最终可合并成一个 XOR 常量。
- **数值采样 + 等价性验证**：对可疑表达式取若干输入值，用 Z3 `(assert (= expr candidate)) (check-sat)` 或直接数值对比；若只在小样本上相等，用随机/边界值再测。Z3 的 `simplify` 与 `check-sat` 能证明位向量恒等式，比人工推导可靠。
- **AI 的定位**：AI 擅长给出“结构上接近”的化简式（如把一大串位操作猜成 `(x ^ C) * K`），但常数/移位方向经常错；正确用法是“AI 提候选 → Z3/数值验证 → 人工修正”，不能直接相信 AI 的输出。
- **重建与求解**：把 22 个块的化简式按调用链串起来，得到从 `some_table[3]`（8 字节输入）到 `some_table[0]`（64 位 hash）的算法；对 8 个目标 hash 分别建 Z3 位向量约束，解出每块 8 字节输入，拼接即 flag。
- **位运算语义坑**：Z3 的 `>>` 是**算术右移**（补符号位），而无符号算法通常要逻辑右移，必须用 `LShR`；Python 的 `>>` 对有符号数是算术右移，`&` 又会把大整数转成无符号语义，且 Python 不会自动按 64 位溢出，需要手动 `& 0xFFFFFFFFFFFFFFFF` 或 `% 2**64`。文章曾因该差异导致 3 个 hash 求不出解或正反向结果不一致。

## 触发条件

- 目标为 OLLVM/LLVM 混淆的二进制，存在控制流平坦化/指令替换/MBA，算法被拆成多个基本块。
- 能定位块间分发（函数指针表、`JMP RAX`、状态数组）并确定每块的输入/输出。
- 有 Triton（或 Angr/Miasm/SymCC 等符号执行框架）与 Z3；能加载目标架构的 ELF/PE。
- 每块的输入/输出可用具体值或符号值表达；不存在强反调试/反符号执行（自修改、时间检查、环境检测）或可绕过。
- 算法本身是可逆/可用约束求解的（hash/校验类），不是不可逆加密。

## 利用步骤

1. **识别结构**：在 IDA 中找主函数的分发调用 `(*(code *)(&PTR_FUN_...)[index])(&some_table)`、块尾 `JMP RAX`、状态数组 `some_table`；用 IDAPython 脚本遍历 22 个块，打印每块的输入/输出索引、两个常数和下一块地址。
2. **定位输入/输出点**：在块入口找读取 `some_table` 的指令（如 `MOV R15, [some_table+RAX*8]`），在块出口找写回 `some_table` 的指令（如 `MOV [some_table+RAX*8], RBP`）；这些就是符号化/取 AST 的位置。
3. **Triton 模拟**：加载 ELF 段，设置假栈；在入口把输入寄存器符号化（固定参数直接写具体值）；逐条执行到出口，取 `ctx.getRegisterAst(输出寄存器)`，`ctx.simplify(ast, True)` 得到精简 SMT-LIB2。
4. **格式化 AST**：写一个括号配对/缩进脚本把长 SMT-LIB2 拆成树，便于按子表达式分块；对 `concat/extract` 特殊处理。
5. **子表达式化简**：对每个可疑子表达式，取 3~5 组输入数值，代入 Z3 求值；猜测候选（XOR 掩码、移位、乘法常量），用 Z3 证明 `expr == candidate`；AI 只用来提候选。
6. **重建算法**：把每块的化简式按调用链组合，消去中间变量；用具体输入验证整条算法与原始二进制输出一致。
7. **反解**：把目标 hash 作为约束，用 Z3 `BitVec(64)` 建模；注意 `LShR`/`>>`、`&`、溢出；对 8 个 hash 分别求解，拼接 `to_bytes(8, 'big')` 得到 flag。
8. **交叉验证**：用正向算法重新计算解出的输入，确认与目标 hash 一致；检查是否有多个解/无解，排查移位/溢出错误。

## PoC

Triton 取输出 AST（结构示意）：

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)
# ... 加载 ELF 段、设置栈 ...
ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x9ffffff0)
ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x9ffffff0)

pc = 0x4636b0
while pc:
    insn = Instruction(pc, ctx.getConcreteMemoryAreaValue(pc, 16))
    ctx.processing(insn)
    if pc == 0x4636ee:
        ctx.symbolizeRegister(ctx.registers.r15)
    if pc == 0x463b0a:
        ast = ctx.getRegisterAst(ctx.registers.rbp)
        print(ctx.simplify(ast, True))
        break
    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
```

Z3 等价性验证/求解骨架：

```python
from z3 import *

x = BitVec('x', 64)
expr = (x ^ 0xffffffffffffffff) ^ 0xcd921463a266a514       # (bvnot x) ^ C1
candidate = x ^ 0x326deb9c5d995aeb                        # = x ^ (C1 ^ 0xffffffffffffffff)

s = Solver()
s.add(expr != candidate)
print(s.check())  # unsat 表示等价

# 反解示例：已知目标 hash，先解出 some_table[22]（真实算法需再按前面各块反推到输入）
t22 = BitVec('table22', 64)
s2 = Solver()
s2.add(12540599618503547147 * (t22 ^ 0xb9b8a788569d772d) == 0x875cd4f2e18f8fc4)
if s2.check() == sat:
    print(hex(s2.model()[t22].as_long()))
```

说明：真实算法有 20+ 步，需按块组合；示例仅展示单步约束。Z3 里无符号右移用 `LShR(x, n)`。

## 变体与关联

- 变体：用 Angr/Miasm/SymCC 替代 Triton 提取 AST；或用 Unicorn 记录指令 trace 后手工重建。
- 变体：OLLVM 的 CFF/BCF/指令替换组合；MBA 表达式可能用更高阶恒等式，需要更多子表达式拆分。
- 变体：算法含不可逆操作（如取模、哈希）时，不能整体反解，只能逐块求逆或爆破小空间。
- 变体：AI 可辅助生成 Z3 脚本/格式化 AST/猜恒等式，但必须用 Z3/数值验证，不能直接采信。
- 关联：[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]（OLLVM 混淆原理）；[[code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register]]（Frida 动态提取指令替换结果）；[[code-analysis-reverse-obfuscation-ollvm-cff-frida-trace]]（CFF 动态 trace）；[[ctf-reverse-z3-constraint-equation-solve]]（Z3 位向量约束求解）；[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（Z3 符号执行解 VM）。

## 检测与防御

- 对分析方：优先用符号执行提取语义，而不是逐行读反编译；先按块求值/采样，再猜恒等式；所有候选必须用 Z3 或数值验证。
- 对分析方：注意 `>>`/`LShR`、`& 0xFFFF...`、Python 大整数溢出、Z3 无符号语义；正反向算法要交叉验证。
- 对防御/混淆设计方：MBA 只提高人工分析成本，无法阻止符号执行；可叠加 VM、环境检测、代码自修改与反调试，但会增加性能/兼容成本。
- 对防御/混淆设计方：避免用简单常数参与可被采样猜出的运算；对关键校验使用带密钥的密码学原语而非纯 MBA。
- 对防守方：该技术用于恶意样本逆向/CTF，不改变网络攻击面；检测重点仍是样本行为与 C2。
