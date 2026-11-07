---
id: ctf-crypto-z3-short-input-128bit-state-constraint
title: Z3 求解 6 字节输入的 128 位状态约束：模乘异或链的逆问题
type: scenario
domain: ctf
path: ctf/crypto
technique: z3-short-input-128bit-state-constraint
tags:
- ctf
- crypto
- z3
- bitvector
- state-machine
- constraint-solving
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:52+08:00'
  notes: 已对照原文「cokecoke」核对并复算：state=((state^b)*0x147) mod 2^128，BASE/TARGET 与原文一致；对原文解 58b306e7192d 回代得目标常量 177830285821087443523022595911573187680，匹配。本机未安装 z3，未实际运行求解器（原文脚本已给出求解输出与回代）。未验证点：z3 求解时间未复测；无版本/CVE；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-z3-short-input-128bit-state-constraint/
draft: false
kb_aliases:
- Z3 状态约束
- 短输入求解
- 128 位模乘
- 位向量约束
- cokecoke
---

## 一句话结论

当程序对 6 字节输入做 `state = ((state ^ b) * x) mod 2^128` 的迭代，并要求最终状态等于固定常量时，可以把 6 个输入字节建模为 8 位位向量、把迭代展开成 128 位位向量表达式，交给 Z3 求满足约束的模型；本题解出 `58 b3 06 e7 19 2d`。

## 原理

- **位向量建模**：`mod 2^128` 等价于 128 位无符号位向量的乘法溢出；`^` 是逐位异或。Z3 的 `BitVec(128)` 精确建模这些运算，不需要手动处理进位/溢出。
- **输入空间小**：6 字节 = 48 bit，暴力枚举 `2^48` 不可行；但约束只是一个 128 位等式，Z3 的位向量求解器（bit-blasting + SAT）通常能在秒级到分钟级求出模型。
- **展开迭代**：`state_0 = BASE`，对每个输入字节 `b_i` 执行 `state_{i+1} = (state_i ^ ZeroExt(120, b_i)) * MULT`（128 位乘法自动截断）；最后约束 `state_6 == TARGET`。
- **为什么成立**：所有运算都是位向量上的确定性函数；Z3 可以反向传播/求解。若存在多个解，模型给出一个；需要按题目格式/回代验证。
- **注意**：`ZeroExt(120, b_i)` 把 8 位扩展到 128 位；若直接写 `state ^ b_i`，Z3 会做位宽提升，语义可能不同。乘法常量 `MULT` 也要用 `BitVecVal`。

## 触发条件

- 程序对短输入（几字节到十几字节）做可建模的位运算/模运算/异或/加法/乘法链。
- 最终有一个明确的等式约束（目标常量、哈希、校验值）。
- 输入空间大于暴力枚举但 Z3 可在可接受时间内求解（通常 < 2^64）。
- 有 `z3-solver`（Python）或等价 SMT 求解器。

## 利用步骤

1. 反编译/阅读校验函数，记录初始状态、每轮变换、常量、目标值。
2. 为每个输入字节创建 `BitVec(f"b{i}", 8)`。
3. 按程序语义展开变换，注意位宽扩展、截断、有无符号、模数。
4. 添加 `solver.add(state == BitVecVal(TARGET, 128))`，调用 `check()`；`sat` 时取模型。
5. 把模型字节按程序要求的格式（大端整数/hex/原始字节）提交；用独立回代确认最终状态等于目标。
6. 本题输入 `58b306e7192d`，回代状态 `177830285821087443523022595911573187680`，flag 为 `flag{58b306e7192d}`。

## PoC

```python
from z3 import BitVec, BitVecVal, Solver, ZeroExt, sat

BASE = 0x25CE7BCC2F1CA7501800C86B77DE214C
MULT = 0x00000000010000000000000000000147
TARGET = 177830285821087443523022595911573187680

byte_vars = [BitVec(f"b{i}", 8) for i in range(6)]
state = BitVecVal(BASE, 128)
for value in byte_vars:
    state = (state ^ ZeroExt(120, value)) * BitVecVal(MULT, 128)

solver = Solver()
solver.add(state == BitVecVal(TARGET, 128))
if solver.check() != sat:
    raise RuntimeError("no solution")

model = solver.model()
raw = bytes(model.eval(v).as_long() for v in byte_vars)
print(raw.hex())          # 58b306e7192d

check = BASE
for v in raw:
    check = ((check ^ v) * MULT) & ((1 << 128) - 1)
assert check == TARGET
```

## 变体与关联

- **变体（模数/位宽）**：`mod 2^64`、`mod p`、有符号算术需要调整位宽与 `ZeroExt`/`SignExt`。
- **变体（哈希/CRC）**：若校验是 CRC/哈希，Z3 可能因非线性/表查找变慢，可改用 meet-in-the-middle/查表。
- **变体（多解）**：约束不足时 Z3 只给一个模型；用题目格式/二次校验筛选，或加约束枚举。
- **关联卡片**：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（格方法解线性约束）、[[ctf-crypto-simon-period-measurement-gf2-nullspace]]（GF(2) 线性方程）。
- **边界**：输入超过 ~64 bit、变换含不可建模的查表/浮点、目标不唯一时，Z3 可能超时；需要分治/代数化简。

## 检测与防御

- **CTF 识别**：短输入 + 固定目标状态 + 位运算/模乘，优先 Z3；先确认位宽和截断语义。
- **密码设计**：不要把短输入经过简单可逆/可建模变换后作为秘密校验；使用带盐的慢哈希/签名。
- **实现**：校验逻辑应服务端可信执行，不要依赖客户端提交的状态；对输入长度/格式做严格校验。
