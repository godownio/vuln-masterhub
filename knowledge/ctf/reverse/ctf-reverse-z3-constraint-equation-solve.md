---
id: ctf-reverse-z3-constraint-equation-solve
title: Z3 求解逆向题约束方程组：按变量表取值，注意移位与逻辑或
type: scenario
domain: ctf
path: ctf/reverse
technique: z3-reverse-constraint-solving
aliases:
- z3 求解
- 约束方程
- Int 变量
- Solver model
- 逆向线性方程组
tags:
- ctf
- reverse
- z3
- constraint-solving
- smt
- linear-equations
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:54:50+08:00'
  notes: 已对照原文 z3 节与图 17/19 核对：16 个 Int 变量、逐条 solver.add、15 个等式、model 按变量表 eval、a8<<7→a8*128、&& 拆分/|| 用 Or、正则 vN→v[N-shift] 批量处理、解出 U_G07_th3_k3y! 及后续异或还原均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

逆向题把 flag 的每个字符拆成整数、再给出一组线性等式时，用 z3 的 `Int` 变量逐条 `solver.add()` 即可求解；关键是按最初定义的变量列表 `model.eval(v[i])` 取值（模型不保证按变量名排序），并把 C 的 `<<` 改写成乘法、把 `||` 写成 `Or`，否则会解出顺序错乱或无解。

## 原理

- **约束求解替代手工解方程**：题目把每个字符与系数相乘后求和，等于若干常数；这是一组整数线性约束，z3 的 SMT 求解器可直接判定 `sat` 并给出模型。
- **变量类型必须是 z3 类型**：`Int('v0')` 或 `[Int(f'v{i}') for i in range(n)]`；普通 Python int 不能进入约束。
- **模型是映射不是有序列表**：`model()` 打印顺序不保证与变量定义顺序一致；输出 flag 必须遍历自己的变量列表 `v`，对每个 `model.eval(i).as_long()` 取字符。
- **C 表达式改写**：`a8 << 7` 在 z3 中改为 `a8 * 128`（左移等价乘 2 的幂，但 z3 的位向量/整数语义不同）；`&` 在位运算中可能是逻辑与，题目用 `&` 连接条件时按 `&&` 处理；`||` 是“或”，要写成 `Or(...)`，不能拆成多个必须同时成立的约束。
- **批量处理**：把反编译条件串清洗成一行，用正则把 `vN` 重命名为 `v[N-shift]`，按 `&&`/`| |` 拆分后逐条 `eval` 添加；注意分隔符空格与换行。

## 触发条件

- 反编译代码中出现大量 `flag[i] * 常数 + ... == 常数` 形式的等式，或对输入字符的线性变换比较。
- 方程组有唯一解/可满足解，变量为整数或字节范围。
- 已知变量个数、系数与常数（可从反编译直接抄）。
- 有 Python + z3-solver 环境。

## 利用步骤

1. 从反编译中提取所有等式，确认变量与 flag 字符的对应关系（如 `v20=flag[0]`、`v19=flag[1]`，注意变量命名逆序）。
2. 定义 z3 变量列表 `v = [Int(f'v{i}') for i in range(n)]`。
3. 逐条 `solver.add(expr)`；`&&` 拆成多条，`||` 用 `Or`。
4. `solver.check()` 为 `sat` 时取 `model`，遍历 `v` 输出 `chr(model.eval(i).as_long())`。
5. 若输出乱序，检查是否按 model 打印顺序而非变量列表；若 `no ans`，检查变量类型、移位改写、约束抄写错误。
6. 若题目还有 XOR/拼接/MD5 等后处理，按源码顺序继续还原。

## PoC

```python
from z3 import Int, Solver, sat

v = [Int(f'v{i}') for i in range(16)]
s = Solver()
s.add(v[0] * 7 == 546)
s.add(v[1] * 2 == 166)
s.add(v[2] * 6 + v[3] + v[5] * 7 == 1055)
# ... 其余等式逐条 add

if s.check() == sat:
    m = s.model()
    print(''.join(chr(m.eval(v[i]).as_long()) for i in range(16)))
else:
    print('no ans')
```

```python
# 批量：把条件串里的 vN 转成 v[N-shift]，按 && / | | 拆分后 eval
import re
s1 = "... v20 == ... && ..."
shift = 2
s1 = re.sub(r'v(2[0-9]|1[0-9]|[1-9])', lambda m: f'v[{int(m.group(1))-shift}]', s1)
conds = s1.split('&&')
solver = Solver()
for c in conds:
    solver.add(eval(c))
```

原文实测：16 个变量、15 条等式解出 `U_G07_th3_k3y!`；把 `(a8 << 7)` 改为 `a8 * 128` 后 z3 才能正确处理。

## 变体与关联

- **变量类型变体**：`Int`、`BitVec`（按位运算）、`Real`；字符范围可加 `0 <= v[i] <= 255` 约束。
- **表达式变体**：`&&`/`||`、`&`/`|`、移位/乘法、取模、XOR；按 C 语义逐项转换。
- **批量变体**：正则重命名、按分隔符拆分、`eval` 动态构造约束；注意不要 `eval` 不可信输入（仅用于本地题目字符串）。
- **关联卡片**：[[ctf-crypto-lfsr-known-plaintext-state-recovery]]（GF(2) 线性方程组）、[[ctf-reverse-base64-table-index-mutation]]（编码还原）。
- **边界**：非线性/不可满足/欠定方程组可能多解或无解；z3 对位向量与整数语义不同，混用会出错。

## 检测与防御

- **CTF 验证**：解出后按源码重新计算等式，确认全部成立；多解时结合 flag 格式/打印约束筛选。
- **防御视角**：用线性等式保护 flag 只是增加逆向成本，不构成密码学保护；关键逻辑应使用标准密码原语。
- **检测信号**：二进制中出现大量 `imul/add/cmp` 线性组合；输入长度固定、逐字符比较。
- **复盘**：先抄全等式再写脚本；优先修正常见错误（变量顺序、移位、逻辑或），不要盲目调参。
