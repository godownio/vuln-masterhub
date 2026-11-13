---
id: ctf-reverse-xor-equation-multisolution-known-prefix-z3
title: 分组异或方程组用 z3 求解：解不唯一时用已知明文前缀（flag{）收紧约束并迭代枚举模型
type: scenario
domain: ctf
path: ctf/reverse
technique: xor-equation-groups-z3-multisolution-prefix-constraint
tags:
- ctf
- reverse
- z3
- xor
- constraint-solving
- python
- pyc
- multisolution
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:54:57+08:00'
  notes: 已对照原文 pycdas 反汇编与提取的 7 条异或公式逐条核对一致（chall 用 cut(flag,6) 分组，每组 6 字节 m 与 6 字节 pad 组合出 7 个值与 7x7 密文矩阵比较）；多解现象、已知明文前缀约束（原文固定 m[0][0..4]=flag{，另加 m[0][5]=84）、Or 排除已得模型迭代枚举、末组手工推导均与原文一致。未实际复跑 z3 全量枚举（模型空间较大），密文矩阵与原文一致。dedup 与 ctf-reverse-z3-constraint-equation-solve 为 related 非同链（基础线性约束求解 vs 多解异或枚举）。
url: /docs/ctf/reverse/ctf-reverse-xor-equation-multisolution-known-prefix-z3/
draft: false
kb_aliases:
- z3 解异或方程组
- 多解 XOR 约束
- flag 前缀约束 z3
- 分组异或还原
- BitVec 异或方程
- 枚举所有模型
- Python pyc 异或题
---

## 一句话结论

当校验把输入按固定长度分组，对每组若干字节做多条异或组合后与密文比较时，可以把每个字节和随机 pad 都建成 8 位 `BitVec`，把每条组合写成等式交给 z3；但异或方程组往往欠定（多解），需要加入已知明文前缀（如 `flag{`）、可打印字符范围等约束，并用“排除已得模型”的方式迭代 `solver.check()` 枚举所有候选，再从候选中挑出语义合理的明文。

## 原理

- **异或方程组建模**：示例程序把 flag（`flag{...}`，6 字节一组共 7 组）的每组 `m[i][0..5]` 与随机 pad 组合出 7 个值：
  ```
  m0^m1^m2^pad0
  m3^m4^pad1^pad2
  pad5^m5^pad1^pad3
  m3^pad3^pad4^pad1
  m5^pad0^m4^pad1
  m2^m4^pad0^pad1
  m2^m0^m4^pad4
  ```
  与 7×7 的密文矩阵比较。每个等式都是 GF(2) 上的线性方程，变量是 42 个明文字节 + 6 个 pad 字节。
- **为什么多解**：方程数量虽多，但存在线性相关/变量未覆盖（如某变量只在组合中出现一次、pad 之间可互换），解空间不止一个点；z3 每次返回一个满足约束的模型，第一个解往往不是真明文。
- **已知格式收紧**：明文有固定格式（`flag{` 开头、`}` 结尾、可见 ASCII），把 `m[0][0..4] == 'f','l','a','g','{'`、每字节 `0x20 <= x < 0x7f` 加进约束，能大幅缩小解空间；必要时再根据语言习惯（可读单词）人工挑选。
- **枚举所有模型**：z3 默认只返回一个模型；循环 `while solver.check() == sat:`，每次取出模型后加入 `Or([var != model[var] for var in vars])` 排除当前解，即可列出全部候选，再逐个检查可打印性/语义。
- **校验**：拿到候选后重建加密过程（用求出的 pad 重算 7 个组合值）与密文比对，验证解的正确性；示例中最终还需要手工推导 pad 与末组。

## 触发条件

- 校验逻辑是“分组异或组合 + 与固定密文比较”，且加密过程可完整提取（如从 pyc 字节码/反编译代码读出组合公式）。
- 输入有已知格式（flag 头尾、固定前缀）或可打印字符约束，用于消除多解。
- 有 z3（或其他 SMT 求解器）可用；变量规模小（几十个 8 位变量），求解很快。
- 仅用于 CTF/授权逆向。

## 利用步骤

1. 从反编译/字节码中提取每组异或组合公式与密文矩阵，确认分组大小、组数、pad 长度。
2. 为每个明文字节和 pad 建立 `BitVec('name', 8)`，把每条组合写成 `solver.add(expr == cipher)`。
3. 加入已知格式约束（如 `m[0][0]==0x66, ..., m[0][4]==0x7b`；所有字节在可打印范围）。
4. 循环求解：`while solver.check() == sat` 打印模型，并加入排除该模型的 `Or` 约束；收集所有候选。
5. 对候选做可打印性/语言合理性筛选，必要时调整约束（后缀 `}`、每组的语义）。
6. 用求出的明文与 pad 重算加密过程，确认与密文完全一致。

## PoC

```python
from z3 import *

num_bits = 8
num_groups = 7
num_per_group = 6
res = [[154, 209, 184, 205, 152, 173, 85],
       [219, 163, 159, 245, 245, 245, 3],
       [244, 244, 153, 245, 164, 191, 126],
       [136, 241, 132, 245, 188, 173, 93],
       [197, 198, 139, 207, 190, 181, 31],
       [167, 206, 128, 197, 183, 183, 76],
       [157, 223, 145, 198, 180, 165, 87]]

m = [[BitVec(f'm_{i}_{j}', num_bits) for j in range(num_per_group)] for i in range(num_groups)]
pad = [BitVec(f'pad_{i}', num_bits) for i in range(6)]

s = Solver()
# 已知明文前缀约束（消除多解）
for j, ch in enumerate(b'flag{'):
    s.add(m[0][j] == ch)

for i in range(num_groups):
    tmp = [
        m[i][0] ^ m[i][1] ^ m[i][2] ^ pad[0],
        m[i][3] ^ m[i][4] ^ pad[1] ^ pad[2],
        pad[5] ^ m[i][5] ^ pad[1] ^ pad[3],
        m[i][3] ^ pad[3] ^ pad[4] ^ pad[1],
        m[i][5] ^ pad[0] ^ m[i][4] ^ pad[1],
        m[i][2] ^ m[i][4] ^ pad[0] ^ pad[1],
        m[i][2] ^ m[i][0] ^ m[i][4] ^ pad[4],
    ]
    for j in range(num_per_group):
        s.add(tmp[j] == res[i][j])

# 迭代枚举所有模型
count = 0
while s.check() == sat:
    model = s.model()
    count += 1
    print(f'model {count}:', ''.join(chr(model[m[i][j]].as_long()) for i in range(num_groups) for j in range(num_per_group)))
    s.add(Or([m[i][j] != model[m[i][j]] for i in range(num_groups) for j in range(num_per_group)] +
             [pad[k] != model[pad[k]] for k in range(6)]))
```

```text
# 多解输出示例（节选）：每行一个候选，挑 flag{...} 且全可打印的那个
model 1: flag{...
model 2: flag{...
...
```

## 变体与关联

- 变体：若方程组独立且未知数唯一，可直接解出无需枚举；欠定时优先加格式约束，再考虑可打印范围、常见单词/词频。
- 变体：变量较多时按组拆分求解（每组 6 字节 + 共享 pad），先解 pad 再解组，降低搜索空间。
- 变体：非线性的“异或 + 加减/置换”混合校验也可用 z3 建模，但注意位宽与无符号语义（`BitVec(8)` 回绕）。
- 关联：[[ctf-reverse-state-chained-plaintext-forward-brute-multi-solution]]（状态链多解的另一处理方式）、[[ctf-reverse-pe-driver-4byte-xor-repair-chained-xor-z3]]（异或修复的 z3 建模）、[[code-analysis-reverse-unpacking-pycdas-constants-key-disassembly]]（本题 pyc 反编译失败时用 pycdas 取字节码与常量）。

## 检测与防御

- 检测：无（CTF 解题技巧）；防御侧可把校验改为不可线性化的结构（S 盒、哈希、带密钥 MAC），避免攻击者用约束求解还原输入。
- 防御：题目/软件中不要用纯异或组合做输入校验；加入非线性变换、随机数与不可逆哈希；关键逻辑放服务端。
- 说明：本文是 CTF 中分组异或校验的多解 z3 求解技巧，severity low；仅用于 CTF/授权逆向。
