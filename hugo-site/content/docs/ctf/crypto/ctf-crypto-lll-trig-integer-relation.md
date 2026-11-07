---
id: ctf-crypto-lll-trig-integer-relation
title: LLL 解三角函数整数关系：高精度 sin/cos 与密文构造格恢复小系数 a,b
type: scenario
domain: ctf
path: ctf/crypto
technique: lll-trigonometric-integer-relation-recovery
tags:
- ctf
- crypto
- lll
- lattice
- integer-relation
- trigonometry
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:44:23+08:00'
  notes: 已对照原文 baby_math 核对并用 sympy+mpmath 复跑：RealField(1000)/10^300 精度、3×4 格 LLL、取第 2/3 列 hex 拼接；复跑得 a=107164967250478127778884915227180531418197665393972、b=18032305077339772662352093494917741105810450484376957，拼接解码出 ISCTF{164a3221-7306-4024-88c3-4ef557b86895}，与原文一致；已补全 enc/x 常量并修正卡片把结果误写为 128bit UUID 的表述（实际为 43 字节完整 flag）
url: /docs/ctf/crypto/ctf-crypto-lll-trig-integer-relation/
draft: false
kb_aliases:
- baby_math
- LLL 整数关系
- sin/cos 高精度
- 三角函数格
- Trendy Windy Trigonity
- 小系数恢复
---

## 一句话结论

若密文满足 `enc ≈ a*cos(x) + b*sin(x)`，其中 a、b 是小整数，则可把 `[cos_x, 1, 0, 0]`、`[sin_x, 0, 1, 0]`、`[-enc, 0, 0, 1]` 作为格基做 LLL；短向量 `a*row1 + b*row2 + 1*row3 = (≈0, a, b, 1)` 直接给出 a、b，把它们的十六进制拼接即可得到 flag。

## 原理

- **整数关系问题**：给定高精度实数 `cos_x`、`sin_x`、`enc`，若存在小整数 a、b 使 `a*cos_x + b*sin_x - enc ≈ 0`，则向量 `(a*cos_x + b*sin_x - enc, a, b, 1)` 的各分量都很小（第一分量接近 0，后三项是小整数）。
- **格构造**：把上述三个行向量组成 3×4 矩阵，格中的整数组合正是 `(a*cos_x + b*sin_x - enc, a, b, 1)`；LLL 会优先找欧氏范数最短的非零向量，因此能恢复 `(a, b, 1)`。
- **精度处理**：`cos_x`、`sin_x`、`enc` 都乘以 `10^300` 转成整数（或使用 `RealField(1000)`），保证第一分量的“接近 0”在整数格中仍然是短向量；精度不足会让目标向量不再最短。
- **结果解读**：LLL 输出矩阵的第一行形如 `(small, a, b, 1)`（可能带符号），取第 2、3 列作为 a、b；把 `hex(a)` 与 `hex(b)` 拼接后 `bytes.fromhex` 得到完整 flag（示例为 `ISCTF{...}`，43 字节），并非只是 UUID 部分。
- **为什么成立**：LLL 在多项式时间内找到短向量；本题的未知系数很小、维度低，目标向量远短于其他格向量，因此恢复是唯一且稳定的。

## 触发条件

- 密文/公开值由少量公开实数常量（sin/cos、根号、π 的有理近似）与小整数系数的线性组合构成。
- 系数 a、b 足够小（示例中 hex(a)||hex(b) 即 43 字节的完整 flag，约 344 bit，远小于 10^300 量级），使目标格向量明显短于随机组合。
- 已知足够高的精度（示例 RealField(1000) / 10^300 缩放）。
- flag 与系数直接相关（示例 hex(a)||hex(b)）。

## 利用步骤

1. 从题目读取 enc、x 及精度；用高精度实数计算 `cos_x`、`sin_x`，统一放大到整数。
2. 构造格基：
   ```text
   [cos_x, 1, 0, 0]
   [sin_x, 0, 1, 0]
   [-enc,  0, 0, 1]
   ```
3. 对矩阵做 LLL（Sage `Matrix(ZZ, ...).LLL()` 或 fpylll）。
4. 在输出中找末列为 1、首列接近 0 的短向量，取第 2、3 列作为 a、b（注意符号）。
5. 按题目格式拼接 a、b（示例 `f"{a:x}{b:x}"`），`bytes.fromhex` 得到 flag；若结果不可读，尝试交换 a/b、取绝对值或调整精度。

## PoC

```python
from sage.all import *

R = RealField(1000)
enc = R("1.24839978408728580181183027675785982784764821592156892598136000363397267152291738689909414790691435938223032351375697399608345468567445269769342300325192248438038963977207296241971217955178443170598629648414706345216797043374408541203167719396818925953801387623884200901703606288664141375049626635852e52")
x   = R("0.75872961153339387563860550178464795474547887323678173252494265684893323654606628651427151866818730100357590296863274236719073684620030717141521941211167282170567424114270941542016135979438271439047194028943997508126389603529160316379547558098144713802870753946485296790294770557302303874143106908193100")

sin_x = int(R(sin(x)) * 10^300)
cos_x = int(R(cos(x)) * 10^300)
enc   = int(enc * 10^300)

M = Matrix(ZZ, [
    [cos_x, 1, 0, 0],
    [sin_x, 0, 1, 0],
    [-enc,  0, 0, 1],
]).LLL()

a = int(M[0, 1])
b = int(M[0, 2])
print(bytes.fromhex(f"{a:x}{b:x}").decode())
```

输出：

```text
ISCTF{164a3221-7306-4024-88c3-4ef557b86895}
```

## 变体与关联

- 常量变体：用 π、e、sqrt(2) 等高精度常量替代 sin/cos；只要关系是“小整数系数 × 公开实数”的线性组合，格方法同理。
- 维度变体：更多未知系数时扩展格矩阵；系数较大时用 Kannan embedding/CVP 或 BKZ。
- 关联：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LLL/Kannan embedding）、[[ctf-crypto-linear-hash-collision-lll]]（线性关系格）。
- 边界：系数过大、精度不足或关系非线性时，简单 LLL 可能找不到目标向量。

## 检测与防御

- 检测：CTF 中看到高精度 sin/cos/π 与整数密文混合，优先尝试整数关系/LLL。
- 防御：不要用公开实数的线性组合编码秘密；密码方案应基于离散对数/大整数分解等难题，并加入随机化。
- 加固：若必须使用数值关系，增加噪声与维度，使短向量恢复不可行。
