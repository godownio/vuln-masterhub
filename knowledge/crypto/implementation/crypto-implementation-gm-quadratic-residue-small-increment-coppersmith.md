---
id: crypto-implementation-gm-quadratic-residue-small-increment-coppersmith
title: GM 变体加密的弱随机 y 递增：结式消元 + Coppersmith 小根逐位恢复明文
type: scenario
domain: crypto
path: crypto/implementation
technique: gm-variant-weak-random-increment-coppersmith
aliases:
- Goldwasser-Micali 弱随机
- GM 加密 Coppersmith
- 二次剩余比特恢复
- 小增量 y Coppersmith
- 结式消元恢复明文
tags:
- crypto
- goldwasser-micali
- quadratic-residue
- coppersmith
- resultant
- small-roots
- weak-randomness
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:16+08:00'
  notes: 已对照原文与全部 89 张图片核对；修正多项式 GCD 代码；未在目标复现
---

## 一句话结论

GM 变体加密中，bit=0 时密文为 `y^2 mod n`，bit=1 时为 `y^2*x mod n`（x 为 Jacobi 符号 1 的非二次剩余）；若 y 每轮只增加一个小于 2^48 的小随机数，相邻密文就存在代数关系：用前两组密文构造关于 y 与增量 k 的多项式，结式消去 y 得到 k 的多项式，Coppersmith 求小根 k，回代求 y；再从后往前对每个密文尝试 bit=0/1，若 `x*(y+k)^2 - c` 存在小根则 bit=1，逐位恢复明文，无需分解 n。

## 原理

- GM 的安全性依赖“判定模 n 的二次剩余”与分解 n 一样困难；密文的二次剩余性直接编码明文比特。
- 题目实现用递推 `y_{i+1} = y_i + k_i`，且 `k_i < 2^48` 远小于 n；这破坏了 y 的独立性，使相邻密文 `c_i = x^{bit_i} * y_i^2 mod n` 之间存在可消元的多项式关系。
- 由 `c_0 = x*y_0^2` 与 `c_1 = (y_0 + k)^2` 得两个多项式 `f1 = x*y^2 - c_0`、`f2 = (y+k)^2 - c_1`；对 y 取结式（Sylvester 矩阵行列式）得到只含 k 的多项式，`small_roots()` 求出小 k。
- 回代后可解出 y；随后从最后一个密文向前遍历：已知当前 y，对每个 c 判断 `x*(y+k)^2 - c` 是否有小根，有则说明该位 bit=1，否则 bit=0。由于 y 与 k 的递推关系，逐位反推即可恢复全部明文。
- 该攻击不分解 n，也不直接判定二次剩余，而是利用加密实现的弱随机性把“判定问题”转化为“小根问题”。

## 触发条件

- 目标使用 GM 变体：`c = y^2`（bit 0）或 `c = y^2*x`（bit 1），x 为 Jacobi=1 的非二次剩余。
- y 的更新方式弱随机（如每次只加一个小整数），使相邻密文存在小增量关系。
- 攻击者能获得公钥 (n, x) 与至少两组连续密文。

## 利用步骤

1. 从 `output.txt` 读取 n、x、密文列表 enc。
2. 在 `Zmod(n)` 上定义多项式环，构造 `f1 = x*y^2 - enc[0]`、`f2 = (y+k)^2 - enc[1]`。
3. 对 y 求结式，得到关于 k 的单变量多项式；用 `small_roots()` 求小根 k（若多解，结合后续密文验证）。
4. 回代求初始 y：对 `f1` 与 `f2` 求 GCD，取系数恢复 y。
5. 从 enc 末尾向前遍历：对每个 c 测试 `x*(y+k)^2 - c` 是否有小根，有则 bit=1，否则 bit=0；更新 y。
6. 把比特串转回字节，得到 flag。

## PoC

```python
# Sage
from Crypto.Util.number import long_to_bytes
exec(open('output.txt').read())   # n, x, enc

P.<y, k> = PolynomialRing(Zmod(n))
f1 = x*y^2 - enc[0]
f2 = (y + k)^2 - enc[1]
f3 = Matrix(f1.sylvester_matrix(f2, y)).determinant()
k = min(f3.univariate_polynomial().monic().small_roots())

def poly_gcd(a, b):
    return a.monic() if not b else poly_gcd(b, a % b)

P.<y> = PolynomialRing(Zmod(n))
f1 = x*y^2 - enc[0]
f2 = (y + k)^2 - enc[1]
g = poly_gcd(f1, f2)
y = n - g.coefficients()[0]

flag = 0
P.<k> = PolynomialRing(Zmod(n))
for c in enc[::-1]:
    flag <<= 1
    if len((x*(y + k)^2 - c).monic().small_roots()):
        flag += 1
print(long_to_bytes(flag))
```

## 变体与关联

- 弱随机形式可换成小范围随机、低熵种子、LCG 短周期；对应地把增量关系写成多项式并用 Coppersmith/格方法求解。
- 若 x 不是非二次剩余，密文的二次剩余性不再直接编码 bit，需要重新推导。
- 关联：RSA 部分明文/高位泄露的 Coppersmith 小根、截断 LCG 状态恢复、GM 方案的标准实现。

## 检测与防御

- GM 加密的 y 必须使用密码学安全随机数，且每轮独立采样，不能用“上一轮 y + 小增量”的递推。
- 避免在密文中暴露任何关于 y 的可预测关系；对实现做随机性测试与熵评估。
- 使用经过审计的密码库实现，避免自定义变体；对密钥/随机数生成器做侧信道与可预测性评估。
