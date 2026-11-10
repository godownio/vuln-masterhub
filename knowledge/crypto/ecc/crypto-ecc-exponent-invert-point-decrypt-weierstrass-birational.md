---
id: crypto-ecc-exponent-invert-point-decrypt-weierstrass-birational
title: 曲线点当密文的指数加密：用 e 在曲线阶上的模逆乘回 eG 还原明文点，借 Edwards↔Weierstrass 双有理映射取曲线阶
type: scenario
domain: crypto
path: crypto/ecc
technique: ecc-exponent-invert-point-ciphertext-birational-order
aliases:
- 曲线点加密求逆解密
- inverse(e, order) 还原基点
- Edwards 转 Weierstrass 求阶
- e 可逆即无需解 DLP
- twisted Edwards 双有理映射
tags:
- ecc
- twisted-edwards
- birational-map
- group-order
- modular-inverse
- point-as-ciphertext
- sage
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:42:26+08:00'
  notes: '已对照原文核对；本次核对未读取图片（本篇 content.md 无图片引用）；原文 exp 的 p/a=362/d=7/c=1/e=0x10001/eG 常量、dd=d*c^4、A=2(a+dd)/(a-dd)、B=4/(a-dd)、aw=(3-A^2)/(3B^2)、bw=(2A^3-9A)/(27B^3)、edwards_to_ECC 与 ECC_to_edwards 三步变换公式、order=E.order()、t=inverse(e,order)、G=t*eG、long_to_bytes(int(G[0])) 均与卡片 PoC 逐行一致。未验证点：卡内「e 与 #E 必须互素」的判据为通用原理，原文直接 inverse(e,order) 未做 gcd 校验；「明文点 x 坐标即明文」按原文 long_to_bytes(int(G[0])) 反推'
---

## 一句话结论

当题目把明文编码成曲线点 `G`、用 `eG` 当密文公开（`e` 是公开指数）时，整个问题根本不是 ECDLP：只要 `gcd(e, #E) = 1`，就可以算出 `t = e⁻¹ mod #E`，用 `t·(eG) = G` 直接把明文点乘回来，再取其 x 坐标转字节即得明文。麻烦只在两处——曲线是 twisted Edwards 形式、`#E` 要在 Weierstrass 模型上算，所以要用一组固定的双有理映射把参数与点在两个模型之间来回搬。

## 原理

- **为什么不需要解离散对数**：加密是标量乘 `C = e·G`，而曲线点的标量乘构成 `#E` 阶循环群（或它的子群）。若 `e` 在模 `#E` 下可逆，则 `t·C = t·e·G = (t·e mod #E)·G = G`。攻击者不掌握任何私钥，只需要 `#E`——这是公开可算的量（Schoof 等算法），于是"解密"退化为一次模逆加一次标量乘。
- **可逆性的判据**：`gcd(e, #E) == 1`。CTF 里 `e` 常取 `0x10001` 这类小素数，而 `#E` 是随机大数，冲突概率极低；但必须显式校验——若不互素，只能恢复 `G` 所在的子群分量，需要额外处理（见变体）。
- **为什么必须换模型**：Sage 的 `EllipticCurve` 只认 Weierstrass 形式，而题目给的是 twisted Edwards `a·x² + y² = 1 + d·x²·y²`。群阶只有在 Weierstrass 模型上才能直接 `E.order()` 得到；同一个群在不同模型下的阶相同，所以"映射 → 求阶 → 求逆 → 乘 → 映射回去"是合法闭环。
- **映射公式的来源**：先做缩放把 `c` 与常数项归一（`x1 = x/c`、`y1 = y/c`，曲线化为 `a·x²+y² = 1+d·x²y²`），再用分式线性变换把四次曲线化为三次：`x2 = (1+y1)/(1-y1)`、`y2 = x2/x1`，得到 `B·y² = x³ + A·x² + x`，其中 `A = 2(a+d)/(a-d)`、`B = 4/(a-d)`；最后按 Weierstrass 短形式配方 `x3 = (3x2 + A)/(3B)`、`y3 = y2/B`，系数为 `a_w = (3-A²)/(3B²)`、`b_w = (2A³-9A)/(27B³)`。反向只需把每一步解出来，公式在卡内 PoC 里给出。
- **x 坐标当明文的代价**：明文被塞进一个坐标后不再保证是"合法点"，因此题目只会取 x；反解时要记得 `long_to_bytes(int(G[0]))`，并注意 Sage 的 `F(x)` 元素要先 `int()` 再转字节，否则会带进制信息。

## 触发条件

- 题目给出非 Weierstrass 曲线（twisted Edwards / Hessian / Montgomery）的参数与一个点 `eG`，并给出整数 `e`。
- `e` 是公开的加密指数（不是私钥），且 `gcd(e, #E) == 1`。
- 明文就是点（或其某个坐标）本身，而不是"私钥 × 基点"之类需要解 DLP 的形式。
- 能用 Sage 计算 `EllipticCurve(...).order()`；曲线系数变换中出现的分母（`a-d`、`B`、`c`、`1-y1`、`x1`）在 `F_p` 上非零。

## 利用步骤

1. 识别模型：确认方程是 `a·x² + y² = c²(1 + d·x²·y²)`（带缩放常数 `c`），记下 `a`、`d`、`c`、`p` 与点 `eG`、指数 `e`。
2. 归一化：`dd = d·c⁴`、`A = 2(a+dd)/(a-dd)`、`B = 4/(a-dd)`，得到 `B·y² = x³ + A·x² + x`；再算 Weierstrass 系数 `a_w = (3-A²)/(3B²)`、`b_w = (2A³-9A)/(27B³)`。
3. 映射密文点：`x1 = x/c`、`y1 = y/c` → `x2 = (1+y1)/(1-y1)`、`y2 = x2/x1` → `x3 = (3x2+A)/(3B)`、`y3 = y2/B`；用 `E(x3, y3)` 构造点（构造失败说明公式或分母出错）。
4. `E = EllipticCurve(GF(p), [a_w, b_w])`；`order = E.order()`；断言 `gcd(e, order) == 1`。
5. `t = inverse(e, order)`；`G_w = t * eG_w`，再按第 3 步的逆变换映射回 twisted Edwards 模型。
6. 取 `G_edwards[0]`，`long_to_bytes(int(...))` 得明文；用 flag 格式校验。
7. 若第 3 步构造点失败或第 5 步得到无穷远点，优先检查 `a-d` 是否为 0（此时曲线退化，映射不成立）与 `y1 == 1` 的例外点。

## PoC

```python
from Crypto.Util.number import long_to_bytes

p  = ...          # 题目给的素模数
a, d, c = ..., ..., 1
e  = 0x10001
eG = (...)        # 题目给的密文点

F = GF(p)
dd = F(d * c**4)
A  = F(2) * F(a + dd) / F(a - dd)
B  = F(4) / F(a - dd)
aw = F(3 - A**2) / F(3 * B**2)
bw = F(2 * A**3 - 9 * A) / F(27 * B**3)

def edwards_to_weierstrass(x, y):
    x1 = F(x) / F(c); y1 = F(y) / F(c)          # a*x^2 + y^2 = 1 + dd*x^2*y^2
    x2 = F(1 + y1) / F(1 - y1)
    y2 = F(x2) / F(x1)                          # B*y^2 = x^3 + A*x^2 + x
    return ((F(3 * x2) + F(A)) / F(3 * B), F(y2) / F(B))

def weierstrass_to_edwards(x, y):
    x2 = (F(x) * F(3 * B) - F(A)) / F(3)
    y2 = F(y) * F(B)
    x1 = F(x2) / F(y2)
    y1 = F(1) - F(2) / F(x2 + 1)
    return (F(x1) * F(c), F(y1) * F(c))

E = EllipticCurve(GF(p), [aw, bw])
order = E.order()
assert gcd(e, int(order)) == 1
eG_w = E(edwards_to_weierstrass(eG[0], eG[1]))
G_w  = inverse(e, int(order)) * eG_w            # t·(eG) = G
G_ed = weierstrass_to_edwards(G_w[0], G_w[1])
print(long_to_bytes(int(G_ed[0])))
```

```text
判据只有一条：gcd(e, #E) == 1 → 求逆即可，无需 discrete_log。
顺序：换模型 → 求阶 → 模逆 → 标量乘 → 换回 → 取 x。
```

## 变体与关联

- **变体一（`e` 与阶不互素）**：`gcd(e, #E) = g > 1` 时只能恢复 `G` 在 `g`-部分的模糊解，需要枚举 `g` 个候选并用 flag 格式/二次校验筛选；实战中先 `factor(g)` 看清结构。
- **变体二（阶不光滑但确实需要 DLP）**：若加密形式是"私钥 × 基点"而 `e` 不可逆或未知，则要回到 DLP：光滑阶用 Pohlig–Hellman，见 [[crypto-ecc-twisted-edwards-small-scalar-pohlig-hellman-aes-cbc]]、[[crypto-ecc-twisted-hessian-curve-weierstrass-pohlig-hellman]]。
- **变体三（映射换成加法群同态）**：某些题的曲线加法等价于 `F_p(√D)` 的乘法，可直接映射到乘法群做 `discrete_log`，见 [[crypto-ecc-twisted-edwards-map-multiplicative-group-dlp]]。
- **变体四（求解阶的其他来源）**：`#E` 也可由题目直接给出，或用 `E.order()` 之外的 `cardinality()`/`order_from_multiple` 交叉验证；曲线若退化（判别式为 0）则群结构变成乘法群/加法群，映射失效。
- **关联**：[[crypto-ecc-twisted-hessian-curve-weierstrass-pohlig-hellman]]（同为"非 Weierstrass 模型 + 双有理映射到 Weierstrass"的骨架，但目标是把 ECDLP 交给 PH 分解；本条完全不解 DLP，只做指数求逆）、[[crypto-ecc-unknown-curve-point-halving-recover-flag]]（同样把明文塞进点坐标，但未知参数靠点减半恢复）。

## 检测与防御

- **对出题/协议设计方**：把点当密文且指数公开可逆，等价于不加密——只能当"编码"用。若真要保密，必须用 ECIES 一类带随机数与 KDF 的方案，或至少让指数私密、并把明文先映射到随机化后的点。
- **实现侧**：Edwards→Weierstrass 的映射存在例外点（分母为 0），实现要显式拒绝退化输入；曲线参数需校验 `a ≠ d`、`c ≠ 0`，并验证已知点在曲线上（`a·x²+y² == c²(1+d·x²y²)`）。
- **检测信号**：协议里出现"公开指数 + 点密文 + 无随机数"的组合；`e` 与 `#E` 的 gcd 恒为 1 的固定小指数（如 `0x10001`）；同一明文重复加密得到完全相同的点（确定性加密）。
- **修复**：改用标准 ECC 加密原语；若只是要"把数据编码到曲线点"，明确其安全性来自后续的 KDF 而非曲线运算本身。
