---
id: crypto-rsa-cm-factorization-hilbert-class-polynomial
title: 合数 CM 分解：Hilbert 类多项式构造 CM 椭圆曲线，除法多项式范数 gcd 取因子
type: scenario
domain: crypto
path: crypto/rsa
technique: cm-factorization-hilbert-class-polynomial
tags:
- crypto
- rsa
- factorization
- cm-method
- elliptic-curve
- hilbert-class-polynomial
- sage
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:27:31+08:00'
  notes: 已对照原文小蓝鲨的后门核对：D=427、hilbert_class_polynomial(-D)、商环求 a、E:y²=x³+3ac²x+2ac³、division_polynomial(N) 取范数 gcd、c=1,u=1 命中及 flag 与原文一致；kronecker(-D,N)=-1 候选 [35,91,123,187,427] 一致；完整脚本未复跑
url: /docs/crypto/rsa/crypto-rsa-cm-factorization-hilbert-class-polynomial/
draft: false
kb_aliases:
- CM 分解
- CM factorization
- Hilbert class polynomial
- 虚二次域判别式 D
- division_polynomial
- 小蓝鲨的后门
---

## 一句话结论

对常规分解方法（试除、费马、Pollard p-1）无效的大合数 N，可选用虚二次域判别式 `-D` 构造 Hilbert 类多项式，在 `Z_N[x]/(H_D)` 商环上得到 CM 椭圆曲线；对随机点计算 N 次除法多项式并取其范数，与 N 求 gcd 即可以较高概率得到非平凡因子，D 可用 `kronecker(-D, N) = -1` 预筛。

## 原理

- **CM 曲线**：虚二次域 `Q(sqrt(-D))` 的 Hilbert 类多项式 `H_D(x)` 的根是 j-不变量，对应具有复乘（CM）的椭圆曲线。把 `H_D` 模 N 取商环 `Q = Z_N[x]/(H_D(x))`，在 Q 上取 j，令 `a = j * (1728 - j)^{-1}`，可构造一族 CM 曲线 `E: y² = x³ + 3ac²x + 2ac³`。
- **除法多项式**：椭圆曲线的 N 次除法多项式 `ψ_N(P)` 的零点对应 N-挠点；在 CM 曲线上，`ψ_N` 的范数 `Norm(ψ_N(u))` 与 N 的因子存在非平凡公因子的概率较高（算法来自 CM 分解/CM-ECM 类方法）。
- **取因子**：对随机 u 计算 `w = ψ_N(u)`，`r = gcd(Norm(w), N)`；若 `1 < r < N` 即分解成功，随后 `q = N // r`，按标准 RSA 求 d 解密。
- **商环中的“不可逆”也是因子**：计算 `(1728 - j)^{-1}` 或多项式 xgcd 时若行列式与 N 不互素，`gcd(det, N)` 直接给出 N 的因子，应作为成功分支处理，而不是只抛异常。
- **D 的选择**：不是所有 D 都可行；先用 `kronecker(-D, N) == -1` 筛候选（示例 [35, 91, 123, 187, 427]），再按类多项式次数/计算时间枚举。D 的类数越小，Hilbert 类多项式次数越低、计算越快。
- **为什么成立**：CM 曲线的自同态结构使除法多项式在模 N 下出现“部分因子归零”的现象，范数把这些分量乘在一起，gcd 就把落在某个素因子域上的零因子提取出来；本质是一种利用椭圆曲线挠点的分解算法。

## 触发条件

- 目标是一个大合数 N（通常是 RSA 模数），常规分解方法不可行或超时。
- 可用的 SageMath 环境（`hilbert_class_polynomial`、`EllipticCurve`、`division_polynomial`、商环）。
- 能找到合适的判别式 -D：`kronecker(-D, N) = -1` 且类数/次数在可计算范围内。
- 有足够时间/内存构造商环并做若干次 (c, u) 尝试（示例 ctries=10、utries=10）。

## 利用步骤

1. 准备 SageMath 环境，输入 N、e、c 与候选判别式集合。
2. 用 `kronecker(-D, N)` 预筛 D；示例候选为 [35, 91, 123, 187, 427]，原题 427 可行。
3. 计算 `H_D = hilbert_class_polynomial(-D)`，在 `Z_N[x]` 中构造商环 `Q = Z_N[x]/(H_D)`。
4. 计算 `a = j*(1728-j)^{-1}`；若求逆失败，取 `gcd(det, N)` 作为因子。
5. 对 c=1..ctries、u=1..utries 枚举：构造 `E: y²=x³+3ac²x+2ac³`，随机取 u，算 `w = E.division_polynomial(N, u)`，`r = gcd(int(w.norm()), N)`。
6. 若 `1 < r < N`，令 `q = N//r`，求 `d = e^{-1} mod φ(N)`，解密 c 得到明文/flag。
7. 若所有尝试失败，换 D 或增大 ctries/utries；记录耗时以评估是否可行。

## PoC

核心思路（完整脚本较长，以下为最小结构）：

```python
from sage.all import *

D = 427
N = Integer(N)
Hx = hilbert_class_polynomial(-D)

R.<x> = PolynomialRing(Integers(N))
Q.<j> = QuotientRing(R, R.ideal(R(Hx)))

a = j * (1728 - j)^(-1)
E = EllipticCurve(Q, [0, 0, 0, 3*a, 2*a])

u = Q(Integers(N).random_element())
w = E.division_polynomial(N, u, two_torsion_multiplicity=0)
r = gcd(int(w.norm()), N)

if 1 < r < N:
    q = N // r
    d = inverse_mod(e, (r - 1) * (q - 1))
    print(long_to_bytes(int(pow(c, d, N))))
```

原文完整脚本对 D=427、ctries=10、utries=10 在 c=1,u=1 即得到非平凡因子，最终解密出：

```text
ISCTF{You_have_an_extraordinary_talent_in_cryptography!_But_do_you_understand_number_theory_well_enough?}
```

## 变体与关联

- D/曲线族变体：不同 -D 的类数、Hilbert 类多项式次数不同；曲线系数中的 c 是 twist 参数，可枚举。
- 失败分支：商环元素不可逆时直接 `gcd` 取因子；多项式 xgcd 的首项系数 gcd 也可能泄露因子。
- 关联：[[crypto-rsa-fermat-close-prime-factorization]]（近邻素数）、[[crypto-rsa-pollard-pminus1-smooth-prime]]（p-1 光滑）、[[crypto-rsa-williams-p-plus-1-smooth-factor]]（p+1 光滑）；CM 分解适用于这些方法均失败且存在合适 D 的场景。
- 边界：D 的类数过大时 Hilbert 类多项式计算不可行；N 的素因子过小应优先试除/ECM；实现错误（未处理不可逆）会漏掉因子。

## 检测与防御

- 检测：CTF 中 N 很大但常规分解无果、题目给出特殊曲线/判别式提示；脚本运行时间与 D 的类数相关。
- 防御：使用标准随机大素数生成 RSA 模数（2048 bit 以上），避免可被 ECM/CM 类算法快速分解的弱模数；不要复用挑战生成器。
- 加固：密钥生成后做素性/结构检查；限制调试接口泄漏 N 的特殊形式；定期轮换密钥。
