---
id: crypto-rsa-franklin-reiter-affine-related-message
title: Franklin-Reiter 相关明文攻击：同一模数下仿射相关明文的 RSA 多项式 GCD
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-franklin-reiter-related-message
aliases:
- Franklin-Reiter
- 相关消息攻击
- related message attack
- 仿射相关明文
- 多项式 GCD
tags:
- rsa
- related-message
- franklin-reiter
- polynomial-gcd
- coppersmith
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:18+08:00'
  notes: 已对照原文核对：m2≡a·m1+b 时对 x^e-c1 与 (a*x+b)^e-c2 求模 n 多项式 GCD、取首一一次式常数项取负得 m1，与原文代码一致；原文对非线性(异或)关系仅一句带过，卡片已标为未给完整解法。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

同一 RSA 模数 `n` 与指数 `e` 下加密了两个满足已知仿射关系 `m2 ≡ a*m1 + b (mod n)` 的明文时，无需私钥，直接对 `x^e - c1` 与 `(a*x+b)^e - c2` 在 `Z_n` 上求多项式 GCD，即可得到一次因子 `x - m1`，恢复 `m1`。

## 原理

- 两个密文分别为 `c1 ≡ m1^e (mod n)`、`c2 ≡ m2^e (mod n)`，且 `m2 ≡ a*m1 + b (mod n)`。
- 构造两个多项式 `f1(x) = x^e - c1` 与 `f2(x) = (a*x + b)^e - c2`，它们都把 `x = m1` 作为模 `n` 的根：`f1(m1) ≡ 0`，`f2(m1) = (a*m1+b)^e - c2 ≡ m2^e - c2 ≡ 0`。
- 因此 `x - m1` 同时整除 `f1` 与 `f2`（在模 `n` 的多项式环中），两者的最大公因式至少包含这个一次因子。`e` 较小时（常见 3、5），用欧几里得算法求 GCD 的代价很低。
- GCD 归一化为首一多项式后，若结果恰为一次式 `x - m1`，其常数项就是 `-m1`，取负即得明文。
- 成立前提是 GCD 过程中出现的首项系数在模 `n` 下可逆；若不可逆，`gcd(首项系数, n)` 往往直接给出 `n` 的因子，反而可以分解模数。

## 触发条件

- 同一 `(n, e)` 下加密了两条或更多明文，且明文之间存在已知的线性/仿射关系。
- 公钥指数 `e` 较小（3、5 等）或关系多项式次数不高，GCD 计算可行。
- 攻击者已知 `a`、`b`、`c1`、`c2`、`n`、`e`。
- 明文没有随机化填充，或填充后的关系仍然已知/可写成低次多项式。

## 利用步骤

1. 确认两条密文使用同一模数与指数，且 `m2 = a*m1 + b` 中的 `a,b` 已知。
2. 在 Sage 中建立 `PolynomialRing(Zmod(n))`，构造 `g1 = x^e - c1`、`g2 = (a*x + b)^e - c2`。
3. 对 `g1,g2` 做多项式欧几里得算法并归一化为首一多项式，得到 GCD。
4. 若 GCD 为一次式，取常数项相反数得到 `m1`；用 `pow(m1,e,n)==c1` 与关系式回代校验。
5. 若 GCD 不是一次式或计算中遇到不可逆系数，检查 `gcd(系数, n)` 是否给出因子，或改用结式/Coppersmith 方法。

## PoC

```python
from gmpy2 import *
from Crypto.Util.number import *

n = ...
a = ...
b = ...
c1 = ...
c2 = ...
e = 5

def attack(c1, c2, a, b, e, n):
    PR.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (a*x + b)^e - c2

    def gcd_poly(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    g = gcd_poly(g1, g2)
    print(g)
    return -g[0]

m1 = attack(c1, c2, a, b, e, n)
flag = long_to_bytes(int(m1))
print(flag)
```

## 变体与关联

- 变体：关系为 `m2 = a*m1 + b` 的仿射形式；`a=1` 时退化为已知固定差值 `m2 = m1 + b`。
- 变体：两条以上密文、同一明文的多项式变换，可推广为多元结式或 Coppersmith 求小根。
- 变体：非线性关系（例如 XOR）不能直接套用线性 GCD，需要按具体关系构造多项式或枚举比特；原文仅提及该方向，未给出完整解法。
- 关联：[[crypto-rsa-affine-broadcast-crt-coppersmith]]（同一明文在多个模数下的仿射广播）、[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]（已知明文部分比特的 Coppersmith 求根）。

## 检测与防御

- 防御：使用 OAEP 等随机化填充，使相同明文每次加密结果不同，相关明文关系不再以明文形式成立。
- 防御：不要在同一密钥下加密存在已知代数关系的消息；需要加密多条相关数据时使用独立随机盐或混合加密。
- 检测：审计中出现同一 `n` 下多条密文、明文间存在线性关系、或 `e` 很小且无填充；CTF 中看到 `m2 = a*m1 + b` 与两组密文即可按本卡求解。
- 响应：确认相关明文泄露后轮换密钥，并检查同模数下的其他密文是否可被同样恢复。
