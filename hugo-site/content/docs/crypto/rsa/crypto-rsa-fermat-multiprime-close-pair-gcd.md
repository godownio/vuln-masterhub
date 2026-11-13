---
id: crypto-rsa-fermat-multiprime-close-pair-gcd
title: 四因子近邻素数模数 n=p·q·p1·q1：从 √n 平方差遍历找两组平衡分解，gcd 还原全部素因子
type: scenario
domain: crypto
path: crypto/rsa
technique: fermat-multiprime-balanced-pair-gcd
tags:
- rsa
- fermat
- factorization
- multiprime
- close-primes
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:12:32+08:00'
  notes: 已对照原文核对：四因子 n=p·q·p1·q1、两组平衡二因子分解 (p·q)(p1·q1) 与 (p·q1)(q·p1)、从 √n 平方差遍历收集两组解、交叉 gcd 还原素因子，与原文绿城杯 RSA2-PLUS 段一致。复算通过：p/q 随机 256 位、p1=next_prime(p)、q1=next_prime(q)，n 1022 位，fermat_pairs 690 步得到两组 511 位平衡分解，交叉 gcd 得到 4 个素数且乘积=n。dedup 与基础费马卡（两素数一次命中）及连续素数链卡（prevprime/nextprime 重建）不同，new 成立。原文无组件版本。
url: /docs/crypto/rsa/crypto-rsa-fermat-multiprime-close-pair-gcd/
draft: false
kb_aliases:
- 多因子费马分解
- p*q*p1*q1 分解
- 近邻素数对乘积分组
- 平方差遍历取两组解
- gcd 还原四因子
- 绿城杯 RSA2-PLUS
---

## 一句话结论

当模数由两对近邻素数构成 `n = p*q*p1*q1`（`p1=next_prime(p)`、`q1=next_prime(q)`）时，n 的 8 种二因子分解中有两组是"平衡"的——`(p*q)*(p1*q1)` 与 `(p*q1)*(q*p1)`，它们都紧邻 `√n`；从 `a=⌊√n⌋` 开始做平方差遍历 `a²-n=b²`，很快能得到这两组复合因子，再对它们两两求 `gcd` 即还原 `p, q, p1, q1`，完成 RSA 分解。

## 原理

- **四素数模数的多种二因子分解**：4 个素数可组成 8 种（无序）二因子分组，如 `(p, q·q1·p1)`、`(p·q, p1·q1)`、`(p·q1, q·p1)` 等。只有"每个因子各含两个素数"的两组乘积量级相近（都是 1024 位），因而靠近 `√n`（n 为 2048 位）；其余分组一小一大，离 `√n` 很远。
- **费马平方差仍然适用**：对任意分解 `n = A·B`，有 `A = a - b`、`B = a + b`，`a=(A+B)/2`、`b=(B-A)/2`，且 `a² - n = b²`。从 `a=⌊√n⌋` 自增，`A、B` 越接近，命中越快；本例两组平衡分解的 `A、B` 差仅由 `p` 与 `p1`、`q` 与 `q1` 的小间距决定，所以遍历步数很少。
- **为什么要收集两组解**：标准费马分解命中一组 `(A, B)` 就结束，但这里 `A、B` 是复合数（各含两个素数），不是最终因子。两组平衡解共享素数：`gcd(p*q, p*q1)=p`、`gcd(p*q, p*q1)=q1` 等，两两求 gcd（或与 `A/B` 对其他组合求 gcd）即可把四个素数全部拆出。只拿到一组时也可用 `gcd(A, n)` 分出其中的公共因子（若分组恰好是 `p·q` 与 `p1·q1`，`gcd(A,n)=p·q` 仍非素数，需要第二组或其它关系）。
- **与标准费马分解的差别**：标准场景 `n=p*q`、p/q 接近，命中一次即得两个素数；本场景 n 有 4 个素因子，费马只能给出"复合因子"，必须结合两组平衡解与 gcd 才能落到素因子。yafu 等通用工具可能返回任意一种分组（甚至非平衡分组），因此需要自己控制从 `√n` 出发的遍历。
- **8 组解中哪些可被遍历到**：从 `√n` 向两侧扫描时，先遇到的就是两组平衡分解；不平衡分组的 `a` 远大于 `√n`，在合理时间内不会被遍历到。这也是"从中间开始"而不是"从 0 开始"的意义。

## 触发条件

- RSA 模数由 4 个素数相乘，且素数成两对近邻（`p1=next_prime(p)`、`q1=next_prime(q)`，或类似小间距关系）。
- 攻击者知道/猜到这种结构（题目源码给出生成方式，或通过对 n 做小指数/结构分析发现可分解）。
- `n` 的位数在可计算范围（本例 2048 位），平方差遍历所需步数与素数对间距相关，近邻时可接受。
- 能运行 Sage/gmpy2 做大整数开方与完全平方判断。

## 利用步骤

1. 计算 `a = isqrt(n)`，从该值开始循环：令 `B2 = a² - n`，若 `B2` 是完全平方，则 `b = √B2`，得到一组分解 `A = a - b`、`B = a + b`（`A·B = n`）。
2. 记录该组解，继续 `a += 1` 寻找第二组平衡分解（两组解的间距通常很小）；若长时间无解，说明近邻假设不成立或需要换方法。
3. 对两组解 `{A1, B1}`、`{A2, B2}` 两两求 `gcd`：`gcd(A1, A2)`、`gcd(A1, B2)` 等，得到 `p`、`q`、`p1`、`q1` 中的素因子（或含两个素数的中间量，继续分解）。
4. 校验四个因子均为素数且乘积等于 n；若只得到两个复合因子，尝试 `gcd(A, n//A)` 或用分解出的素数重组。
5. 按多素数 RSA 计算 `φ(n) = ∏(prime_i - 1)`、`d = e⁻¹ mod φ(n)`，解密 `m = c^d mod n`。
6. 若题目实际是标准两素数 n，直接用同一遍历得到 `p、q` 即可（见基础费马卡）。

## PoC

```python
from gmpy2 import iroot, gcd
from Crypto.Util.number import long_to_bytes, isPrime

def fermat_pairs(n, max_steps=10**7):
    """从 sqrt(n) 向上遍历，收集平方差分解 (A, B)，A<=B。"""
    a = int(iroot(n, 2)[0])
    pairs = []
    for _ in range(max_steps):
        b2 = a*a - n
        if b2 >= 0:
            b, exact = iroot(b2, 2)
            if exact:
                pairs.append((a - int(b), a + int(b)))
                if len(pairs) >= 2:
                    break
        a += 1
    return pairs

pairs = fermat_pairs(n)          # n = p*q*p1*q1
factors = set()
for i in range(len(pairs)):
    for j in range(i + 1, len(pairs)):
        for u in pairs[i]:
            for v in pairs[j]:
                g = int(gcd(u, v))
                if 1 < g < n:
                    factors.add(g)

# 若得到的是复合因子（例如 p*q），再与 n 的其它因子求 gcd 继续拆分
factors = {f for f in factors if isPrime(f)}   # 如未全为素数，需继续 gcd/分解
assert sorted(factors) and n == __import__('math').prod(factors)
phi = 1
for f in factors:
    phi *= (f - 1)
d = pow(e, -1, phi)
print(long_to_bytes(int(pow(c, d, n))))
```

## 变体与关联

- **基础费马分解**：`n=p*q` 且 p、q 由 next_prime 生成时只需一次命中，见 `[[crypto-rsa-fermat-close-prime-factorization]]`；本卡是其多因子扩展。
- **素数链模数**：17 个相邻素数之积的结构见 `[[crypto-rsa-consecutive-prime-chain-nextprime-product]]`，靠 prevprime/nextprime 重建链，与本卡的平衡分解思路不同。
- **更多因子/更多近邻对**：`n` 含 2k 个素数、每对近邻时，从 √n 可先遇到多组平衡分解，用两两 gcd 逐步还原；若分组不对称，可枚举分组或结合已知关系。
- **边界**：若近邻对间距较大（next_prime 多次跳号、素数对随机），遍历步数会平方级增长；若 yafu 已直接返回素因子则无需本方法。

## 检测与防御

- **生成侧**：RSA 素数必须独立随机生成，禁止 `next_prime` 链或成对近邻结构；多素数 RSA 也要求因子随机且量级分散。
- **密钥检测**：对 n 做费马分解预检（从 √n 少量迭代）可发现近邻素数模数；对多因子 n，检查是否存在多个平衡二因子分解。
- **参数建议**：使用标准库生成的 2048/4096 位 RSA，因子间距足够大；避免为了"多素数加速"而引入可预测结构。
