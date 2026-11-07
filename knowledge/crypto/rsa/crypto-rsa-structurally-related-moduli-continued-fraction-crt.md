---
id: crypto-rsa-structurally-related-moduli-continued-fraction-crt
title: 结构相似双模数 RSA：N1/N2 连分数恢复小参数后 CRT 求 φ 或近似 d 解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-structurally-related-moduli-cf-parameter-recovery
aliases:
- CISCN 2022 东北赛区 math
- 结构相似 RSA
- N1/N2 连分数恢复 a2 k
- 近似 d 爆破
- bounded BSGS RSA
- 相关模数 RSA
tags:
- crypto
- rsa
- continued-fraction
- related-moduli
- crt
- approximate-private-exponent
- lll
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T13:48:42+08:00'
  notes: 已对照原文与3张公式图核对：N1/N2≈a2/k、连分数收敛子筛选、CRT求φ(N1)、近似d路径与 exp1/exp2 一致；bounded BSGS/LLL/Coppersmith 为原文拓展。已修正原卡中“误差2^-511~2^-512 小于2^-513”的自相矛盾表述，改为按原文陈述并注明以收敛子枚举/解密验证为准。PoC 未复跑；无 sources/source_url；affected_versions 未设置（CTF 题，无组件版本）。
---

## 一句话结论

当同一 RSA 公钥指数 `e` 下使用两个结构相似的模数 `N1≈a1·b1·a2·b2`、`N2≈a1·b2·k·b1`（共享 `a1,b1,b2`，`a2,k` 各约 256 bit）加密同一明文时，`N1/N2≈a2/k`，对 `N1/N2` 做连分数展开即可从收敛子中恢复 `a2,k`；随后可用 CRT 拼出 `φ(N1)` 的同余式并小范围爆破 `p+q` 分解 `N1`，或直接用 `d mod (a2·k)` 与近似私钥 `_d` 恢复 `d`，最终解密。

## 原理

- **密钥生成留下结构关系**。题目中 `n1=a1·b1+1`、`n2=a2·b2+1`、`N1=n1·n2`；`n3=a1·b2+1`、`v2=k·b1+1`、`N2=n3·v2`。展开后 `N1≈a1·b1·a2·b2`、`N2≈a1·b2·k·b1`，两者共享 `a1,b1,b2`，因此 `N1/N2≈a2/k`。
- **连分数逼近成立的条件**。若既约分数 `p/q` 满足 `|x - p/q| < 1/(2q²)`，则 `p/q` 必是 `x` 的某个收敛子（Legendre 定理）。本题 `a2,k` 约 256 bit，`q≈2^256`，`1/(2q²)≈2^-513`；原文称误差约 `2^-511` 到 `2^-512` 并判定满足该临界条件（原文未给出更细的误差推导），实际能否命中以收敛子枚举与后续解密验证为准。
- **候选筛选**。对 `N1/N2` 做连分数展开，枚举收敛子 `p/q`，保留分子、分母均约 256 bit 且互素的候选；可能有不止一组，后续步骤会自然筛掉错误候选。
- **收尾路径 A：CRT 求 φ(N1)**。由 `φ(N1)=a1·b1·a2·b2` 得 `φ(N1)≡0 (mod a2)`；由 `e·d-1=k·φ(N1)` 得 `k·φ(N1)≡-1 (mod e)`，即 `φ(N1)≡-k^{-1} (mod e)`。两式 CRT 得 `φ(N1)≡φ0 (mod a2·e)`（要求 `gcd(a2,e)=1`；否则模数为 `lcm`）。
- **为什么能定位 φ**。`φ(N1)=N1-(n1+n2)+1`，`n1,n2` 各约 512 bit，故 `φ` 与 `N1` 的差约 513 bit；而 `a2·e` 约 512 bit。于是 `φ = floor(N1/M)·M + i·M + φ0`，`i` 只需在很小范围（如 -10..10）枚举。
- **分解验证**。对每个候选 `φ` 令 `s=N1-φ+1=p+q`，判别式 `s²-4N1` 为完全平方即得到 `p,q`；再 `d=e^{-1} mod φ` 解密。
- **收尾路径 B：直接近似 d**。由 `d≡e^{-1} (mod a2·k)` 得 `d0=inva2k`；用 `φ≈N1+1` 估计 `_d=(k(N1+1)+1)/e`。真实误差 `x=_d-d=k(n1+n2)/e` 约 512 bit，且 `x≡_d-inva2k (mod a2·k)`，故 `x=((_d-inva2k) mod (a2·k))+t·a2·k`，`t` 很小，枚举 `t` 后 `d=_d-x` 即可解密，无需分解 `N1`。
- **扩展：bounded BSGS**。若 `t` 的搜索空间变大，可由 `g^{ed}≡g (mod N1)` 与 `d=inva2k+t·a2k` 得 `(g^{e·a2k})^t≡g^{1-e·inva2k} (mod N1)`，把线性枚举转为已知上界的离散对数，用 bounded BSGS 把 `O(B)` 降到 `O(√B)`。
- **等价路线**：第一步也可用 LLL 解小关系 `N1·k-N2·a2≈0`（需按数量级缩放）；收尾也可用“爆破少量高位 + Coppersmith”恢复 `q`，但边界较紧、稳定性不如主线。

## 触发条件

- 两个约 1024 bit 的 RSA 模数 `N1,N2` 使用同一 `e` 加密同一明文，且由共享小因子/小参数生成。
- 生成参数满足 `2·dbit < nbit`（如 256 bit vs 1024 bit），使 `N1/N2` 的有理逼近误差落在 `1/(2q²)` 内。
- 能拿到生成脚本或从题面推断结构；知道 `a2,k` 的大致位宽。
- 需要 `gcd(a2,e)=1`（CRT 路径）与可枚举的 `i`/`t` 范围；通常题目参数保证范围很小。

## 利用步骤

1. 计算 `N1/N2` 的连分数展开与全部收敛子。
2. 过滤分子/分母位宽约 256 bit 且互素的收敛子，得到候选 `(a2,k)`。
3. 对每个候选走路径 A：
   - `inve=inverse(k,e)`，`φ0=CRT([a2,e],[0,-inve mod e])`，`M=a2*e`。
   - 对 `i` 在 `-10..10` 枚举 `φ=(N1//M)*M+i*M+φ0`；令 `s=N1-φ+1`，检查 `s²-4N1` 是否完全平方。
   - 命中后 `p,q=(s±√Δ)/2`，`d=inverse(e,(p-1)(q-1))`，`m=pow(c1,d,N1)`。
4. 或走路径 B：`inva2k=inverse(e,a2*k)`，`_d=(k*(N1+1)+1)//e`；枚举 `i` 使 `x=((_d-inva2k) mod (a2*k))+i*a2*k`，`d=_d-x`，解密并检查明文格式（如 `flag{`）。
5. 若 `t/i` 范围过大，改用 bounded BSGS 或 LLL/Coppersmith 路线。
6. 用解出的明文验证 flag/格式；错误候选会在判别式或明文检查处被淘汰。

## PoC

```python
from math import gcd, isqrt
from Crypto.Util.number import inverse, long_to_bytes
from sympy.ntheory.modular import crt

# e, N1, N2, c1 为题目公开值（此处省略长整数，按实际题目填入）
def cf_convergents(num, den):
    # 返回 N1/N2 的所有收敛子 (p, q)
    terms, out = [], []
    while num != 1:
        q = num // den
        terms.append(q)
        num, den = den, num % den
    out.append((terms[0], 1))
    for i in range(1, len(terms)):
        p, q = terms[i], 1
        for j in range(i):
            p, q = q + p * terms[i - j - 1], p
        out.append((p, q))
    return out

for a2, k in cf_convergents(N1, N2):
    if a2.bit_length() != 256 or k.bit_length() != 256 or gcd(a2, k) != 1:
        continue
    # 路径 A：CRT 求 phi
    inve = inverse(k, e)
    phi0 = int(crt([a2, e], [0, (-inve) % e])[0])
    M = a2 * e
    for i in range(-10, 11):
        phi = (N1 // M) * M + i * M + phi0
        s = N1 - phi + 1
        delta = s * s - 4 * N1
        if delta <= 0:
            continue
        t = isqrt(delta)
        if t * t == delta:
            p, q = (s + t) // 2, (s - t) // 2
            d = inverse(e, (p - 1) * (q - 1))
            print(long_to_bytes(pow(c1, d, N1)))
```

```python
# 路径 B：直接近似 d（同一 (a2,k)）
inva2k = inverse(e, a2 * k)
_d = (k * (N1 + 1) + 1) // e
for i in range(10):
    x = ((_d - inva2k) % (a2 * k)) + i * a2 * k
    d = _d - x
    pt = long_to_bytes(pow(c1, d, N1))
    if b"flag" in pt:
        print(pt)
```

说明：原文在 CISCN 2022 东北赛区 math 题上两条路径均解出 flag；本卡未在本机复跑，长整数常量按题目实际值填入。

## 变体与关联

- **第一步变体**：连分数换成 LLL，构造 `N1·k - N2·a2` 的小量关系并缩放各维数量级；容错性更高但计算更重。
- **收尾变体**：CRT 求 φ -> 二次方程分解；直接近似 d；bounded BSGS；爆破高位 + Coppersmith；不同路径共享同一个 `(a2,k)`。
- **结构变体**：三个或更多相关模数、共享不同小因子、`N_i/N_j` 逼近其他小有理数；核心都是“结构泄漏 -> 近似有理关系 -> 恢复小参数 -> 分解/求 d”。
- **关联**：[[crypto-rsa-wiener-small-private-exponent-large-e]]（连分数恢复小 d 的经典形式）、[[crypto-rsa-continued-fraction-lambda-factorization]]（连分数恢复 λ(n)）、[[crypto-rsa-known-prime-sum-quadratic-factorization]]（已知 p+q 的二次分解）、[[crypto-rsa-boneh-durfee-small-private-exponent]]（格方法恢复小 d）、[[crypto-rsa-dual-rsa-lattice-small-d]]（共模多模数格攻击）。
- **边界**：`a2,k` 位宽不够小或误差超过 `1/(2q²)` 时，连分数收敛子不含目标；`gcd(a2,e)≠1` 时 CRT 模数需改为 `lcm`；`i/t` 范围过大时需 BSGS/格方法；错误候选会在判别式或明文检查处失败。

## 检测与防御

- **密钥生成**：RSA 素数必须独立随机生成，不同模数之间不得共享小因子或复用生成参数；使用标准库（OpenSSL 等）而不是自定义 `n=a*b+1` 结构。
- **部署检查**：对同一服务/租户的多张公钥做 `gcd(N_i,N_j)` 与比值连分数检查；发现 `N1/N2` 逼近小有理数、共享素因子或异常小参数时立即轮换密钥。
- **CTF/审计**：看到两个同 bit 长模数、同 `e`、同明文时，先算 `N1/N2` 连分数并筛 256-bit 收敛子；再按 CRT 或近似 d 收尾。
- **检测**：证书/密钥清单中出现相关模数、共享素因子或生成参数复用；批量 `gcd` 与连分数筛查可作为密钥卫生检查项。
