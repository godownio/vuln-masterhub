---
id: crypto-rsa-hint-difference-gcd-factorization
title: RSA hint 值差值 GCD 分解：多组提示同余于同一素因子时直接取公因子
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-hint-difference-gcd-factorization
aliases:
- 小蓝鲨的费马谜题
- Hint 分解
- gcd(s1-s2, n)
- 修改版费马分解
- 提示值公因子
- RSA 多 hint
tags:
- crypto
- rsa
- factorization
- gcd
- fermat
- hint-leak
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:27:52+08:00'
  notes: 已对照原文小蓝鲨的费马谜题核对：正则提取 Hint 三元组、两两 gcd(abs(si-sj),N)、索引 12/17 命中 309 位因子、常规 RSA 解密与 flag 一致；同余解释为合理归纳，未复跑
---

## 一句话结论

题目给出多组 `(a_i, b_i, s_i)` 提示时，若这些 `s_i` 都同余于同一个素因子（例如都满足 `s_i ≡ r (mod p)`），则任意两组之差 `s_i - s_j` 都是 p 的倍数，直接计算 `gcd(|s_i - s_j|, N)` 即可恢复 p，随后按常规 RSA 求 d 解密。

## 原理

- **同余产生公因子**：设 N=pq，若所有提示值满足 `s_i ≡ r (mod p)`（同一残差 r），则 `s_i - s_j ≡ 0 (mod p)`，即 p 整除每一对差值。
- **GCD 提取**：`gcd(|s_i - s_j|, N)` 在理想情况下等于 p（或 q）；若得到 1，说明该对提示不同余或差值不含因子；若得到 N，说明差值同时是 p、q 的倍数，需要换一对。
- **与费马分解的关系**：经典费马分解利用 `a² - N = b²` 的平方差；本题是“提示值同余”的推广——只要提示值共享某个模 p 的不变量，差值就携带 p 的倍数，GCD 即可分解。
- **批量形式**：有多组提示时，可对所有配对做 GCD，或先计算相邻差值/乘积树做批量 GCD；命中后立即用 `q=N//p` 验证。
- **后续**：恢复 p、q 后计算 `φ=(p-1)(q-1)`、`d=e^{-1} mod φ`，`m=c^d mod N`；若明文小于较小因子，也可用 `d_r=e^{-1} mod (r-1)` 简化。

## 触发条件

- RSA 模数 N 与多组提示值 `s_i` 一并泄露；提示值由同一秘密因子派生，且共享模 p（或 q）的残差。
- 至少两组有效提示；提示数量越多，命中概率越高。
- 提示值未被随机噪声破坏（若有噪声需用近似 GCD/格方法）。
- 已知 e 与密文 c，拿到因子后可正常解密。

## 利用步骤

1. 从 output.txt/附件中用正则提取所有 `Hint i: a, b, s` 三元组。
2. 对所有提示对计算 `g = gcd(abs(s_i - s_j), N)`。
3. 检查 `1 < g < N` 且 `N % g == 0`；命中即得到 p（或 q）。
4. 令 `q = N // g`，计算 `φ=(p-1)(q-1)`、`d=e^{-1} mod φ`。
5. `m = c^d mod N`，`long_to_bytes(m)` 得到 flag；若失败，换其他提示对或先做批量 GCD。
6. 若差值 GCD 全为 1/N，检查提示公式是否应使用和、积或带符号组合。

## PoC

```python
from itertools import combinations
from math import gcd
import re
from Crypto.Util.number import long_to_bytes, inverse

txt = open("output.txt").read()
hint_re = re.compile(r"Hint \d+:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)")
hints = [(int(m.group(1)), int(m.group(2)), int(m.group(3)))
         for m in hint_re.finditer(txt)]

def find_factor_from_hints(hints):
    for (i, (a1, b1, s1)), (j, (a2, b2, s2)) in combinations(list(enumerate(hints)), 2):
        g = gcd(abs(s1 - s2), n)
        if g != 1 and g != n:
            return i, j, g
    return None

i, j, p = find_factor_from_hints(hints)
q = n // p
d = inverse(e, (p - 1) * (q - 1))
print(long_to_bytes(pow(c, d, n)).decode())
```

原文在 18 组 hint 中由第 12、17 组差值得到 309 位因子 p，解密出：

```text
ISCTF{M0dIFi3D_f3RM47_7H30r3m_I5_fUn_8U7_h4rD3r!}
```

## 变体与关联

- 组合方式变体：若提示满足 `s_i ≡ -r (mod p)`，则用 `s_i + s_j`；若提示带系数，先做线性组合再取 GCD。
- 噪声变体：提示值有随机误差时，`s_i - s_j` 不再是 p 的精确倍数，需用近似 GCD（AGCD）或格方法；见 [[ctf-crypto-agcd-sda-lattice-small-error-recovery]]。
- 关联：[[crypto-rsa-fermat-close-prime-factorization]]（经典平方差）、[[crypto-rsa-shared-prime-batch-gcd]]（多模数共享素因子）。
- 边界：提示值与 N 的因子无同余关系、或提示数量不足/全部被噪声污染时，GCD 路线失效。

## 检测与防御

- 检测：CTF 中 output 含大量 `Hint i: a,b,s`；对提示两两做 GCD 是否出现非平凡因子。
- 防御：不要向不可信方泄露同一秘密因子的多组派生值；密钥生成使用随机大素数，避免结构化提示。
- 加固：若业务必须提供 hint，加入随机化/盲化并限制查询次数；定期轮换密钥。
