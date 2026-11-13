---
id: crypto-rsa-consecutive-prime-chain-nextprime-product
title: RSA 连续素数链模数：n 为 17 个相邻素数之积，已知链中一个素数用 prevprime/nextprime 双向还原
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-consecutive-prime-chain-nextprime-product
tags:
- crypto
- rsa
- ctf
- nextprime
- prevprime
- multiprime
- euler-phi
- prime-chain
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:23:04+08:00'
  notes: 已对照原文并独立复算：按 P_p=P[9] 用 sympy.prevprime/nextprime 双向重建 17 个相邻素数（全部为素数且严格递增，P[0] 128 位），n=∏P[i] 为 2164 位、φ_n=∏(P[i]-1) 同位数，d1=invert(65537,φ_n)，p=nextprime(pow(P_factor,d1,n)) 得 1024 位素数；q=nextprime(pow(sub_Q,Q_2,Q_1)) 亦为 1024 位；最终 RSA 解密得到明文 MRCTF{sti11_@_b@by_qu3st10n}（原文注释写作 flag{...} 漏了 MRCTF 前缀，卡片已按复算结果修正并注明）。卡片的多素数欧拉函数、p<n 前提、q 分支、边界与防御描述均成立。10 张图片全部 Read（img_small 已补全），图片为文章后四题（多文件型、base64 隐写、pem 共模、加解密文件）的截图，与连续素数链卡无冲突。dedup Top 候选（ed-1 位长 k/prevprime、十进制逆序 nextprime、多素数立方提示、素数模数、完全平方模数、结构化素数 etc.）均为不同素数生成结构，全部 related，本卡链式还原不重复。affected_versions 空、cve 空合理。未验证点：无（数值已复算）。
url: /docs/crypto/rsa/crypto-rsa-consecutive-prime-chain-nextprime-product/
draft: false
kb_aliases:
- 连续素数链
- 相邻素数乘积模数
- prevprime nextprime 递推
- P_p P_factor
- 多素数欧拉函数
- nextprime 链还原
---

## 一句话结论

当题目把 RSA 中间模数构造成“相邻素数链”的乘积（`P[0]=getPrime(128)`、`P[i]=sympy.nextprime(P[i-1])`、`n=∏P[i]`），并只泄漏链中某一个素数 `P[k]` 与 `factor = p^e mod n` 时，由于相邻素数唯一，可用 `prevprime/nextprime` 双向重建整条链；再按多素数 RSA 求 `φ(n)=∏(P[i]-1)` 与 `d1 = e^{-1} mod φ(n)`，即可从 `factor` 还原出真正的 RSA 素数 `p = nextprime(factor^{d1} mod n)`。

## 原理

- **题目构造**：`gen_p()` 先取 128 位素数 `P[0]`，再对它反复取下一个素数得到 17 个连续素数 `P[0..16]`；把 17 个素数相乘得到中间模数 `n`；另取 1024 位随机素数 `p`，输出 `P[9]` 与 `factor = p^e mod n`，最终 RSA 使用的 `p' = nextprime(p)`。
- **可逆的关键**：`nextprime` 是确定性函数且相邻素数之间不存在其他素数，所以“链中任意一个元素”都能唯一确定整条链——向前用 `prevprime`、向后用 `nextprime` 递推即可。题目只给 `P[9]` 也足够（本题实际给的是 P_p=P[9]）。
- **多素数欧拉函数**：`n` 是 17 个互异素数之积，`φ(n) = ∏(P[i]-1)`。只要 `gcd(e, φ(n)) = 1`，就能求 `d1 = e^{-1} mod φ(n)`；由欧拉定理，`(p^e)^{d1} ≡ p (mod n)`（`p` 为素数且远小于 `n`，与 `n` 互素）。
- **还原 p**：`p` 是 1024 位、`n` 约 17×128≈2176 位，故 `p < n`，模运算结果就是 `p` 本身；题目最终返回的是 `nextprime(p)`，所以 `p' = sympy.nextprime(pow(factor, d1, n))`。
- **q 的分支**：另一分支 `q = nextprime(sub_Q^{Q_2} mod Q_1)`，其中 `sub_Q`、`Q_1`、`Q_2` 全部已知，可直接计算后取 `nextprime`。
- **本质**：这不是 RSA 数学被攻破，而是“密钥材料的生成方式可预测”——用可推导的素数序列当模数因子，等同于把因子信息泄漏给攻击者。

## 触发条件

- 题目给出连续素数链乘积得到的模数 `n`（或给出 `factor` 与 `n`），且链中至少一个素数可见；
- `e` 与 `φ(n)` 互素（本题 e=65537 满足）；
- 链的递推规则已知（`nextprime` 逐次取下一个素数）。

## 利用步骤

1. 从题目输出取得链中已知元素（如 `P_p = P[9]`）。
2. 用 `sympy.prevprime` 向前还原 `P[8]..P[0]`，用 `sympy.nextprime` 向后还原 `P[10]..P[16]`。
3. 计算 `n = ∏P[i]` 与 `φ_n = ∏(P[i]-1)`，求 `d1 = gmpy2.invert(e, φ_n)`。
4. 计算 `p = sympy.nextprime(pow(P_factor, d1, n))`；`q = sympy.nextprime(pow(sub_Q, Q_2, Q_1))`。
5. 按常规 RSA（`φ=(p-1)(q-1)`、`d=e^{-1} mod φ`）解密密文得到 flag。

## PoC

```python
import sympy, gmpy2
from Crypto.Util.number import long_to_bytes

base = 65537
P_p = 206027926847308612719677572554991143421          # P[9]
P_factor = <题目给出的 pow(p, base, n)>
Q_1, Q_2, sub_Q = <题目给出的三个大数>
c = <密文>

P = [0] * 17
P[9] = P_p
for i in range(9, 0, -1):        # 9..1
    P[i - 1] = sympy.prevprime(P[i])
for i in range(9, 16):           # 9..15
    P[i + 1] = sympy.nextprime(P[i])

n = 1
phi_n = 1
for i in range(17):
    n *= P[i]
    phi_n *= (P[i] - 1)

d1 = gmpy2.invert(base, phi_n)
p = sympy.nextprime(pow(P_factor, d1, n))
q = sympy.nextprime(pow(sub_Q, Q_2, Q_1))
phi = (p - 1) * (q - 1)
d = gmpy2.invert(base, phi)
m = pow(c, d, p * q)
print(long_to_bytes(m))
```

按原文给定数值复算（P 链重建→φ_n→d1→p/q→RSA 解密）成功，明文为 `MRCTF{sti11_@_b@by_qu3st10n}`（原文注释写作 `flag{sti11_@_b@by_qu3st10n}`，漏了 MRCTF 前缀；n 实际 2164 位、p/q 各 1024 位、p·q 2047 位，与卡片描述相符）。

## 变体与关联

- **变体**：链元素可能给出不止一个（多个 `P[k]` 输出），可直接交叉验证；也可能只给出 `n` 与“链起点范围”，需要按位长枚举候选起点。
- **关联卡**：`nextprime` 生成 `p` 的其他题型见 [[crypto-rsa-permutation-count-nextprime]]；相邻素数近邻导致的 Fermat/开方分解见 [[crypto-rsa-fermat-close-prime-factorization]]；多素数模数的其它攻击面可参考 `crypto-rsa-common-private-exponent-multiprime-lattice`。
- **边界**：若链的递推不是确定性的（如 `randprime` + 随机间隔），或链元素完全不可见，则无法直接重建，需要其他泄漏。

## 检测与防御

- **CTF 视角**：看到“多个素数相乘作模数 + 只泄漏其中部分素数/`pow(p,e,n)`”时应立即想到链的可逆性，而不是尝试分解大整数。
- **现实视角**：RSA 素数必须来自密码学安全的随机源（CSPRNG），禁止用 `nextprime`/固定序列/其他可推导关系生成密钥材料；生成脚本中任何“确定性递推”都会把因子信息泄漏给攻击者。
- **审计**：检查密钥生成代码是否使用 `sympy.nextprime`、固定种子、低熵种子或由用户可控输入派生素数。
