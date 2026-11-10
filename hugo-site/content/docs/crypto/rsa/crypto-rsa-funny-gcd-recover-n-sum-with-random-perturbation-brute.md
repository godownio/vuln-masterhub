---
id: crypto-rsa-funny-gcd-recover-n-sum-with-random-perturbation-brute
title: funny_rsa：用两组乘积表达式 gcd 恢复 n，再对 p+q+rand(−1025,+1025) 枚举扰动解二次方程分解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-gcd-recover-modulus-random-sum-perturbation-brute
tags:
- crypto
- rsa
- gcd
- modulus-recovery
- p-plus-q
- quadratic
- bruteforce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:16:25+08:00'
  notes: 已对照 16579 原文核对：funny1..funny4 定义、n=(funny3+1025)//gcd(funny3+1025,funny2)、±1025 枚举得 r=1025、d=invert(e,phi)、hint=pow(funny4,d,n)、funny2//hint 得 fake flag 与图19 一致；未验证点：原文第二条 print(long_to_bytes(<固定整数>) 给真 flag 属题目预置，非本链推导
url: /docs/crypto/rsa/crypto-rsa-funny-gcd-recover-n-sum-with-random-perturbation-brute/
draft: false
kb_aliases:
- funny_rsa
- 春秋杯 funny_rsa
- gcd(funny3+1025, funny2) 恢复 n
- p+q 加随机扰动
- ±1025 枚举 p+q
- funny2 除以 hint
---

## 一句话结论

题目不直接给 `n`，而是给四个“趣味数”：`funny1 = p+q-p*q+rand(-1025,+1025)`、`funny2 = m*hint`、`funny3 = m*n*hint-1025`、`funny4 = hint^e mod n`。由 `funny3+1025 = m*n*hint` 与 `funny2 = m*hint` 可知 `funny3+1025` 与 `funny2` 的 gcd 里含 `n`，除以 gcd 即恢复 `n`；再由 `funny1+n = p+q+rand`，在 `[-1025,1025]` 内枚举 `rand`，把 `S = p+q` 代回 `x^2-Sx+n=0` 解出 p、q，最后 `d=invert(e,phi)` 解 `hint = funny4^d mod n`，用 `funny2/hint` 得到明文 `m`。

## 原理

- **n 藏在两个乘积的 gcd 里**：`funny3 = m*n*hint - 1025` 所以 `funny3+1025 = m*n*hint`；`funny2 = m*hint`。两者都含 `m*hint` 这个公因子，`gcd(funny3+1025, funny2)` 得到 `m*hint` 量级（或含 `m*hint` 的因子），原题脚本直接 `n = (funny3+1025)//gcd(funny3+1025, funny2)` 即可得到 2048 位 `n`。这里能成立的关键是 `m*hint` 的位长远小于 `n`，gcd 不会把 `n` 的因子搅进来——即 `g = m*hint` 恰为公因子。
- **p+q 带随机扰动**：`funny1 = p+q - p*q + rand`，而 `p*q = n`，所以 `funny1 + n = p+q + rand`，rand 在 `[-1025,1025]`。枚举 `r ∈ [-1025,1025]`，令 `S = funny1+n-r`（即候选 `p+q`），解 `x^2-Sx+n=0`：判别式 `D = S^2-4n` 必须是非负完全平方；`p,q=(S±√D)/2`。原题解出 `r=1025` 这一组（等价于 `p+q = funny1+n-1025`），并且 p/q 互换是同一组解。
- **为什么必须暴力 rand 而不是直接解**：`funny1+n` 比真实 `p+q` 大 1025，直接用会把 `D` 算成负数或非平方，二次方程无整数解；±1025 的窗口很小（2051 次），用 `sympy.solve` 或 `isqrt` 都可秒出。
- **拿到 p、q 后解 hint 再解 m**：`phi=(p-1)(q-1)`、`d=invert(e,phi)`、`hint=funny4^d mod n`（`funny4` 是 `hint` 的 RSA 密文）；因为 `funny2=m*hint` 是整数乘法，`m = funny2//hint` 直接整除恢复。原文先用 `long_to_bytes(funny2//hint)` 得到 fake flag（说明除出来的其实是诱饵/占位串），再用 `long_to_bytes(<literal>)` 打印 true flag——即真实 flag 由另一段固定整数直接给字节，属题目把“真值”放在第二条打印里。
- **边界**：若 `m*hint` 与 `n` 有公因子（例如 m 恰为 p 的倍数），gcd 会得到 `p*(m*hint)` 这类结果而非 `m*hint`，需要再按位长/整除性拆；若 `funny3` 没带 `-1025` 这种可逆偏移，则 gcd 前要先恢复这个常量。

## 触发条件

- 题目给出形如 `a*m*hint + c` 与 `m*hint` 两个数（`c` 为已知小常量），使得 `a*m*hint+c` 与 `m*hint` 可做 gcd 提取 `m*hint` 并恢复 `n`。
- 另外给出 `p+q+rand` 形式的和（rand 范围已知且小），或等价的 `φ(n)`、`p-q` 带小扰动。
- 公钥指数 `e` 与 `n` 互素，`n` 可分解（本题 n 为两个 1024 位素数之积）。
- 明文/提示的整数乘法结果未取模（`funny2`、`funny3` 是普通整数而非 mod n），否则除法/整除恢复不成立。

## 利用步骤

1. 抄下四个 `funny` 数与 `e`，确认 `funny3 = m*n*hint - 1025`、`funny2 = m*hint` 的量级关系（funny3 约为 funny2 的 n 倍）。
2. `g = gcd(funny3+1025, funny2)`；`n = (funny3+1025)//g`。用 `n % p == 0` 之类方式核对 n 的位长（应约 2048 bit）。
3. `S0 = funny1 + n`；对 `r in range(-1025,1026)` 令 `S = S0 - r`（注意方向：`funny1+n = p+q+rand`），解 `x^2-Sx+n=0`，`D=S^2-4n` 为完全平方时得 `p=(S+isqrt(D))//2`、`q=(S-isqrt(D))//2`，并验证 `p*q==n`。
4. `phi=(p-1)*(q-1)`、`d=invert(e,phi)`、`hint=pow(funny4,d,n)`。
5. `m = funny2 // hint`，`long_to_bytes(m)` 打印；若结果是占位串（fake flag），检查原文是否另有直接给定整数。
6. 若第 3 步不唯一（p/q 互换、r 对称），两组解都试一次即可。

## PoC

```python
import gmpy2, sympy
from Crypto.Util.number import long_to_bytes, inverse

funny1 = -176962576976735335176952153444...   # p+q-p*q+rand
funny2 = 236867288804947582330267984878...    # m*hint
funny3 = 419166458284161364374927086939...    # m*n*hint - 1025
funny4 = 135418983810471208265737438741...    # hint^e mod n
e = 65537

n = (funny3 + 1025) // gmpy2.gcd(funny3 + 1025, funny2)
print(n)

S0 = funny1 + n                                # = p + q + rand
for r in range(-1025, 1026):
    S = S0 - r
    D = S * S - 4 * n
    if D <= 0:
        continue
    t = gmpy2.isqrt(D)
    if t * t != D:
        continue
    p, q = (S + t) // 2, (S - t) // 2
    if p * q == n:
        print('p+q 扰动 r =', r)
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        hint = pow(funny4, d, n)
        print(long_to_bytes(funny2 // hint))
        break
```

说明：`rand` 的方向取决于 `funny1` 的定义（`p+q-p*q+rand`）；若第一轮无解就把 `S = S0 + r` 也试一遍。原文用 `sympy.solve` 解符号方程，等价。

## 变体与关联

- 变体：`funny3` 的偏移不是 -1025 而是未知小常量 c 时，可对 c 做小范围枚举，或直接用 `gcd(funny3, funny2)`（若 c 恰被吸收）。
- 变体：和的扰动换成“给 `φ(n)` 加噪声”“给 `p−q` 加噪声”，同样用枚举 + 二次方程；也可用 `φ(n)` 与 `n` 直接求 `p+q = n-φ(n)+1`。
- 变体：若两个表达式分别是 `m^a*hint^b` 的不同幂次，gcd 得到的是幂次组合，需按 `gcd` 的指数拆（用位长判断）。
- 关联：[[crypto-rsa-known-prime-sum-quadratic-factorization]]（已知 p+q 直接解二次方程；本卡是 p+q 未知且带扰动，多了 gcd 恢复 n 与枚举两步）、[[crypto-rsa-m-e-and-m-p-plus-q-linear-combination]]（已知 m^(p+q) 用线性组合恢复明文）、[[crypto-rsa-hint-difference-gcd-factorization]]（gcd 型提示分解）。
- 边界：`m*hint` 若与 `n` 共享因子，`n` 会被“污染”，需先验证 `n` 的位长与 `n|(funny3+1025)`；`m` 若很大（接近 n），`funny2//hint` 仍成立但 `funny2` 会超过 n 量级，注意 Python 大整数无溢出问题。

## 检测与防御

- 检测（出题侧/审计侧）：不要在同一次输出里给出含同一秘密因子的两个乘积（`m*hint` 与 `m*n*hint`），gcd 会直接拆出 `n`；也不要用“小范围随机扰动”来掩护和——2051 次枚举即可打穿。
- 修复（真实 RSA 实现）：模数 n 只通过公钥给出；任何中间量（hint、随机数、乘积）都不应可预测或多个线性相关；对解密/签名接口做常量时间与盲化，避免“提示值”设计。
- 加固（CTF 之外）：私钥运算使用 blinded RSA/ CRT 并确保 padding（OAEP）正确，防止类似“已知线性组合”的代数攻击。
