---
id: crypto-rsa-two-linear-hints-small-coefficient-gcd
title: RSA 两个线性 hint 都是 p、q 的小系数组合：枚举 ≤211 的系数让一边系数抵消，差值即素因子倍数，gcd 直接分解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-two-hint-small-coefficient-pairing-gcd
aliases:
- hint = x*p + y*q - c
- 小系数配对 gcd 分解
- RSA 双 hint 系数爆破
- gcd(i*hint1 - j*hint2, n)
- rasnd
tags:
- crypto
- rsa
- hint-leak
- gcd
- factorization
- bruteforce
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:37:49+08:00'
  notes: 已对照原文核对；本次核对未读取图片；hint1=x1*p+y1*q-0x114、hint2=x2*p+y2*q-0x514、系数 randint 上界 211/2114/211/2514、以及原 exp 在 211x211 网格上对 (hint+常数) 做线性组合取 gcd 并 isPrime 判定的做法均与正文一致；卡片把系数区间概括为 [0,211)/[0,2514) 属近似表述，y1 实际上界为 2114；原有求解脚本里被 Markdown 吞掉的乘号（如 n = p q）卡片未照抄、按语义还原；
---

## 一句话结论

当两个 hint 形如 `hint1 = x1·p + y1·q - C1`、`hint2 = x2·p + y2·q - C2`（系数、常数都较小且已知常量偏移）时，先补回常数得到 `S1 = x1·p + y1·q`、`S2 = x2·p + y2·q`，再在小范围里枚举整数 `i, j`：一旦 `i·y1 == j·y2`，`i·S1 - j·S2 = p·(i·x1 - j·x2)` 就是 p 的倍数，`gcd(i·S1 - j·S2, n)` 直接给出 p。

## 原理

- **两个线性式的 gcd 直觉不成立，配对系数才成立**：`S1`、`S2` 各自都不是 p 的倍数（都含 q 项），所以直接 `gcd(S1 - S2, n)` 通常为 1。要让差值只含 p，必须让 q 的系数相消：`i·y1 - j·y2 = 0`。
- **小系数让枚举可行**：题中 `x1,y1,x2,y2` 落在 `[0, 211)`／`[0, 2514)` 这类小范围，`i, j` 也只需枚举到同量级（本题 211×211 次），命中条件是两个小整数互成比例（`i/j = y2/y1`），在 4 万组配对里必然出现。
- **差值即因子倍数**：命中后 `i·S1 - j·S2 = (i·x1 - j·x2)·p`，是 p 的整数倍且远小于 `n`，所以 `gcd(差值, n)` 等于 p（偶尔因同时整除 q 而得到 n，换个配对即可）；拿到 p 后 `q = n//p`，常规 `d = e^{-1} mod φ` 解密。
- **常数偏移必须先补回**：`hint` 里减掉的 `0x114`、`0x514` 是公开常量，忘记加回去会让方程的 p/q 系数组合被常数污染，差值不再整除 p。

## 触发条件

- 已知 `n`、`e`、密文 `c`，并泄露至少两个 p、q 的线性组合（系数小、常数已知）。
- 系数范围足够小，可对 `i, j` 做 `O(K²)` 枚举（K 约几百）。
- 密文对应的明文短于 `n`（常规 RSA 解密前提）。

## 利用步骤

1. 从题目输出里抓 `n`、`c`、两个 hint，以及 hint 定义里的常数偏移。
2. 还原 `S1 = hint1 + C1`、`S2 = hint2 + C2`。
3. 双重循环枚举 `i, j ∈ [1, K]`，计算 `g = gcd(i*S1 - j*S2, n)`；`1 < g < n` 且 `g` 为素数时即命中 `p`。
4. `q = n//g`，`d = inverse(e, (p-1)*(q-1))`，`m = pow(c, d, n)`，`long_to_bytes(m)`。

## PoC

```python
from math import gcd
from Crypto.Util.number import inverse, long_to_bytes, isPrime

K = 211
for i in range(1, K):
    for j in range(1, K):
        g = gcd(i * (hint1 + C1) - j * (hint2 + C2), n)
        if 1 < g < n and isPrime(g):
            p, q = g, n // g
            d = inverse(65537, (p - 1) * (q - 1))
            print(long_to_bytes(pow(c, d, n)).decode())
            raise SystemExit
```

上面的 `g` 命中判据要收紧为 `isPrime(g)`：差值有时同时含 p 与 q 的更高次幂，`gcd` 会返回合数，此时换下一组 `(i, j)`。

## 变体与关联

- 三变量/多 hint：可先对两两 hint 做批量 gcd，或把 `i·y1 - j·y2` 的配对方程当成整数线性方程组求小解（LLL），避免平方枚举。
- 系数带噪声：差值不再精确整除 p，需改用近似 GCD 或格约减（把 `i·S1 - j·S2` 当短向量）。
- 与「多 hint 同余同一素因子 → 直接 gcd 差值」的卡相比：那张卡靠**残差相同**，本卡靠**系数配平**，题目给的是 `x·p + y·q` 型而非 `s ≡ r (mod p)` 型。
- 与「hint 泄露 p+q / p-q」类卡相比：本卡两个 hint 都不是 p+q 或 p-q 的干净形式，必须先解系数。

## 检测与防御

- 不要泄露 p、q 的任何线性组合，哪怕是「加了小随机系数」的版本；只要系数范围可控即可被枚举配平。
- hint 若要发布，应保证其中一个系数足够大（接近 p 的量级）或引入秘密乘数，使配平枚举不可行。
- 出题侧自检：拿 `gcd(i*S1 - j*S2, n)` 对小系数网格扫一遍，确认不出现素因子。
