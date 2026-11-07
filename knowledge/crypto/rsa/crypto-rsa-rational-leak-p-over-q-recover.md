---
id: crypto-rsa-rational-leak-p-over-q-recover
title: RSA 有理泄漏 (3p²−1)/(3pq)：由 p/q 近似开方恢复 p、q 并用给定 d 解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-rational-leak-p-over-q-recovery
aliases:
- babyRSA
- leak=(3p^2-1)/(3pq)
- p/q 泄漏
- 高精度有理泄漏
- RSA 近似开方分解
- HECTF babyRSA
tags:
- crypto
- rsa
- leak
- rational-approximation
- factorization
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:10+08:00'
  notes: 已对照原文推导与脚本核对：leak=p/q-1/(3n)、r修正、sqrt(n*r)±2000搜索、给定d解密，flag一致；未独立复算大数
---

## 一句话结论

若 RSA 额外泄漏 `leak = (3p²−1)/(3pq)`，化简得 `leak = p/q − 1/(3n)`；由于 `1/(3n)` 极小，`r = leak + 1/(3n)` 是 `p/q` 的高精度近似，令 `p0 ≈ sqrt(n·r)` 并在附近小范围搜索即可找到整除 n 的 p，分解后（题目已给 d）直接 `m = c^d mod n` 解出 flag。

## 原理

- **化简 leak**：
  `leak = (3p²−1)/(3pq) = (3p²)/(3pq) − 1/(3pq) = p/q − 1/(3n)`，因为 `n=pq`。
- **恢复 p/q**：`p/q = leak + 1/(3n)`；`1/(3n)` 约 `2^-2048` 量级，`leak` 用高精度十进制（如 `decimal.prec=1024`）输出时，修正项几乎不影响高精度近似，但加上它可以精确到足以定位 p。
- **由比值求 p**：`p² = n·(p/q) ≈ n·r`，所以 `p ≈ sqrt(n·r)`；同理 `q ≈ sqrt(n/r)`。真实 p 与 `sqrt(n·r)` 只差很小（因为 r 是精确比值的近似），在 `p0` 附近枚举几百到几千个整数，找到 `n % p == 0` 即可。
- **为什么可行**：leak 把“分解 n”变成“已知两因子比值的高精度近似”；RSA 的困难性依赖于 p、q 独立随机，任何能给出 p/q 近似的泄漏都会破坏它。
- **解密**：题目直接给了私钥 d，分解出 p、q 后无需再求 d，`m = pow(c,d,n)`，`long_to_bytes(m)` 即 flag。
- **精度边界**：若 leak 只给有限位十进制且修正项被截断，`p0` 可能与真实 p 有偏移；偏移量与 leak 的精度/`1/(3n)` 的量级有关，原文在 ±2000 内搜索即可命中。若 leak 精度不足，需要扩大搜索或改用连分数/Coppersmith。

## 触发条件

- 已知 `n、c、d`（或 e 与 φ 可求），且额外泄漏形如 `(a·p²−1)/(a·p·q)` 的有理表达式。
- leak 以足够精度输出（十进制/有理数字符串），能恢复 `p/q` 的近似。
- p、q 为大素数，`n=pq`；`p0=isqrt(n·r)` 与真实 p 的偏移在可枚举范围内。
- 解密指数 d 已知或可由分解后的 φ 求出。

## 利用步骤

1. **解析 leak**：把十进制字符串转成 `Fraction`（分子/分母），避免浮点误差。
2. **修正为 p/q**：`r = leak + Fraction(1, 3*n)`。
3. **估算 p**：`t = (n * r.numerator) // r.denominator`，`p0 = isqrt(t)`。
4. **小范围搜索**：对 `delta in range(-2000, 2001)`，令 `p = p0 + delta`；若 `p > 1` 且 `n % p == 0`，则 `q = n // p`。
5. **解密**：`m = pow(c, d, n)`，`long_to_bytes(m)`；若 d 未给，`d = inverse(e, (p-1)*(q-1))`。
6. **验证**：`p*q == n`、明文含 flag 格式。

## PoC

```python
from fractions import Fraction
from math import isqrt
from Crypto.Util.number import long_to_bytes, inverse

def frac_from_decimal(s: str) -> Fraction:
    s = s.strip()
    neg = s.startswith("-")
    if neg: s = s[1:]
    if "." in s:
        a, b = s.split(".")
        f = Fraction(int(a + b), 10 ** len(b))
    else:
        f = Fraction(int(s), 1)
    return -f if neg else f

leak = frac_from_decimal(leak_str)
r = leak + Fraction(1, 3 * n)
p0 = isqrt((n * r.numerator) // r.denominator)

for delta in range(-2000, 2001):
    p = p0 + delta
    if p > 1 and n % p == 0:
        q = n // p
        break

m = pow(c, d, n)
print(long_to_bytes(m))
```

原文输出：`flag{th1s_1s_4_ture_fl4g}`。

## 变体与关联

- 变体：泄漏 `(a·p²−b)/(a·pq)`、`p/q + c/n`、`p−q` 的近似、`φ(n)` 的高位；leak 精度不足时用连分数/Coppersmith/格；p、q 接近时用 Fermat。
- 关联：[[crypto-rsa-low-bit-nonlinear-leak-bitlifting]]（低位非线性泄漏的逐位恢复）、[[crypto-rsa-structurally-related-moduli-continued-fraction-crt]]（连分数恢复参数）、[[crypto-rsa-fermat-close-prime-factorization]]（p、q 接近）、[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（部分私钥泄漏）。
- 同题：`babyRSA` 给出 `n、c、leak、d`；`simple_math`、`ez_rsa`、`ez_ecc` 是同一场 CTF 的其他密码题。

## 检测与防御

- **不要泄漏因子的有理函数**：任何 `p/q`、`(p²)/(pq)`、`φ` 高位等近似都可能被开方/连分数还原；输出只应给 `n、e、c`。
- **密钥生成**：p、q 独立随机，避免结构化关系；使用标准 RSA + OAEP。
- **审计**：检查日志/接口是否输出 p、q 的组合表达式、精度过高的中间值；对已泄露的参数轮换密钥。
- **CTF 之外**：真实协议中出现“比值/近似值”泄漏应按密钥泄露处理，评估历史密文可解性。
