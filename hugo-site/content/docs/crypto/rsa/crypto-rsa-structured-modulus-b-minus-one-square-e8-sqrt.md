---
id: crypto-rsa-structured-modulus-b-minus-one-square-e8-sqrt
title: 结构 RSA e=8：N=P(B−1)²+BS² 参数恢复与三层平方根解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-structured-modulus-e8-multi-sqrt
tags:
- crypto
- rsa
- structured-modulus
- factorization
- square-root
- crt
- e8
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:18:57+08:00'
  notes: 已对照原文脚本与图12核对：N=P(B-1)^2+BS^2、P_low=N mod B、N//B^3±500搜索、二次方程恢复f/g、e=8三层平方根+CRT，flag输出一致；未独立复算大数
url: /docs/crypto/rsa/crypto-rsa-structured-modulus-b-minus-one-square-e8-sqrt/
draft: false
kb_aliases:
- simple_math
- N=P(B-1)^2+B*S^2
- e=8 RSA
- 多层平方根解密
- 低 128 位恢复 P
- RSA 结构分解
- HECTF simple_math
---

## 一句话结论

当 RSA 模数由 `p=(f·B+g)`、`q=(g·B+f)` 生成时，`N = P·(B−1)² + B·S²`（`P=f·g`、`S=f+g`，`B=2^128`）；由 `N mod B = P mod B` 取 P 的低 128 位、用 `N // B³` 估算 P 的高位并小范围搜索，即可恢复 P、S，解二次方程得到 f、g 与 p、q；随后因 `e=8=2³`，对密文连续做 3 轮模 p/q 平方根 + CRT 组合，枚举候选明文找出 flag。

## 原理

- **模数结构**：设 `p = f·B + g`、`q = g·B + f`，则
  `p·q = f·g·(B²+1) + B·(f²+g²)`。
  令 `P=f·g`、`S=f+g`，有 `f²+g² = S²−2P`，代入得
  `N = P·(B²−2B+1) + B·S² = P·(B−1)² + B·S²`。
  这就是题目给出的特殊结构。
- **低 128 位直接给出 P mod B**：`N mod B = P·(B−1)² + B·S² mod B`；`(B−1)² ≡ 1 (mod B)`、`B·S² ≡ 0 (mod B)`，所以 `N mod B = P mod B`。
- **高位估算**：`P` 约 256 bit（f、g 各 128 bit 相乘），`P·(B−1)²` 约 512 bit，`B·S²` 约 386 bit；`N // B³` 与 P 的高位只差少量进位（原文在 ±500 内搜索），组合 `P_cand = high·B + low` 后验证 `N − P_cand·(B−1)²` 能被 B 整除且商为完全平方，即得到 S。
- **恢复 f、g**：`f、g` 是 `x² − S·x + P = 0` 的两根（韦达定理）；判别式 `S²−4P` 开方后 `f=(S+√Δ)/2`、`g=(S−√Δ)/2`。
- **恢复 p、q**：`p=(f<<128)+g`、`q=(g<<128)+f`，用 `p·q==N` 验证。
- **e=8 的多层平方根**：RSA 加密 `c=m^8 mod N`；解密等价于对 c 连续开 3 次平方根（因为 `8=2³`）。在 `Z_p` 中，若 `p≡3 (mod 4)`，平方根为 `±c^((p+1)/4)`；分别对 p、q 求根后用 CRT 组合，每层最多 4 个根，3 层最多 64 个候选；对候选转字节检查 `flag`/`{` 即可筛出明文。
- **为什么可行**：模数结构把 512 bit 的分解问题降为“已知低 128 位 + 高位小范围搜索 + 完全平方判定”；e=8 又允许逐层开方而不是求逆元（若 gcd(8,φ)≠1，常规 `d=e^{-1} mod φ` 不存在）。这两个缺陷叠加使题目可解。

## 触发条件

- 已知 `N、e=8、c`，且题目/生成脚本提示模数由两个 128 bit 参数按上述结构生成（或能从 N 的低位/高位关系推断）。
- `p、q` 为素数且满足 `p≡q≡3 (mod 4)`（否则 `(p+1)/4` 求根公式不适用，需要 Tonelli-Shanks）。
- `c` 是模 N 的二次剩余（每一层都要能开方）；明文较短/有可识别格式（如 `HECTF{...}`）。
- 计算资源足够做 3 层根组合（最多 64 个候选）与候选解码。

## 利用步骤

1. **取低位**：`B=2^128`，`P_low = N % B`。
2. **估高位**：`approx_high = N // B**3`，在 `approx_high ± 500` 内枚举 `P_high`，令 `P_cand = P_high·B + P_low`。
3. **验证 P/S**：计算 `rem = N − P_cand·(B−1)²`；要求 `rem ≥ 0`、`rem % B == 0`，令 `S2 = rem // B`；若 `isqrt(S2)² == S2`，则 `P=P_cand`、`S=isqrt(S2)`。
4. **解二次方程**：`Δ=S²−4P`，`f=(S+isqrt(Δ))//2`、`g=(S−isqrt(Δ))//2`；`p=(f<<128)+g`、`q=(g<<128)+f`；验证 `p*q==N`。
5. **三层开方**：对 `c` 做 3 轮：每轮对 `val mod p`、`val mod q` 用 `pow(a,(p+1)//4,p)` 求根（先检查 `pow(a,(p-1)//2,p)==1`），再用 CRT 组合；收集所有候选。
6. **筛 flag**：对每个候选 `long_to_bytes`，检查是否包含 `flag`/`{` 或可 UTF-8 解码；输出明文。

## PoC

核心恢复与开方代码（按原文脚本简化）：

```python
from math import isqrt
from Crypto.Util.number import long_to_bytes, inverse

B = 1 << 128
P_low = n % B
approx_high = n // (B ** 3)

for delta in range(-500, 500):
    P = (approx_high + delta) * B + P_low
    rem = n - P * ((B - 1) ** 2)
    if rem < 0 or rem % B:
        continue
    S2 = rem // B
    S = isqrt(S2)
    if S * S != S2:
        continue
    D = S * S - 4 * P
    f = (S + isqrt(D)) // 2
    g = (S - isqrt(D)) // 2
    p = (f << 128) + g
    q = (g << 128) + f
    assert p * q == n
    break

def sqrt_mod_prime(a, p):
    if pow(a, (p - 1) // 2, p) != 1:
        return []
    x = pow(a, (p + 1) // 4, p)      # 需 p % 4 == 3
    return [x, p - x]

def crt(rp, rq):
    return (rp * q * inverse(q, p) + rq * p * inverse(p, q)) % (p * q)

cands = [c]
for _ in range(3):
    nxt = []
    for v in cands:
        for rp in sqrt_mod_prime(v % p, p):
            for rq in sqrt_mod_prime(v % q, q):
                nxt.append(crt(rp, rq))
    cands = list(set(nxt))

for m in cands:
    b = long_to_bytes(m)
    if b'flag' in b or b'{' in b:
        print(b.decode())
```

原文输出：`HECTF{this_is_a_flag_emm_is_a_true_flag_ok_all_right}`。

## 变体与关联

- 变体：`B` 位数、e=4/16（更多/更少平方根层）；p、q 不满足 3 mod 4 时用 Tonelli-Shanks；P/S 搜索范围更大时用 Coppersmith/格；把结构换成 `N=P·(B+1)²+B·S²` 等变体。
- 关联：[[crypto-rsa-rabin-random-square-root-oracle]]（e=2 的平方根与 CRT 四根）、[[crypto-rsa-known-prime-sum-quadratic-factorization]]（已知 p+q 解二次方程）、[[crypto-rsa-perfect-square-modulus-p-squared]]（模数结构退化）、[[crypto-rsa-structurally-related-moduli-continued-fraction-crt]]（另一类结构 RSA）。
- 同题：`ez_rsa` 用连分数恢复相邻素数；`ez_ecc` 用点减半恢复 ECC 参数（见关联卡）。

## 检测与防御

- **密钥生成**：不要用有代数关系的 f、g 生成 p、q；使用标准 RSA 密钥生成（随机大素数、足够熵），避免模数出现完全平方/低比特线性关系。
- **公钥指数**：不要用 `e=8` 等与 φ 不互素的指数；常规应使用 `e=65537` 且 `gcd(e,φ)=1`，配合 OAEP 填充。
- **审计**：检查 N 的低位/高位是否存在可预测结构、`N mod 2^k` 是否泄露因子；对自研 RSA 参数做随机性与结构测试。
- **CTF 之外**：真实协议中出现 e=8/结构化模数通常意味着实现错误；应轮换密钥并评估历史密文是否可解。
