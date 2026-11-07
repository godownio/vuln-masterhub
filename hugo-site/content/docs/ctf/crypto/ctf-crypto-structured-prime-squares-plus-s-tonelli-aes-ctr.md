---
id: ctf-crypto-structured-prime-squares-plus-s-tonelli-aes-ctr
title: 结构化素数 p=s²+s+3 与椭圆曲线阶泄露：模平方根枚举 t 恢复 p 并解 AES-CTR
type: scenario
domain: ctf
path: ctf/crypto
technique: structured-prime-squares-plus-s-tonelli-shanks-aes-ctr
tags:
- ctf
- crypto
- structured-prime
- tonelli-shanks
- modular-sqrt
- aes-ctr
- ecc
- hasse
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:20+08:00'
  notes: 已对照原文核对：p=pp^2+pp+3、gift=E.order()%mod、Hasse 近似 p、D=1+4(gift-3) 的 Tonelli-Shanks、两个残类枚举 t、long_to_bytes(p)[:16] 作 AES-CTR key+给定 nonce，与原文推导/exp 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-structured-prime-squares-plus-s-tonelli-aes-ctr/
draft: false
kb_aliases:
- myPrime
- p=pp^2+pp+3
- 结构化素数
- Tonelli-Shanks 模平方根
- E.order mod mod
- AES-CTR 密钥恢复
---

## 一句话结论

当私钥素数具有 `p = s² + s + 3`（`s` 为约 256 位）的结构，且程序泄露 `gift = E.order() mod mod`（`mod` 也是约 256 位素数）时，利用 Hasse 定理把 `E.order` 近似为 `p`，在模 `mod` 下解二次方程 `s² + s − (gift−3) ≡ 0`（判别式 `D = 1 + 4R`，用 Tonelli-Shanks 求模平方根），得到两个残类后在合理位宽内枚举少量 `t`，即可恢复 `p`；再用 `long_to_bytes(p)[:16]` 作 AES-CTR 密钥解密 flag 密文。

## 原理

- **结构化素数**：`p = s(s+1) + 3`，`s` 为 256-bit 随机数，`p` 约 512-bit。已知 `p` 就等价于已知 `s`，而 `s ≈ √p`。
- **椭圆曲线阶泄露**：程序计算某条曲线（isogeny 后）的阶 `E.order()` 并对 256-bit 的 `mod` 取余输出 `gift`。Hasse 定理给出 `|#E(F_p) − (p+1)| ≤ 2√p`，因此 `E.order ≈ p`；在模 `mod` 下可近似认为 `p ≡ gift (mod mod)`（误差项 `1−t` 相对 `mod` 很小，必要时对少量偏移枚举）。
- **模二次方程**：由 `p − 3 = s(s+1)` 得 `s² + s − (gift−3) ≡ 0 (mod mod)`。判别式 `D = 1 + 4·(gift−3)`；若 `mod` 为素数且 `D` 是二次剩余，Tonelli-Shanks 求出 `sqrt(D) mod mod`，两个根为 `s ≡ (−1 ± sqrt(D)) · 2⁻¹ (mod mod)`。
- **枚举真实 s**：真实 `s` 约在 `[2^255, 2^257)`，而 `mod` 也是 256-bit，故 `s = s_res + t·mod` 中 `t` 的范围很小（通常 0..几）。对每个候选计算 `p = s(s+1)+3`，按位宽/素性/AES 解密结果筛选。
- **AES key 派生**：程序用 `long_to_bytes(p)[:16]` 作为 AES 密钥，`AES.MODE_CTR` 使用给定 8 字节 nonce（PyCryptodome 默认 counter=0）；对每个候选 `p` 尝试解密，命中 `QnQSec{`/`flag{` 即正确。
- **为什么成立**：泄露把 512-bit 的 `p` 压缩成 256-bit 模方程的两个残类；结构化又把剩余搜索空间压到个位数候选，整体从 2^512 降到多项式级。

## 触发条件

- 已知 `gift、mod、AES-CTR 密文 c、nonce`，且 `mod` 为素数（或至少能求模平方根）。
- 私钥素数满足可写成 `s² + s + 3`（或类似低次多项式）的结构，`s` 位宽与 `mod` 相当。
- 泄露值来自 `E.order() mod mod`，且 Hasse 误差相对 `mod` 可忽略或可枚举。
- AES 密钥直接取 `long_to_bytes(p)` 的前 16 字节；CTR 的 nonce 已知，counter 初值可推断（常为 0）。
- 有 Tonelli-Shanks/模平方根与大整数运算能力。

## 利用步骤

1. 从题目代码确认素数结构 `p = pp^2 + pp + 3`、`gift = int(E_.order()) % mod`、AES key=`long_to_bytes(p)[:16]`、`AES.MODE_CTR(nonce=...)`。
2. 计算 `R = (gift − 3) mod mod`、`D = (1 + 4R) mod mod`；用 Tonelli-Shanks 求 `sqrtD = D^((mod+1)/4) mod mod`（`mod ≡ 3 mod 4` 时）或通用算法。
3. 计算 `inv2 = pow(2, -1, mod)`，得到两个残类 `s0 = (−1 + sqrtD)·inv2 mod mod`、`s1 = (−1 − sqrtD)·inv2 mod mod`。
4. 对每个残类，按 `s` 的预期位宽（如 `[2^255, 2^257)`）计算 `t_min/t_max`，枚举 `t` 得到候选 `s = s_res + t·mod`，再算 `p = s(s+1)+3`。
5. 过滤：`p` 位宽合理、素性测试通过（可选）；用 `long_to_bytes(p)[:16]` 作 key、给定 nonce 解 AES-CTR，检查明文是否含 flag 前缀。
6. 命中后输出 flag；若 Hasse 误差不可忽略，对 `gift` 附近的小偏移（`±1, ±2, ...`）重复步骤 2-5。

## PoC

```python
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES

def tonelli_shanks(n, p):
    n %= p
    if n == 0: return 0
    if p % 4 == 3:
        x = pow(n, (p + 1) // 4, p)
        return x if x * x % p == n else None
    # 通用 Tonelli-Shanks：分解 p-1=q*2^s，找非剩余 z，迭代求根
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2; s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p; i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t, r = t * c % p, r * b % p
    return r

R = (gift - 3) % mod
D = (1 + 4 * R) % mod
sqrtD = tonelli_shanks(D, mod)
inv2 = pow(2, -1, mod)
for s_res in {((-1 + sqrtD) * inv2) % mod, ((-1 - sqrtD) * inv2) % mod}:
    lo, hi = 1 << 255, 1 << 257
    for t in range((lo - s_res) // mod, (hi - s_res) // mod + 2):
        s = s_res + t * mod
        p = s * (s + 1) + 3
        key = long_to_bytes(p)[:16]
        pt = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(c)
        if b"QnQSec{" in pt or b"flag{" in pt:
            print(pt)
```

## 变体与关联

- 变体：`E.order` 与 `p` 的偏差（Hasse 误差、同源映射引入的小因子）不可忽略时，枚举 `gift + δ` 的小 `δ` 再解方程。
- 变体：结构化素数可能是 `p = a·s² + b·s + c`、`p = s² + 1`、`p = P(B−1)² + B·S²` 等；都在模 `mod` 下化为一元二次/低次方程。
- 关联：[[crypto-rsa-structured-modulus-b-minus-one-square-e8-sqrt]]（另一类结构化模数恢复）、[[crypto-rsa-perfect-square-modulus-p-squared]]（完全平方模数）、[[ctf-crypto-small-discrete-log-crt-channel-selection]]（模方程 + 小范围枚举思路）。
- 边界：`mod` 必须是素数才能用 Tonelli-Shanks（合数需分解或换算法）；`t` 范围随 `mod` 与 `s` 的位宽差增大；AES-CTR 的 counter 初值不对会导致解密失败。

## 检测与防御

- 检测（CTF）：题目给出 `gift = E.order() % mod`、prime 结构与 AES-CTR 参数；先验证 `D` 的二次剩余性，再枚举 `t`。
- 修复（真实设计）：不要用可预测结构的素数；密钥不要直接取素数字节；使用标准 KDF（HKDF）派生 AES 密钥并配合随机 nonce/认证加密。
- 加固：泄露曲线阶时避免与私钥素数产生可解模方程；对敏感参数做白盒/常量时间处理，避免侧信道与结构泄露。
