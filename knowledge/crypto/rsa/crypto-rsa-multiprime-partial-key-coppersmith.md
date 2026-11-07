---
id: crypto-rsa-multiprime-partial-key-coppersmith
title: 三素数 RSA 高位泄露：Coppersmith 小根 + beta 逐档下调恢复 82 位未知低位
type: scenario
domain: crypto
path: crypto/rsa
technique: multiprime-rsa-partial-key-coppersmith
aliases:
- MultiGuard
- 三素数 RSA 部分密钥
- Coppersmith small_roots beta 下调
- 素数高位泄露
- Howgrave-Graham 格
- N^(1/9) 界
tags:
- rsa
- multiprime
- coppersmith
- partial-key-exposure
- lattice
- small-roots
- howgrave-graham
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:22+08:00'
  notes: 对照 Crypto472：430/512 高位泄露、beta 逐档下调、mm=6/tt=3 Howgrave-Graham 一致；未复跑
---

## 一句话结论

三素数 RSA 中每个 512 位素数泄露高 430 位、仅低 82 位未知时，`f(x)=p_hi·2^82+x` 是模 p 的小根问题；Coppersmith 在 beta=1/3 的界 `X≈N^(1/9)≈2^170` 远大于 `2^82`，即使某个素数略低于 `N^(1/3)` 导致标准 beta 失败，逐档下调 beta（1/3→0.32→0.30→0.25→0.20）并用 Howgrave-Graham 格求解即可恢复三个因子。

## 原理

- 设 512 位素数 `p = p_hi·2^82 + x`，其中 `p_hi` 是已知高 430 位，`x < 2^82` 未知。构造 `f(x)=p_hi·2^82+x`，则 `f(x)≡0 (mod p)`，且 `x` 很小。
- Coppersmith 的单一小根定理：对模 N 的因子 `p ≥ N^β`，若 `X < N^(β²/δ)`（δ 为多项式次数，这里 δ=1），可在多项式时间内求出 `|x|<X` 的根。三素数时 `p≈N^(1/3)`，取 β=1/3 得 `X≈N^(1/9)`。N 为 1535 bit 时 `N^(1/9)≈2^170`，远大于 `2^82`，理论上轻松可解。
- 但 `β=1/3` 的前提是 `p ≥ N^(1/3)`。三个素数随机生成，某个因子可能略小于 `N^(1/3)`，此时该界不成立，Sage 的 `small_roots(beta=1/3)` 可能返回空。
- 解法是把 β 逐档下调（1/3、0.32、0.30、0.25、0.20），每档用对应的 `X` 求根；对每个候选根 `x` 计算 `p_hi·2^82+x` 并检查是否整除 N。只要真实因子的 β 落在所选档位内就能出根。
- 另一个实测细节：Sage 自带 `small_roots` 在 β=1/3 边界数值稳定性不佳；改用自实现的 Howgrave-Graham 格（参数 mm=6、tt=3）后稳定命中。恢复三个因子后 `phi=(p-1)(q-1)(r-1)`，标准 RSA 解密。

## 触发条件

- RSA 使用三个或更多素数，且每个素数的高位（约 430/512）被公开。
- 未知低位长度小于 Coppersmith 界（本例 82 bit < ~170 bit）。
- 攻击者能拿到 N、e、c 与各素数高位；模数位数量级允许格构造。
- 素数彼此独立，乘积等于 N，便于用候选根整除校验。

## 利用步骤

1. 确认 N 为三素数乘积（1535 bit 左右），每个因子 512 bit，且服务端公开 `p_hi/q_hi/r_hi`。
2. 估计未知位数 `SHIFT`（本例 82），构造 `f(x)=hi·2^SHIFT+x`。
3. 对每个 hi，从 β=1/3 开始逐档下调，调用 `small_roots(X=2^SHIFT, beta=β)` 或自实现 Howgrave-Graham 格；候选根需满足 `N % cand == 0`。
4. 三个因子都恢复后计算 `phi` 与 `d`，解密密文；用 `p*q*r==N` 与明文格式交叉验证。
5. 若标准 `small_roots` 不稳定，增大格参数（mm/tt）或切换到自实现格基约减。

## PoC

```python
def recover_prime(hi, N, SHIFT, X):
    for beta in (1/3, 0.32, 0.30, 0.25, 0.20):
        for rt in (hi * 2**SHIFT + x).small_roots(X=X, beta=beta, epsilon=1/100):
            cand = int(hi) * 2**SHIFT + int(rt)
            if N % cand == 0:
                return cand
    raise ValueError("no root")

p = recover_prime(p_hi, N, 82, 2**82)
q = recover_prime(q_hi, N, 82, 2**82)
r = recover_prime(r_hi, N, 82, 2**82)
assert p * q * r == N
phi = (p - 1) * (q - 1) * (r - 1)
m = pow(c, pow(e, -1, phi), N)
```

```python
# 自实现 Howgrave-Graham 格的参数示例（Sage）
# mm, tt = 6, 3；按 f(x)=hi*2^SHIFT+x 与模 N 构造格，
# LLL 后取短向量还原小根；再对候选做 N % cand == 0 校验。
```

## 变体与关联

- 变体：泄露高位/低位、多个素数共享高位、已知 p+q 或 p-q 的一部分，都可转成 Coppersmith 小根/近似公因子问题。
- 变体：双素数时 β=1/2，界为 `N^(1/4)`；多素数时 β=1/k，界相应变小，需要更多泄露位或更强格。
- 关联：[[crypto-rsa-common-modulus]]（共享模数）、[[crypto-rsa-pell-equation-prime-generation]]（素数生成规律导致的分解）。
- 边界：未知位数超过界时无解；β 下调会增加格维数与计算量；Sage 版本/数值精度会影响边界行为；模数不是精确三因子乘积时需先确认因子个数。

## 检测与防御

- 检测：公钥/接口是否暴露素数高位、`p_hi` 等字段；密钥生成是否使用多素数且泄露部分因子；对 N 做因子个数与位长分布检查。
- 修复：不要公开素数的任何部分；使用标准双素数 RSA 或成熟库生成密钥；多素数场景下确保未知位远大于 Coppersmith 界。
- 加固：密钥生成后自检因子独立性；对 API 返回的公钥参数做最小化；定期轮换密钥；避免在调试接口返回 `p_hi/q_hi/r_hi`。
