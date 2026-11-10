---
id: ctf-crypto-dsa-square-related-nonce-quadratic-congruence-key-recovery
title: DSA 两次签名的 nonce 满足 k2=k1²：消去私钥得 k1 的二次同余方程，用 Tonelli-Shanks 开方解出私钥
type: scenario
domain: ctf
path: ctf/crypto
technique: dsa-square-related-nonce-quadratic-congruence-recovery
tags:
- ctf
- crypto
- dsa
- nonce
- quadratic-residue
- tonelli-shanks
- signature
- sage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:42:33+08:00'
  notes: 已对照原文核对；本次核对未读取图片（本篇 content.md 无图片引用）；并用原文常量复算：q%4=3，A=r1*s2、B=-r2*s1、C=r2*H1-r1*H2 的判别式欧拉判别为 1（二次剩余），delta^((q+1)/4) 平方回 delta 成立，两候选根之一恰为正文给出的 k=9455554284687443083，回代 x=(s1*k-H1)*inverse(r1,q)%q 得正文的 e=44519，说明卡内消元与开方闭式描述正确。未验证点：正文 exp 中 solve_quadratic_congruence 函数把全局 a 覆盖为 r1*s2 的命名混乱，卡片按数学正确写法表述、未照抄；C 的符号在正文整理式与 exp 实现间存在写法差异（(r2*H1-r1*H2)），卡内采用能复算出结果的 exp 版本
url: /docs/ctf/crypto/ctf-crypto-dsa-square-related-nonce-quadratic-congruence-key-recovery/
draft: false
kb_aliases:
- k2 = k1^2
- DSA 二次同余恢复 nonce
- nonce 平方关系
- 消去私钥的二次方程
- DSA 私钥即隐藏指数
---

## 一句话结论

同一私钥 `x` 的两次 DSA 签名若 nonce 满足 `k₂ = k₁²`，把两个签名方程中的 `x` 消掉就得到关于 `k₁` 的一元二次同余方程 `r₁s₂k₁² − r₂s₁k₁ − (r₁H₂ − r₂H₁) ≡ 0 (mod q)`；判别式开方（`q ≡ 3 mod 4` 时直接 `Δ^((q+1)/4)`）取两个根并用「`r = g^k mod p mod q` 必须等于给出的 `r₁`」筛出真根，回代即得私钥 `x`——本题的私钥正是下一步 RSA 里隐藏的公钥指数。

## 原理

- **签名方程**：`s = (H + r·x)·k⁻¹ mod q`，即 `s·k ≡ H + r·x (mod q)`。两次签名给出两条线性方程，未知量是 `x`、`k₁`、`k₂`；只有两个方程、三个未知量，正常情况下信息不足。
- **nonce 之间的代数关系补上第三个约束**：`k₂ = k₁²` 把未知量降到两个（`x`、`k₁`），于是可解。这一步是整道题的"漏洞"——nonce 不该有任何可预测关系，`k²` 让攻击者能用一条等式消元。
- **消元过程**：由第一式 `x ≡ (s₁k₁ − H₁)·r₁⁻¹`，第二式 `x ≡ (s₂k₁² − H₂)·r₂⁻¹`；两式相等并交叉相乘得 `r₂(s₁k₁ − H₁) ≡ r₁(s₂k₁² − H₂) (mod q)`，整理即二次同余 `A·k₁² + B·k₁ + C ≡ 0`，其中 `A = r₁s₂`、`B = −r₂s₁`、`C = r₂H₁ − r₁H₂`。
- **为什么要开二次剩余**：`q` 是素数，`k₁ = (−B ± √Δ)·(2A)⁻¹ mod q`，`Δ = B² − 4AC`。若 `Δ` 非二次剩余则方程无解（说明关系假设不成立或数据抄错）；`q ≡ 3 (mod 4)` 时开方有闭式 `Δ^((q+1)/4)`，否则用 Tonelli-Shanks。
- **根的筛选**：两个根都可能让方程成立，但只有真 `k₁` 满足 `pow(g, k₁, p) mod q == r₁`；也可以回代求 `x` 后检查 `pow(g, x, p) == y`。这一步把数学解收敛到唯一。
- **私钥的语义**：本题把私钥设成 `bytes_to_long(b'e = ?')` 之类的隐藏值，恢复 `x` 后按字节/整数解释才发现它就是 RSA 部分缺失的 `e`；这类"签名题只为泄露另一个参数"的设计很常见，恢复出 `x` 后要立刻回看其它参数缺什么。

## 触发条件

- 目标用标准 DSA（`s = (H + r·x)k⁻¹ mod q`，`r = (g^k mod p) mod q`），且公开了同一私钥的两组及以上签名 `(H, r, s)`。
- nonce 之间存在可表达的代数关系（本题 `k₂ = k₁²`；也可能是一次函数、倍数、异或等）。
- `q` 为大素数，`gcd(A, q) = 1`（`A = r₁s₂`，实战中几乎必然成立）。
- 已知 `p`、`q`、`g`、`y`，可用于验证恢复结果。

## 利用步骤

1. 从题面取出 `p、q、g、y` 与两组签名 `(H₁,r₁,s₁)、(H₂,r₂,s₂)`，并确认 nonce 关系（题面直接给 `k₂ = k₁²`）。
2. 计算 `A = r₁s₂ mod q`、`B = −r₂s₁ mod q`、`C = (r₂H₁ − r₁H₂) mod q`。
3. 计算 `Δ = (B² − 4AC) mod q`；用欧拉判别 `Δ^((q−1)/2) == 1` 确认是二次剩余；`q ≡ 3 mod 4` 时 `sqrtΔ = Δ^((q+1)/4)`，否则用 `sqrt_mod(Δ, q, all_roots=True)` 或 Tonelli-Shanks。
4. 求两个候选 `k₁ = (−B ± sqrtΔ)·inverse(2A, q) mod q`；对每个候选检查 `pow(g, k₁, p) % q == r₁`（或等价地验证 `k₁ == k₂` 的平方关系）。
5. 用真 `k₁` 回代 `x = (s₁k₁ − H₁)·inverse(r₁, q) mod q`；用 `pow(g, x, p) == y` 验证。
6. 把 `x` 转成字节或按题面语义解释（本题即 RSA 的公钥指数 `e`），继续后续解密链。
7. 若 `Δ` 非二次剩余或两个根都不满足 `r₁`，先怀疑抄错了 `H`（哈希输入是题目随机串而非消息本体）或 nonce 关系不是纯平方（可能带常数项 `k₂ = k₁² + c`，此时方程变成四次，需要另一条签名或格方法）。

## PoC

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

p, q, g, y = ..., ..., ..., ...
H1, r1, s1 = ..., ..., ...
H2, r2, s2 = ..., ..., ...

A = (r1 * s2) % q
B = (-r2 * s1) % q
C = (r2 * H1 - r1 * H2) % q

delta = (B * B - 4 * A * C) % q
assert pow(delta, (q - 1) // 2, q) == 1, "delta 非二次剩余：关系假设错误"

if q % 4 == 3:
    sqrt_delta = pow(delta, (q + 1) // 4, q)          # q ≡ 3 (mod 4) 的闭式开方
else:
    sqrt_delta = sqrt_mod(delta, q)                    # Tonelli-Shanks

inv_2a = inverse_mod(2 * A, q)
cands = [((-B + sqrt_delta) * inv_2a) % q,
         ((-B - sqrt_delta) * inv_2a) % q]

k1 = next(k for k in cands if pow(g, int(k), p) % q == r1)   # 用 r1 筛真根
x  = (s1 * k1 - H1) * inverse_mod(r1, q) % q
assert pow(g, int(x), p) == y, "私钥验证失败"
print(long_to_bytes(int(x)), bytes_to_long(long_to_bytes(int(x))))
```

```text
要点：
1) 两个签名方程 + k2 = k1^2 → 消去 x 得 k1 的二次同余；
2) q ≡ 3 (mod 4) 时 sqrt = delta^((q+1)/4)；
3) 两个根用 r1 == g^k1 mod p mod q 筛选，再回代求 x。
```

## 变体与关联

- **变体一（关系带常数/线性）**：`k₂ = a·k₁ + b` 时消元后是一次同余，直接解出 `k₁`，比本题更简单；`k₂ = k₁² + c` 时变成四次方程，或改写成 "非线性关系 + 未知×未知" 的格/结式问题。
- **变体二（多组签名）**：有 3 组以上签名时，`k_i = k₁²` 会给出多个二次方程，可用结式或 GCD 交叉验证，不必依赖单一方程的判别式开方。
- **变体三（换曲线/换方案）**：ECDSA 上同理，只是模数换成曲线基点阶 `n`；格方法的 nonce 线性相关场景见 [[ctf-crypto-dsa-linear-related-nonce-lattice-k0-forgery]]，nonce 完全复用（`k₁=k₂`）见 [[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]。
- **变体四（私钥只用于泄露另一参数）**：恢复 `x` 后若字节不可读，按"另一个缺失参数"去试（指数、模数因子、种子），本题即把 `x` 当 RSA 的 `e`。
- **关联**：[[ctf-crypto-dsa-linear-related-nonce-lattice-k0-forgery]]（同为"nonce 有关系"的 DSA 攻击，但那条关系是线性、规模大，必须上格；本条关系是平方、只有一条二次同余，纯数论即可）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（nonce 复用的极端情形）、[[crypto-rsa-known-p2-plus-q2-cornacchia-factor]]（本题后半段的 `C = p² + q²` 分解，属该卡场景，故不重复建卡）。

## 检测与防御

- **根因**：nonce 必须由 CSPRNG 独立生成，绝不能由其它 nonce 派生（平方、倍数、加常数都不行）；`k` 一旦可预测或有代数关系，私钥就从"解离散对数"降级为"解一元方程"。
- **实现侧**：用 RFC 6979 的确定性 nonce（由私钥与消息哈希经 HMAC-DRBG 派生），既避免复用也避免弱随机；禁止自研 nonce 生成逻辑。
- **检测信号**：同一公钥的多条签名中 `k` 存在数学关系（可由 `r` 反查）；签名实现里出现 `k*k`、`k+1`、固定种子等模式；`q ≡ 3 mod 4` 之外还用了不安全的 `sqrt` 实现。
- **响应**：一旦怀疑 nonce 泄露或有关系，立即视为私钥泄露——轮换密钥、重签历史内容、审计所有由该私钥保护的会话。
