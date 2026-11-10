---
id: crypto-rsa-amm-nth-root-mod-p-unit-roots-crt
title: AMM（Adleman-Manders-Miller）在模 p 下开 e 次方根：e^t·s 分解迭代、单位根枚举与 CRT 组合
type: scenario
domain: crypto
path: crypto/rsa
technique: amm-nth-root-finite-field-unit-roots-crt
tags:
- crypto
- rsa
- amm
- nth-root
- finite-field
- unit-root
- crt
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:11:39+08:00'
  notes: 已对照原文与全部 37 张公式图核对：p-1=e^t·s 分解、t=1（c^d）、t≥2 迭代、e 次非剩余与单位根子群 K、由一根乘单位根得全部根、CRT 组合均与原文推导一致。已发现并核对原文脚本缺陷：math.log(d,a) 求子群离散对数在 t≥2 时错误（原文示例 p=131,e=5 属 t=1 未暴露）；卡片按 a^j=δ^{-1} 枚举重写并自测，我复跑 p=101,q=131,e=5,m=42 得 25 个候选且包含明文 42，PoC 成立。未验证点：大 e/大素数下的性能未测；affected_versions 已 --clear（原文无版本信息）。
url: /docs/crypto/rsa/crypto-rsa-amm-nth-root-mod-p-unit-roots-crt/
draft: false
kb_aliases:
- AMM 算法
- Adleman-Manders-Miller
- 模 p 开 e 次方
- e 次剩余求根
- 单位根枚举
- RSA e 与 p-1 不互素
---

## 一句话结论

当 RSA 的 `e` 与 `p-1`（或 `q-1`）不互素、简单约化后仍无法用整数开根恢复明文时，只要 `e | p-1`，就可以用 AMM 算法在 `F_p` 上求 `x^e ≡ c` 的一个根：把 `p-1` 分解为 `e^t·s`，`t=1` 时根为 `c^{e^{-1} mod s}`，`t≥2` 时迭代消去 `e` 的幂并用 `e` 次非剩余校正；再乘遍 `e` 个单位根得到全部根，最后把模 `p`、模 `q` 的根两两 CRT 组合，按格式筛选明文。

## 原理

- **为什么常规解密失效**：RSA 解密要求 `gcd(e, φ(n)) = 1`，否则 `d = e^{-1} mod φ` 不存在。若 `g = gcd(e, φ)` 较小，可先求 `m^g = c^{(e/g)^{-1} mod φ}` 再开 `g` 次整数根；但当 `e | p-1` 且 `e | q-1` 时 `g` 可能就等于 `e`，约化后指数变成 1，得到的是 `m^e` 在模 `n` 下的余数，整数开根不再可用——必须在有限域内开 `e` 次根。
- **AMM 的分解**：设 `p` 为奇素数且 `e | p-1`，把 `p-1` 写成 `p-1 = e^t·s`，其中 `e ∤ s`。令 `d = e^{-1} mod s`（`e` 与 `s` 互素），则 `e d - 1 = k s`。
- **t = 1 的情况**：此时 `s = (p-1)/e`。对 `e` 次剩余 `c`，有
  `(c^d)^e = c^{e d} = c^{1 + k s} = c·(c^s)^k ≡ c (mod p)`，
  所以 `c^d mod p` 就是一个 `e` 次根。这一步与 Tonelli-Shanks 在 `p-1 = 2s` 时的 `c^{(s+1)/2}` 同源。
- **t ≥ 2 的迭代**：取一个 `e` 次非剩余 `z`（即 `z^{(p-1)/e} ≠ 1`），令
  - `a = z^{e^{t-1}·s} mod p`（阶为 `e`，用于表示单位根），
  - `b = c^{e d - 1} mod p`，
  - `u = z^s mod p`，`h = 1`。
  对 `i = 1..t-1` 循环：
  - `δ = b^{e^{t-1-i}} mod p`；
  - 在阶为 `e` 的子群中求 `j ≡ -log_a(δ) (mod e)`（`e` 小则直接枚举 `j = 0..e-1`，或让 `a^j = δ^{-1}`）；
  - `b ← b·(u^e)^j`，`h ← h·u^j`，`u ← u^e`。
  循环结束后 `c^d·h mod p` 即为一个 `e` 次根。本质是逐层消去 `e^t` 中的 `e` 因子，每一层用单位根修正当前结果。
- **全部根**：若 `x0` 是一个根，则所有根为 `x0·ζ`，其中 `ζ` 遍历 `e` 次单位根（`ζ^e ≡ 1`）。取随机 `α` 使 `ζ = α^{(p-1)/e} ≠ 1`，则 `ζ^0..ζ^{e-1}` 给出全部 `e` 个单位根；模 `p` 侧共有 `gcd(e, p-1) = e` 个根。
- **CRT 组合**：设 `n = p·q`，把模 `p` 的 `e` 个根与模 `q` 的 `e` 个根两两 CRT，得到 `n` 上全部 `e^2` 个候选（一般更多，按各侧 `gcd` 计）；再用 `pow(m, e, n) == c` 与明文格式（`flag{`、可打印字节）筛选出真实明文。
- **复杂度**：每层一次模幂与小规模离散对数；`e` 很小时（CTF 常见 2/3/5/7）代价极低，`e` 很大时子群离散对数是瓶颈——这也是 AMM 通常用于小 `e` 的原因。
- **常见实现误区**：迭代中的 `j` 是阶为 `e` 子群里的离散对数，必须按 `a^j ≡ δ^{-1}`（或 `a^{-j} ≡ δ`）求；不能用实数对数 `math.log(δ, a)` 代替，否则在 `t ≥ 2`、`e > 2` 时会算错。若目标例子恰好 `t = 1`（如 `p = 131, e = 5` 时 `p-1 = 5·26`），代码会走 `c^d` 分支而不暴露该错误，换一个 `e^2 | p-1` 的素数（如 `p = 101, e = 5`，`100 = 5^2·4`）才会触发。

## 触发条件

- 已知 `n` 或其分解 `p`、`q`；已知 `e`、`c`。
- `gcd(e, φ(n)) > 1`，且 `e | p-1` 或 `e | q-1`（至少一侧需要有限域开根；另一侧按 `gcd(e, p-1)` 的情况分别处理）。
- `e` 较小，使单位根枚举与子群离散对数可行。
- 明文是整数且 `m < n`；若 `m` 与 `n` 不互素可直接分解 `n`，不走本链。
- 有明文格式/前缀可用于在多解中筛选。

## 利用步骤

1. 分解 `n` 得 `p`、`q`（题给或通过提示/共模/弱素数等分解）。
2. 计算 `gcd(e, p-1)`、`gcd(e, q-1)`：
   - 若 `e ∤ p-1`，用 `pow(c, e^{-1} mod (p-1), p)` 求唯一根或按 `gcd` 做约化；
   - 若 `e | p-1`，用 AMM 求一个根，再枚举单位根得到全部 `p` 侧根。
3. 对 `q` 侧重复同样处理。
4. 将 `p` 侧与 `q` 侧根两两 CRT，得到候选 `m`；验证 `pow(m, e, n) == c` 并转字节筛格式。

## PoC

```python
from itertools import product
from Crypto.Util.number import long_to_bytes

def amm(c, e, p):
    """p 为素数且 e | p-1，返回 x^e ≡ c (mod p) 的一个根。"""
    t, s = 0, p - 1
    while s % e == 0:
        t += 1
        s //= e
    d = pow(e, -1, s)                      # e 在模 s 下可逆
    if t == 1:
        return pow(c, d, p)
    z = 2
    while pow(z, (p - 1) // e, p) == 1:    # 找 e 次非剩余
        z += 1
    a = pow(z, e ** (t - 1) * s, p)        # 阶为 e 的子群生成元
    b = pow(c, e * d - 1, p)
    u = pow(z, s, p)
    h = 1
    for i in range(1, t):
        delta = pow(b, e ** (t - 1 - i), p)
        if delta == 1:
            j = 0
        else:
            # j = -log_a(delta) mod e：a^j ≡ delta^{-1}
            target = pow(delta, -1, p)
            j = next(j for j in range(1, e) if pow(a, j, p) == target)
        b = b * pow(pow(u, e, p), j, p) % p
        h = h * pow(u, j, p) % p
        u = pow(u, e, p)
    return pow(c, d, p) * h % p

def all_roots(x0, e, p):
    """由一个 e 次根得到全部 e 个根（e | p-1）。"""
    z = 2
    while pow(z, (p - 1) // e, p) == 1:
        z += 1
    zeta = pow(z, (p - 1) // e, p)
    return list({x0 * pow(zeta, k, p) % p for k in range(e)})

def crt(a, p, b, q):
    """x ≡ a (mod p), x ≡ b (mod q)"""
    return (a + p * ((b - a) * pow(p, -1, q) % q)) % (p * q)

# 示例：小素数验证（p=101 时 5^2 | 100，会走 t>=2 分支）
p, q, e, m = 101, 131, 5, 42
n = p * q
c = pow(m, e, n)

rp = all_roots(amm(c % p, e, p), e, p)
rq = all_roots(amm(c % q, e, q), e, q)
for a, b in product(rp, rq):
    cand = crt(a, p, b, q)
    if pow(cand, e, n) == c:
        print(cand, long_to_bytes(cand))
```

说明：以上为按 AMM 原理重写并在小素数上自测通过的实现，非原文脚本；原文脚本的 `math.log` 求子群离散对数在 `t ≥ 2` 时不可用，已在此修正。

## 变体与关联

- **e = 2**：退化为 Tonelli-Shanks 求模平方根，AMM 的 `t`、`j∈{0,1}` 推导与二次剩余一致；Rabin 类题目可复用。
- **t = 1 快速路径**：`e | p-1` 但 `e^2 ∤ p-1` 时直接 `c^{e^{-1} mod s}`，无需选取非剩余与迭代。
- **不互素但可约化**：若 `gcd(e, φ)` 较小且 `m^g < n`，用“约化指数 + 整数开根”更简单，见 [[crypto-rsa-e-not-coprime-phi-reduced-inverse-root]]。
- **分域求根的其他实现**：Sage 的 `(x^e - c).roots()` 或 `nth_root` 可直接替代 AMM；实现层缺陷导致不互素的案例见 [[crypto-rsa-custom-pow-wrapper-odd-exponent-minus-one-root-crt]]。
- **扩展域**：`F_{q^m}` 上的 `r` 次根可用 BV 算法（`r | q-1` 且 `(m,r)=1` 等条件下复杂度更低）。
- **边界**：`p` 非素数、`e ∤ p-1`、`e` 很大导致子群离散对数不可行、或根数量爆炸且无格式可筛时，本链不适用。

## 检测与防御

- **CTF/实现侧**：密钥生成必须校验 `gcd(e, φ(n)) = 1`；避免让 `e` 整除 `p-1`/`q-1`（例如避免小素数 `e` 搭配 `p ≡ 1 mod e` 的素数）；使用标准库生成密钥，不自造 `e`。
- **检测**：解密代码出现“无模逆”后转向分域开根/枚举单位根/CRT 多解筛选；`e` 为小素数且 `p-1`、`q-1` 含其高次幂；同一密文对应多个合法明文候选（映射非单射）。
- **防御**：参数初始化时断言 `gcd(e, φ)=1` 并做已知明文自检 `dec(enc(m)) == m`；对不满足条件的密钥直接拒绝使用并重新生成。
