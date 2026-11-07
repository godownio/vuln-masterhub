---
id: crypto-rsa-boneh-durfee-small-private-exponent
title: Boneh-Durfee 攻击：d < n^0.292 时用格基约减恢复 RSA 小私钥
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-boneh-durfee
tags:
- rsa
- small-d
- lattice
- boneh-durfee
- lll
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:22+08:00'
  notes: 已对照原文核对：delta=0.271、m=8、t=int((1-2δ)m)、X=2⌊N^δ⌋、Y=⌊N^0.5⌋、A=(N+1)/2、pol=1+x(A+y)、d=pol(solx,soly)/e 与原文完整脚本一致；d<n^0.292 界与 Wiener 对比表述正确。未验证点：原文格脚本未本机复跑；无受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-boneh-durfee-small-private-exponent/
draft: false
kb_aliases:
- Boneh-Durfee
- 小私钥格攻击
- d < n^0.292
- Wiener 扩展
- 部分密钥暴露格方法
---

## 一句话结论

当 RSA 私钥 `d` 小于 `n^0.292`（超过 Wiener 的 `n^0.25` 界但未达到安全规模）时，利用 `e·d ≡ 1 (mod φ(n))` 构造二元多项式 `f(x,y)=1+x(A+y)`（`A=(n+1)/2`），在模 `e` 下建立 Boneh-Durfee 格，LLL 约减后对短向量求结式，可恢复 `x=2k`、`y=-(p+q)/2`，进而得到 `d` 并解密。

## 原理

- `e·d ≡ 1 (mod φ(n))` 等价于存在整数 `k` 使 `e·d - 1 = k·φ(n)`。又 `φ(n)=n-p-q+1`。
- 令 `A=(n+1)/2`、`y=-(p+q)/2`，则 `A+y = φ(n)/2`。取 `x=2k`，有 `1 + x(A+y) = 1 + k·φ(n) = e·d ≡ 0 (mod e)`。
- 因此 `(x,y)=(2k, -(p+q)/2)` 是二元多项式 `f(x,y)=1+x(A+y)` 在模 `e` 下的小根。`x` 的规模约为 `d`（因为 `k≈d`），`y` 的规模约为 `√n`。
- Boneh-Durfee 把 `f` 的移位多项式（`x^i·e^{m-k}·f^k` 与 `y^j·f^k·e^{m-k}`）组成格，利用 `x`、`y` 都较小使对应向量成为短向量；LLL 后取两个独立短向量，对其多项式求结式消去一个变量，解出 `(x0,y0)`。
- 由 `1 + x0(A+y0) = e·d` 得 `d = (1 + x0(A+y0))/e`。`d` 恢复后即可解密密文。
- 界：Wiener 攻击要求 `d < n^0.25`；Boneh-Durfee 把可解范围推进到 `d < n^0.292`。超过该界需要部分密钥泄露、多密钥等额外信息。

## 触发条件

- 已知 `n`、`e`、`c`，且 `d` 明显小于正常规模（`d < n^0.292`）。
- `e` 较大（通常与 `n` 同量级），使 `f` 模 `e` 的小根条件成立。
- 能运行 LLL/BKZ 与多项式结式运算（Sage）。
- 格参数 `m`、`t` 需按 `delta` 调整；`delta` 越接近 0.292，所需格维数与计算量越大。

## 利用步骤

1. 估计 `d` 的比特规模，确认 `d < n^0.292`（若 `d < n^0.25` 可先试更简单的 Wiener 连分数）。
2. 取 `delta≈0.271`、`m=8`、`t=int((1-2·delta)·m)`、`X=2·floor(n^delta)`、`Y=floor(n^(1/2))`。
3. 构造 `P.<x,y> = PolynomialRing(ZZ)`，`A=int((n+1)/2)`，`pol = 1 + x*(A+y)`。
4. 调用标准 `boneh_durfee(pol, e, m, t, X, Y)`：生成移位多项式、构造格、LLL、取短向量、求结式并解出 `(solx,soly)`。
5. 计算 `d = int(pol(solx,soly)/e)`，用 `pow(pow(2,e,n),d,n)==2` 或直接解密校验。
6. `m = pow(c,d,n)`，转字节得到明文。

## PoC

```python
from Crypto.Util.number import *

N = ...
e = ...
c = ...

delta = 0.271
m = 8
t = int((1 - 2 * delta) * m)
X = 2 * floor(N^delta)
Y = floor(N^(1/2))

P.<x, y> = PolynomialRing(ZZ)
A = int((N + 1) / 2)
pol = 1 + x * (A + y)

# boneh_durfee 为标准的 Boneh-Durfee 格实现：
# 生成 x/y 移位多项式 -> 构造格 -> LLL -> 取短向量 -> 结式消元
solx, soly = boneh_durfee(pol, e, m, t, X, Y)
d = int(pol(solx, soly) / e)
m_int = power_mod(c, d, N)
print(long_to_bytes(m_int))
```

> 说明：`boneh_durfee` helper 较长（原文附带完整脚本），核心是格构造、`BB.LLL()`、对两行短向量求 `resultant` 并解根；本卡只保留可调参数与调用方式。

## 变体与关联

- 变体：`d < n^0.25` 时用 Wiener 连分数攻击，计算量更小；Boneh-Durfee 是其扩展。
- 变体：同一模数多把密钥、`d` 略大于 0.292 时，用 Howgrave-Graham–Seifert 多密钥方法把界推高。
- 变体：已知 `d` 的高位/低位时，可结合部分密钥泄露的 Coppersmith/格方法。
- 关联：[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（多密钥小 d）、[[crypto-rsa-private-exponent-low-bits-partial-p]]（d 低位泄露）、[[crypto-rsa-dual-rsa-lattice-small-d]]（同一 d 用于多个模数）。

## 检测与防御

- 防御：`d` 必须足够大（至少 `n^0.5` 量级），使用标准库生成密钥，不要为了“加速解密”人为选择小 `d`。
- 防御：优先使用 `e=65537` 的标准密钥；若必须用小 `d`，改用 CRT-RSA 并确保 `dp/dq` 也足够大。
- 检测：审计密钥参数，检查 `d.bit_length()` 是否明显小于 `n.bit_length()`；CTF 中看到 `d` 约为 `n^0.27` 即可按本卡尝试。
- 响应：确认小私钥后可被恢复，立即轮换密钥并审计历史密文。
