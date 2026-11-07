---
id: crypto-ecc-singular-cubic-cusp-additive-group
title: 奇异三次曲线（尖点）上的 ECDLP 退化：参数化把群运算化为有限域加法
type: scenario
domain: crypto
path: crypto/ecc
technique: singular-cubic-cusp-parameterization-additive-group
tags:
- crypto
- ecc
- singular-curve
- cusp
- discrete-log
- parameterization
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:03+08:00'
  notes: 已对照原文核对：曲线 y^2+cy=x^3+bx^2+dx+e、a=0、r=-b/3、d=3r^2、e+c^2/4=-r^3、Y=y+c/2、u=(x-r)/Y、m=u(P)/u(G) mod p、flag xmctf{A_s1ngu14r_Curv3_15_n0t_s3cur3!} 均一致。注意点：检测段中“判别式 4a^3+27b^2=0”是短 Weierstrass 形式的通用写法，对本卡含 c/b 项的方程应以 d=3r^2 与 e+c^2/4=-r^3（配方后完全立方）为准，卡片利用步骤已给出正确判据。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/crypto/ecc/crypto-ecc-singular-cubic-cusp-additive-group/
draft: false
kb_aliases:
- polarisCTF ECC
- 尖点奇异曲线
- cusp curve
- y^2=(x-r)^3
- 参数化 u=(x-r)/Y
- 奇异曲线 ECDLP
- 退化群
---

## 一句话结论

曲线 `y^2 + c y = x^3 + b x^2 + d x + e` 在参数满足 `d = 3r^2`、`e + c^2/4 = -r^3`（`r = -b/3`）时退化为 `Y^2 = (x-r)^3` 的尖点奇异曲线；用 `u = (x-r)/Y`（`Y = y + c/2`）参数化后，群运算变成有限域 `F_p` 上的普通加法，`P = [m]G` 可直接由 `m = u(P) · u(G)^{-1} mod p` 解出，无需任何离散对数算法。

## 原理

- **配方**：令 `Y = y + c/2`，原方程变为 `Y^2 = x^3 + b x^2 + d x + (e + c^2/4)`。
- **完全立方**：取 `r = -b/3`。若题目参数满足 `d = 3r^2` 且 `e + c^2/4 = -r^3`，右边就是
  `x^3 - 3r x^2 + 3r^2 x - r^3 = (x-r)^3`。
- **奇异性**：曲线 `Y^2 = (x-r)^3` 在 `(x,Y)=(r,0)` 处有尖点（cusp），判别式为 0，不是椭圆曲线；其群结构退化。
- **参数化**：对非奇异点（`Y != 0`）令 `u = (x-r)/Y`。由 `Y^2 = (x-r)^3` 得 `x-r = u^{-2}`、`Y = u^{-3}`，即 `x = r + u^{-2}`、`y = u^{-3} - c/2`。每个非奇异点由唯一的 `u` 表示。
- **群运算退化**：把参数化代回题目实现的加法公式，可化简为 `P(u1) + P(u2) = P(u1 + u2)`；标量乘法随之变成 `[m]P(u) = P(m u)`。
- **解出标量**：`P = [m]G` 在参数域中即 `u(P) = m · u(G) mod p`，所以 `m = u(P) · u(G)^{-1} mod p`；把 `m` 转回字节串即得消息/flag。
- **为什么成立**：题目保留了椭圆曲线加法的外观，但曲线本身是奇异的；奇异曲线的非奇异点群同构于加法群（尖点）或乘法群（节点），离散对数不再是困难问题。

## 触发条件

- 目标使用自定义椭圆曲线，曲线方程为 `y^2 + c y = x^3 + b x^2 + d x + e`（`a=0`）或可配方成类似形式。
- 参数满足完全立方/完全平方条件，使判别式为 0（尖点或节点）。
- 攻击者拿到基点 `G`、公钥/输出点 `P` 与模数 `p`，且点非奇异（`Y != 0`）。
- 曲线定义在素域 `F_p` 上，`2`、`3` 在 `p` 下可逆（用于配方）。

## 利用步骤

1. 计算 `r = -b/3 mod p`，验证 `d == 3r^2`、`e + c^2/4 == -r^3`，确认曲线是 `(x-r)^3` 型尖点曲线。
2. 计算 `Y_G = y_G + c/2`、`Y_P = y_P + c/2`；若任一为 0，该点是奇异点，换点或特殊处理。
3. 计算 `u_G = (x_G - r) · Y_G^{-1} mod p`、`u_P = (x_P - r) · Y_P^{-1} mod p`。
4. 计算 `m = u_P · u_G^{-1} mod p`；把 `m` 按大端转字节得到明文。
5. 用题目原始 `mul(m, G) == P` 复核，确认参数化与实现一致。

## PoC

```python
p = ...  # 题目模数
a, b, c, d, e = ...  # 曲线参数
G = (xG, yG); P = (xP, yP)

inv = lambda x: pow(x, -1, p)
inv2, inv3, inv4 = inv(2), inv(3), inv(4)

r = (-b * inv3) % p
const = (e + c * c * inv4) % p
assert (-3 * r - b) % p == 0
assert (3 * r * r - d) % p == 0
assert ((-pow(r, 3, p)) - const) % p == 0

def u_map(pt):
    x, y = pt
    Y = (y + c * inv2) % p
    return ((x - r) % p) * inv(Y) % p

m = u_map(P) * inv(u_map(G)) % p
flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(flag)
```

```text
# 例：polarisCTF ECC
# m = u(P)/u(G) mod p
# flag = b'xmctf{A_s1ngu14r_Curv3_15_n0t_s3cur3!}'
```

## 变体与关联

- 节点奇异曲线：`Y^2 = x^2(x-r)` 型节点曲线同构于乘法群 `F_p^*`，离散对数退化为乘法群 DLP；可用类似参数化 `u = (Y + ...)/(x)` 处理。
- 其他退化：异常曲线（`#E(F_p)=p`）可用 Smart 攻击，见 [[crypto-ecc-anomalous-curve-smart-attack]]；小阶/光滑阶曲线可用 Pohlig-Hellman，见 [[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]。
- 关联：[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（正常曲线的通用 DLP）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（ECDSA nonce 复用）。

## 检测与防御

- 检测：曲线参数使判别式 `4a^3 + 27b^2 = 0`（或配方后右边为完全立方/平方）；自定义曲线未做奇异性检查；公钥点可由简单参数化表示。
- 防御：使用标准曲线（secp256k1、P-256 等）；实现前校验判别式非零、基点阶为大素数；不要自创曲线或自定义群运算。
- 加固：对曲线参数做完整性校验；使用成熟库的曲线验证函数；避免在自定义曲线上直接做 ECDH/ECDSA。
