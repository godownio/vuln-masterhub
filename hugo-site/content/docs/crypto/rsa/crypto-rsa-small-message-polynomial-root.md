---
id: crypto-rsa-small-message-polynomial-root
title: RSA 小明文多项式泄露：c=m³+a2m²+a1m+a0 的高精度求根与低 16 位爆破
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-small-message-polynomial-newton-root
tags:
- crypto
- rsa
- small-message
- polynomial
- newton
- low-exponent
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:41:40+08:00'
  notes: 已对照原文小蓝鲨的RSA密文核对并本机复跑：c=m^3+a2m^2+a1m+a0、a2 高16位/低16位未知、Decimal 牛顿求根+±2^16 爆破、AES-CBC 解密；复跑命中 m=155455820692697783953491152103673430935、delta=-3406、a2=590661429227，flag 一致；已修正卡片中总位数与 N 位长（实际 N 为 1024 bit）
url: /docs/crypto/rsa/crypto-rsa-small-message-polynomial-root/
draft: false
kb_aliases:
- RSA 多项式小明文
- c=m^3+a2m^2+a1m+a0
- 高精度牛顿求根
- a2 高位泄露
- AES key 恢复
- 小蓝鲨的RSA密文
---

## 一句话结论

当 RSA 输出不是 `c=m^e mod N` 而是 `c=m^3+a2m^2+a1m+a0 mod N`，且 m 很短、多项式总量小于 N 时模约减不发生，c 就是精确整数多项式；利用已知的 a2 高位构造近似三次方程，高精度牛顿法逼近根后在 ±2^16 内爆破 m，即可恢复作为 AES 密钥的 m 并解出 flag。

## 原理

- **无模约减条件**：m 为 16 字节（约 128 bit）时 `m^3` 约 384 bit；`a2*m^2` 约 40+256=296 bit；`a1*m`、`a0` 更小；各项之和约 385 bit，远小于 N（约 1024 bit）。因此 `c = (m^3 + a2m^2 + a1m + a0) mod N` 中的 `mod N` 不改变值，c 就是精确整数。
- **部分系数已知**：题目只给出 a2 的高位 `a2_high`（`a2 = a2_high << 16 + low`），a1、a0 已知。先忽略低位，把 `A = a2_high << 16` 代入 `Q(x) = x^3 + A x^2 + a1 x + a0 - c`。
- **高精度求根**：用 Decimal 提高精度（`prec=200`），从 `x = c^(1/3)` 出发做牛顿迭代 `x ← x - Q(x)/Q'(x)`，得到与真实 m 接近的整数根；由于 a2 的低 16 位未知，根有误差。
- **局部爆破**：在 `m_approx ± 2^16` 内枚举 delta，令 `num = c - m^3 - a1*m - a0`，若 `num % m^2 == 0`，则 `a2_candidate = num // m^2`；检查 `a2_candidate >> 16 == a2_high`，命中即真实 m。
- **后续利用**：m 被直接当作 16 字节 AES-128-CBC 密钥，用已知 iv 解密密文并去填充即可。

## 触发条件

- RSA 或类 RSA 加密使用小指数 e=3，且明文 m 很短（示例 16 字节）。
- 密文计算包含多项式附加项（`a2 m^2 + a1 m + a0`），且总量小于 N，未发生模约减。
- 攻击者知道 a1、a0 与 a2 的高位（或可通过枚举/侧信道获得）。
- m 可直接作为对称密钥或包含可验证格式（flag/填充），便于确认命中。

## 利用步骤

1. 确认 `c < N` 且各多项式项的量级之和小于 N，排除模回绕。
2. 用已知的 a2 高位构造 `A = a2_high << 16`，写出 `Q(x)=x^3+A x^2+a1 x+a0-c`。
3. 用高精度 Decimal/整数牛顿法求近似根 `m_approx`。
4. 在 `±2^16` 范围内枚举 delta，利用 `num % m^2 == 0` 与 `a2 >> 16` 两个条件筛选真实 m。
5. 把 m 转 16 字节作为 AES 密钥解密密文，去 PKCS#7 填充得到 flag。

## PoC

```python
from decimal import Decimal, getcontext
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

getcontext().prec = 200
c_dec = Decimal(c)
A = Decimal(a2_high << 16)
a1_dec, a0_dec = Decimal(a1), Decimal(a0)

x = Decimal(c) ** (Decimal(1) / Decimal(3))
for _ in range(50):
    Q = x**3 + A*x**2 + a1_dec*x + a0_dec - c_dec
    Qp = 3*x**2 + 2*A*x + a1_dec
    x_new = x - Q / Qp
    if abs(x_new - x) < Decimal(1):
        x = x_new
        break
    x = x_new

m_approx = int(x)
for delta in range(-2**16, 2**16 + 1):
    m = m_approx + delta
    if m <= 0:
        continue
    num = c - m**3 - a1*m - a0
    if num % (m*m) != 0:
        continue
    a2 = num // (m*m)
    if a2 >> 16 == a2_high:
        key = m.to_bytes(16, 'big')
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex(iv))
        print(unpad(cipher.decrypt(bytes.fromhex(ct)), 16).decode())
        break
```

原文数据命中 `m=155455820692697783953491152103673430935`（delta=-3406，a2=590661429227），解出：

```text
ISCTF{i7_533M5_Lik3_You_R34lLy_UNd3R574nd_Polinomials_4nD_RSA}
```

## 变体与关联

- 若附加项完全已知（a2 无未知低位），可直接对 c 开三次方或解精确三次方程，无需爆破；见 [[crypto-rsa-e3-small-plaintext-integer-cube-root]]。
- 若 m 更大导致 `m^3 > N`，需改用 Coppersmith 小根；见 [[crypto-rsa-e3-known-prefix-suffix-coppersmith]]。
- 多项式次数/项数可变：核心是“总量小于 N → 精确多项式 → 求根 + 局部枚举未知系数/低位”。
- 关联：[[crypto-rsa-polynomial-derivative-hidden-exponent-enum]]（同为多项式系数泄漏类攻击）。

## 检测与防御

- 检测：CTF 中检查密文是否小于 N、是否存在未约减的多项式结构；AES 密钥短、由 RSA 小明文直接派生是典型信号。
- 防御：使用 OAEP 等随机化填充，使 m 接近模长且随机；不要用短明文/短密钥直接派生对称密钥；避免泄露多项式系数的高位。
- 加固：RSA 密钥至少 2048 bit，密文输出前统一做模约减并校验范围。
