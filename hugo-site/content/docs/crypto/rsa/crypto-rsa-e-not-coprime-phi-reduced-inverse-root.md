---
id: crypto-rsa-e-not-coprime-phi-reduced-inverse-root
title: e 与 φ(n) 不互素：用 e/t 的模逆解得 m^t 再开 t 次方根，单条密文即可恢复明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-e-not-coprime-phi-reduced-inverse-t-root
tags:
- crypto
- rsa
- non-coprime
- gcd
- integer-root
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:13:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文 2.6 节给出 e=74、gcd 检查、d=invert(e//t,phi)、m2=pow(c,d,n)、iroot(m2,2) 及 n=15/e=4 的碰撞示例，卡片把 t 泛化并补 k*n 偏移，与原文一致；原文 iroot 第二个参数硬编码为 2（该例 t=2）。未复算。
url: /docs/crypto/rsa/crypto-rsa-e-not-coprime-phi-reduced-inverse-root/
draft: false
kb_aliases:
- e 与 phi 不互素
- gcd(e,phi)=t
- d=invert(e//t, phi) 后开 t 次根
- 非互素指数单密文解密
---

## 一句话结论

若密钥生成时选到的 `e` 与 `φ(n)` 不互素（例如 `e=74`、`gcd(e,φ)=2`），直接 `invert(e, φ)` 会抛「无模逆」而整套常规解密失效；正确做法是令 `t = gcd(e, φ)`、`e' = e/t`，用 `d' = e'^{-1} mod φ` 对密文求幂得到 `m^t mod n`，再对结果开 `t` 次整数根（必要时按 `k·n` 偏移枚举）即恢复明文 `m`。

## 原理

- **为什么 `invert` 失败**：模逆存在的充要条件是 `gcd(e, φ) = 1`；当 `t > 1` 时 `e` 在模 `φ` 下不可逆，`d = e^{-1} mod φ` 不存在，标准「解密 = 求 e 的逆」链路断裂。
- **约化后可以得到 `m^t`**：令 `e = t·e'`、`d' = e'^{-1} mod φ`，则对 `c = m^{e} mod n = (m^{t})^{e'} mod n` 计算 `c^{d'} ≡ m^{t·e'·d'} ≡ m^{t} (mod n)`（因 `e'·d' ≡ 1 mod φ`，指数在模 φ 下可约）。于是攻击者拿到的是明文的 t 次幂而非明文本身。
- **开 t 次根还原**：若 `m^t < n`（明文较短、t 较小），`m = ⌊(m^t)^{1/t}⌋` 直接成立；若发生过模约减，则对 `m^t + k·n` 枚举小 `k` 逐个开根并检查完全 `t` 次方。
- **安全性根源**：`e` 与 `φ` 不互素意味着映射 `m ↦ m^e mod n` 不再单射（如 `n=15, e=4` 时 `2^4 ≡ 7^4 ≡ 1 mod 15`），加密本身就已退化，属于密钥生成实现缺陷而非数学难题被攻破。
- **常见触发形态**：出题人随手取偶数 `e`、或自行实现密钥生成时未校验 `gcd(e, φ)=1`；真实系统中 OpenSSL 等库会拒绝这类参数，因此多见于自研/教学实现与 CTF。

## 触发条件

- 已知 `n`、`e`、`c`，且 `t = gcd(e, φ(n)) > 1`（`φ(n)` 可由分解 `n` 得到，或题目直接给出 p、q）。
- 明文 `m` 与 `n` 互素（否则可用 `gcd(c, n)` 直接分解）。
- `t` 较小（如 2、3、4、74/2=37 等），使开根与 `k` 枚举可行。

## 利用步骤

1. 由 `p`、`q` 计算 `n`、`φ = (p-1)(q-1)`；若无 p、q 先分解 `n`。
2. 计算 `t = gcd(e, φ)`；`t == 1` 时用常规解密，`t > 1` 走本链。
3. 计算 `d' = invert(e // t, φ)`，`m2 = pow(c, d', n)`，此时 `m2 = m^t mod n`。
4. 对 `m2 + k·n`（`k = 0,1,2,...`，小范围）求 `t` 次整数根，筛出完全 `t` 次方且字节串可打印/符合格式的候选。
5. `long_to_bytes(m)` 得到明文。

## PoC

```python
from gmpy2 import gcd, invert, iroot
from Crypto.Util.number import long_to_bytes

p, q, e, c = ...  # 题给参数

n   = p * q
phi = (p - 1) * (q - 1)
t   = gcd(e, phi)                 # 例如 e=74 时 t=2
assert t > 1

d2  = invert(e // t, phi)         # 约化指数
m2  = pow(c, d2, n)               # 这里等于 m^t mod n

for k in range(0, 1000):
    root, exact = iroot(m2 + k * n, t)
    if exact:
        print(long_to_bytes(int(root)))
        break
```

若确认未发生模约减（明文很短），直接 `iroot(m2, t)` 即可，无需 k 循环。

## 变体与关联

- **两个不互素指数共模**：把 `gcd(e1,e2)` 当 `t`，用扩展欧几里得得到 `m^t` 后开根，见 [[ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain]]。
- **指数被实现改小导致不互素**：如自定义幂函数在奇数指数时少乘一次使实际指数变为 `e-1`，需分域开根再 CRT，见 [[crypto-rsa-custom-pow-wrapper-odd-exponent-minus-one-root-crt]]。
- **开根思路的同族**：`m^e < n` 的直接开根（[[crypto-rsa-e3-small-plaintext-integer-cube-root]]）、多项式小明文求根（[[crypto-rsa-small-message-polynomial-root]]）。
- **前提侧的分解**：`gcd(c, n) ≠ 1` 时先分解（[[ctf-crypto-rsa-ciphertext-gcd-factor-leak]]）。

## 检测与防御

- **检测**：密钥生成代码中缺少 `gcd(e, φ(n)) == 1` 校验；解密侧出现「invert 抛出无模逆」或对 `m^t` 反复开根的异常逻辑；同一明文在不同密钥下产生相同密文的碰撞现象。
- **防御**：密钥生成必须校验 `gcd(e, φ(n)) = 1` 并在不满足时重新选 `e`（标准库默认行为）；不要自行实现 RSA 密钥生成；对已有密钥做参数检查，发现不互素立即重新生成密钥对。
