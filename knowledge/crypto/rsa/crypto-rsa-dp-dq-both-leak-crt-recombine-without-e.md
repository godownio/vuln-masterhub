---
id: crypto-rsa-dp-dq-both-leak-crt-recombine-without-e
title: dp 与 dq 同时泄露：m1=c^dp mod p、m2=c^dq mod q 后用 CRT 重组明文，不需要 e 与私钥 d
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-dp-dq-simultaneous-leak-crt-recombine
aliases:
- dp dq 同时泄露
- CRT 重组明文
- 无需 e 解密
- m = ((m1-m2)*I mod p)*q + m2
tags:
- crypto
- rsa
- dp-leak
- dq-leak
- crt
- partial-key
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:13:34+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文 2.5 节给出 BUUCTF RSA1 的 p/q/dp/dq/c 与 I=invert(q,p)、m1=pow(c,dp,p)、m2=pow(c,dq,q)、m=(((m1-m2)*I)%p)*q+m2 与卡片一致；未复算例题参数。
---

## 一句话结论

当题目/实现同时泄露 `dp = d mod (p-1)` 与 `dq = d mod (q-1)`（通常连同 p、q 一起给出）时，不必求 `e` 的模逆也不必恢复完整私钥 `d`：分别算 `m1 = c^dp mod p`、`m2 = c^dq mod q`，再用 `m = ((m1-m2)·I mod p)·q + m2`（`I = q^{-1} mod p`）即可把明文从两个模数分量重组出来。

## 原理

- **CRT 解密的分量形式**：标准 RSA-CRT 先算 `m1 = c^{dp} mod p`、`m2 = c^{dq} mod q`，再按中国剩余定理把两个「模 p / 模 q 的明文」拼回模 `n` 的唯一解。攻击者拿到 dp、dq 就等价于拿到了这两步的指数。
- **为什么不需要 e**：常规解密需要 `d = e^{-1} mod φ(n)`；而 dp/dq 本身就是 `d` 在 `p-1`、`q-1` 下的约化指数，直接指数运算即可得到 `m mod p` 与 `m mod q`，绕过了对 `e` 的依赖，也绕过了 `e` 与 `φ` 是否互素的问题。
- **重组公式的来源**：令 `m = m2 + k·q`，要求 `m ≡ m1 (mod p)`，即 `k·q ≡ m1 - m2 (mod p)`，于是 `k = (m1-m2)·q^{-1} mod p`，代回即得 `m = ((m1-m2)·I mod p)·q + m2`，`0 ≤ m < pq`。
- **为什么能解出**：只要 `c` 与 `n` 互素，欧拉定理保证 `c^{dp} ≡ c^{d} (mod p)`（因 `dp ≡ d (mod p-1)`），两个分量都等于真实明文在对应素因子下的余数，CRT 的唯一性给出原明文。
- **边界**：若 `gcd(c, n) ≠ 1`（即 c 与 p 或 q 有公因子），`p` 或 `q` 依旧可从 `gcd(c,n)` 直接得到，明文仍可恢复；反之极端情况下分量退化，需要按 `gcd` 结果分别处理。

## 触发条件

- 泄露 `dp`、`dq`，且同时给出 `p`、`q`（或能先由 n 分解得到 p、q）。
- 持有密文 `c`；`c < n`。
- 明文在 `[0, n)` 范围内（标准 RSA 无填充或填充已知）。

## 利用步骤

1. 收集 `p`、`q`、`dp`、`dq`、`c`。
2. 计算 `m1 = pow(c, dp, p)`、`m2 = pow(c, dq, q)`。
3. 计算 `I = invert(q, p)`。
4. 重组：`m = (((m1 - m2) * I) % p) * q + m2`。
5. `long_to_bytes(m)` 得到明文，按需再去掉填充。

## PoC

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

p  = 0x...   # 已知素数 p
q  = 0x...   # 已知素数 q
dp = 0x...   # d mod (p-1)
dq = 0x...   # d mod (q-1)
c  = 0x...   # 密文

I  = gmpy2.invert(q, p)
m1 = pow(c, dp, p)
m2 = pow(c, dq, q)
m  = (((m1 - m2) * I) % p) * q + m2

print(long_to_bytes(m))
```

## 变体与关联

- **只泄露 dp（或 dq）**：`e·dp-1` 是 `p-1` 的倍数，枚举小 k 分解 n 后按常规解密，见 [[crypto-rsa-dp-leak-enumerate-k-factorization]]；本卡是其「两个分量都给了」的简化形态，不需要枚举也不需要 e。
- **dp 高位泄露**：转 Coppersmith 求低位，见 [[crypto-rsa-dp-high-bits-bivariate-coppersmith]]。
- **dp 落在复合模数上**：见 [[crypto-rsa-dp-leak-composite-modulus-power-coppersmith]]。
- **实现视角**：dp/dq/iqmp 属于私钥组件，一旦与 p、q 同时外泄，等于完整私钥泄露。

## 检测与防御

- **检测**：日志、报错、序列化输出中同时出现 `dp`、`dq`、`p`、`q` 字段；私钥结构被整体导出到不受控位置（如 JSON 接口、崩溃转储）。
- **防御**：CRT 参数与私钥同等级保护，不得进入日志/接口响应；私钥文件加密存储并限制读取；对含私钥字段的对象做序列化白名单；一旦怀疑泄露立即轮换密钥对。
