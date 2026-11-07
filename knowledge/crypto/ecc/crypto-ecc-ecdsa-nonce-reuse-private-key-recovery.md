---
id: crypto-ecc-ecdsa-nonce-reuse-private-key-recovery
title: ECDSA nonce 复用：同一 k 签两条消息直接恢复私钥
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-nonce-reuse-key-recovery
aliases:
- ECDSA k 复用
- nonce reuse
- 相同随机数签名
- r 相同恢复私钥
- ECDSA 私钥恢复
- k 重用攻击
tags:
- ecdsa
- ecc
- nonce-reuse
- private-key
- signature
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:43:45+08:00'
  notes: 已对照原文核对：公式、PoC 与原文一致；原文无受影响版本，frontmatter 无 sources/source_url；PoC 未本机复跑。
---

## 一句话结论

同一私钥对两条不同消息签名时若复用了随机数 `k`，两个签名会有相同的 `r`；由 `s1 = k^{-1}(e1 + d*r)`、`s2 = k^{-1}(e2 + d*r)` 可先解出 `k = (e1-e2)/(s1-s2) mod n`，再解出 `d = (s1*k - e1)/r mod n`，直接恢复私钥。

## 原理

- ECDSA 签名：`r = (k*G).x mod n`，`s = k^{-1}(e + d*r) mod n`，其中 `e = Hash(M)`、`d` 为私钥、`n` 为基点阶。
- 若两条消息使用同一个 `k`，则 `r` 相同。两式相减消去 `d*r`：
  - `s1*k = e1 + d*r`
  - `s2*k = e2 + d*r`
  - `(s1-s2)*k = e1-e2` → `k = (e1-e2)/(s1-s2) mod n`。
- 得到 `k` 后代入任一式：`d = (s1*k - e1)/r mod n`。
- 即使 `r` 不完全相同，若已知两次使用同一 `k`（或 `k` 有线性关系），也可按类似方程求解。
- 这是 ECDSA 最经典的实现缺陷；随机数必须每次唯一且不可预测。

## 触发条件

- 同一私钥、同一曲线/阶 `n`，存在两条（或更多）签名。
- 两个签名的 `r` 相同（或已知 `k` 相同），消息/哈希不同。
- 已知曲线阶 `n` 与消息哈希 `e1,e2`（或能重算）。
- `s1 != s2` 且 `s1-s2` 在模 `n` 下可逆。

## 利用步骤

1. 收集同一公钥的两条签名 `(r,s1)`、`(r,s2)` 与对应消息。
2. 计算 `e1=Hash(msg1)`、`e2=Hash(msg2)`（按题目哈希方式，常见 SHA256）。
3. 计算 `k = (e1-e2) * inverse(s1-s2, n) mod n`。
4. 计算 `d = (s1*k - e1) * inverse(r, n) mod n`。
5. 用 `d*G == Q` 验证私钥；若不等，检查哈希截断、曲线阶/坐标、签名字节序。
6. 用恢复的 `d` 伪造目标签名/解密 token。

## PoC

```python
from hashlib import sha256

r  = ...
s1 = ...
s2 = ...
msg1 = b"Hello Alice"
msg2 = b"Hello Bob"

n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141  # secp256k1
e1 = int(sha256(msg1).hexdigest(), 16)
e2 = int(sha256(msg2).hexdigest(), 16)

k = ((e1 - e2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - e1) * pow(r, -1, n)) % n
print(hex(d))
```

## 变体与关联

- 变体：同一 `k` 被多个用户/多个会话复用；只要 `r` 相同即可按上式恢复。
- 变体：`k` 只泄露部分位或满足线性关系时，改用格攻击（见 ECDSA 部分 nonce 泄露卡）。
- 变体：`k` 由弱随机数/时间种子生成时，可枚举/预测 `k`，再解 `d`。
- 关联：[[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]（部分 k 泄露）、[[crypto-ecc-anomalous-curve-smart-attack]]（曲线阶异常）、[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（弱随机数）。

## 检测与防御

- 防御：使用 RFC 6979 确定性 nonce 或密码学安全随机数；每次签名必须唯一，禁止复用。
- 防御：使用经过审计的签名库/HSM；签名代码不要在失败重试时复用同一个 `k`。
- 检测：签名日志中出现相同 `r`；同一私钥对多条消息的 `r` 重复；异常签名批量生成。
- 响应：发现 nonce 复用后立即吊销密钥/证书，重新生成密钥对，审计历史签名与 token。
