---
id: crypto-ecc-ecdsa-smooth-order-pohlig-hellman
title: ECDSA 弱曲线：基点阶光滑时用 Pohlig-Hellman 分解 ECDLP
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-smooth-order-pohlig-hellman
tags:
- ecdsa
- ecc
- pohlig-hellman
- discrete-log
- smooth-order
- sage
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:43:47+08:00'
  notes: 已对照原文核对：公式、PoC 与原文一致；原文无受影响版本，frontmatter 无 sources/source_url；PoC 未本机复跑。
url: /docs/crypto/ecc/crypto-ecc-ecdsa-smooth-order-pohlig-hellman/
draft: false
kb_aliases:
- 弱曲线攻击
- 光滑阶 ECDLP
- Pohlig-Hellman 椭圆曲线
- Sage discrete_log
- 基点阶分解
- ECDSA 弱曲线
---

## 一句话结论

自定义/魔改椭圆曲线的基点阶 `n` 若可分解为多个小素数（光滑），ECDSA 的私钥恢复就退化为 ECDLP：用 Pohlig-Hellman 把 `Q = d*G` 拆到各小素数因子的子群分别求解，再用中国剩余定理拼回 `d`；Sage 的 `G.discrete_log(Q)` 会自动走这条路径，`factor(n)` 看到一堆小素数即可确认。

## 原理

- ECDLP：已知 `G`、`Q = d*G`，求 `d mod n`。一般曲线的最佳算法是 Pollard rho，复杂度约 `O(sqrt(n))`。
- 若 `n = p1^e1 * p2^e2 * ...` 且每个 `pi` 很小，Pohlig-Hellman 先在每个 `pi^ei` 子群上求解，再用 CRT 合并；总复杂度由最大素因子决定，而不是 `n`。
- 在 `pi^ei` 子群上，把 `G`、`Q` 乘以 `n/pi^ei` 得到阶为 `pi^ei` 的点，再用逐位/暴力求出 `d mod pi^ei`。
- ECDSA 的 `Q = d*G` 与 ECDLP 完全一致；拿到 `d` 后即可伪造签名/解密。
- 若某个因子等于 `p`（曲线阶 `E.order()==p`），普通 Pohlig-Hellman 仍可能很慢，此时应改用 Smart attack（见关联卡）。
- Sage 的 `discrete_log` 会根据阶的分解自动选择 Pohlig-Hellman/Pollard rho；`G.order()` 与 `factor(n)` 是第一步。

## 触发条件

- 题目给出自定义曲线参数 `p,a,b,G,Q`，且 `n = G.order()` 可分解为小素数。
- 私钥 `d` 直接用于 ECDSA 签名或作为 `Q=d*G` 的离散对数。
- 计算资源足以对最大素因子做 `O(sqrt(pi))` 运算。
- 曲线未使用标准安全曲线（secp256k1/P-256 等）。

## 利用步骤

1. 在 Sage 中定义 `E = EllipticCurve(GF(p), [a,b])`、`G`、`Q`。
2. 计算 `n = G.order()`，用 `factor(n)` 查看分解；若最大因子很大，Pohlig-Hellman 不可行，改用 Pollard rho/其他攻击。
3. 若因子都较小，调用 `d = G.discrete_log(Q)`（Sage 自动 Pohlig-Hellman）；或手动按因子求解 + CRT。
4. 验证 `d*G == Q`。
5. 用 `d` 伪造目标签名/恢复明文；若题目是 ECDSA 签名，按签名公式计算 `r,s`。

## PoC

```python
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = -3
b = 0x64210519e59c80e70fa7e9ab72243049feb8dee14228b359
FF = GF(p)
E = EllipticCurve(FF, [a, b])
G = E(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
      0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)
Q = E(0x62b12d60330bc45687a88b27a6524770f9011c1075a21a4e,
      0x47a10a48b5ff402b8da040aa912803823485ab891a20b085)
n = G.order()
print("n =", n)
print("factors =", factor(n))     # 若是一堆小素数，继续
d = G.discrete_log(Q)             # Sage 自动 Pohlig-Hellman
print("d =", d)
assert d * G == Q
```

## 变体与关联

- 变体：`n` 有多个小因子 + 一个大因子时，可先解小因子部分，再用 Pollard rho 解大因子，CRT 合并。
- 变体：曲线阶 `E.order()==p`（反常曲线）时，Pohlig-Hellman 可能卡在等于 p 的因子，改用 Smart attack。
- 变体：曲线参数被魔改（`a/b/p` 非标准）时，先检查 `E.order()` 是否光滑/是否等于 p，再选算法。
- 关联：[[crypto-ecc-anomalous-curve-smart-attack]]（E.order==p）、[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（大素数阶 Pollard rho）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（nonce 复用）。

## 检测与防御

- 防御：使用标准安全曲线（secp256k1、P-256、Curve25519 等），不要自定义小阶/光滑阶曲线。
- 防御：生成曲线后校验 `n` 为大致数且 `n != p`；使用经过审计的曲线参数与库。
- 检测：配置/代码中出现自定义 `a,b,p`、`G.order()` 可分解为小素数、`E.order()==p`。
- 响应：发现弱曲线后停止使用该曲线，轮换密钥/签名方案，审计历史签名是否可被恢复私钥。
