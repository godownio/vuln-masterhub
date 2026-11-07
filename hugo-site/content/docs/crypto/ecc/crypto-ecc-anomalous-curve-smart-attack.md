---
id: crypto-ecc-anomalous-curve-smart-attack
title: ECDSA 反常曲线：E.order()==p 时 Smart attack 线性时间求私钥
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-anomalous-curve-smart-attack
tags:
- ecdsa
- ecc
- smart-attack
- anomalous-curve
- p-adic
- discrete-log
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
  verified_at: '2026-11-06T01:43:49+08:00'
  notes: 已对照原文核对：公式、PoC 与原文一致；原文无受影响版本，frontmatter 无 sources/source_url；PoC 未本机复跑。
url: /docs/crypto/ecc/crypto-ecc-anomalous-curve-smart-attack/
draft: false
kb_aliases:
- 反常曲线攻击
- Smart attack
- E.order() == p
- 迹为 1 的椭圆曲线
- anomalous curve
- p-adic 提升
---

## 一句话结论

当椭圆曲线的点阶满足 `E.order() == p`（反常曲线/anomalous curve）时，ECDLP 可在多项式时间内求解：把曲线提升到 p-adic 域 `Qp`，利用 `p*P`、`p*Q` 落在形式群核中，计算 `phi(P) = -x/y`、`phi(Q) = -x/y`，则私钥 `d = phi(Q)/phi(P) mod p`；Sage 的 SmartAttack 脚本可直接复用。

## 原理

- 正常曲线 `E.order()` 与 `p` 不同；反常曲线满足 `#E(F_p) = p`，其迹 `t = p + 1 - #E = 1`。
- 对反常曲线，ECDLP 可以通过 p-adic 提升线性化：把 `E` 提升到 `Qp`（精度 2 足够），取 `P,Q` 的提升 `P_Qp,Q_Qp`。
- 计算 `p*P_Qp`、`p*Q_Qp`，它们落在提升曲线核中；在形式群坐标下取 `phi(P) = -x_P/y_P`、`phi(Q) = -x_Q/y_Q`（均在 `Qp` 中）。
- 由于 `Q = d*P`，有 `phi(Q) = d*phi(P) mod p`，因此 `d = phi(Q)/phi(P)`，在 `Z_p` 中取整即得私钥。
- 复杂度为 `O(log p)` 级别的 p-adic 运算，远快于 Pollard rho；这是“阶等于 p”这一特殊结构的致命缺陷。
- 若 `E.order()` 的某个因子等于 `p`（多因子情况），也可以在该子群上使用 Smart attack。

## 触发条件

- 自定义/魔改椭圆曲线，`E.order() == p`（或某个因子等于 p）。
- 已知 `G`、`Q = d*G`、`p`、曲线参数。
- 能用 Sage/PARI 做 `Qp(p, 2)` 上的提升与点运算。
- 私钥 `d` 用于 ECDSA/加密，恢复后可伪造签名或解密。

## 利用步骤

1. 在 Sage 中定义 `E = EllipticCurve(GF(p), [a,b])`、`G`、`Q`。
2. 计算 `E.order()`，确认等于 `p`（或 `factor(E.order())` 中含 `p`）。
3. 构造 `Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0,p)*p for t in E.a_invariants()])`。
4. 对 `P`、`Q` 分别 `lift_x` 到 `Eqp`，选择与 `GF(p)` 上 y 坐标一致的分支。
5. 计算 `p*P_Qp`、`p*Q_Qp`，取 `x/y` 并取负得到 `phi_P/phi_Q`。
6. `d = ZZ(phi_Q / phi_P) mod p`，验证 `d*G == Q`。
7. 用 `d` 伪造签名/解密。

## PoC

```python
def SmartAttack(P, Q, p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break
    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp
    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()
    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)
    return ZZ(phi_Q / phi_P)

p = 142347241249764531633512398413340578893
E = EllipticCurve(GF(p), [1, 2])
G = E(112108138241434310034135261314112001, 574768393556534571936413243118947)
Q = E(91248012481024823471024720194821034, 123891248901248910247901248912410)
if E.order() == p:
    print("d =", SmartAttack(G, Q, p))
```

## 变体与关联

- 变体：`E.order() == p + 1` 或 `p - 1` 时不是 Smart attack，需用 MOV/Frey-Rück 等配对攻击或其他结构。
- 变体：`E.order()` 含因子 `p` 时，把 `P,Q` 映射到该 p 阶子群再执行 Smart。
- 变体：曲线定义在扩域 `GF(p^k)` 时，p-adic 提升与形式群公式需相应调整。
- 关联：[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（光滑阶）、[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（大素数阶）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（nonce 复用）。

## 检测与防御

- 防御：使用标准安全曲线；自定义曲线必须校验 `#E != p` 且阶为大素数（或含大素因子）。
- 防御：不要仅检查 `p` 的大小；`E.order()==p` 的反常曲线即使 p 很大也可线性求解。
- 检测：曲线参数/生成脚本中出现 `E.order() == p`、迹 `t=1`、自定义短参数曲线。
- 响应：发现反常曲线后立即更换曲线与密钥，审计历史签名/密文是否可被恢复。
