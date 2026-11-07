---
id: crypto-ecc-unknown-curve-point-halving-recover-flag
title: 未知曲线参数 + 点减半：由 2P、P+Q、2Q 恢复 p/b 并反推 P、Q
type: scenario
domain: crypto
path: crypto/ecc
technique: ecc-unknown-curve-point-halving
tags:
- crypto
- ecc
- point-halving
- unknown-curve
- parameter-recovery
- sage
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:19:03+08:00'
  notes: 已对照原文Sage脚本与图14核对：gcd差值恢复p/b、四次方程点减半、P+Q=PQ筛选、x坐标拼接flag均一致；未在本机Sage复跑
url: /docs/crypto/ecc/crypto-ecc-unknown-curve-point-halving-recover-flag/
draft: false
kb_aliases:
- ez_ecc
- 点减半
- point halving
- 未知曲线参数恢复
- 2P P+Q 2Q
- 四次方程求半点
- HECTF ez_ecc
---

## 一句话结论

只给 `2P`、`P+Q`、`2Q` 三条曲线点时，先用 `y²−x³−x` 的差值最大公约数恢复模数 p 与曲线参数 b（曲线形如 `y²=x³+x+b`），再把倍点公式逆成关于 P 的 x 坐标的四次方程，解出每条的半点点候选，最后用 `P+Q=PQ` 筛选唯一组合，取两个 x 坐标转字节拼接即得 flag。

## 原理

- **曲线参数恢复**：曲线 `E: y² = x³ + x + b (mod p)` 上任意点满足 `v = y² − x³ − x ≡ b (mod p)`。因此三个点的 `v1、v2、v3` 两两之差都是 p 的倍数，`p = gcd(v1−v2, v2−v3)`（可能是 p 的倍数，需结合曲线验证/分解）；`b = v1 mod p`。
- **点减半**：已知 `T = 2P`，要求 P。对 `y²=x³+ax+b`，把倍点公式（`x_T = λ²−2x_P`、`λ=(3x_P²+a)/(2y_P)`）消去 y 后，可得到只含 `x_P` 的四次方程。本文曲线 `a=1`，原文给出的四次方程为：
  `x⁴ − 4·x_T·x³ − 2·x² − (8b + 4·x_T)·x + (1 − 4b·x_T) = 0`。
- **候选与验证**：四次方程在 `GF(p)` 上最多 4 个根；对每个根 `rx` 计算 `ry² = rx³ + rx + b`，若为二次剩余则 `ry = sqrt(ry²)`，得到 `(rx, ±ry)` 两个候选；用 `2·Candidate == T` 验证，过滤增根。
- **组合筛选**：分别得到 P 的候选集合与 Q 的候选集合；对每一对 `(P_c, Q_c)` 验证 `P_c + Q_c == PQ`，满足者即真实 P、Q（可能有多个数学解，需用 flag 可解码性筛选）。
- **恢复 flag**：题目把 P、Q 的 x 坐标分别作为明文两段，`long_to_bytes(x_P) + long_to_bytes(x_Q)` 拼接；错误的“影子解”通常无法 UTF-8 解码或不含 flag 格式，正确解输出可读字符串。
- **为什么可行**：题目给的三个点都是倍点/和点，泄露了 P、Q 的线性组合；曲线形式简单（a=1）且模数可通过 gcd 恢复，点减半把“求离散对数”降为“解四次方程 + 小规模枚举”。

## 触发条件

- 已知曲线上的 `2P`、`P+Q`、`2Q`（或类似线性组合），但不知道 p、b 或 P、Q。
- 曲线形式为短 Weierstrass `y²=x³+a·x+b` 且 a 已知/可推断（本文 a=1）；点坐标在 `GF(p)` 上。
- 能恢复 p（差值 gcd）并在 `GF(p)` 上解四次方程/开平方；有 SageMath 或等价代数工具。
- 候选数量小（每步最多 4 个根），可暴力组合；flag 有可识别格式或可 UTF-8 解码。

## 利用步骤

1. **恢复 p/b**：对三个点计算 `v_i = y_i² − x_i³ − x_i`；`p = gcd(v1−v2, v2−v3)`；`b = v1 mod p`；验证三个点都满足 `y² ≡ x³ + x + b (mod p)`。
2. **构造曲线**：在 Sage 中 `E = EllipticCurve(GF(p), [1, b])`，把 `P2、PQ、Q2` 转为曲线点。
3. **点减半**：对 `P2` 解四次方程得到 x 候选，开方得 y 候选，验证 `2*P == P2`；对 `Q2` 同样处理。
4. **组合验证**：遍历 P、Q 候选对，检查 `P+Q == PQ`。
5. **提取 flag**：对满足组合取 `int(P[0])`、`int(Q[0])`，`long_to_bytes` 拼接并尝试 UTF-8 解码；输出可读字符串。
6. **处理多解**：若 p 恢复成倍数或方程有增根，先验证曲线/点，再调整 gcd 分解或用 `E(...)` 过滤。

## PoC

SageMath 核心代码（对应原文脚本）：

```python
P2 = (14964670759245329390375308321411786978157102161189322115734645373169213999800,
      15559632617790587507311758059936601413780195603883582327743315824295031740424)
PQ = (51100085833472068924911572616418783709145128504503165799653950174447959545831,
      34374474833785437488342051727913857907583782324172232648593714071718811330923)
Q2 = (58182088469274002379975156536635905530143308283684486683439461054185269349870,
      60318982918282038994679589134874004093617373250696961967201026789735803518347)

def get_val(pt):
    x, y = pt
    return y**2 - x**3 - x

v1, v2, v3 = get_val(P2), get_val(PQ), get_val(Q2)
p = gcd(v1 - v2, v2 - v3)
b = v1 % p

R = GF(p)
PR.<x> = PolynomialRing(R)
E = EllipticCurve(R, [1, b])

def half_candidates(T):
    xt, yt = T
    poly = x**4 - 4*xt*x**3 - 2*x**2 - (8*b + 4*xt)*x + (1 - 4*b*xt)
    out = []
    for r, _ in poly.roots():
        ry2 = r**3 + r + b
        if not ry2.is_square():
            continue
        ry = ry2.sqrt()
        for sign in (1, -1):
            cand = (r, sign * ry)
            if 2 * E(cand) == E(T):
                out.append(cand)
    return out

for pc in half_candidates(P2):
    for qc in half_candidates(Q2):
        if E(pc) + E(qc) == E(PQ):
            flag = long_to_bytes(int(pc[0])) + long_to_bytes(int(qc[0]))
            print(flag.decode())
```

原文输出：`HECTF{w0000w_Y0U_g0t_th3_ez_Ecc!!!}`。

## 变体与关联

- 变体：曲线 `a≠1` 时把四次方程换成一般 `a` 的倍点逆公式；只给 `P+Q` 与 `2P` 时用 `Q=(P+Q)−P` 验证；模数 p 是 gcd 的因子时需要分解/试除；点减半多解时用已知明文格式筛选。
- 关联：[[crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp]]（未知曲线参数拟合）、[[crypto-ecc-singular-cubic-cusp-additive-group]]（奇异曲线退化）、[[crypto-ecc-anomalous-curve-smart-attack]]（异常曲线 Smart 攻击）、[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（一般 ECDLP）。
- 同题：`simple_math` 用特殊 RSA 模数 + 多层平方根；`ez_rsa` 用相邻素数双模数 + 连分数。

## 检测与防御

- **协议设计**：不要在不可信信道暴露 `2P`、`P+Q`、`2Q` 等线性组合；使用标准曲线（secp256k1/P-256）与成熟库，避免自研曲线。
- **曲线校验**：收到点后做 on-curve 校验、子群校验（禁止小群/无效点）；不要用可被 gcd 恢复参数的弱曲线。
- **密钥生成**：私钥/随机数使用 CSPRNG，避免相关点/倍点泄露；点乘实现防侧信道。
- **CTF 之外**：真实系统若泄露倍点/和点，可能被点减半或离散对数攻击；评估时应把这类点视为敏感信息。
