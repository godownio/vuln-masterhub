---
id: crypto-ecc-twisted-hessian-curve-weierstrass-pohlig-hellman
title: Twisted Hessian 曲线已知点反解参数 d：双有理映射到 Weierstrass 后用 Pohlig–Hellman 求 DLP
type: scenario
domain: crypto
path: crypto/ecc
technique: twisted-hessian-to-weierstrass-pohlig-hellman
aliases:
- TH_Curve
- Twisted Hessian 曲线
- 扭曲 Hessian 曲线离散对数
- Hessian 曲线转 Weierstrass
- 双有理映射 ECDLP
- Pohlig-Hellman 曲线
tags:
- crypto
- ecc
- twisted-hessian
- weierstrass
- birational-map
- pohlig-hellman
- discrete-log
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:19+08:00'
  notes: 已对照原文 TH_Curve 段核对：d=(2x1^3+y1^3+1)/(x1y1)、a1..a6 双有理映射系数、phi 映射公式、Pohlig–Hellman+CRT 与输出 e@sy_cuRvL_c0o! 均一致。原文脚本有切片/位运算转录错误，卡片已注明按标准 PH 重写骨架；未在 Sage 复跑。
---

## 一句话结论

题目给出 Twisted Hessian 曲线 `a·x³ + y³ + 1 = d·x·y` 上的若干点而不直接给参数 d 时，可由已知点反解 `d = (a·x³ + y³ + 1)/(x·y)`；再用双有理变换把曲线和点映射到 Weierstrass 形式，对光滑的曲线阶做 Pohlig–Hellman 分解 ECDLP，最后用 CRT 合并各素因子子群的离散对数即可恢复私钥/明文。

## 原理

- **曲线模型与参数恢复**：Twisted Hessian 曲线的射影方程为 `a·X³ + Y³ + Z³ = d·X·Y·Z`；取仿射坐标 `Z=1` 得 `a·x³ + y³ + 1 = d·x·y`。只要知道曲线上一个非退化点 `(x1,y1)` 和系数 `a`，就能直接解出 `d = (a·x1³ + y1³ + 1) · (x1·y1)⁻¹ mod p`；不需要暴力搜索。
- **双有理等价**：Hessian 曲线与 Weierstrass 曲线 `v² + a1·u·v + a3·v = u³ + a2·u² + a4·u + a6` 之间存在双有理映射。将 `d` 代入固定公式得到 `a1,a2,a3,a4,a6`，再把已知点按 `u = f(x,y)`、`v = g(x,y)` 映射过去，得到 Weierstrass 模型上的基点 `G` 和目标点 `Q`。双有理映射在除有限个例外点外保持群运算，因此原曲线上的 DLP 等价于 Weierstrass 曲线上的 DLP。
- **Pohlig–Hellman**：若 `#E(F_p) = ∏ q_i^{e_i}` 的素因子都不大（光滑阶），对每个 `q_i^{e_i}` 计算 `t = n / q_i^{e_i}`，把 `G、Q` 分别乘以 `t` 投影到该素因子子群，用 `discrete_log`/BSGS 求出私钥模 `q_i^{e_i}` 的余数，最后 CRT 合并得到完整私钥。
- **为什么成立**：参数 d 由公开点唯一确定；曲线模型变换保持群结构；阶光滑时 ECDLP 的复杂度从 `O(√n)` 降为各小素因子子问题之和。三者叠加使原本“不可解”的曲线 DLP 变成可计算问题。

## 触发条件

- 题目给出 Hessian/Edwards/Montgomery 等非 Weierstrass 曲线模型上的点，参数（如 `d`）未直接给出，但可由已知点方程反解。
- 曲线阶 `#E(F_p)` 可计算且分解后各素因子足够小，`discrete_log`/BSGS 可在可接受时间内求解。
- 攻击者能使用 SageMath（`EllipticCurve`、`factor`、`discrete_log`、`crt`）或等价的 ECC 库。
- 私钥/标量就是最终目标（共享密钥、AES key 派生输入等）。

## 利用步骤

1. 写出曲线方程，代入已知点反解缺失参数。以 `a=2` 的 Twisted Hessian 为例：`d = (2*x1**3 + y1**3 + 1) * inverse(x1*y1, p) % p`。
2. 按该模型的固定双有理变换公式计算 Weierstrass 系数 `a1,a2,a3,a4,a6`，并映射基点 `G` 与目标点 `Q`；检查映射后的点确实满足 Weierstrass 方程。
3. `E = EllipticCurve(GF(p), [a1,a2,a3,a4,a6])`，计算 `n = E.order()`，分解 `n`；筛选出可用 `discrete_log` 处理的素因子（大因子需 BSGS/题目提示/私钥范围）。
4. 对每个素因子幂 `mod = q**e`：`t = n // mod`，`dlog = discrete_log(t*Q, t*G, operation='+')`，记录 `(dlog, mod)`。
5. `x = crt(remainders, moduli)`；若私钥还有未处理的大因子导致多解，结合题目给定范围或额外校验（哈希、AES 明文格式）筛选 `x + k·L`。
6. `long_to_bytes(int(x))` 或按题目要求转成 AES key/共享密钥，完成后续解密。

## PoC

```python
# SageMath；参数与点取自题目，映射公式按所选 Hessian 模型固定
p = 10297529403524403127640670200603184608844065065952536889
a = 2
x1, y1 = 8879931045098533901543131944615620692971716807984752065, 4106024239449946134453673742202491320614591684229547464
x2, y2 = 6784278627340957151283066249316785477882888190582875173, 6078603759966354224428976716568980670702790051879661797

d = (a*x1**3 + y1**3 + 1) * inverse_mod(x1*y1, p) % p

D = a - d**3 / 27
a1 = -3 * (d/3) / D
a2 = -9 * (d/3)**2 / D**2
a3 = -9 / D**2
a4 = -27 * (d/3) / D**3
a6 = -27 / D**4

E = EllipticCurve(GF(p), [a1, a2, a3, a4, a6])
def phi(x, y):
    den = d*x/3 + y + 1
    u = (-3 / D) * x / den
    v = (-9 / D**2) * (-y) / den
    return E(u, v)

G, Q = phi(x1, y1), phi(x2, y2)
n = E.order()
moduli, residues = [], []
for q, e in factor(n):
    if q > 2**40:          # 大因子按题目提示/BSGS 处理，或先跳过
        continue
    mod = q**e
    t = n // mod
    residues.append(discrete_log(t*Q, t*G, operation='+'))
    moduli.append(mod)
x = crt(residues, moduli)
print(x)
print(bytes.fromhex(hex(int(x))[2:].zfill(2)))
```

```text
# 该题最终解出的字节串示例：b'e@sy_cuRvL_c0o!'
# 说明：文章脚本中存在位运算/切片转录问题，以上为按 Pohlig-Hellman 标准流程重写的骨架；
# 若存在未处理的大素因子，需要结合题目私钥范围或额外校验枚举 x + k*L。
```

## 变体与关联

- **曲线模型变体**：Twisted Edwards、Montgomery、Hessian 曲线都有到 Weierstrass 的双有理映射；先找对应公式，再套 PH。
- **参数未知变体**：若 `a`、`d` 都未知，可用多个已知点联立方程（或采样点拟合射影三次曲线）恢复参数，再映射。
- **阶不光滑变体**：最大素因子过大时，Pohlig–Hellman 只能求出部分余数；若私钥有范围/低位泄露，用 BSGS/格方法补全；否则需换攻击面。
- **关联卡片**：[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（光滑阶 PH 基础）、[[crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp]]（未知曲线拟合 + Weierstrass 化）、[[crypto-ecc-twisted-edwards-map-multiplicative-group-dlp]]（Edwards 曲线映射到乘法群）、[[crypto-ecc-invalid-point-secp256k1-bsgs]]（小范围 ECDLP 的 BSGS）。
- **边界**：曲线阶含超大素因子、映射退化点（分母为 0）、或题目未给足够点恢复参数时，本链不成立或只能部分恢复。

## 检测与防御

- **CTF/设计视角**：不要使用光滑阶曲线；选择阶含大素因子的标准曲线（如 secp256k1/P-256），并公开参数而不是让攻击者反解。
- **实现视角**：曲线参数应由可信标准给出；自定义曲线需验证阶的素因子、嵌入度、异常点（supersingular/anomalous）等安全性质。
- **检测信号**：题目给出非 Weierstrass 模型上的点且参数缺失；曲线阶可分解为大量小素数；出现 `discrete_log`、`crt`、`factor(E.order())` 等解题特征。
- **取证/审计**：遇到自定义 ECC 协议，先恢复曲线参数与群阶，再检查阶是否光滑、是否存在小主子群；不要只验证点是否在曲线上。
