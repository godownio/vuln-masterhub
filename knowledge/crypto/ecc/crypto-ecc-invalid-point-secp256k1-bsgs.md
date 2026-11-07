---
id: crypto-ecc-invalid-point-secp256k1-bsgs
title: 无效点攻击：G 不在题给曲线上仍按公式标量乘，小 k 用 BSGS 解 ECDLP
type: scenario
domain: crypto
path: crypto/ecc
technique: invalid-point-scalar-multiplication-bsgs
aliases:
- Invalid curve attack
- 无效曲线攻击
- 无效点
- G 不在曲线上
- secp256k1 标准基点
- 小蓝鲨的数学题
tags:
- crypto
- ecc
- invalid-curve
- point-validation
- bsgs
- ecdlp
- secp256k1
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:41:42+08:00'
  notes: 已对照原文沉迷数学的小蓝鲨核对并本机复跑：secp256k1 p、a=3、G 为 secp256k1 基点、按公式 add/mul、BSGS k<2^32、md5(hex(k))；复跑得 k=954761，flag=ISCTF{43896099...} 与原文一致。已修正卡片：原文称 Q 满足 b=27 与实算不符，实算 G 与 Q 都不在 b=27，而满足同一条 a=3 的 b' 曲线（b'=66385...）；已补 isqrt/hashlib 导入与除零保护
---

## 一句话结论

当自定义椭圆曲线实现只按短 Weierstrass 点加/倍点公式计算、却不校验输入点是否满足 `y² = x³ + ax + b` 时，攻击者可使用不在曲线上但共享同一 `a` 的点作为生成元；若标量 k 较小（示例 k < 2³²），用 BSGS 在这些“无效点”轨道上求解 `Q = kG` 即可恢复 k，并以 `md5(hex(k))` 等形式得到 flag。

## 原理

- **点加公式只依赖 a**：短 Weierstrass 曲线 `y² = x³ + ax + b` 的点加斜率公式为 `λ = (y₂-y₁)/(x₂-x₁)`（倍点为 `(3x₁²+a)/(2y₁)`），只用到系数 a，不使用 b；b 只决定点是否在曲线上。
- **缺失校验的后果**：如果实现只检查坐标范围、不验证 `y² = x³ + ax + b`，则任意点都能进入标量乘。对固定点 G 反复使用同一套公式，会得到一条确定的“轨道”；即使 G 不满足题目声明的 b，轨道仍可计算。若 Q 由同一公式生成，`Q = kG` 的离散对数问题就可在这个轨道上求解。
- **示例参数冲突**：题目曲线写作 `y² = x³ + 3x + 27 (mod p)`，但使用的 G 是 secp256k1 标准基点（secp256k1 实际为 a=0、b=7）。按题给 a=3 实算，G 与 Q 都不满足 b=27，二者反而满足同一条 `y² = x³ + 3x + b'`（b' = 66385389407800359838405813331870212727788158969948345552414605934650319155613 mod p）；原文注释称 Q 满足 b=27 与实算不符。关键是实现未做 on-curve 校验，点加公式只依赖 a=3，G 与 Q 在同一轨道上，因此可按公式枚举 k。
- **小标量空间**：k 被限制在 `[0, 2³²)`，BSGS 以 `m ≈ sqrt(N)` 的时间和空间求解：先建 `jG` 表，再从 Q 开始每次加 `-mG`，命中即 `k = i*m + j`。
- **为什么是安全问题**：标准 ECC 实现必须在接受外部点前验证曲线方程与子群归属；跳过校验会允许无效曲线/无效点攻击，把大群上的 ECDLP 降级到小阶子群或可控轨道。

## 触发条件

- 自定义/非标准 ECC 实现，点加、倍点、标量乘自行实现，且缺少 `y² = x³ + ax + b (mod p)` 与子群阶校验。
- 标量 k 较小或落在可枚举范围（示例 < 2³²），使 BSGS/Pollard rho 可行。
- 攻击者知道曲线参数（p、a、b）与基点/目标点，能提交或计算无效点。
- 目标使用标准曲线基点等已知点，但曲线 b 与标准值不同（示例 b=27 vs secp256k1 b=7）。

## 利用步骤

1. 读取题目曲线方程与参数，确认实现只使用 a 计算点加/倍点，未校验 b。
2. 选择已知的标准基点 G（即使它不满足题给 b），或构造共享同一 a 的无效点。
3. 实现与目标一致的 `add`/`mul`（只用 a，不检查曲线方程），验证 `Q` 在该轨道上。
4. 估算 k 的范围 N；用 BSGS：`m=isqrt(N)+1`，建 `jG` 表，计算 `-mG`，从 Q 迭代相加查找碰撞。
5. 得到 k 后按题目要求格式化（示例 `md5(hex(k))`）得到 flag；若 k 超范围，换更大 N 或 Pollard rho。

## PoC

```python
from math import isqrt
import hashlib

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # secp256k1 p
a, b = 3, 27
Gx = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
Gy = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
Qx = int("a61ae2f42348f8b84e4b8271ee8ce3f19d7760330ef6a5f6ec992430dccdc167", 16)
Qy = int("8a3ceb15b94ee7c6ce435147f31ca8028d1dd07a986711966980f7de20490080", 16)
G, Q = (Gx, Gy), (Qx, Qy)

def add(P, Qp):                     # 只用 a，不校验 b
    if P is None: return Qp
    if Qp is None: return P
    x1, y1 = P; x2, y2 = Qp
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P != Qp:
        denom = (x2 - x1) % p
        if denom == 0: return None
        lam = (y2 - y1) * pow(denom, -1, p) % p
    else:
        denom = (2*y1) % p
        if denom == 0: return None
        lam = (3*x1*x1 + a) * pow(denom, -1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    return (x3, (lam*(x1 - x3) - y1) % p)

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

def bsgs(G, Q, N):
    m = isqrt(N) + 1
    table = {}
    P = None
    for j in range(m):
        table.setdefault(P, j)
        P = add(P, G)
    mG = mul(m, G)
    factor = (mG[0], (-mG[1]) % p)
    R = Q
    for i in range(m + 1):
        if R in table:
            return i*m + table[R]
        R = add(R, factor)

k = bsgs(G, Q, 2**32)
print("ISCTF{%s}" % hashlib.md5(format(k, "x").encode()).hexdigest())
```

原文解得 k 后输出：

```text
ISCTF{43896099feea21a3d5804863075e1aaa}
```

## 变体与关联

- 标准无效曲线攻击：攻击者向服务端提交小阶无效点 P，服务端返回 `d*P`，在小子群上解 DLP 后用 CRT 组合私钥 d；本卡是“固定 G 无效 + 小标量 BSGS”的变体。
- 曲线变体：同一 a、不同 b 的 twist 曲线；b 不参与点加公式，因此同一套代码可作用于多个 b。
- 关联：[[crypto-ecc-anomalous-curve-smart-attack]]（反常曲线）、[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（光滑阶）、[[crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp]]（未知曲线恢复）。
- 边界：若实现校验 on-curve 与子群阶、或 k 很大（256 bit），BSGS 不可行；需要真正的无效曲线小阶子群 + CRT。

## 检测与防御

- 检测：代码中是否存在 `y*y % p == (x*x*x + a*x + b) % p` 校验、子群阶检查；外部点是否直接进入标量乘；曲线 b 是否与标准参数一致。
- 防御：所有外部点必须通过曲线方程校验、子群阶校验（`n*P == O`）与 cofactor 检查；使用 vetted 库（如 libsodium、OpenSSL）而非自实现点运算。
- 加固：拒绝非标准曲线参数；标量空间使用完整 256 bit 并做常量时间实现；对无效点返回统一错误，避免侧信道。
