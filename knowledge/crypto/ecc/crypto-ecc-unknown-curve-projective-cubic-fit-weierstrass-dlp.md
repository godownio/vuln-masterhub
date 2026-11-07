---
id: crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp
title: 黑盒群未知椭圆曲线恢复：采样点射影三次拟合 + Weierstrass 化 + 有界 DLP
type: scenario
domain: crypto
path: crypto/ecc
technique: unknown-curve-projective-cubic-fitting
aliases:
- 未知椭圆曲线参数恢复
- 射影三次曲线拟合
- 黑盒群曲线拟合
- 广义 Weierstrass 化
- fit_projective_cubic
- 有理函数群加法还原曲线
tags:
- crypto
- ecc
- curve-recovery
- projective-geometry
- weierstrass
- discrete-log
- ctf
- sage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:31:26+08:00'
  notes: 已对照原文与 5 张公式图核对：射影三次拟合、M·c=0 右核、Weierstrass 化 a1=-B/s/a3=-E/s、T=Py-Pg1；修正原卡有界 DLP 复杂度表述（原句误写为远低于 O(2^27) 的通用 Pollard rho）；key/flag 为原文结果，未在本机复跑
---

## 一句话结论

题目只给出模数 `p`、两个黑盒有理函数 `have`（群加法）与 `fun`（倍点）、单位元 `g1`、基点 `g2` 和 `y = key·g2` 时，可以先用 `have/fun/have_fun` 采样出一批点，解线性方程组拟合出通过它们的射影三次曲线 `F(X,Y,Z)=0`；确认曲线光滑后把它化为广义 Weierstrass 形式，把点映射过去，再用有界离散对数（key < 2^54，lambda 算法约 O(2^27)）求出 `key`。

## 原理

- **黑盒运算暴露代数群结构**：`have(s,t)` 与 `fun(t)` 都是 `F_p` 上的有理函数（分子分母为多项式，含乘除与高次项），且 `have_fun` 是标准的 double-and-add 标量乘、初始值为 `g1`。这说明 `g1` 是单位元，`have` 是交换群加法，`fun` 是倍点，群是定义在 `F_p` 上的一维代数群。
- **排除加法群/乘法群**：加法群的标量乘应是线性的；乘法群（genus 0）应存在低次有理参数化，运算中只出现乘法和平方。题目的 `have` 含大量混合线性项、二次项与分式叠加，不符合这两类，候选只剩椭圆曲线（genus 1）。
- **三次曲线拟合**：平面三次齐次多项式有 10 个单项式基
  `X^3, X^2Y, XY^2, Y^3, X^2Z, XYZ, Y^2Z, XZ^2, YZ^2, Z^3`。
  把每个采样点按仿射片 `Z=1` 代入 `(X,Y,Z)=(x,y,1)`，得到一行关于 10 个系数的线性方程；N 个点构成矩阵 `M`，曲线系数向量 `c` 是 `M·c=0` 的右核。核维数为 1 说明除整体倍数外只有唯一一条三次曲线通过所有点，排除了偶然拟合；若维数 >1 说明采样不足或点退化，需要补点。
- **光滑性 = 椭圆曲线**：对拟合出的仿射三次方程求 `f_x`、`f_y`，联立 `f=f_x=f_y=0` 解奇异点；解集为空说明曲线光滑，genus=1，是椭圆曲线；若有奇异点则是有理曲线，对应加法群/乘法群的变体（见关联卡片）。
- **广义 Weierstrass 化**：拟合结果形如
  `X^3 + A X^2 Z + B X Y Z + C Y^2 Z + D X Z^2 + E Y Z^2 + F Z^3 = 0`，
  在 `Z=1` 上整理为
  `-C y^2 - (Bx+E)y = x^3 + A x^2 + D x + F`。
  取 `s^2 = -C`（`-C` 必须是 `F_p` 中的平方，否则曲线是二次扭曲，需换处理方式），令 `y' = s y`，则 `-C y^2 = y'^2`，方程变为
  `y'^2 + a1 x y' + a3 y' = x^3 + a2 x^2 + a4 x + a6`，
  其中 `a1=-B/s`、`a2=A`、`a3=-E/s`、`a4=D`、`a6=F`。Sage 的 `EllipticCurve(Fp,[a1,a2,a3,a4,a6])` 可直接识别。
- **点映射与偏移**：把每个黑盒点 `(x,y)` 映射为 `(x, s·y)`。黑盒群单位元 `g1` 在 Weierstrass 模型中可能不是无穷远点，因此求 `key·g2` 时要按 `T = P_y - P_g1`、`G = P_g2` 消去单位元偏移（若 `P_g1` 恰为无穷远点则 `T=P_y`）。
- **有界 DLP**：`key` 被限制在 `2..2^54`，用区间离散对数（lambda 算法）复杂度约 `O(2^27)`；而曲线群阶约 `p≈2^140`，对整个群做通用 Pollard rho 约为 `O(sqrt(p))≈2^70`，因此利用有界信息把计算量降低约 2^43 倍；Sage `discrete_log(..., bounds=(lb,ub), algorithm='lambda')` 可直接解。
- **为什么整体可行**：整条链只依赖“群运算是有理函数”这一结构信息，不需要知道曲线参数；拟合把隐式群还原成显式曲线，Weierstrass 化把自定义运算交给成熟库，最后用小密钥空间把 DLP 降到可计算。

## 触发条件

- 题目/目标给出素数 `p`，以及黑盒群加法 `have(s,t)`、倍点 `fun(t)`、标量乘 `have_fun(a,b)`（或等价的自定义群运算）。
- 能调用这些函数采样点，且曲线是光滑三次曲线（非奇异），定义在素域 `F_p` 上。
- 已知单位元 `g1`、基点 `g2` 和 `y = key·g2`，`key` 空间足够小（示例 `<2^54`）或有其他有界信息。
- 采样点数量 ≥ 9 且分布不退化，使拟合矩阵右核维数为 1；`-C` 在 `F_p` 中可开平方。
- 拟合后能恢复出完整曲线（含低次项）；随后可用 Sage 的椭圆曲线与离散对数工具。

## 利用步骤

1. **采样**：用 `fun` 连续倍点、`have_fun(g2,k)` 取小倍数、`have(g2,y)`、`have(fun(g2),g2)` 等混合运算生成大量点；去重并加入 `g1/g2/y`，保证点分散。
2. **拟合射影三次**：构造 10 个三次单项式基，把每个点 `(x,y,1)` 代入得到矩阵 `M`；求 `M.right_kernel()`。核维数为 1 时取基向量作为系数，得到 `F(X,Y,Z)`。
3. **光滑性检查**：在 `Z=1` 上令 `f=F(x,y,1)`，求 `f_x,f_y`，解理想 `(f,f_x,f_y)`；无解则确认是椭圆曲线。
4. **Weierstrass 化**：提取 `A,B,C,D,E,F`，验证 `-C` 是平方，取 `s=sqrt(-C)`；构造 `a1=-B/s, a2=A, a3=-E/s, a4=D, a6=F`，建立 `E=EllipticCurve(Fp,[...])`。
5. **映射点**：`P(x,y) -> E(x, s*y)`；用 `assert` 验证 `g1/g2/y` 映射后都在 `E` 上。
6. **消偏移**：`G=P_g2`，`T=P_y - P_g1`（`P_g1` 为无穷远点时 `T=P_y`）。
7. **解有界 DLP**：`discrete_log(T, G, bounds=(lb, ub), operation='+', algorithm='lambda')` 得 `key`；用原始 `have_fun(g2,key)==y` 复核。
8. **后续解密**：按题目逻辑用 `key` 派生密钥（示例 `str(key).encode()[:16]` 作 AES-128-ECB key）解密密文。

## PoC

以下为最小化 Sage 骨架（`have/fun/have_fun` 按题面原样代入；示例参数与结果来自原文，未在本机复跑）：

```python
from sage.all import *
p = 1361137685787644823054950239221481267310111
Fp = GF(p)
# have(s,t), fun(t) 按题面定义；have_fun(a,b) 按 double-and-add 定义
# g1, g2, y = 题面给出的点

def fit_projective_cubic(pts):
    R.<X,Y,Z> = PolynomialRing(Fp, 3)
    mons = [X^3, X^2*Y, X*Y^2, Y^3,
            X^2*Z, X*Y*Z, Y^2*Z,
            X*Z^2, Y*Z^2, Z^3]
    M = Matrix(Fp, [[m(x, y0, Fp(1)) for m in mons] for (x, y0) in pts])
    K = M.right_kernel()
    assert K.dimension() == 1, f"kernel dim={K.dimension()}, add more points"
    v = K.basis()[0]
    return R, sum(v[i]*mons[i] for i in range(10))

# 1) sample: fun doubles + small multiples + mixed additions + g1/g2/y
pts = [...]
R, F = fit_projective_cubic(pts)
print(F)

# 2) smoothness: singular ideal has no solution
f = F(X, Y, 1)          # 注意变量替换按实际多项式环
# I = ideal([f, f.derivative(X), f.derivative(Y)]); assert I.variety() == []

# 3) extract A..F0 from F, then:
s = (-C).sqrt()          # 需 -C 为二次剩余
Ecurve = EllipticCurve(Fp, [(-B)/s, A, (-E1)/s, D, F0])
P = lambda pt: Ecurve(Fp(pt[0]), Fp(pt[1]) * s)
Pg1, Pg2, Py = P(g1), P(g2), P(y)

# 4) bounded DLP: y = key*g2 (g1 is identity, subtract its image if finite)
T = Py - Pg1
G = Pg2
key = int(discrete_log(T, G, bounds=(10**15, (1 << 54) - 1),
                       operation='+', algorithm='lambda', verify=False))
assert have_fun(g2, key) == y
print("key =", key)      # 15946553602128288
```

原文验证结果：`key = 15946553602128288`，AES 解密得到 `flag{Tw1s7ed_5tr4nge_Curve_but_S0_3asy}`。

## 变体与关联

- **奇异曲线分支**：若拟合出的三次曲线有奇异点（尖点/节点），群退化为加法群/乘法群，可用参数化直接求标量，见 [[crypto-ecc-singular-cubic-cusp-additive-group]]。
- **正常曲线但阶特殊**：若曲线光滑且阶光滑，用 Pohlig-Hellman，见 [[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]；若 `#E=p`，用 Smart attack，见 [[crypto-ecc-anomalous-curve-smart-attack]]；无特殊结构时用 Pollard rho，见 [[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]。
- **拟合失败变体**：采样点太少/全落在子群会导致核维数 >1，需增加混合运算采样；`-C` 非平方说明曲线为二次扭曲，可在二次扩域上映射或改用其他仿射片；若曲线不是平面三次（高 genus），本方法不适用。
- **密钥空间变体**：若 `key` 不是小空间，可在恢复曲线后用通用 ECDLP；若密钥派生只取十进制字符串前 16 字节，有效熵约 53 bit，仍属可暴力/有界求解范围。
- **边界**：本方法要求能任意调用黑盒群运算并得到 `F_p` 坐标；若运算被限制查询次数、返回压缩/哈希值或曲线带特殊结构导致拟合退化，需调整采样策略。

## 检测与防御

- **CTF/题目侧**：不要把“隐藏曲线参数”当作安全边界；自定义群运算的有理函数会泄露曲线结构。使用标准曲线（secp256k1、P-256、Curve25519）并公开参数。
- **密钥空间**：密钥必须取自足够大的空间（≥128 bit）；不要用 `str(key)[:16]` 这类截断/十进制转换派生 AES key，避免熵损失。
- **实现侧**：对自定义曲线做判别式/光滑性检查，拒绝奇异曲线；校验基点阶为大素数；避免让攻击者无限采样群运算。
- **检测**：短时间内大量群运算/标量乘调用；提交的点呈现低维结构；密钥空间明显偏小（如 `<2^54`）。
- **响应**：若参数已泄露，视为曲线/密钥不安全，轮换密钥并迁移到标准曲线。
