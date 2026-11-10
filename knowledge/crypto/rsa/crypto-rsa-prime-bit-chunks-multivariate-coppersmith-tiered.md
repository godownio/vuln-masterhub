---
id: crypto-rsa-prime-bit-chunks-multivariate-coppersmith-tiered
title: RSA 素数比特分段残缺：一元/二元/三元 Coppersmith 按未知块数分档求解
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-prime-bit-chunks-multivariate-coppersmith
aliases:
- RS-Survey
- 素数中间比特缺失
- 三元 Coppersmith
- Herrmann-May demo10
- p 分段恢复
tags:
- crypto
- rsa
- coppersmith
- multivariate
- herrmann-may
- partial-key
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:18+08:00'
  notes: 已对照原文核对：三层嵌套分别为 p 高384+低384（缺中间256，一元 small_roots）、中间768已知两侧各128未知（二元 bivariate+resultant+gcd）、5 段中 p1/p3/p5 各 64bit 未知（Herrmann-May demo10 + flatter + jacobian），exp 与原文代码结构一致；卡片把原文的 bivariate/multivariate 工具函数简化为调用点并注明需 flatter 与自实现，属正常归纳；未设 affected_versions（CTF 题无版本）；未复跑
---

## 一句话结论

题目只给出素数 `p` 的若干比特段（高位+低位、或中间 768 bit、或 5 段里 3 段各 64 bit 全缺），本质都是“已知部分比特的因子分解”：未知段连续时用一元 `small_roots`、未知段两侧各缺一块时用二元 Coppersmith、未知段被切成 3 个独立小块时用 Herrmann-May 多元格 + Jacobian/Newton 求根，逐档升级即可把 1024 bit 的 `p` 拼回来。

## 原理

- **共同骨架**：已知 `N = p·q` 与 `p` 的比特位掩码泄漏值 `a`，把缺失比特写成若干未知量 `x_i`，构造模 `N` 的多项式并求其小根。因为 `p` 整除 `N`，所以 `f(x) ≡ 0 (mod p)`，`p` 是 `N` 的一个大因子，`small_roots` 的界随未知比特总量与 `beta` 变化。
- **一元档（缺一段连续比特）**：`f(x) = p_h + x·2^k + p_l`，未知量只有 `x` 一个、上界 `2^k`。`beta` 取 0.4~0.5 时 `k` 可达 256 bit 左右（`N` 2048 bit）。
- **二元档（中间已知、两侧各缺一块）**：`f(x,y) = x·2^(1024-k) + p_m·2^k + y`，两个未知量都小于 `2^k`。用二元 Coppersmith（对 `y^h x^i f^j` 组格、LLL 后对消元结果取 `gcd` 再 `roots()`）同时解出 `x`、`y`；本例两侧各 128 bit。
- **三元档（缺多段、彼此不相邻）**：`p` 被切成 `p1|p2|p3|p4|p5`，其中 `p1/p3/p5` 各 64 bit 未知。多项式变成含 3 个变量的线性多项 `f = a + x0·2^960 + x1·2^480 + x2`；用 Herrmann-May 的 `m` 阶移位多项式组（`f^k·N^(t-k)` 按总次数枚举）建格、LLL（维数大时用 `flatter` 代替 Sage 的 `LLL`）得到若干短向量多项式，再用 Jacobian + Newton 迭代或 Gröbner 基在 `ZZ` 上求公共零点。
- **为什么多元可行**：LLL 后的短向量多项式与原多项式在根处同为零（相差 `N` 的倍式），当未知量上界之积小于格的判定阈值时，这些多项式的公共根就是真实根；未知量个数多时格维数与判定阈值同时变差，所以 3×64 bit 已接近手工可解上限。
- **对齐陷阱**：以上所有位移都按 bit 计；`generate_polynomial` 之类工具按十六进制字符模板 `?` 生成，4 bit 一格，写错一位就整条链失败。原文最后一档用一个 `?` 模板字符串生成多项式，正是这个思路的自动化。

## 触发条件

- 已知 `N`、`e`（此处 `e=65537`）与 `p` 的部分比特（分段掩码泄漏）。
- 未知比特总量在 Coppersmith 界内：一元 ≤ `N^(1/e)` 量级对应 `beta` 下的界；多元时未知量个数 ≤ 3、每块 ≤ 64 bit 较稳。
- 能运行 Sage；多元档建议装 `flatter`（LLL 维数上百时 Sage 自带 `LLL` 会非常慢）。
- 密文用 AES 包裹时还需要先解出 `p`、`q` 才能算 `d`。

## 利用步骤

1. 由 `a`（掩码后的 `p`）还原已知比特段：`p_h = a >> (1024 - 384) << (1024 - 384)`、`p_l = a % 2**384` 之类；用 `mask` 的置零位置判断缺口长度。
2. 缺一段连续比特 → 一元：`f = p_h + x*2^k + p_l`，`f.monic().small_roots(X=2^k, beta=0.4)`。
3. 中间已知、两侧各缺 → 二元：`f = x*2^(1024-k) + p_m*2^k + y`，自实现 `bivariate(f, 2^k, 2^k, kk=4~5)`，用 `resultant` + `gcd` 求 `x`、`y`。
4. 缺 3 段各 64 bit → 三元：按模板生成 `f(x0,x1,x2)`，`multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=5)`；LLL 用 `flatter`。
5. 拼回 `p`，`q = N // p`，验证 `p*q == N` 且 `is_prime(p)`；再 `d = inverse(e, (p-1)*(q-1))` 解 RSA 拿 AES key，逐层解密（原文三层嵌套，每层掩码不同，需重跑一遍）。
6. 拿到的 AES key 解 `part_N_encrypted` 之类的密文，得到下一层压缩包，递归处理直到 flag。

## PoC

```python
# sage 10.4；多元档需 flatter
from Crypto.Util.number import long_to_bytes, inverse

# ---- 一元档：缺一段连续比特 ----
p_h = a >> (1024 - 384) << (1024 - 384)
p_l = a % 2**384
R.<x> = PolynomialRing(Zmod(N))
f = p_h + x * 2**384 + p_l
r = f.monic().small_roots(X=2**256, beta=0.4)
p = p_h + int(r[0]) * 2**384 + p_l

# ---- 二元档：中间已知、两侧各缺 unknown bit ----
unknown = 128
p_m = a >> unknown
R.<x, y> = PolynomialRing(Zmod(N))
g = x * 2**(1024 - unknown) + p_m * 2**unknown + y
xr, yr = bivariate(g, 2**unknown, 2**unknown, 5)   # 自实现：LLL + resultant + gcd
p = int(xr) * 2**(1024 - unknown) + p_m * 2**unknown + int(yr)

# ---- 三元档：3 段各 64 bit 未知（见上文的模板生成 + Herrmann-May）----
q = N // p
d = inverse(65537, (p - 1) * (q - 1))
print(long_to_bytes(pow(ct, d, N)))
```

## 变体与关联

- 变体：掩码形状变化时不必换算法，只需重算 `p_h/p_m/p_l` 与未知量系数；三元档可用十六进制 `?` 模板自动生成多项式。
- 变体：多元档若 Jacobian 迭代不收敛，可改用 Gröbner 基（`I.variety(ring=ZZ)`）并加超时枚举子方程组。
- 关联：[[crypto-rsa-multiprime-partial-key-coppersmith]]（高位泄漏 + `beta` 逐档下调）、[[crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits]]（先 CRT 拼出高位再一元求低位）、[[crypto-rsa-bivariate-coppersmith-two-small-roots]]（自实现二元 Coppersmith 的通用写法）。

## 检测与防御

- 防御：不要把素数的任何比特段（掩码结果、高位截断、分块拼接）对外输出；调试日志中打印 `p & mask` 等于直接泄密。
- 防御：密钥生成后按位校验输出内容，禁止十六进制/十进制分段打印；CTF 之外这类“部分比特”泄漏常来自内存 dump 截断。
- 检测：代码里出现 `p >> k`、`p & mask`、`bin(p)[:n]` 等对素数做截取并打印的位置。
- 响应：确认素数部分比特泄露后，该模数必须整体作废并重新生成密钥对。
