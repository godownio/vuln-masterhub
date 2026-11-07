---
id: ctf-crypto-dilithium-like-exact-t-as-linear-system-secret-recovery
title: 类 Dilithium 签名缺少误差项：t = A·s 精确线性方程组在 Z_q 上直接解出私钥
type: scenario
domain: ctf
path: ctf/crypto
technique: dilithium-like-exact-t-as-linear-system-secret-recovery
aliases:
- 格中余响
- Dilithium 类签名私钥恢复
- t=A·s 精确等式
- 负循环卷积矩阵
- 模 q 高斯消元恢复 s
tags:
- crypto
- lattice
- dilithium
- signature
- linear-algebra
- negacyclic
- gaussian-elimination
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:44:40+08:00'
  notes: 已对照原文核对：t=A·s 缺误差项、负循环卷积 64×64 矩阵拼成 128×128、模 q 高斯消元中心化得 [-2,2] 系数、HMAC 校验与 02.png 输出一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

类 CRYSTALS-Dilithium 的格签名若把公钥关系写成精确的 `t = A·s`（没有 Dilithium 的误差项 `s2`、也没有高低位舍入），验证等式 `w = A·z - c·t` 就退化为关于私钥 `s` 的线性方程组；攻击者用 `rho` 展开矩阵 `A`，把负循环多项式乘法转成 64×64 矩阵拼成 128×128 线性系统，在模 `q` 下高斯消元即可唯一恢复 `s`，再用 HMAC 封存校验确认。

## 原理

- **方案结构**：工作在 `R_q = Z_q[x]/(x^64+1)`，`A` 为 `k×l` 多项式矩阵（本题 2×2），由 `rho` 经 SHAKE-256 展开；公钥 `t = A·s`，签名 `z = y + c·s`（`y` 为随机 nonce，`c` 为稀疏挑战）。
- **验证等式**：`w = A·z - c·t = A·(y + c·s) - c·t = A·y + c·(A·s - t)`。要验证通过，必须 `t = A·s`。
- **破绽**：真实 Dilithium 的 `t = A·s1 + s2`，误差项 `s2` 与高低位舍入使 `t = A·s` 不精确，无法直接线性求解；本题去掉了误差项，等式精确成立，等价于把私钥恢复问题降级为模 `q` 线性代数。
- **负循环卷积矩阵**：多项式 `a` 乘 `s` 在 `R_q` 中对应矩阵 `M[i][j] = a[i-j] (i≥j)`，`M[i][j] = -a[i-j+64] (i<j)`（越界变号）。把 `A` 的每个多项式块转成 64×64 矩阵，拼成 `(k·64)×(l·64)` 的 `B`，未知量为 `s` 的 `l·64` 个系数，右端为 `t` 的 `k·64` 个系数。
- **求解与验证**：`B·s = t (mod q)` 是方阵（本题 128×128）；对增广矩阵做模 `q` 高斯消元，得到唯一解，再把系数中心化到 `[-q/2, q/2]`。恢复出的系数全部落在 `[-2,2]`，与 `eta=2` 吻合；用该 `s` 走 `open_sealed` 的 HMAC 校验通过，证明与真实私钥一致。
- **为什么能唯一解**：`A` 由哈希展开、块矩阵在模素数 `q` 下满秩；方程数与未知量数相等，且没有误差项，因此解唯一。

## 触发条件

- 目标使用 Dilithium/ML-DSA 类格签名，但实现中缺少误差项 `s2` 或高低位舍入，公钥关系退化为 `t = A·s`。
- 攻击者能获得公钥 `(rho, t, q, k, l, n)` 与至少一份签名/封存数据。
- `A` 的展开算法与参数（SHAKE-256、域分隔符、系数采样方式）公开或可从代码还原。
- `q` 为素数，矩阵可逆；否则需要处理奇异/欠定情况。

## 利用步骤

1. 从公钥读取 `n, q, k, l, rho, t`；按 verifier 的 `expand_matrix` 逻辑用 SHAKE-256 展开 `A`。
2. 对每个多项式块 `A[r][c]` 构造 64×64 负循环矩阵 `M`：`i>=j` 取 `a[i-j]`，`i<j` 取 `-a[i-j+64] mod q`。
3. 拼成 `(k·n)×(l·n)` 的矩阵 `B`，右端 `rhs` 为 `t` 的各多项式系数。
4. 在模 `q` 下对增广矩阵做高斯消元（选主元、求逆、消元），得到解向量。
5. 把每个系数中心化：`x > q//2` 时减 `q`；检查系数是否落在 `[-eta, eta]`（本题 `[-2,2]`）。
6. 把解按 `l` 个多项式重组为 `s`，序列化为签名字节（每个系数 1 字节有符号小端）。
7. 用 `s` 重算 `seed = SHA256(serialize_s(s) + "|ge-zhong-yu-xiang|v1")`，派生 `mac_key`，校验 `sealed` 的 HMAC tag；通过后解密 `ct` 得明文。
8. 若矩阵奇异，检查 `q` 是否为素数、`A` 展开的域分隔符/字节序是否正确，或增加签名样本联立方程。

## PoC

```python
import hashlib, hmac, base64

def expand_matrix(rho, n, q, k, ell):
    matrix = []
    for row in range(k):
        cr = []
        for col in range(ell):
            stream = hashlib.shake_256(rho + b"|A|" + bytes([row, col])).digest(n * 3)
            poly = [int.from_bytes(stream[3*i:3*i+3], "little") % q for i in range(n)]
            cr.append(poly)
        matrix.append(cr)
    return matrix

def mulmat(a, n, q):
    M = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            d = i - j
            M[i][j] = a[d] % q if d >= 0 else (-a[d+n]) % q
    return M

# 组装 B (k*n x l*n) 与 rhs，模 q 高斯消元
# 解中心化后得到 s；再用 open_sealed 校验 HMAC
```

原文恢复出的 `s` 系数全部在 `[-2,2]`，`open_sealed` 的 HMAC tag 校验通过并输出 `flag{...}`；未在本机复跑。

## 变体与关联

- **误差项变体**：真实 Dilithium 有 `s2`，需用 LLL/BKZ 解带误差的 LWE/线性系统，不能直接高斯消元。
- **舍入变体**：若验证使用高低位舍入（`HighBits`/`LowBits`），需处理模 `q` 的舍入误差。
- **矩阵变体**：`k≠l` 时用最小二乘/超定方程；`A` 不可逆时联立多份签名。
- **关联**：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（带误差的格问题）、[[crypto-zk-*]]（格签名/零知识）；本卡强调“缺少误差项导致精确线性方程”这一设计缺陷。

## 检测与防御

- 实现标准 Dilithium/ML-DSA，保留 `s2` 误差项与高低位舍入；不要用“精确 `t=A·s`”的简化版。
- 对签名方案做安全审计：检查公钥关系、验证等式、挑战生成与 nonce 是否可预测。
- 检测：公钥/签名参数与标准 Dilithium 不一致、`t` 可由 `A·s` 精确解出、`s` 系数分布异常集中。
