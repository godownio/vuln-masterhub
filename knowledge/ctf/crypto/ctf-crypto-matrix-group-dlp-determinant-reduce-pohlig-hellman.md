---
id: ctf-crypto-matrix-group-dlp-determinant-reduce-pohlig-hellman
title: 3×3 矩阵群上的离散对数：取行列式把非交换问题降到 F_p*，再 Pohlig-Hellman + CADO-NFS 分解阶并用行列式等式定解
type: scenario
domain: ctf
path: ctf/crypto
technique: matrix-group-dlp-determinant-mapping-pohlig-hellman-det-check
aliases:
- QAQTAT
- 矩阵离散对数
- 行列式降维
- MatrixSpace 上的 DLP
- GF(p^2) 矩阵群
tags:
- ctf
- crypto
- dlp
- matrix-group
- determinant
- pohlig-hellman
- cado-nfs
- crt
- sha256-mask
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:15:53+08:00'
  notes: 已对照原文核对；本次核对未读取图片；3x3 矩阵 GF(p^2) 上的 D=G^s、E=A*T*A、F=D*E*D、key=sum(K[i])、sha256 mask 异或、r 与 s1/s2 常量、det 等式消歧，均与原文 exp 一致；未验证点：卡内 PoC 对原文 pk/F_list/ct 做了占位化（原文为超长矩阵常量），未在本机执行
---

## 一句话结论

当协议用 `3×3` 矩阵在 `GF(p²)` 上做“`D = G^s`、共享密钥 `D·S·D`”的非交换群 Diffie-Hellman 时，对等式两边取行列式就把问题降成素域乘法群里的普通 DLP：`det(D) = det(G)^s`；再用 Pohlig-Hellman 把 `det(G)` 的阶拆成小因子（配 CADO-NFS 解大素因子），最后用行列式等式在多组候选 `s` 里筛出唯一正确解。

## 原理

- 矩阵乘法不交换，`G^s` 的直接 DLP 在一般矩阵群里代价高；但行列式是**乘法同态**：`det(A·B) = det(A)·det(B)`，因此 `det(G^s) = det(G)^s mod p`，把问题映射到 `F_p*` 上的标量 DLP，与 `ctf-crypto-quaternion-norm-dlp-bsgs` 里“用范数降维”的思路同构。
- `F_p*` 的阶是 `p-1`，若可分解为小素因子之积，Pohlig-Hellman 能把每个因子上的 DLP 用小步长解出再 CRT 组合；本例 `(p-1)` 含一个大素因子 `r`，用 CADO-NFS 的 `-dlp -ell r` 单独解该因子上的对数，其余小因子直接算，最后 CRT。
- 映射有核：`det(G)^s` 只决定 `s mod ord(det(G))`，所以得到的是 `s` 的一个同余类，可能有多个候选（本例 6 个：`s + i·(p-1)/6`）。
- 定解靠密文里额外给的 `F = D·E·D`（`E = A·T·A` 已知）：由 `F = G^s·E·G^s` 得 `det(F) = det(G)^{2s}·det(E)`，即 `det(D)² = det(F)/det(E)`。逐个候选 `s` 校验该式（等价于校验 `D.det()*detE*D.det() == detF`），只有正确解满足。
- 密钥派生：`K = D·S·D`，取 `key = sum(K[0]) + sum(K[1]) + sum(K[2])`（矩阵元素在 `GF(p²)` 上的某种整数表示求和），`mask = SHA256(str(key))`，`ct = pt XOR mask`，所以拿到 `s` 即可复现 `D` 并解出明文。

## 触发条件

- 协议用非交换群（矩阵、四元数、扩域元素）做 DH，且公开了“次数”关系 `D = G^s`。
- 群的某个同态映射（行列式/范数/迹）把元素映到可解 DLP 的乘法群，且映射在目标元素上非退化（`det(G) ≠ 0`）。
- 群阶可分解或可部分分解（小因子 Pohlig-Hellman + 大因子专用 NFS）。
- 密文/公钥中另有一个与 `s` 相关的冗余等式可用于消歧。

## 利用步骤

1. 识别群与生成元：确认 `G`、`A`、`T`、`S` 都是同阶矩阵，运算为普通矩阵乘法。
2. 取行列式：`t1 = det(G)`、`t2 = det(D)`，问题变成 `t2 = t1^s mod p`。
3. 分解 `p-1`：小因子直接解 DLP，大素因子 `r` 交给 CADO-NFS `-dlp -ell r`。
4. 用 CRT 组合各因子上的解，得到 `s mod (p-1)`；若 `ord(det(G))` 小于 `p-1`，得到的是同余类，需枚举候选。
5. 对每个候选构造 `D = G^s`，用 `F = D·E·D` 的行列式等式消歧，唯一满足者即真 `s`。
6. 复现 `K = D·S·D`、`key = sum of rows`、`mask = SHA256(str(key))`，异或 `ct` 得明文。

## PoC

```python
# sage 骨架
p = 72887242108660141996862343556330151015969690949835567252527194788428065480383
Fp2.<i> = GF(p^2, modulus=x^2+1)
M = MatrixSpace(Fp2, 3, 3)
A, T, S, G = [M(ii) for ii in pk]
F = M(F_list)

E = A * T * A
detA, detT, detS, detG, detE, detF = A.det(), T.det(), S.det(), G.det(), E.det(), F.det()
r = 2244966557637008779362441591080406338119704738381872153797151   # p-1 的大素因子

# 1) 用 CADO-NFS 解 r 上的对数（t1 = det(G)、t2 = det(D) 由公钥给出）
#    ./cado-nfs.py -dlp -ell r target=<t1^...> <p>   -> 得 s1、s2
Fr = GF(r)
s1 = Fr(1541758195020130454925136833461872657607368759409055632195831)
s2 = Fr(780392429787953543532147509264510635118839088869098098140941)

# 2) 小因子部分直接在 F_p* 上解，再与 r 上的解 CRT
ss = discrete_log(pow(t1, 6*r, p), pow(t2, 6*r, p), operation="*", ord=(p-1)//r)
s = crt([int(ss), int(s1 / s2)], [(p-1)//(6*r), r])

# 3) 用 det(F) = det(D)^2 * det(E) 消歧候选
for ii in range(6):
    cand = s + ii * (p-1)//6
    D = G ** int(cand)
    if D.det() * detE * D.det() == detF:
        K = list(D * S * D)
        key = sum(K[0]) + sum(K[1]) + sum(K[2])
        mask = int(sha256(str(key).encode()).hexdigest(), 16)
        print(long_to_bytes(ct ^^ mask))
        break
```

## 变体与关联

- 变体：映射换成迹（`Tr`）、范数（四元数 `a²+b²+c²+d²`）或特征多项式系数时，只要保持乘法同态就能同样降维。
- 变体：`p-1` 光滑时不需要 CADO-NFS，Pohlig-Hellman 一次解完；`p-1` 含两个大素因子时分别解再 CRT。
- 变体：没有冗余等式消歧时，用“明文含已知 flag 头 + SHA256 mask 校验”逐候选试解。
- 关联：[[ctf-crypto-quaternion-norm-dlp-bsgs]]（范数降维的同构手法）、[[crypto-ecc-twisted-edwards-map-multiplicative-group-dlp]]（曲线上 DLP 映射到 `F_p*`）、[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（Pohlig-Hellman 本身）。
- 边界：`det(G)` 为 0 或阶极小、`p-1` 有超大素因子且无 NFS 资源、映射的核过大导致候选爆炸时，本链代价不可接受。

## 检测与防御

- 本题为 CTF 题，工程侧教训：**不要用非交换群 + 同态可降维的组合做密钥交换**；矩阵/四元数做 DH 必须保证所用生成元的阶足够大且没有廉价同态像（选用无小范数像的元素），否则离散对数可被降到 `F_p*`。
- 协议层：DH 参数应使用标准群（安全素数的子群、椭圆曲线），并对生成元阶做校验。
- 实现层：不要把 `sum` 之类的线性组合直接当 KDF 输入；用 HKDF 处理群元素序列化结果。
