---
id: crypto-rsa-crt-hints-small-d-lattice-wiener-like
title: RSA 小私钥 + d 的小素数 CRT 残差：构造 (k1,1,k2) 格恢复 d
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-crt-hints-small-d-lattice
aliases:
- ezRSA2
- NepCTF 2025
- d 的 CRT 残差
- 小私钥格攻击
- 类 Wiener 格
- CRT hints small d
- k1 k2 三维格
tags:
- rsa
- partial-key-exposure
- small-private-exponent
- crt
- lattice
- lll
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V247
  verified_at: '2026-11-07T12:33:08+08:00'
  notes: 已对照原文核对：hints 54 个小素数 CRT、dd/tmp、d=dd+k1*tmp、格 [[K1,0,e*tmp],[0,K2,e*dd-1],[0,0,N+1]]、K1=2^1360/K2=2^1720、d 位长 675=int(2048*0.33) 约束均与原文一致；无 CVE/版本。未验证点：原文未贴最终 flag 输出、未复跑 Sage PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

已知 RSA 私钥 `d` 对前 54 个小素数的余数（CRT 得到 `dd = d mod tmp`，`tmp` 为这些小素数之积），且 `d` 只有 675 位（约 `N^0.33`，单独用 Wiener `N^0.25` 或 Boneh-Durfee `N^0.292` 都覆盖不到）时，把 `e(dd + k1·tmp) - 1 = k2·(N-p-q+1)` 整理成线性组合，构造 3×3 格 `(k1,1,k2)·[[K1,0,e·tmp],[0,K2,e·dd-1],[0,0,N+1]]`，LLL 找到短向量 `(K1·k1, K2, k2·(p+q))`；由第一分量恢复 `k1` 与完整 `d`，再用 `pow(c,d,N)` 解密。

## 原理

- **CRT 残差**：`hints[i] = d mod p_i`（`p_i` 为小素数）。由 CRT 得 `dd = d mod tmp`、`tmp = ∏p_i`，因此 `d = dd + k1·tmp`，`k1` 为未知整数。
- **RSA 关系**：`e·d - 1 = k2·φ(N)`，`φ(N)=N-p-q+1`。代入 `d` 得
  `e·dd - 1 + k1·e·tmp = k2·(N+1) - k2·(p+q)`，
  移项即 `e·dd - 1 + k1·e·tmp + k2·(N+1) = k2·(p+q)`。
- **造格**：把上式看成 `(k1, 1, k2)` 与三列基向量的线性组合。为了让三个分量量级接近、短向量能被 LLL 找到，给 `k1` 与常数项分别乘配平系数 `K1、K2`：
  `(k1,1,k2)·[[K1,0,e·tmp],[0,K2,e·dd-1],[0,0,N+1]] = (K1·k1, K2, k2·(p+q))`。
  取 `K1≈2^1360`、`K2≈2^1720`（原文值）时，三个分量分别约为 `2^1700、2^1720、2^1695`，LLL 可将其识别为短向量。
- **为什么能覆盖 Boneh-Durfee 之外**：`d` 约 675 位而 `N` 约 2048 位，`d` 的比例约 0.33，超过 `N^0.292` 界；但 CRT 残差把 `d` 的低约 300 位“钉死”，只剩 `k1`（约 375 位）未知，等价于把问题缩小到可 LLL 的规模。
- **验证与解密**：从短向量第一分量 `row[0]` 得 `k1 = row[0] // K1`，`d = dd + k1·tmp`；检查 `d.bit_length() == int(2048*0.33)≈675`，再 `m = pow(c,d,N)`、`long_to_bytes(m)`。

## 触发条件

- 已知 `N、e、c`，以及 `d` 对一组小素数的余数（或等价地给出 `d mod tmp` 与 `tmp`）。
- `d` 明显小于 `N` 的安全规模（本例 675/2048 ≈ 0.33），且 `tmp` 足够大，使 `k1` 的未知位数可由 LLL 处理。
- 可使用 SageMath/LLL（原文用 Sage 的 `Matrix(ZZ)` 与 `LLL()`）。

## 利用步骤

1. 收集 hints 与对应小素数列表，计算 `dd = CRT(hints, primes)` 与 `tmp = ∏primes`。
2. 按上式和原文参数设置 `K1=2^1360`、`K2=2^1720`，构造 3×3 整数矩阵。
3. 对矩阵做 LLL，遍历约减后的行；对每行按 `k1 = row[0] // K1` 计算 `d = dd + k1·tmp`。
4. 用两个约束筛选：`d` 的位数应约等于 `N` 位数的 0.33（本例 675 位），且短向量第二分量应等于 `K2`（即 `row[1] == K2`）。
5. 对候选 `d` 解密 `m = pow(c,d,N)`，`long_to_bytes(m)` 应得到可打印 flag；若失败，微调 `K1/K2` 或 `k1` 范围。

## PoC

```python
from Crypto.Util.number import long_to_bytes
from sage.all import Matrix, ZZ, prod, CRT, sieve_base

e = 0x73915608ed64c9cf1a2279684cab4f4a78fba229d45d4f860971a241481363470a19cb0dc0d00f816b5befdaca017cf71483e96ef17b36179012f5194a0e6bf481bb06c2644f74c6812efb65d05c00631f282d6aa55c0bc140a1830b95a1cf4b6024cb0db53f2c2189897c41f22e2eec773723f531ec4bfa537fae6de5fe480cf46fe17850f7eb47df08194d95db3d26ac923b26e110ee645239ab586bbc546ddc5906f280a106edbb727ccb05536b5a3f5c0ebcf865c95ce58be54f7f3547aa53baa218b0dfa98e42d925fa341e45f94a3b16b0c83802660c7f34de3336cb21f219073cf8e9f5e39d47f0a9a9ee7c255f09a6add9a2f7a47960f4a853183d29
N = 0xba8956e81394f3f1265ca5d9c4ad1ab0078bb43c4b80a231ab2cc62246ae45f66a562252622aed2cbbfc08647ef2fec0f97a632bf2242845f4b3af0c427cec3d90f42e90278a5a0feeed0922a8cd2278074ac54e9cfc0e96ff68f8d8f266dd87dc1cc59c2895ec884de2022311767f6a9a7e0bd288c79620e28b83bb3c8d8ad1047c839d6ccf5544eaf434a5f00b951769ab3121298d04b63a162757beb3d49917cd0c9e02ee1ac29398c8130961d5a2f2833aba1e538edb7bb97071f40fae543d1622f0c9206c6d4d8abb2ac1b93ebfb603c2f3a909ede357ade4043550fe540d13a4e87db8d731fe130f15a43a1a00364f5da2d87f7b660c3a04e734218a11
ct = 0x101b284ad196b5bbd3d3df00a7d3577caeb29c681bdd122582b705afc671febf45d4f3786640e55aadd6a31ecc49175f97b772720f1735f8555f768b137a4643cd6958f80a3dfca4d0270ad463d6dde93429940bd2abb5ad8408b0906fa8d776544a1c50cc0d95939bef4c3fb64d0b52dca81ff0f244fc265bfc0bc147435d05f8f1a146e963a1403b3c123b4d6e73d1fd897109995009be1673212607f0ea7ae33d23f3158448b05c28ea6636382eee9436c4a6c09023ead7182ecd55ac73a68d458d726e1abc208810468591e63f4b4c2c1f3ce27c4800b52f7421ccab432c03e88b3b255740d719e40e0226eabb7633d97ed210e32071e2ac36ed17ef442e
hints = [1, 3, 0, 3, 9, 16, 10, 14, 5, 11, 21, 18, 30, 30, 38, 2, 20, 62, 66, 1, 22, 56, 41, 13, 78, 59, 51, 6, 57, 117, 73, 75, 96, 112, 50, 93, 158, 97, 146, 8, 65, 96, 186, 161, 90, 131, 46, 32, 140, 133, 50, 43, 151, 234]

primes = list(sieve_base)[1:len(hints) + 1]
dd = CRT(hints, primes)
tmp = prod(primes)

K1, K2 = 2**1360, 2**1720
Ge = Matrix(ZZ, 3, 3)
Ge[0, 0], Ge[1, 1] = K1, K2
Ge[0, 2] = e * tmp
Ge[1, 2] = e * dd - 1
Ge[2, 2] = N + 1

for row in Ge.LLL():
    d = dd + (row[0] // K1) * tmp
    if int(d).bit_length() == int(2048 * 0.33):
        m = pow(ct, int(d), N)
        print(long_to_bytes(int(m)))
```

说明：原文按 `row[1]==K2` 与 `d` 位数两个约束调参；`K1/K2` 是配平系数，可按实际 `N` 位数/`tmp` 大小缩放。

## 变体与关联

- 变体：若 hints 是 `d mod` 一组较大素数，`tmp` 更大，`k1` 更小，LLL 更容易；若 hints 覆盖的位数不足，需增大格维数或结合其他泄漏。
- 变体：已知 `d` 高位/低位时可用 [[crypto-rsa-d-low-bits-k-enumeration-perfect-square]]、[[crypto-rsa-private-exponent-low-bits-partial-p]]；已知 `dp` 时可用 [[crypto-rsa-dp-leak-enumerate-k-factorization]]。
- 变体：`d` 小于 `N^0.292` 时可直接用 Boneh-Durfee（[[crypto-rsa-boneh-durfee-small-private-exponent]]）；小于 `N^0.25` 时 Wiener（[[crypto-rsa-wiener-small-private-exponent-large-e]]）。
- 边界：LLL 只在配平系数合适时找到短向量；若 `K1/K2` 偏差过大、或 `tmp` 太小导致 `k1` 过大，需调整参数或改用更高维格。

## 检测与防御

- 检测（CTF/审计）：题目同时给出 `n,e,c` 与一串“小素数模 d 的余数”，且 `d` 位数明显偏小，即为部分私钥暴露。
- 防御（密码实现）：私钥 `d` 必须接近 `φ(N)` 的规模（如 2048 位以上）；不要泄露 `d` 对任何模数的余数；密钥生成后检查 `d.bit_length()` 是否达到安全下限。
- 加固：使用标准库/HSM 生成密钥；避免自定义 CRT 提示/调试输出；定期轮换密钥。
