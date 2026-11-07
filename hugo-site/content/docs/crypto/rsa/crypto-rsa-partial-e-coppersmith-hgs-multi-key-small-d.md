---
id: crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d
title: 同模数多把 RSA 私钥：Coppersmith 补全缺失 e + HGS 小私钥分解 N
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-partial-e-coppersmith-hgs-multi-key-small-d
tags:
- crypto
- rsa
- coppersmith
- hgs
- partial-key
- small-d
- common-modulus
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:49:56+08:00'
  notes: 已对照原文核对；256 bit e 低位 Coppersmith、三把同 n 密钥 HGS d≈n^0.375、E=e0e1e2 解密一致
url: /docs/crypto/rsa/crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d/
draft: false
kb_aliases:
- HGS 攻击
- Howgrave-Graham-Seifert
- 多密钥小私钥
- 部分公钥指数
- Coppersmith 补 e
- 同模数多私钥
---

## 一句话结论

三把损坏的 RSA 私钥共用同一个 1024-bit `n`，其中两把只缺 `e` 的低 256 bit；用 `(e_hi·2^256+x)^3 ≡ fingerprint (mod n)` 的 Coppersmith 小根恢复完整 `e`，再利用三把私钥的 `d` 只有 384 bit（≈`n^0.375`）且共享 `n`，用 Howgrave-Graham–Seifert 多密钥小私钥攻击分解 `n`，最后以 `E=e0·e1·e2` 解密。

## 原理

- **部分 e 恢复**：已知 `e = e_hi·2^256 + x`，`0 ≤ x < 2^256`，且 `e^3 ≡ fingerprint (mod n)`。构造 `f(x)=(e_hi·2^256+x)^3-fingerprint`，在模 `n` 下求小根；`x` 只有 256 bit，远小于 Coppersmith 界（`n` 为 1024 bit，三次多项式界约 `n^(1/3)≈341 bit`），`small_roots(X=2^256, beta=1.0)` 可恢复。
- **HGS 多密钥小私钥**：多把密钥共享 `n`，私钥 `d_i` 满足 `e_i d_i ≡ 1 (mod φ(n))`，即 `e_i d_i - 1 = k_i φ(n)`。若 `d_i` 较小，可用 Howgrave-Graham–Seifert 的格方法同时利用多组 `(e_i, n)` 求 `φ(n)` 的倍数，进而分解 `n`。论文给出的界：两个密钥且 `d < n^0.357` 时可高效恢复；样本增多时界可到 `n^0.5`。本题 `d≈n^0.375`，略高于 0.357，但有三把密钥，仍可解。
- **与 Wiener/Boneh-Durfee 的区别**：Wiener 针对单密钥 `d < n^0.25`；Boneh-Durfee 针对单密钥 `d < n^0.292`；HGS 利用“同一模数、多把密钥”的额外信息，把界推到 `n^0.357` 以上。本题 `d` 约 384 bit，`n` 约 1024 bit，`d≈n^0.375`，单密钥方法不够，必须用多密钥 HGS。
- **分解后**：`φ=(p-1)(q-1)`，`d=inverse(E,φ)`，`m=pow(c,d,n)`；`E=e0·e1·e2` 是题目组合后的指数。
- **为什么成立**：部分 `e` 的未知量小，Coppersmith 可在多项式时间求小根；多密钥共享模数时，`e_i d_i - 1` 与 `φ(n)` 的关系在格中形成短向量，LLL 可恢复 `φ(n)` 的倍数，从而解出 `p/q`。

## 触发条件

- 多个 RSA 密钥共享同一 `n`（common modulus），且至少一个私钥指数 `d` 较小（`d < n^0.357` 左右，密钥越多界越宽）。
- 部分公钥指数 `e` 有已知高位、未知低位足够小（可 Coppersmith）。
- 有 `fingerprint = e^3 mod n` 之类的校验值；有密文 `c` 和组合指数 `E`。
- 能运行 Sage 的 `small_roots` 与格基约减（LLL/BKZ）。
- 损坏的 PEM 仍能解析出共同的 `n` 与残缺 `e`；否则需要先修复/提取。

## 利用步骤

1. 从损坏 PEM 提取共同的 `n` 和残片 `e0/e1_hi/e2_hi`；确认 `e1/e2` 各缺 256 bit。
2. 对每个残片构造 `f(x)=((hi<<256)+x)^3 - fingerprint`，`small_roots(X=2^256, beta=1.0)` 求 `x`；用 `pow(e,3,n)==fingerprint` 校验。
3. 得到 `e0/e1/e2` 后，构造 HGS 多密钥格（多变量多项式、monomials、`construct_relation`），对 `alpha` 从 0.30 到 0.45 逐档尝试 LLL，解出 `φ(n)` 的倍数，进而求 `p/q`（判别式 `s^2-4n` 为完全平方）。
4. 计算 `φ=(p-1)(q-1)`，`d=inverse(e0*e1*e2, φ)`，`m=pow(c,d,n)`，转字节得到 flag `0xGame{Welcome home}`。

## PoC

```python
R.<x> = PolynomialRing(Zmod(n))
B = 2^256

def recover(hi, fp):
    f = ((hi * B + x)^3 - fp).monic()
    roots = f.small_roots(X=B, beta=1.0, epsilon=0.05)
    assert roots, "small_roots failed"
    e = hi * B + int(roots[0])
    assert pow(e, 3, n) == fp
    return e

e1 = recover(e1_hi, fp1)
e2 = recover(e2_hi, fp2)
```

HGS 部分的核心是构造 `L = [[pI_n,0,0],[M_A^T,I_n,0],[-B^T,0,c]]` 之外的多密钥关系格：对每个 `e_i` 建立 `e_i d_i - 1 = k_i φ(n)` 的多项式，按 `construct_relation()` 生成 monomial 行，LLL 后从短向量反推 `φ(n)` 的倍数；原文用 `alpha` 从 0.30～0.45 逐档尝试，判别式开方得到 `p/q`。完整 `hgs_factor()` 较长，建议按论文/原文实现并用 `p*q==n` 校验。

## 变体与关联

- **变体（单密钥小 d）**：Wiener（`d<n^0.25`）、Boneh-Durfee（`d<n^0.292`）；本题 `d≈n^0.375`，单密钥方法不够。
- **变体（部分私钥泄露）**：若已知 `d` 的高位/低位，用部分密钥暴露攻击（Coppersmith）恢复 `d` 或分解 `n`。
- **变体（共模）**：若同一明文用同一 `n`、不同互素 `e` 加密，直接用共模攻击（扩展欧几里得）恢复明文，不需要私钥。
- **关联卡片**：[[crypto-rsa-common-modulus]]（共模攻击）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（Coppersmith 小根与 beta 下调）、[[crypto-rsa-fermat-close-prime-factorization]]（分解）、[[crypto-rsa-pollard-pminus1-smooth-prime]]（分解）。
- **边界**：`d` 超过 HGS 界、密钥样本不足、`e` 缺失位数超过 Coppersmith 界时不可行；PEM 损坏严重/缺失 `n` 时需先恢复；LLL 参数/`alpha` 选错会失败。

## 检测与防御

- **密钥生成**：每个密钥使用独立 `n`，不要复用模数；`n` 至少 2048 bit；`d` 必须足够大（≥`n^0.5` 更安全），避免小私钥。
- **密钥保护**：私钥文件不要部分泄露/损坏后继续使用；发现 `e` 指纹可被验证时，尽快轮换密钥。
- **检测**：审计中搜索共享 `n` 的多把公钥/私钥、异常小的 `d`、损坏 PEM 中的残缺 `e`；CTF 中看到 `fingerprint=e^3 mod n` 与多把同 `n` 私钥时，按本卡先补 `e` 再 HGS。
- **响应**：一旦确认模数复用或私钥部分泄露，视为密钥已失陷，立即吊销/轮换并排查历史密文。
