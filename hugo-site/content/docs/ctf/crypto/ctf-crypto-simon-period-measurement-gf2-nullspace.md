---
id: ctf-crypto-simon-period-measurement-gf2-nullspace
title: Simon 型周期测量恢复隐藏周期：GF(2) 零空间求 80 bit 周期
type: scenario
domain: ctf
path: ctf/crypto
technique: simon-period-measurement-gf2-nullspace
tags:
- crypto
- ctf
- simon
- period-finding
- gf2
- linear-algebra
- nullspace
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:49:58+08:00'
  notes: 已对照原文核对；8 实例 24x10 GF(2) 零空间、80 bit LSB-first 打包与 de970acad204c1714017 一致
url: /docs/ctf/crypto/ctf-crypto-simon-period-measurement-gf2-nullspace/
draft: false
kb_aliases:
- Simon 算法
- 周期测量
- GF(2) 零空间
- 隐藏周期
- 量子周期发现
- LSB-first 打包
---

## 一句话结论

当题目给出多组“测量向量 `y` 与隐藏周期 `s` 在 GF(2) 上正交（`y·s=0`）”的比特串时，把每个实例的向量堆成矩阵求零空间，即可恢复唯一的非零周期 `s`；多个实例拼接后按 LSB-first 打包得到字节串。

## 原理

- **Simon 算法的经典后处理**：Simon 算法的量子部分输出满足 `y·s=0 (mod 2)` 的测量向量；恢复周期只需解 GF(2) 上的线性方程组，不需要量子计算。
- **零空间**：每个 10-bit 测量向量给 `s` 的 10 个比特一个线性约束。每个实例收集 24 条向量，构造 24×10 GF(2) 矩阵；零空间维数为 1 时，唯一的非零解就是隐藏周期（全零解排除）。
- **多实例拼接**：本题 8 个实例的 nullity 均为 1，得到 8 个 10-bit 周期；按实例顺序拼接成 80 bit，再按 LSB-first 打包成 10 字节（本题为 `de970acad204c1714017`）。
- **为什么成立**：测量向量与周期的正交关系是线性的；向量数量足够多时，约束空间被压到 1 维。位宽、实例顺序和打包端序由题目 JSON 给出，按此解析即可。
- **边界**：若零空间维数 >1（约束不足），需要更多测量向量或额外信息；若向量解析位序/端序错误，会得到错误周期；全零向量不提供约束。

## 触发条件

- 有若干组测量向量，已知每组与同一隐藏周期 `s` 正交；位宽/实例数已知（本题 8 实例 × 10 bit）。
- 每个实例的向量数量足以让零空间维数为 1（本题每实例 24 条）。
- 周期在 GF(2) 上非零；拼接顺序和打包端序（LSB-first）由题目给出。
- 能运行 Sage/GF(2) 线性代数。

## 利用步骤

1. 按 JSON 的 `instance_count`、`secret_bits`、`samples` 解析每个实例的向量，把字符串转为 GF(2) 行向量。
2. 对每个实例构造矩阵，求右零空间；断言 `nullity==1`，取非零基向量作为该实例周期。
3. 按实例编号顺序拼接 8 个 10-bit 周期为 80 bit。
4. 按 LSB-first 打包成字节（每 8 bit 取低位在前），得到 `de970acad204c1714017`。
5. 用该字节串作为后续容器/载荷的输入（本题用于 QFLAC2 的 auxiliary 派生）。

## PoC

```python
# Sage
rows = [vector(GF(2), [int(c) for c in s]) for s in samples]
M = matrix(GF(2), rows)
B = M.right_kernel().basis()
assert len(B) == 1
period = ''.join(str(int(x)) for x in B[0])
print(period)
```

```python
# 拼接 8 个 10-bit 周期后按 LSB-first 打包
bits = ''.join(periods)            # 80 bit
out = bytearray()
for i in range(0, len(bits), 8):
    byte = 0
    for j, b in enumerate(bits[i:i+8]):
        byte |= (int(b) << j)      # LSB-first
    out.append(byte)
print(out.hex())                   # de970acad204c1714017
```

## 变体与关联

- **变体（Bernstein-Vazirani）**：测量结果是 `y·s` 的线性函数，同样用 GF(2) 线性代数恢复 `s`。
- **变体（约束不足）**：零空间维数 >1 时，枚举候选或增加测量；也可结合已知明文/格式校验筛选。
- **变体（位序/端序）**：MSB-first/LSB-first、实例顺序、字符串左右方向都会影响结果，需按题目 JSON/说明核对。
- **关联卡片**：[[crypto-aes-gcm-nonce-reuse-keystream-xor]]（同一挑战中利用该周期派生 auxiliary 明文）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（另一种线性代数/格攻击）。
- **边界**：真实量子 Simon 算法需要量子硬件；本题是“测量数据已给出”的经典后处理。若向量有噪声/缺失，需要纠错或更多样本。

## 检测与防御

- **CTF 识别**：看到“每条测量向量与周期正交”“Simon”“period”以及 GF(2) 位串，优先构造矩阵求零空间。
- **密码设计**：不要依赖隐藏周期结构作为安全假设；后量子密码使用标准 PQC 算法（格、哈希、编码）。
- **数据校验**：对恢复出的周期用后续格式/校验值验证（本题用 FLAC 头/GCM 异或结果验证），避免位序错误。
