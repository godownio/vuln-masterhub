---
id: crypto-classical-hill-cipher-3x3-matrix-inverse-mod26
title: Hill 密码 3×3 矩阵求逆模 26 解密
type: scenario
domain: crypto
path: crypto/classical
technique: hill-cipher-3x3-matrix-inverse-mod26
tags:
- crypto
- classical
- hill
- cipher
- matrix
- mod26
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:33+08:00'
  notes: 已对照原文「hiller」核对并复算 PoC：K=[[1,2,3],[0,1,2],[3,1,2]]、det=3、3^{-1} mod 26=9，密文 MHZMXJNNN 分块得 [6,17,8]/[4,25,12]/[0,13,13] => GRIEZMANN，复算输出一致，flag{GRIEZMANN} 正确。未验证点：未持附件复跑；无版本/CVE；frontmatter 无 sources/source_url。
url: /docs/crypto/classical/crypto-classical-hill-cipher-3x3-matrix-inverse-mod26/
draft: false
kb_aliases:
- Hill 密码
- 希尔密码
- 矩阵加密
- 模 26 矩阵求逆
- GRIEZMANN
---

## 一句话结论

当 Hill 密码给出 3×3 密钥矩阵与密文时，把字母映射为 0..25、每 3 个字符组成列向量，求密钥矩阵在模 26 下的逆矩阵（`det` 必须与 26 互素），再逐块乘回即可得到明文；本题密钥行列式为 3、逆元为 9，密文 `MHZMXJNNN` 解出 `GRIEZMANN`。

## 原理

- **Hill 密码**：把明文分成 n 个字母一组，映射为 0..25 的向量 `p`，用 n×n 密钥矩阵 `K` 加密：`c = K·p mod 26`。解密需要 `K` 在模 26 下可逆，即 `gcd(det(K), 26)=1`。
- **模逆与伴随矩阵**：`K^{-1} = det(K)^{-1} · adj(K) mod 26`，其中 `adj(K)` 是余子式矩阵的转置；本题 `det(K)=3`，`3^{-1} mod 26 = 9`，所以逆矩阵每个元素乘 9。
- **分块解密**：密文 `MHZMXJNNN` 按 3 个字符分块 `MHZ`、`MXJ`、`NNN`，每块转数字向量后乘 `K^{-1}`，得到 `[6,17,8]`、`[4,25,12]`、`[0,13,13]`，对应 `GRI`、`EZM`、`ANN`，拼接为 `GRIEZMANN`。
- **为什么成立**：矩阵乘法在模 26 下是线性的，逆矩阵存在时解密是确定性的；字母表顺序（A=0 或 A=1）和分组方式必须与加密方一致。
- **边界**：`det` 与 26 不互素时矩阵不可逆（如 det 为偶数或 13 的倍数），需要换模数/字母表或已知明文攻击；密文长度不是 n 的倍数时需要填充。

## 触发条件

- 已知 Hill 密码的密钥矩阵（或可通过已知明文求出）与字母表映射。
- 密钥矩阵行列式与 26 互素；密文长度是分组大小的整数倍（或可去填充）。
- 密文只含 A–Z（或题目定义的字母表）；分组方向（行/列向量）与加密方一致。
- 可用 Python/Sage 做模逆与矩阵乘法。

## 利用步骤

1. 确认字母表映射（通常 A=0..Z=25）、分组大小 n（本题 3）和向量方向（本题列向量）。
2. 计算 `det(K) mod 26`，求 `det^{-1} mod 26`；若不存在则检查映射/矩阵是否抄错。
3. 求余子式矩阵、转置得伴随矩阵，乘 `det^{-1}` 得 `K^{-1} mod 26`。
4. 密文按 n 个字符分块，转数字向量，逐块 `K^{-1}·c mod 26`，再映射回字母。
5. 用可读性/flag 格式验证；本题得到 `GRIEZMANN`，最终 `flag{GRIEZMANN}`。

## PoC

```python
K = [[1, 2, 3], [0, 1, 2], [3, 1, 2]]
ciphertext = "MHZMXJNNN"

def minor(a, row, col):
    return [[a[r][c] for c in range(3) if c != col]
            for r in range(3) if r != row]

def det2(a):
    return a[0][0] * a[1][1] - a[0][1] * a[1][0]

det = (K[0][0] * det2(minor(K, 0, 0))
       - K[0][1] * det2(minor(K, 0, 1))
       + K[0][2] * det2(minor(K, 0, 2)))
det_inv = pow(det % 26, -1, 26)

# 伴随矩阵 = 余子式矩阵的转置
inverse = []
for i in range(3):
    row = []
    for j in range(3):
        sign = -1 if (i + j) % 2 else 1
        row.append((det_inv * sign * det2(minor(K, j, i))) % 26)
    inverse.append(row)

numbers = [ord(ch) - ord('A') for ch in ciphertext]
plain = []
for off in range(0, len(numbers), 3):
    block = numbers[off:off + 3]
    plain.extend(sum(inverse[i][j] * block[j] for j in range(3)) % 26
                 for i in range(3))

print(''.join(chr(v + ord('A')) for v in plain))   # GRIEZMANN
```

## 变体与关联

- **变体（已知明文攻击）**：不知道密钥矩阵但有多组明密文对时，用线性方程组/矩阵求逆恢复 `K`；明文不足时枚举/格方法。
- **变体（2×2/4×4）**：分组大小变化，求逆方法相同；注意行列式与模数互素。
- **变体（字母表/模数）**：模 27（含空格）、模 29 或自定义字母表；需按题目调整。
- **关联卡片**：[[crypto-classical-pigpen-variant-fence-column-decode]]（另一种古典密码）、[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（现代公钥离散对数）。
- **边界**：`det` 不可逆、分组/向量方向错误、字母表 A=1 与 A=0 混用都会得到乱码；密文长度不足需填充。

## 检测与防御

- **CTF 识别**：题目给出数字矩阵和全大写密文、提示“矩阵/线性代数”时，优先 Hill 密码；先算 det 与模逆。
- **现实安全**：Hill 密码是线性替换，已知明文可恢复密钥，不能用于真实加密；使用现代 AEAD/公钥方案。
- **教学**：强调模逆存在条件、分组与字母表一致性；不要把古典密码当作安全机制。
