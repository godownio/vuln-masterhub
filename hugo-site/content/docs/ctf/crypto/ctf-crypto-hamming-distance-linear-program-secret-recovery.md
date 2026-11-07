---
id: ctf-crypto-hamming-distance-linear-program-secret-recovery
title: 用 Hamming 距离线性约束 + 整数规划恢复 256 位密钥：浮点泄露 + SHA-256 哈希对
type: scenario
domain: ctf
path: ctf/crypto
technique: hamming-distance-linear-program-secret-recovery
tags:
- ctf
- crypto
- linear-programming
- pulp
- hamming-distance
- sha256
- aes-ctr
- key-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:29+08:00'
  notes: 已对照原文 qrandom 脚本核对浮点/64位哈希解析、111 组、Hamming 距离线性恒等式、pulp CBC 约束与 MD5→AES-CTR(nonce=suan) 解密流程；未验证点：无 output.txt，未实跑 ILP，未在原题环境验证。frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-hamming-distance-linear-program-secret-recovery/
draft: false
kb_aliases:
- qrandom
- 浮点数泄露汉明距离
- 线性规划恢复密钥
- pulp 二进制变量
- SHA-256 哈希对
- Hamming distance ILP
---

## 一句话结论

当每个样本给出一个浮点数 `c` 和一条 SHA-256 哈希 `h`，而 `c` 实际是“256 位秘密 `s` 与 `h` 的 Hamming 距离 / 256”时，可把 `c` 还原成整数 `C=round(c·256)`，利用恒等式 `d(h,s)=weight(h)+Σ_j s_j(1-2h_j)` 为每个样本建立一条 0/1 整数规划约束，111 条样本即可用 `pulp` + CBC 解出 256 位秘密；秘密的 MD5 作 AES-CTR 密钥即可解出 flag。

## 原理

- **Hamming 距离展开**：对二进制向量 `h` 与 `s`，
  `d(h,s) = Σ_j [h_j ≠ s_j] = Σ_j h_j(1-s_j) + (1-h_j)s_j = weight(h) + Σ_j s_j(1-2h_j)`。
  因此 `Σ_j (1-2h_ij)·s_j = d_i - weight(h_i)`，左边对未知 `s_j∈{0,1}` 是线性的。
- **浮点泄露**：题目输出 `c_i`，其 8 位小数值对应 `d_i/256` 的近似；`C_i = round(c_i*256)` 即整数距离。只要 `c_i` 的小数精度足够，`C_i` 就等于真实距离。
- **为什么 111 条够**：未知数是 256 个二进制位，每条样本提供一个整数线性方程；`pulp` 用 CBC 求解 0/1 规划，模型在真值处可行。原文用 111 条约束（`floats[:111]` 与 `hashes[:111]`）即可解出唯一 256 位秘密。
- **后续解密**：解出的 32 字节 `secret` 作为 `MD5(secret)` 的输入，得到 16 字节 AES key；密文用 `AES-CTR`、`nonce=b"suan"` 解密。
- **成立前提**：浮点输出没有截断到丢失距离信息；哈希与秘密的位序/字节序在建模时一致；密文与样本在同一 `output.txt` 中且可区分 64 字符哈希与偶数长度十六进制密文。

## 触发条件

- 题目/日志给出多组 `(浮点数, 64 位十六进制哈希)`，浮点数在 `[0,1]` 且与哈希-秘密的 Hamming 距离成比例。
- 样本数量足以约束全部秘密位（原文 111 条对 256 位）。
- 有 Python + `pulp`（CBC 求解器）或任意 0/1 ILP 求解器。
- 最后一段十六进制密文与样本在同一文件中，可用于验证解出的密钥。

## 利用步骤

1. 解析 `output.txt`：用正则提取小数 `[01]?\.\d+` 与十六进制串；过滤掉 64 字符哈希，剩下的偶数长度十六进制串中最后一段是密文。
2. 把前 111 个浮点数与 111 条哈希配对；对每条哈希按位展开成 256 维 0/1 向量 `Y_i`。
3. 令 `C_i = round(float_i*256)`，建立 256 个二进制变量 `s_j`，对每个样本添加约束：
   `Σ_j (1 - 2*Y_i[j]) * s_j == C_i - sum(Y_i)`。
4. 用 `pulp.PULP_CBC_CMD` 求解，读出 256 位并转成 32 字节 `secret`。
5. `key = MD5(secret).digest()`；用 `AES.new(key, AES.MODE_CTR, nonce=b"suan")` 解密密文，得到 flag。

## PoC

```python
import re, math
from hashlib import md5
import pulp
from Crypto.Cipher import AES

data = open("output.txt", "r").read()
floats = [float(x) for x in re.findall(r'(?<![0-9a-f])([01]?\.\d+)', data)]
hexes = re.findall(r'\b[0-9a-fA-F]+\b', data)
ct_hex = [h for h in hexes if len(h) % 2 == 0 and len(h) != 64][-1]
ciphertext = bytes.fromhex(ct_hex)
hashes = re.findall(r'\b[0-9a-fA-F]{64}\b', data)

def bits(h):
    return [int(b) for byte in bytes.fromhex(h) for b in f"{byte:08b}"]

pairs = list(zip(floats[:111], hashes[:111]))
Y, C = [], []
for f, h in pairs:
    b = bits(h)
    Y.append(b)
    C.append(round(f * 256))

prob = pulp.LpProblem("recover", pulp.LpMaximize)
s = [pulp.LpVariable(f"s{j}", cat="Binary") for j in range(256)]
for i in range(len(Y)):
    prob += pulp.lpSum((1 - 2 * Y[i][j]) * s[j] for j in range(256)) == C[i] - sum(Y[i])
prob.solve(pulp.PULP_CBC_CMD(msg=False))

secret = bytearray()
for i in range(32):
    v = 0
    for j in range(8):
        v = (v << 1) | int(s[i * 8 + j].value())
    secret.append(v)

key = md5(bytes(secret)).digest()
plain = AES.new(key, AES.MODE_CTR, nonce=b"suan").decrypt(ciphertext)
print(plain.decode(errors="replace"))
```

## 变体与关联

- **距离变体**：如果浮点是 `1 - 距离/256`，取补即可；若是字节级匹配数/编辑距离，也可以类似展开成线性约束。
- **哈希变体**：SHA-256/SHA-512/自定义哈希均可，只要哈希的位向量已知且秘密与哈希同长。
- **求解器变体**：`pulp`/OR-Tools/Z3 的 `Optimize`；样本有噪声时可改为容差约束或最大似然。
- **关联**：[[crypto-hash-md5-three-way-collision-nested-fastcoll]]（哈希构造）、[[ctf-crypto-linear-hash-collision-lll]]（线性哈希约束）。

## 检测与防御

- **CTF 性质**：这是对“泄露 Hamming 距离”这一设计缺陷的攻击。
- **设计防御**：不要输出与密钥相关的距离/相似度；需要距离时加入噪声或只给区间；密钥使用 KDF/高熵随机值，不要用 MD5 派生 AES key。
- **检测**：日志/接口中出现大量 `(浮点, 哈希)` 对且浮点精度异常时，评估是否泄露了隐藏向量的距离信息。
