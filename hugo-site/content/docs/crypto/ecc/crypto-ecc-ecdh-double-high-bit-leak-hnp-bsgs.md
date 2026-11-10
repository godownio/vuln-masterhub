---
id: crypto-ecc-ecdh-double-high-bit-leak-hnp-bsgs
title: ECDH 双值高位泄露构造 HNP：sb 与 B_pri_r 各泄露 28bit，LLL 恢复 128bit 私钥后用 BSGS 补齐低 36bit
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdh-double-high-bit-leak-hnp-bsgs
tags:
- ecc
- ecdh
- hnp
- lattice
- lll
- bsgs
- partial-key-leak
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-08T01:03:10+08:00'
  notes: 已完整 Read content.md 并逐张 Read img 01-10.svg（MathJax 字形）：01 sb-B_pri_r=retbar(B_pub_R)*B_pri_w mod n；02 l+h=retbar(B_pub_R)*B_pri_w mod n；03 28*10>128；04 l_i+h_i=r_i*w mod n；05 w=r_i^{-1}(l_i+h_i)；06 l_i=r_i r_0^{-1} l_0 + r_i r_0^{-1} h_0 - h_i；07 A_i=r_i r_0^{-1}；08 B_i=r_i r_0^{-1} h_0 - h_i；09 l_i=A_i l_0+B_i；10 格矩阵（-n、A_i、B_i、1、2^128），与卡内公式一致。已核对原文 retbar(P)=(int(P[0])%2^65+2^65)%n、LS=leakageS=sb>>100、LR=B_pri_r>>100、10 组、w=1178130499626730132053516693988590569、x0>>36<<36 与 2^18 步 BSGS、md5(long_to_bytes(w)) AES-ECB 解密，均与卡内一致。\n【修正】原理『格构造』原写『(n+1)x(n+1) 格，前 n-1 行…（q=n）』，混淆了样本数与模数；按原文 L=Matrix(ZZ,n+1,n+1) 中 n=10（样本数）与 q=n（模数）已改为 (m+1)x(m+1)、前 m-1 行。\n未验证点：卡内 PoC 为骨架（BR 只列首组、c 未在卡内定义），未本机跑 Sage；原文 WP 未展示解密出的 flag 明文，confidence=medium 合理；frontmatter 无 sources/source_url；CTF 题无 affected_versions。kb show 存在；dedup top1 为自身，最高相关 crypto-ecc-ecdh-small-nonce-brute-shared-point-key 为小 nonce 暴力、crypto-ecc-ecdsa-partial-nonce-leak-lattice 为 ECDSA 部分 k，协议/泄漏/格构造不同；dup-scan 无本篇 pair。单卡单一原子（双高位泄露
    HNP+BSGS）。
url: /docs/crypto/ecc/crypto-ecc-ecdh-double-high-bit-leak-hnp-bsgs/
draft: false
kb_aliases:
- ezsign1n
- ECDH 高位泄露
- sb B_pri_r 高位
- retbar HNP
- 格恢复私钥
- BSGS 补齐低位
---

## 一句话结论

一个类 X25519 的 ECDH 交换中 `sb = B_pri_r + retbar(B_pub_R)·B_pri_w mod n`；题目给出 10 组 `sb` 与 `B_pri_r` 的高 28bit（低 100bit 未知）。把两式相减消去已知部分，得到 `A_i·w + h_i + l_i ≡ 0 (mod n)`（`A_i=retbar(B_pub_R_i)`、`l_i` 为小于 `2^100` 的未知低位），以第一组为基准消元构造 HNP 格，LLL 恢复 128bit 私钥 `B_pri_w` 的高位（低 36bit 未知），再用 2^18 步 BSGS 补齐低 36bit；最后以 `md5(long_to_bytes(w))` 为 AES-ECB 密钥解密 flag。

## 原理

- **retbar 可公开计算**：`retbar(P) = (int(P.x) mod 2^65 + 2^65) mod n`，只依赖公开点 `B_pub_R` 的 x 坐标，因此每组的系数 `A_i = retbar(B_pub_R_i)` 已知。
- **泄漏关系**：`sb = B_pri_r + A·B_pri_w mod n`，移项得 `sb - B_pri_r ≡ A·w (mod n)`。`sb` 与 `B_pri_r` 各只泄露高 28bit（`LS[i]=sb>>100`、`LR[i]=B_pri_r>>100`），所以 `h_i = (LS[i]-LR[i])<<100` 是 `A_i·w` 的高位近似，误差为两者未知低位之差 `l_i`（`|l_i| < 2^100`），即 `A_i·w ≡ h_i + l_i (mod n)`。
- **消元构造 HNP**：以第 0 组为基准，`l_i = (A_i·A_0^{-1})·l_0 + (A_i·A_0^{-1}·h_0 - h_i) (mod n)`。记 `A'_i = A_i A_0^{-1}`、`B'_i = A'_i h_0 - h_i`，则 `l_i = A'_i l_0 + B'_i (mod n)`，其中 `l_0` 是小于 `2^100` 的小未知数。
- **格构造**：取 `(m+1)×(m+1)` 格（`m` 为样本数，本例 10；模数为 `q=n`），前 `m-1` 行是 `(-q, A'_i, B'_i)`，倒数第二行放 `(0,...,0,1,0)`，最后一行放 `(0,...,0,0,2^128)`。短向量对应 `l_0` 的组合；LLL 后找最后一维为 `2^128` 的向量，其倒数第二维 `b0` 给出 `l_0` 的近似，`w ≈ (h_0 + b0)·A_0^{-1} mod n`。
- **为何只到高位**：格中误差项 `l_i < 2^100`、目标 `w` 约 128bit，10 组泄漏共 280bit 信息（`28×10 > 128`），LLL 能恢复 `w` 但低 36bit 仍不确定；把结果 `x0` 截断为 `x0 >> 36 << 36`。
- **BSGS 补齐**：剩下的搜索空间为 `w = x0 + r`、`0 ≤ r < 2^36`。以 `G` 做 baby-step 表（`2^18` 个点），再以 `B_pub_W - x0·G` 为起点、每次减 `2^18·G` 做 giant-step（`2^18` 次），命中即得 `r = i·2^18 + j`，总复杂度约 `2^19` 次点运算。
- **密钥派生**：`key = md5(long_to_bytes(w)).hexdigest().encode()`，AES-ECB 解密题目密文得 flag。

## 触发条件

- ECDH/自定义密钥交换中，攻击者能获得同一私钥参与的两个线性组合的高位（本例 `sb` 与 `B_pri_r` 各高 28bit），且低位范围有界（100bit）。
- 样本数足够：泄漏总位数明显超过私钥位长（本例 28×10=280 > 128）。
- 系数 `retbar(B_pub_R)` 可由公开点计算；模数 `n` 为素数（点阶）。
- 私钥剩余未知位数可承受 BSGS（本例 36bit，约 2^18+2^18 步）。

## 利用步骤

1. 解析 `B_pub_W`、`LS`、`LR`、`BR`，计算每组的 `A_i = retbar(BR[i])` 与 `h_i = (LS[i]-LR[i])<<100`。
2. 以第 0 组为基准，对 `i=1..m-1` 计算 `A'_i = A_i·A_0^{-1} mod n`、`B'_i = A'_i·h_0 - h_i mod n`。
3. 构造 `(m+1)×(m+1)` 格：对角线 `-n`、倒数第二列 `A'_i`、最后一列 `B'_i`，最后两行分别为 `1` 和 `2^128`；LLL 约减。
4. 遍历约减基，取最后一维等于 `2^128` 的向量，`b0=|倒数第二维|`，`x0=(h_0+b0)·A_0^{-1} mod n`，并截断低 36bit。
5. BSGS：枚举 `0..2^18` 的 `jG` 建表，再对 `h=B_pub_W - x0·G` 每次减 `2^18·G` 查表，得到 `w`。
6. 用 `w` 派生 MD5 密钥，AES-ECB 解密。

## PoC

```python
# Sage
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
import hashlib

p = 174523845247570741054964008585718839267
E = EllipticCurve(GF(p), [0, 486662, 0, 1, 0])
G = E(2247961404505753398791635923994899528, 108711418033303501028455466081133667288)
n = G.order()

def retbar(P):
    return (int(P[0]) % (2**65) + 2**65) % n

B_pub_W = E(56142839234500040174315077324489019612,
            143186177525574678948140963663687495447)
LS = [12160779, 70634852, 136488679, 93279448, 51769705, 99408367, 94011238, 46255543, 136054320, 126842658]
LR = [117789932, 85602320, 136131278, 85538539, 33115646, 15821127, 122073977, 40205177, 40509142, 121833940]
BR = [(43128875586771925869851532015581155657, 108714366549720544283054523544596695631),
      # ... 其余 9 组
      ]

q = n
A = [retbar(BR[i]) for i in range(len(LS))]
h = [((LS[i] << 100) - (LR[i] << 100)) for i in range(len(LS))]

D, Ee = [], []
for i in range(len(A) - 1):
    D.append((inverse(A[0], q) * (A[i+1] * h[0] - A[0] * h[i+1])) % q)
    Ee.append((inverse(A[0], q) * A[i+1]) % q)

m = len(A)
L = Matrix(ZZ, m + 1, m + 1)
for i in range(m - 1):
    L[i, i] = -q
    L[-2, i] = Ee[i]
    L[-1, i] = D[i]
L[-2, -2] = 1
L[-1, -1] = 2**128
M = L.LLL()

x0 = None
for row in M:
    if row[-1] == 2**128:
        b = vector(row)
        x0 = ((h[0] + abs(b[-2])) * inverse(A[0], q)) % q
x0 = x0 >> 36 << 36          # 低 36bit 未知

# BSGS 补 36bit
baby = {}
tmp = 0
for i in range(2**18):
    tmp += G
    baby[tmp] = i + 1
target = B_pub_W - x0 * G
step = 2**18 * G
for i in range(2**18):
    if target in baby:
        w = x0 + i * 2**18 + baby[target]
        break
    target -= step

key = hashlib.md5(long_to_bytes(w)).hexdigest().encode()
print(AES.new(key, AES.MODE_ECB).decrypt(c))
```

## 变体与关联

- 若只泄露一个值的高位，可用 ECDSA 部分 nonce 的 HNP 直接构造；本卡的特殊点是把同一私钥的两个线性组合相减后，误差仍受控，从而得到系数不同的多组同余式。
- 样本更多或泄漏位数更多时，格维度可减小、BSGS 可省略；泄漏更少时需增大格维或改用 CVP/Babai。
- 相关：[[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]（ECDSA 部分 k 泄露）、[[ctf-crypto-hnp-msb-oracle-babai-nearest-plane]]（HNP 通用构造）、[[crypto-ecc-ecdh-small-nonce-brute-shared-point-key]]（小 nonce 暴力）。

## 检测与防御

- 不要把私钥参与值的任何高位写入日志、响应或侧信道；泄漏高位会显著降低私钥熵。
- ECDH 实现使用常数时间点乘与固定格式输出，避免高位/低位相关泄露。
- 若必须公开统计值，应加噪声或只公开不可逆的哈希，而不是原始点坐标/组合值的高位。
