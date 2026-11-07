---
id: crypto-side-channel-aes-cpa-hamming-weight
title: AES-128 CPA 相关功耗分析：汉明重量模型逐字节恢复密钥
type: scenario
domain: crypto
path: crypto/side-channel
technique: aes-cpa-hamming-weight
aliases:
- CPA
- Correlation Power Analysis
- 相关功耗分析
- 汉明重量
- 功耗侧信道
- AES 侧信道
tags:
- side-channel
- aes
- cpa
- hamming-weight
- pearson
- key-recovery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:26+08:00'
  notes: 已对照原文核对：plaintexts(500,16)/traces(500,100)、HW(Sbox(P^K)) 逐字节 CPA、恢复密钥 66dc...f52e、峰值 0.68~0.80 落在采样点 20~35、IV+CBC 解密 flag 均与原文一致；S-box 十六进制已校验为 256 字节双射。未验证点：无附件，PoC 未本机复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

已知 500 组明文和对应功耗轨迹时，对 AES-128 每个密钥字节枚举 0..255，用 `HW(Sbox(P_i[b]^k))` 作为预测泄漏、与轨迹逐采样点做皮尔逊相关，取绝对相关最大的猜测即可恢复全部 16 字节密钥；再用 16 字节 IV + AES-CBC 解密密文即得 flag。

## 原理

- **CPA 模型**：AES 第一轮 `Sbox(P[b] ^ k)` 的结果会进入寄存器/总线；很多硬件实现的功耗与寄存器中“1 的个数”（汉明重量 HW）线性相关。对正确密钥猜测，预测 HW 序列与真实轨迹在泄漏时刻高度相关；错误猜测近似随机。
- **逐字节独立**：第一轮 16 个字节的 S-box 查表互不依赖，因此可以分别攻击每个字节，搜索空间从 `2^128` 降到 `16 × 256`。
- **皮尔逊相关**：对每个猜测 `k`，计算 500 个预测值 `L_i` 和轨迹第 `t` 个采样点的相关系数 `corr(L, T[:,t])`；取 `max_t |corr|` 作为该猜测的分数。
- **数据规模**：本题 `plaintexts.shape=(500,16)`、`traces.shape=(500,100)`；100 个采样点足够，峰值点严格落在 20..35，对应 16 个字节依次处理。
- **结果**：恢复密钥 `66 dc e1 5f b3 3d ea cb 5c 03 62 f3 0e 95 f5 2e`；`encrypted_flag.bin` 前 16 字节是 IV，后 48 字节是密文，AES-CBC 解密并去 PKCS#7 填充得到 `texsaw{d1ffer3nti&!_p0w3r_@n4!y51s}`。
- **为什么相关峰高**：本题轨迹干净、泄漏点集中、明文随机且数量足够；峰值 0.68~0.80，基本没有歧义。

## 触发条件

- 能拿到同一密钥下的多组已知明文/密文和对应功耗/电磁轨迹。
- 轨迹与明文按次对齐（同一索引对应同一次加密）。
- 泄漏模型与实现匹配（本题为汉明重量；也可能是汉明距离、比特翻转等）。
- 第一轮或最后一轮 S-box 输出与轨迹相关性足够强；轨迹采样点覆盖泄漏时刻。

## 利用步骤

1. 读取 `plaintexts.npy`、`traces.npy`，确认形状和对齐关系。
2. 对每个字节位置 `b=0..15`，枚举 `k=0..255`，计算 `hyp = HW[Sbox[pt[:,b] ^ k]]`。
3. 对 `hyp` 和每条轨迹中心化，逐采样点算皮尔逊相关，取 `max |corr|`。
4. 选分数最高的 `k` 作为该字节密钥；记录峰值采样点，检查是否按字节顺序排列。
5. 拼出 16 字节 AES-128 密钥；用密文前 16 字节作 IV、AES-CBC 解密。
6. 去 PKCS#7 填充，检查可打印性和 flag 格式；必要时用已知明文重新加密验证密钥。

## PoC

```python
import math
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SBOX = np.frombuffer(bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
), dtype=np.uint8)
HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)

def recover_key(plaintexts, traces):
    T = traces - traces.mean(axis=0)
    T_norm = np.sqrt((T * T).sum(axis=0))
    key = []
    for b in range(16):
        pt = plaintexts[:, b]
        best_k, best_score = 0, -1.0
        for k in range(256):
            hyp = HW[SBOX[np.bitwise_xor(pt, k)]].astype(np.float64)
            H = hyp - hyp.mean()
            H_norm = math.sqrt(float((H * H).sum()))
            corr = (H[:, None] * T).sum(axis=0) / (H_norm * T_norm)
            score = np.max(np.abs(corr))
            if score > best_score:
                best_k, best_score = k, score
        key.append(best_k)
        print(f"byte {b:02d} = {best_k:02x} corr={best_score:.4f}")
    return bytes(key)

key = recover_key(np.load("plaintexts.npy"), np.load("traces.npy"))
data = open("encrypted_flag.bin", "rb").read()
iv, ct = data[:16], data[16:]
dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
pt = dec.update(ct) + dec.finalize()
print(pt[:-pt[-1]].decode())
```

## 变体与关联

- **泄漏模型变体**：汉明距离 `HW(Sbox(P^K) ^ 前一状态)`、比特模型、加权汉明重量；先画轨迹/相关性图选模型。
- **攻击轮次变体**：第一轮、最后一轮（需密文）、中间轮；最后一轮常用逆 S-box。
- **轨迹处理变体**：对齐/去噪/降采样、多点组合、CPA/DPA/模板攻击；轨迹少时可用多字节联合。
- **关联卡片**：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（AES 常量识别）、[[crypto-aes-partial-key-suffix-bruteforce]]（密钥爆破）、[[crypto-side-channel]]（侧信道目录）。
- **边界**：若轨迹未对齐、泄漏模型错误、实现有掩码/隐藏/随机延迟，相关性会显著下降；需要更多轨迹或更精确模型。

## 检测与防御

- **防御**：AES 实现加掩码（Boolean/arithmetic masking）、隐藏（随机延迟、乱序、双轨逻辑）、恒定功耗/恒定时间；密钥更新。
- **评估**：用 TVLA/CPA 对实现做泄漏评估；限制功耗轨迹采集接口。
- **检测信号**：大量已知明文/密文与同步采集；设备功耗/电磁异常采集；CPA 峰值在固定采样点。
