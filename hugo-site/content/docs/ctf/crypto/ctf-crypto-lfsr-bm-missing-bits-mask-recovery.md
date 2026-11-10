---
id: ctf-crypto-lfsr-bm-missing-bits-mask-recovery
title: LFSR B-M 算法：仅 504 位连续输出、爆破缺失 8 位后建 256×256 GF(2) 方程恢复 mask 与 KEY
type: scenario
domain: ctf
path: ctf/crypto
technique: lfsr-berlekamp-massey-missing-bits-mask-recovery
tags:
- ctf
- crypto
- lfsr
- berlekamp-massey
- gf2
- linear-system
- mask-recovery
- brute-force
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-07T23:48:40+08:00'
  notes: 已对照原文与5张图：LCG 公式、MT 优点、移位/反馈寄存器、B-M 256 元方程组图均一致；原文 504 位（63×8）输出、爆破缺失 8 位、256×256 GF(2) 求解 mask、get_key 反推 KEY、SHA256 前缀 1224 过滤与卡内 PoC 一致。LCG 与 MT19937 两节已由既有 crypto-prng-lcg-parameter-recovery-delta-gcd、crypto-prng-mt19937-untemper-state-recovery-predict 覆盖（后者含自定义 temper 的 GF(2) 矩阵法与 unshift 函数），SUCTF2019 变体按 merge 跳过合理。原文未给最终 flag 输出、未本机复跑，confidence=medium 合理。
url: /docs/ctf/crypto/ctf-crypto-lfsr-bm-missing-bits-mask-recovery/
draft: false
kb_aliases:
- LFSR B-M 算法
- Berlekamp-Massey
- 504 位输出爆破 8 位
- LFSR mask 恢复
- GF(2) 矩阵求 mask
- de1ctf B-M
---

## 一句话结论

Berlekamp-Massey（B-M）算法表明 n 级 LFSR 的连续 2n 个输出比特足以确定反馈 mask；某题只给出 504 位（63 字节）输出而 LFSR 度 n=256 需要 512 位，于是爆破缺失的 8 位（256 种可能），对每个候选 512 位序列按 `a_i·m1 ⊕ ... ⊕ a_{i+255}·m256 = a_{i+256}` 建立 256×256 的 GF(2) 方程组求 mask，再用 mask 反推 256 位初始 KEY；最后用 `SHA256(hex(KEY))` 前 4 位为 `1224` 的约束过滤出正确 mask/KEY，得到 flag。

## 原理

- **LFSR 线性反馈**：n 级 LFSR 的下一输出位是当前 n 位状态与固定 mask 的 GF(2) 点积：`a_{t+n} = Σ_{i=0}^{n-1} m_i · a_{t+i} (mod 2)`。因此连续 2n 位输出中，前 n 位到后 n 位之间存在 n 个线性方程，未知量是 n 位 mask。
- **B-M 定理**：长度为 2n 的连续输出序列（n 位初始状态 + n 位输出，或任意连续 2n 位）即可通过构造矩阵求出 mask，时间复杂度 O(n²) 比特操作、空间 O(n) 比特；它给出的是“2n 位足够”的界，因此缺少的位数可以用爆破补齐。
- **本题的缺口**：程序每 8 位打包成一个字节，共 63 字节 = 504 位；LFSR 度 n=256，需要 512 位。作者选择爆破最后缺失的 8 位（2^8=256 种），对每个候选序列执行一次矩阵求解。
- **矩阵构造**：对候选序列 `r`，取 `A[i][j] = r[i+j]`（i=0..255，j=0..255），`b[i] = r[256+i]`；解 `A · mask = b`（GF(2)）。若 A 可逆，`mask = b · A^{-1}`；不可逆则跳过该候选。
- **反推 KEY**：已知 mask 和一段 256 位状态，可以按 LFSR 递推反向或正向恢复出题目使用的 256 位 `KEY`；`get_key(mask, state)` 用当前 mask 逐位计算新反馈并滑动状态，得到 256 位 KEY 的整数表示。
- **约束过滤**：题目断言 `FLAG == "de1ctf{" + sha256(hex(KEY)[2:]) + "}"` 且 `FLAG[7:11]=='1224'`，即 SHA256(hex(KEY)) 的前 4 个 hex 字符必须是 `1224`。256 个候选 mask/KEY 中只有满足该前缀的一个（或极少）为真，从而唯一确定 KEY 并输出 flag。
- **为什么成立**：LFSR 是纯线性系统，B-M 保证 2n 位输出的线性复杂度足以恢复反馈多项式；爆破只针对“采集缺失”的 8 位，不改变线性求解的确定性；SHA256 前缀作为外部约束用于在多个候选里挑选正确解。

## 触发条件

- 题目使用 n 级 LFSR 生成比特流，反馈函数线性、mask 固定且未知；输出按字节/比特打包，攻击者能拿到接近 2n 位的连续输出。
- 输出位数不足 2n（本题 504 < 512），但缺口很小（8 位），可爆破；若缺口更大，需要额外已知明文/更多输出/其他约束。
- 题目把 KEY 与 flag 绑定（如 `flag{sha256(hex(KEY))}`），并提供可验证的前缀/格式约束，用于筛选候选。
- 有 SageMath 或 GF(2) 高斯消元代码；n=256 时矩阵 256×256，计算量可接受。

## 利用步骤

1. 把输出字节串转成比特串 `r`；确认 LFSR 度 n=256、打包顺序与状态更新方向。
2. 对缺失的 8 位枚举 0..255，拼成 512 位候选序列。
3. 对每个候选构造 256×256 矩阵 A（行是连续 256 位窗口）和向量 b（接下来的 256 位）；在 GF(2) 上求 `A^{-1}`，解 `mask = b·A^{-1}`；矩阵不可逆则跳过。
4. 用 `mask` 和已知的 256 位状态运行 LFSR，恢复出 256 位 KEY。
5. 计算 `sha256(hex(KEY)[2:])`，检查前 4 位是否为 `1224`（或题目给定的其他约束）；命中则输出 `flag{...}`。
6. 用恢复的 mask 重新生成 504 位已知输出做验证，确保模型/移位方向正确；若验证失败，调整位序、移位方向或输出位定义。

## PoC

原文 Sage 脚本的关键片段（n=256、504 位输出、爆破 8 位、GF(2) 矩阵求 mask）：

```python
from sage.all import *

def pad(x):
    return '0' * (8 - len(x)) + x

def get_key(mask, key):
    R = ""
    index = 0
    key = key[255] + key[:256]
    while index < 256:
        tmp = 0
        for i in range(256):
            if mask >> i & 1:
                tmp = (tmp + int(key[255 - i])) % 2
        R = str(tmp) + R
        index += 1
        key = key[255] + str(tmp) + key[1:255]
    return int(R, 2)

def get_int(x):
    return int(''.join(str(x[i]) for i in range(256)), 2)

sm = []
for pad_bit in range(2**8):          # 爆破缺失的 8 位
    r = key + pad(bin(pad_bit)[2:])
    a = [int(c) for c in r]
    res = []
    for i in range(256):
        res.extend(a[i:i+256])       # 256×256 矩阵
    sn = a[256:512]                  # 右侧 256 位
    MS = MatrixSpace(GF(2), 256, 256)
    MSS = MatrixSpace(GF(2), 1, 256)
    A, s = MS(res), MSS(sn)
    try:
        inv = A.inverse()
    except ZeroDivisionError:
        continue
    mask = s * inv                   # mask = b * A^{-1}
    sm.append(hex(get_key(get_int(mask[0]), key[:256])))

for i in range(len(sm)):
    FLAG = hashlib.sha256(sm[i][2:].encode()).hexdigest()
    if FLAG[:4] == '1224':
        print('flag{' + FLAG + '}')
```

> 说明：`key` 为 504 位输出的比特串；`pad` 补齐 8 位；矩阵/向量构造按原文脚本。原文没有最终输出截图，本卡按脚本逻辑整理，未复跑。

## 变体与关联

- **已有主卡**：[[ctf-crypto-lfsr-mask-recovery-output-state]] 覆盖 initState 已知 + outputState 前 128 位建 GF(2) 方程解 mask 的主场景，并在变体中提到“只有 2n 位输出时可用 B-M 求线性复杂度/反馈多项式”；本卡是该变体的具体展开：未知 initState、只有 2n-8 位输出、爆破缺失位后用矩阵求 mask。
- **已知明文变体**：[[ctf-crypto-lfsr-known-plaintext-state-recovery]] 用已知帧头反推密钥流比特再解初始状态；[[crypto-prng-lfsr]] 系列覆盖条件 LFSR/滤波 LFSR 的 SAT/Z3 恢复。
- **缺口更大时**：若缺失位数多，单纯爆破不可行；可结合已知明文、多个连续段、输出位线性组合或 B-M 的线性复杂度递推求最小多项式，再补状态。
- **非线性和滤波**：NFSR/滤波 LFSR 需要 SAT/SMT/Z3 或代数攻击，不能直接用 GF(2) 消元。
- **约束过滤**：flag 的 SHA256 前缀/格式是常见的选择器；如果没有外部约束，多个 mask 候选都需验证输出或 KEY 的用途（解密、签名等）。

## 检测与防御

- 该场景为 CTF/授权测试密码分析；LFSR/线性 PRNG 不能用于生成密钥、令牌或验证码，因为连续 2n 位输出即可恢复反馈多项式与内部状态。
- 加固：使用 CSPRNG（`secrets`/`os.urandom`/AES-CTR DRBG）代替 LFSR；若必须用 LFSR，增加状态长度、使用非线性/滤波函数、限制输出位数并避免暴露连续比特。
- 检测/分析：拿到长比特流时先用 B-M 估计线性复杂度；若线性复杂度远小于序列长度，说明是 LFSR 并可尝试恢复 mask/状态；结合 SHA256 前缀、flag 格式等外部约束筛选候选。
