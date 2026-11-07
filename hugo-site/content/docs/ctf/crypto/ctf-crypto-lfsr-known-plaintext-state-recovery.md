---
id: ctf-crypto-lfsr-known-plaintext-state-recovery
title: LFSR 流密码已知明文恢复：64 比特帧头建立 GF(2) 方程组解初始状态
type: scenario
domain: ctf
path: ctf/crypto
technique: lfsr-known-plaintext-linear-recovery
tags:
- ctf
- crypto
- lfsr
- stream-cipher
- known-plaintext
- gf2
- gaussian-elimination
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:44:54+08:00'
  notes: 已对照原文核对；三条通道各 10 帧、秩 64 残差 0，第二条 ror64 路径与计数器复用旁证一致
url: /docs/ctf/crypto/ctf-crypto-lfsr-known-plaintext-state-recovery/
draft: false
kb_aliases:
- LFSR 密钥恢复
- 线性反馈移位寄存器
- 已知明文攻击
- GF(2) 高斯消元
- 帧头已知明文
---

## 一句话结论

LFSR 流密码的输出与明文异或时，每帧固定帧头提供已知明文比特；用密文异或已知明文得到密钥流比特，为 64 位初始状态建立 GF(2) 线性方程组，多帧联立后高斯消元即可唯一恢复状态并解密整条通道。

## 原理

- **LFSR 是线性系统**：下一状态是当前状态的线性函数，输出比特也是状态比特的线性组合；因此“输出密钥流比特”对“初始状态比特”是线性的，可写成 `A·s = b`（GF(2)）。
- **已知明文给出密钥流**：流密码 `C = P XOR KS`，已知 `P` 的比特即可反推 `KS` 的比特；每帧 8 字节固定头 `A5 5A <ch_id> 'NRWF-'` 提供 64 个已知比特。
- **多帧联立消除未知**：单帧 64 个方程理论上足够解 64 位状态，但实际可能有填充/计数器/帧间偏移；用 10 帧得到 640 个方程，高斯消元后秩为 64、残差为 0，说明模型正确且解唯一。
- **按通道分组**：不同上行通道密钥独立，必须按 `ch_id` 分组分别解；台账 `status=current` 的通道才是有取证价值的目标。
- **为什么成立**：LFSR 的线性性使已知明文攻击从“爆破 2^64”降为“解线性方程组”，计算量是多项式级。

## 触发条件

- 加密使用 LFSR（或线性反馈移位寄存器）生成的密钥流，且输出直接与明文异或。
- 明文存在固定/可预测的帧头、协议标识、填充或已知字段，能提供至少 64 个已知比特。
- 能抓到同一通道的多帧密文（示例 10 帧）。
- LFSR 的抽头/反馈多项式可从帧结构或脚本推断（示例 LFSR-64）。

## 利用步骤

1. 从帧结构中识别 LFSR 模型（位宽、抽头、输出位），确认输出参与异或加密。
2. 对每帧取已知明文比特（固定帧头），与密文对应比特异或，得到密钥流比特。
3. 对每个密钥流比特，按 LFSR 的状态转移写成 64 个状态比特的线性方程；收集多帧形成方程组。
4. 在 GF(2) 上做高斯消元，检查秩是否为 64、残差是否为 0；解出初始状态。
5. 按通道分组重复；用台账 `status` 选择 current 通道。
6. 用恢复的状态生成密钥流，解密目标通道；用第二条独立路径（如 `key = ror64(state,13) ^ (salt*ctr)`）或计数器复用特征交叉验证。

## PoC

```python
# 示意：为每个已知明文比特建立一行 GF(2) 方程
def build_system(frames):
    rows = []
    for frame in frames:
        ks_bits = [c ^ p for c, p in zip(frame.cipher_bits, frame.known_plain_bits)]
        for out_bit in ks_bits:
            # out_bit = sum(state[i] * coeff[i]) over GF(2)
            rows.append(coefficients_for_output_bit(out_bit))
    return rows

# 高斯消元（GF(2)）解 64 元方程组；秩=64、残差=0 时解唯一
```

原文实测：三条上行通道各取 10 帧，640 个方程消元后秩 64、残差 0；ch1 计数器 `0x0036`，解密得到 `flag{N4rr0wb4nd_LFSR_St4t3_26}`。第二条路径用 `key = ror64(state, 13) ^ (salt * ctr)` 逐帧反推，结果一致；ch2 两帧计数器同为 `0x14`，密文差等于明文差，是计数器复用的旁证。

## 变体与关联

- **已知明文变体**：固定帧头、协议魔数、全零填充、固定长度字段、可预测的遥测初值。
- **模型变体**：LFSR-16/32/64、Galois 与 Fibonacci 结构、非线性组合/滤波生成器（线性攻击需先近似或相关攻击）。
- **验证变体**：计数器复用、状态递推一致性、独立密钥派生公式。
- **关联卡片**：[[ctf-crypto-self-referential-key-tea-variant]]（同篇结构缺陷）、[[crypto-prng-glibc-rand-output-sequence-prediction]]（线性递推恢复随机数）。
- **边界**：若 LFSR 输出经过非线性滤波/组合，简单线性方程组不成立；已知明文不足 64 比特时方程欠定；模型（抽头）判断错误会解出错误状态。

## 检测与防御

- **CTF 验证**：秩等于未知数个数且残差为 0 才说明模型正确；解密结果需用第二条独立路径或协议字段交叉验证。
- **工程防御**：不要用 LFSR 作为密码学密钥流；使用 CSPRNG/AES-CTR/ChaCha20；每帧使用唯一 nonce/计数器并认证；避免固定可预测帧头泄漏密钥流。
- **检测信号**：协议中存在固定帧头且加密为简单异或；同一计数器重复出现；密文差异与已知明文差异一致。
- **复盘**：LFSR 题先找已知明文，再建立 GF(2) 方程；不要一上来爆破 2^64。
