---
id: ctf-crypto-arx-xor-rot-invert-differential-carry-weight-key-recovery
title: 6 轮 ARX 块密码选择明文差分攻击：x^rot(x,a)^rot(x,b) 可逆迭代 8 次撤销末轮，单比特差分旋转定位 + 进位权重奇偶统计逐位恢复 256 位密钥，尾部 6 位与错位暴力修正
type: scenario
domain: ctf
path: ctf/crypto
technique: arx-differential-bitwise-carry-recovery
tags:
- crypto
- arx
- differential
- chosen-plaintext
- key-recovery
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:24:10+08:00'
  notes: 已对照原文核对：原理（M=I+C^a+C^b 逆迭代、差分进位统计、权重位置 172-176）、PoC（undo_rotations/get_weight）、触发条件与原文一致；原文未给出处 URL，卡无 sources 字段，作为未验证点。
url: /docs/ctf/crypto/ctf-crypto-arx-xor-rot-invert-differential-carry-weight-key-recovery/
draft: false
kb_aliases:
- ARX 差分攻击
- xor rot 逆函数迭代
- 进位权重统计恢复密钥
- UMDCTF2025 arx
---

# 6 轮 ARX 块密码选择明文差分攻击：x^rot(x,a)^rot(x,b) 可逆迭代 8 次撤销末轮，单比特差分旋转定位 + 进位权重奇偶统计逐位恢复 256 位密钥，尾部 6 位与错位暴力修正

## 一句话结论

对「每轮 `X += K; X ^= rot(X,a) ^ rot(X,b)`」的 6 轮 256 位 ARX 块密码，在仅限 2^14 次查询、单次 ≤300 块的选择明文 oracle 下：先用 `M=I+C^a+C^b` 满足 `M^32=nI`（n 奇数时为 I）的性质把 XOR+rot 层的逆写成 5 次平方迭代（a、b 逐次翻倍），从密文撤销末轮该层回到「加 key 后」中间态；再对每个 key_index 构造只在该位附近扰动 8 bit 的旋转明文差分，利用 `1+key_bit` 是否进位的差分位置偏差（bit3→bit4）做加权统计，25 轮 ×256 样本按奇偶分布判定每一位，250 位统计恢复 +6 位及 1~2 位错位暴力枚举，解出 flag 密文（UMDCTF-2025 实战，成功率约 25%/次尝试）。

## 原理

- **XOR+rot 层可逆**：把该层看作 GF(2) 上线性算子 `M = I + C^a + C^b`（C 为循环移位算子）。展开得 `M^2 = I + C^{2a} + C^{2b}`（交叉项成对相消），归纳有 `M^{2^k} = I + C^{2^k a} + C^{2^k b}`；32 位字上 `C^{32a}=I` 故 `M^32 = 3I = I`（256 位字则 `M^256 = I`）。于是 `M^{-1} = M^{31} = M·M^2·M^4·M^8·M^16`，即连续 5 轮「x ^= rot(x,a) ^ rot(x,b)，然后 a、b 翻倍」的迭代即为逆变换（代码里做 8 次更保险）；配合每轮 `X -= K` 即可整体解密——前提是先拿到 K。
- **差分对消除未知量**：纯 XOR 层的差分 `C0⊕C1 = m0⊕m1` 与密钥无关；ARX 中唯一的非线性来源是加 key 的进位。设 `ΔP` 只有 bit i 为 1，则 `X = P+K` 与 `X' = P'+K` 在 bit i 上的和差直接暴露 `K_i`：`K_i=0` 时差分留在 bit i（无进位），`K_i=1` 时差分跳到 bit i+1（进位）。
- **统计判定**：撤销末轮 XOR+rot 后对相邻样本计算 `ΔX = X⊕X'`，在 `(172-key_index)...(176-key_index)` 五个位置加权求和（`2^6,2^4,2^3,2^2,2^1`，越靠近起点的进位越可靠权重越大），累计 25 轮样本后按样本编号奇偶分布（偶数号高权重多 → 猜 1）判定该位。
- **样本构造**：`base = 2^246·j` 保证低 246 位为 0，`base + k (k<256)` 只在低 8 位变化且不与高位进位纠缠；`rot(base+k, 256-key_index)` 把 8-bit 差分精确旋到待测位位置；`key_index>200` 时改用 `2^100·j` 避免与高位重叠。
- **容错**：统计恢复 250 位后剩 6 位噪声大，直接 2^6 枚举；若仍有 1~2 位统计错误，组合枚举翻转位再配合前 6 位枚举，用解密结果是否含 flag 前缀校验。

## 触发条件

- 加密服务提供选择明文 oracle：任意明文 → 6 轮 ARX 密文（查询次数/块数有限也能在配额内完成 25×256 采样）；
- 轮函数为「加常量密钥 + XOR 双旋转」，旋转常数已知（硬编码）；
- 最后给出一个未知明文（flag）的密文用于验证恢复的密钥。

## 利用步骤

1. 从题目源码抄下轮常数与 encrypt 实现，本地复现。
2. 实现 `undo_rotations`（5~8 次 `x ^= rot(x,a)^rot(x,b)`，同步 a=(a+a)&0xff）与完整 `decrypt`（逆序撤销 XOR+rot 层、减 key）。
3. 对 key_index = 0..249 逐位攻击：构造 256 个 `rot(2^246·j + k, 256-key_index)` 明文（每轮换 j 共 25 轮）发送 oracle；密文逐块 `undo_rotations` 后取相邻差分，`get_weight` 累计进位权重。
4. 权重 ≥600 的样本按编号奇偶统计得该位猜测，填入 guessed_key[255-key_index]。
5. 发送 `q` 结束输入，取 flag 密文；用猜测密钥 decrypt，命中 flag 前缀即成功；否则枚举前 6 位、再枚举翻转 1~2 位错误组合。

## PoC

核心片段（完整 EXP 见原文）：

```python
def undo_rotations(block, a, b):
    for _ in range(8):
        block = block ^ rot(block, a) ^ rot(block, b)
        a = (a + a) & 0xff
        b = (b + b) & 0xff
    return block

def get_weight(key_index, diff):
    return (diff[(172-key_index)%256])*2**6 + (diff[(173-key_index)%256])*2**4 + \
           (diff[(174-key_index)%256])*2**3 + (diff[(175-key_index)%256])*2**2 + \
           (diff[(176-key_index)%256])*2**1

# 每位：25 轮 × 256 样本，weights>=600 的样本按 k 奇偶分布猜 0/1
```

## 变体与关联

- 变体：轮数、字长、旋转常数不同时按 `M^{字长}=I` 重新核对逆迭代次数与权重位置偏移（172/176 等常数与轮常数具体取值相关）。
- 变体：进位判定统计可换成似然比/多数表决；查询配额更紧时可减少 attempts 提高单轮样本复用。
- 关联：[[ctf-crypto-feistel-gf2-16-cubic-rank-drop-key-recovery]]（代数降秩恢复轮密钥，同为自研轮函数攻击）。
- 关联：[[ctf-crypto-blackbox-chosen-input-mapping]]（黑盒选择输入映射分析）。

## 检测与防御

- 防御（密码设计视角）：ARX 轮函数做密钥调度（每轮不同子密钥）、加轮前混合轮常数、提高轮数，避免全轮共用同一 256 位密钥使加法层差分逐位独立可测；oracle 应限制查询总数与差分结构查询。
- 检测：加密服务被高频单比特差分枚举访问（明文低位规则递增/旋转模式）可作为 oracle 滥用特征告警。
