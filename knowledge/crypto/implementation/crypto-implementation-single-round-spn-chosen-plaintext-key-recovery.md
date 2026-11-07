---
id: crypto-implementation-single-round-spn-chosen-plaintext-key-recovery
title: 单轮 SPN 白盒式选择明文攻击：逐字节线性差分表恢复 k0，中间相遇解目标密文
type: scenario
domain: crypto
path: crypto/implementation
technique: single-round-spn-chosen-plaintext-key-recovery
aliases:
- Babyfa
- 单轮 SPN 密钥恢复
- 选择明文线性层攻击
- 差分表 GF(2) 线性判定
- S-box 已知 k0 恢复
- 中间相遇 2^16
tags:
- crypto
- spn
- block-cipher
- chosen-plaintext
- key-recovery
- sbox
- linear-layer
- meet-in-the-middle
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:28+08:00'
  notes: 对照 Crypto469：单轮 SPN、差分表 GF(2) 线性判定 k0、MITM 解目标密文、1025 次查询一致；未复跑
---

## 一句话结论

只有一轮的 SPN `c = k1 ⊕ L(S(x ⊕ k0))` 中，若 S-box 已知、L 是 32 位线性映射，则每个明文字节的密钥可独立恢复：固定基准明文逐字节扫描 256 个值，只有正确的 k0 字节能让差分表在 GF(2) 上严格线性；恢复 k0 后回代求 k1，目标密文用 2^16 中间相遇解出，全程仅 1025 次选择明文查询。

## 原理

- 一轮 SPN 的结构是：明文 4 字节 `x` 先与 k0 逐字节异或，过 4 个 8→8 S-box，再经 32 位线性层 L，最后与 k1 异或得到密文 `c`。
- L 是线性的，可按输入字节拆成 4 个 8→32 的线性单射 `M0..M3`，于是
  `c = k1 ⊕ M0(S(x0⊕k0_0)) ⊕ M1(S(x1⊕k0_1)) ⊕ M2(S(x2⊕k0_2)) ⊕ M3(S(x3⊕k0_3))`。
  四个字节的密钥相互独立，整体 32 位密钥恢复降解为 4 个 8 位子问题加线性映射。
- 固定基准明文 `x=00000000`，只改变第 i 字节 w∈0..255，记录差分 `T[w] = E(x with byte i=w) ⊕ E(base)`。若 L 完全线性，`T[w]` 恰好是 `M_i(S(w⊕k0_i)) ⊕ M_i(S(k0_i))`，其集合是 8 维线性子空间（在 32 位空间内），四个字节的子空间独立张满。
- 对候选 K∈0..255，定义 `T_K[w]=E(byte i=w)⊕E(byte i=K)`；只有 K=k0_i 时，`T_K` 满足 GF(2) 线性：`T_K[0]=0`，且对每个 w，`T_K[w]` 等于其二进制分解在基向量 `T_K[1<<j]` 上的异或。256 个候选中恰好一个通过，从而逐字节恢复 k0。
- k0 已知后，任取已知明文/密文对回代 `k1 = c ⊕ L(S(x⊕k0))` 即得 k1。
- 目标密文（4 字节）的明文恢复可用中间相遇：枚举前两字节 `(x0,x1)` 共 2^16 种，计算 `M0(S(x0⊕k0_0))⊕M1(S(x1⊕k0_1))` 建哈希表；枚举后两字节 `(x2,x3)` 共 2^16 种，计算 `c⊕k1⊕M2(...)⊕M3(...)` 查表，命中后经 S-box 逆还原明文。
- 关键不是统计弱点而是结构弱点：一轮、S-box 公开、L 线性，使选择明文查询数与密钥长度无关（1025 次），远少于暴力 2^32。

## 触发条件

- 加密设备/接口允许选择明文查询，且同一密钥会话内可多次加密（本题同一条 TCP 连接内完成观测、求密钥、解密、提交）。
- 分组只有一轮 SPN，S-box 已知或可泄露，线性层 L 已知/可建模。
- 密钥按字节独立进入 S-box（无密钥扩展把字节混合到多轮）。
- 目标密文在同一会话内给出，攻击者需要在连接关闭前完成恢复。

## 利用步骤

1. 确认分组长度（4 字节）、S-box 表、线性层结构；固定基准明文 `00000000`，记录密文。
2. 对每个字节位置 i=0..3，扫描 w=0..255，记录 `E(byte i=w)`；用 `T_K` 的 GF(2) 线性判定逐字节恢复 k0_i。
3. 用任一已知明文/密文对回代求 k1。
4. 对目标密文做 2^16+2^16 中间相遇，命中后经 S-box 逆得到明文。
5. 在同一连接内提交明文（或按题目要求提交解密结果）换取 flag。

## PoC

```python
def lin_ok(T):
    if T[0] != 0:
        return False
    img = [T[1 << j] for j in range(8)]
    for w in range(256):
        acc = 0
        for j in range(8):
            if (w >> j) & 1:
                acc ^= img[j]
        if T[w] != acc:
            return False
    return True

def recover_k0_byte(enc):
    # enc[w] = E(base with byte i = w)；返回唯一使差分表线性的 K
    for K in range(256):
        T = [enc[w] ^ enc[K] for w in range(256)]
        if lin_ok(T):
            return K
    raise ValueError("no candidate")
```

```python
# 目标密文中间相遇（前两字节建表，后两字节查表）
table = {}
for x0 in range(256):
    for x1 in range(256):
        v = M0[S[x0 ^ k0[0]]] ^ M1[S[x1 ^ k0[1]]]
        table[v] = (x0, x1)

for x2 in range(256):
    for x3 in range(256):
        v = c ^ k1 ^ M2[S[x2 ^ k0[2]]] ^ M3[S[x3 ^ k0[3]]]
        if v in table:
            x0, x1 = table[v]
            print(bytes([x0, x1, x2, x3]))
            break
```

## 变体与关联

- 变体：两轮及以上时需积分/差分/线性密码分析，或利用密钥扩展的独立性问题；S-box 未知时需先做差分/线性特征恢复。
- 变体：线性层换成比特置换/矩阵乘法仍可分解；若 L 含非线性分量，差分线性判定不成立，需要改用统计区分器。
- 关联：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（弱密钥/固定密钥）、[[crypto-implementation-dirichlet-convolution-parameter-inversion]]（自定义密码的可逆结构）。
- 边界：选择明文次数受限或连接一次性时需压缩查询；S-box 随机但泄露是前提；中间相遇需要足够内存（2^16 项）。

## 检测与防御

- 检测：加密接口允许大量选择明文且同一密钥会话内可查询；分组很短、轮数很少；S-box/线性层被公开或可从实现中提取。
- 修复：使用标准分组密码（AES 等）并保证足够轮数；S-box 与密钥扩展不要公开；限制每密钥的加密查询次数与会话时长。
- 加固：加入随机化（nonce/IV）、认证加密（AEAD）；对加密 oracle 做限速、认证与审计；不要把目标密文与查询接口放在同一会话中。
