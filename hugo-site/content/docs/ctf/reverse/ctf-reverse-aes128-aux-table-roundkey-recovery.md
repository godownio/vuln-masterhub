---
id: ctf-reverse-aes128-aux-table-roundkey-recovery
title: AES-128 辅助表泄露 RK9/RK10：逐字节枚举恢复轮密钥并反推主密钥
type: scenario
domain: ctf
path: ctf/reverse
technique: aes128-aux-table-roundkey-recovery
tags:
- ctf
- reverse
- aes
- whitebox
- round-key
- key-schedule
- sbox
- cryptanalysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:43+08:00'
  notes: 已对照原文核对：unk_40A120 16 个 block、常量状态逐字节置 0、枚举 RK9[q] 求唯一 RK10[p]、反向 Key Schedule 均与原文脚本一致；未复跑求解脚本。
url: /docs/ctf/reverse/ctf-reverse-aes128-aux-table-roundkey-recovery/
draft: false
kb_aliases:
- AES 轮密钥恢复
- 白盒 AES 辅助表
- RK9 RK10 枚举
- 反推 AES Key Schedule
- findkey
---

## 一句话结论

当程序内置一张 256 字节辅助表，且每个 16 字节 block 对应“把常量状态某个字节置 0 后经过 MixColumns→AddRoundKey(RK9)→SubBytes→ShiftRows→AddRoundKey(RK10)”的输出时，可对每个位置枚举 RK9 字节（0..255），只有正确值能让 16 个 block 推出同一个 RK10 字节；恢复完整 RK9/RK10 后反向执行 AES-128 Key Schedule 即得原始密钥。

## 原理

- **AES-128 结构**：明文 16 字节，10 轮；每轮 SubBytes、ShiftRows、MixColumns、AddRoundKey。最后两轮轮密钥 RK9、RK10 决定从第 9 轮状态到密文的映射。
- **辅助表的构造**：`unk_40A120` 有 16 个 block；block i 是把常量状态 C 的第 i 字节置 0 得到 C_i，再执行 `MixColumns(C_i) → AddRoundKey(RK9) → SubBytes → ShiftRows → AddRoundKey(RK10)` 的结果。
- **逐字节约束**：对输出位置 p，令 q = ShiftRows⁻¹(p)，有 `dest[i][p] = S(MC_i[q] xor RK9[q]) xor RK10[p]`。固定 p 时，`MC_i[q]` 可对 16 个 block 计算，`dest[i][p]` 已知；未知只有 RK9[q] 与 RK10[p]。
- **枚举求唯一解**：对每个候选 RK9[q]∈0..255，用 16 个 block 分别算 `RK10[p] = dest[i][p] xor S(MC_i[q] xor RK9[q])`；只有正确 RK9[q] 会让 16 个结果全部相同，从而同时确定 RK9[q] 与 RK10[p]。
- **反推主密钥**：AES-128 Key Schedule 可逆；已知 RK9（w[36..39]）与 RK10（w[40..43]），按 `w[i-4] = w[i] xor (SubWord(RotWord(w[i-1])) xor Rcon)` 反向迭代到 w[0..3]，拼接即原始 16 字节密钥（flag）。
- **前提**：能静态提取 S-box、辅助表与常量状态；辅助表与常量状态的字节序/ShiftRows 方向要与实现一致。

## 触发条件

- 逆向目标实现标准或近似标准 AES-128，且内置一张与轮密钥相关的辅助表/校验表。
- 辅助表的每个 block 对应“单字节置 0”的输入，或其他可建立逐字节约束的构造。
- 已知固定明文/常量状态与期望密文，或能推导出对应关系。
- 可使用 Python/Sage 实现 AES 的 MixColumns、ShiftRows、S-box 与 Key Schedule。

## 利用步骤

1. 从二进制提取 S-box（256 字节）、辅助表（16×16 字节）与常量状态（两个 qword 小端拼接）。
2. 对每个 i，把常量状态第 i 字节置 0，计算 `MC_i = MixColumns(C_i)`。
3. 建立 ShiftRows 的逆映射 q = ShiftRows⁻¹(p)。
4. 对每个 p，枚举 RK9[q]=0..255，检查 16 个 block 推出的 RK10[p] 是否一致；记录唯一解。
5. 得到完整 RK9/RK10，执行 AES-128 反向 Key Schedule 得到原始密钥。
6. 用该密钥加密固定明文，确认等于程序内置密文；输出 key/flag。

## PoC

```python
def recover_rk9_rk10(dest_blocks, const_state, sbox, shift_inv):
    mc = []
    for i in range(16):
        c = const_state[:]
        c[i] = 0
        mc.append(mix_columns(c))

    rk9, rk10 = [0]*16, [0]*16
    for p in range(16):
        q = shift_inv[p]
        for k9 in range(256):
            vals = [dest_blocks[i][p] ^ sbox[mc[i][q] ^ k9] for i in range(16)]
            if len(set(vals)) == 1:
                rk9[q], rk10[p] = k9, vals[0]
                break
    return bytes(rk9), bytes(rk10)

# reverse AES-128 key schedule from RK9/RK10
def reverse_key_schedule(rk9, rk10, sbox):
    w = [None]*44
    w[36:40] = [list(rk9[i:i+4]) for i in range(0, 16, 4)]
    w[40:44] = [list(rk10[i:i+4]) for i in range(0, 16, 4)]
    rcon = [0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    for i in range(43, 3, -1):
        temp = w[i-1].copy()
        if i % 4 == 0:
            temp = [sbox[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= rcon[i // 4]
        w[i-4] = [a ^ b for a, b in zip(w[i], temp)]
    return bytes(sum(w[0:4], []))
```

## 变体与关联

- 变体：辅助表泄露的是 RK8/RK9、RK10 或中间状态；只要能建立“单字节未知 + 多 block 一致性”的约束，都可枚举。
- 变体：AES-192/256 轮密钥更多，反向 Key Schedule 的步长与 Rcon 不同，但方法相同。
- 变体：若 S-box 被魔改或轮函数顺序不同，先还原 S-box/ShiftRows 映射再套约束。
- 关联：[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]（自定义 Rcon/Key Schedule）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（AES 参数复现）、[[ctf-reverse-png-lsb-custom-sbox-aes256-decrypt]]（自定义 S-box 的 AES 解密）。

## 检测与防御

- CTF 分析：先确认 AES 轮数、S-box、ShiftRows 方向与端序；辅助表的 block 顺序与常量状态要逐字节核对。
- 防御：不要把轮密钥/中间状态以可推导形式内置在客户端；使用白盒 AES 时也要做密钥隐藏与完整性校验。
- 该技术为离线逆向/密码分析，不影响运行中的服务；仅用于授权 CTF/安全研究。
