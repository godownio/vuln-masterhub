---
id: ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root
title: AES-GCM nonce 复用：tag 差分在 GF(2^128) 求根恢复 GHASH 子密钥 H
type: scenario
domain: ctf
path: ctf/crypto
technique: gcm-nonce-reuse-ghash-h-recovery
tags:
- ctf
- crypto
- aes-gcm
- nonce-reuse
- ghash
- gf128
- hkdf
- authenticated-encryption
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:44:56+08:00'
  notes: 已对照原文核对；GHASH 差分式与 GF(2^128) 求根流程正确，三份许可 HMAC 验证及 status=current 裁决一致
url: /docs/ctf/crypto/ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root/
draft: false
kb_aliases:
- GCM nonce 复用
- GHASH 子密钥恢复
- H 子密钥
- tag 差分
- GF(2^128) 求根
- nonce reuse
---

## 一句话结论

AES-GCM 在同一 nonce、同一 AAD、同长度下加密多帧时，两帧 tag 异或会消去 `Ek(J0)` 与长度块，只剩关于 GHASH 子密钥 `H` 的多项式；在 GF(2^128) 上求根并用第三帧验证，即可恢复 `H`，进而解密同链路其他载荷或作为 HKDF 输入解开许可。

## 原理

- **GHASH 是 H 的多项式**：GCM 的认证标签 `tag = Ek(J0) XOR GHASH(H, AAD, C)`；同一 nonce 下 `J0` 相同，`Ek(J0)` 在 tag 异或时抵消。
- **同长度同 AAD 进一步简化**：两帧明文长度相同则长度块相同，AAD 相同则 AAD 项相同，差分后只剩密文块差分构成的多项式。示例 32 字节明文 = 2 个密文块、16 字节 AAD = 1 块，差分形式为 `tag1^tag2 = dC1*H^3 ^ dC2*H^2`。
- **GF(2^128) 上求根**：在 `x^128 + x^7 + x^2 + x + 1` 定义的域上解三次多项式，最多 3 个根；用第三帧的 GHASH/tag 验证，只有一个根能同时满足三帧。
- **H 的价值**：H 是 GHASH 子密钥，示例中同时被用作 HKDF 的 IKM（`ikm = H`）；泄露 H 等价于泄露所有由它派生的许可密钥。
- **nonce 复用还直接泄露密钥流**：`C1 XOR C2 = P1 XOR P2`，已知一段明文即可推出另一段；本卡以 H 恢复为主，两条路径可互相验证。

## 触发条件

- AES-GCM 使用 12 字节 nonce，且同一 nonce 在不同帧中重复（计数器跳变、epoch 复用、随机数碰撞）。
- 复用组内 AAD 相同、明文长度相同（示例每组三帧）。
- 攻击者拿到 nonce、AAD、密文与 tag（抓包/日志）。
- GHASH 位序与域多项式已知（NIST SP 800-38D 标准实现）。

## 利用步骤

1. 按 `(nonce, AAD)` 分组统计，找出现次数大于 1 的复用组。
2. 确认组内帧长度相同、AAD 相同；不同 nonce 的帧不参与。
3. 取两帧 tag 异或，按 GHASH 结构写出关于 H 的多项式；同长度同 AAD 时只剩密文差分项。
4. 在 GF(2^128) 上求多项式根，得到候选 H（最多 3 个）。
5. 用第三帧代入 GHASH 计算 tag，与抓包 tag 比对，筛出唯一真 H。
6. 用 H 作为 HKDF IKM 派生许可密钥，或直接恢复其他帧明文；用 HMAC/回环验证。

## PoC

```python
def gf128_mul(a, b):
    p = 0
    for i in range(127, -1, -1):
        if (b >> i) & 1:
            p ^= a
        a = (a >> 1) ^ (0xE1000000000000000000000000000000 if a & 1 else 0)
    return p

# SageMath：在 GF(2^128) 商域上求根
R.<x> = PolynomialRing(GF(2))
S.<a> = R.quotient(x^128 + x^7 + x^2 + x + 1)
h = S.from_integer(candidate)
poly = S.from_integer(dC1) * h^3 + S.from_integer(dC2) * h^2
roots = poly.roots(multiplicities=False)
# 用第三帧 GHASH/tag 验证唯一根
```

```python
# H 作为 HKDF IKM 派生许可密钥
def hkdf(ikm, salt, info, n=32):
    prk = hmac.new(salt, ikm, sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), sha256).digest()
        okm += t; i += 1
    return okm[:n]
```

原文实测：三个复用组各三帧；三帧 tag 联立求出 H，三份许可 HMAC 全部校验通过；仅 `status=current` 的 ch1 为有效许可，ch2/ch3 明文自写 `N0t_4_Fl4g`/`N0t_4_Us3` 为诱饵；flag `flag{GCM_N0nc3_R3u53_1s_F0rb1dd3n_26}`。

## 变体与关联

- **复用形态变体**：同 nonce 不同 AAD、同 nonce 不同长度、计数器回绕/epoch 复用；AAD/长度不同时差分多项式项更多，但思路相同。
- **目标变体**：恢复 H、恢复明文（密钥流复用）、伪造 tag、解密由 H 派生的下游密钥。
- **实现陷阱**：GHASH 位序是反射的，块内字节按大端进入域元素；位反转错误会安静地给出错误多项式。
- **关联卡片**：[[ctf-crypto-lfsr-known-plaintext-state-recovery]]（同篇流密码状态恢复）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（AES 参数复现）。
- **边界**：nonce 不复用时不成立；若 H 未用于下游密钥派生，恢复 H 只能伪造 tag/验证，不一定直接解密；位序/多项式错误会导致求根失败。

## 检测与防御

- **CTF 验证**：用第三帧 GHASH/tag 验证唯一根；用 HMAC/回环校验下游密钥；不要只看明文可读。
- **工程防御**：GCM nonce 必须唯一（随机 96 位或严格递增计数器）；密钥与 nonce 分离管理；限制单密钥加密次数；使用 AEAD 库并审计 nonce 生成。
- **检测信号**：抓包/日志中 `(nonce, AAD)` 重复；计数器跳变/回绕；同一 nonce 多帧；tag 校验失败。
- **复盘**：GCM 题先按 nonce 分组，再看 tag 差分能否构造关于 H 的多项式；同时检查密钥流复用这条更简单的路径。
