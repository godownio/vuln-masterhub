---
id: crypto-aes-gcm-nonce-reuse-keystream-xor
title: AES-GCM nonce 复用：同 key/nonce 两段密文异或恢复目标明文
type: scenario
domain: crypto
path: crypto/aes
technique: aes-gcm-nonce-reuse-keystream-xor
aliases:
- GCM nonce reuse
- 密钥流复用
- GCM 复用 nonce
- CTR 密钥流异或
- 已知明文异或恢复
tags:
- crypto
- aes
- gcm
- nonce-reuse
- keystream
- known-plaintext
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:49:47+08:00'
  notes: 已对照原文核对；同 key/nonce、P2=C1^C2^P1、SHA256-counter auxiliary 与 FLAC 帧头校验一致
---

## 一句话结论

AES-GCM 的加密部分是 CTR 模式，密钥流只由 key/nonce 决定；同一 key/nonce 加密两段不同明文时，`C1⊕C2 = P1⊕P2`。已知其中一段明文 `P1`，即可恢复另一段 `P2 = C1⊕C2⊕P1`，不需要 key，也不需要验证 tag。

## 原理

- **GCM = CTR + GHASH**：GCM 用 `E_K(J0+i)` 生成密钥流，与明文异或得到密文；GHASH 只负责认证 tag。CTR 的密钥流只依赖 `(key, nonce, counter)`，与明文无关。
- **nonce 复用的直接后果**：若两段消息使用同一 key、同一 nonce，则 `S_i` 相同，`C1_i⊕C2_i = (P1_i⊕S_i)⊕(P2_i⊕S_i) = P1_i⊕P2_i`。已知 `P1` 即可恢复 `P2`；即使长度不同，对齐的前缀也可恢复。
- **已知明文的来源**：本题的 auxiliary 载荷由公开信息派生：`P1 = SHA-256(label ‖ packed_measurements ‖ counter_be)` 逐块拼接，共 1,049,026 个 32 字节块；因此 `P1` 完全可计算。两段载荷同属一个加密会话，nonce 复用为 `493f129a43aa177e65baca25`。
- **格式校验**：恢复出的 `P2` 以 `ff f8` 开头，是 FLAC 帧同步码；把它与容器中的公开 FLAC 元数据（以 `fLaC` 开头）拼接，得到可播放 FLAC，读取 Vorbis comment 即可得到答案。
- **认证不等于保密**：GCM 的 tag 不能阻止已知明文下的异或恢复；nonce 复用还会破坏认证（理论上可恢复 GHASH 认证密钥并伪造 tag），本题只利用机密性。
- **为什么成立**：CTR/GCM 是流密码式加密，密钥流复用是最经典的“两次一密”（two-time pad）问题；只要一段明文已知或可预测，另一段就泄露。

## 触发条件

- 同一 key/nonce 加密两段消息（nonce reuse），或 nonce 可预测且重复。
- 至少一段明文已知或可预测（known plaintext），或能通过文件头/协议字段猜出部分明文。
- 两段密文可获取且能按字节对齐；nonce 在容器/协议中可见或可推导。
- 目标数据长度不超过已知明文可覆盖的范围；超出部分只能恢复已知前缀对应的明文。

## 利用步骤

1. 解析容器/协议，定位两段密文 `C1`、`C2`、`nonce`，确认 key/nonce 相同（本题两段载荷同会话，nonce 为 `493f129a43aa177e65baca25`）。
2. 恢复/构造 `P1`：本题从 manifest 的 `auxiliary` 字段读取 `scheme=sha256-counter`、`label`、`source`，按 `SHA256(label ‖ source ‖ counter_be)` 逐块生成。
3. 计算 `P2 = C1⊕C2⊕P1`（长度取三者最小；本题两段载荷长度一致）。
4. 用文件格式头校验：`P2` 以 `ff f8`（FLAC 帧同步）开头；把公开 FLAC 元数据（`fLaC` 开头）与 `P2` 拼接成完整 FLAC。
5. 解析 FLAC 的 Vorbis comment，读取 Title/Album/Artist；本题答案为 `打上花火`。

## PoC

```python
from hashlib import sha256

def aux_block(label: bytes, source: bytes, ctr: int) -> bytes:
    return sha256(label + source + ctr.to_bytes(4, "big")).digest()

# manifest 中 auxiliary 的公开参数
label = b"QFLAC-NONCE-REUSE-PROBE"
source = packed_measurements          # 80 bit 测量材料打包后的字节串
nblocks = 1_049_026
P1 = b"".join(aux_block(label, source, i) for i in range(nblocks))

# C1、C2 为容器中定位到的两段密文（同 key/nonce）
P2 = bytes(a ^ b ^ c for a, b, c in zip(C1, C2, P1))
assert P2[:2] == b"\xff\xf8"          # FLAC 帧同步
flac = flac_meta + P2                  # flac_meta 以 b"fLaC" 开头
open("recovered.flac", "wb").write(flac)
```

## 变体与关联

- **变体（GCM 认证密钥恢复）**：nonce 复用下，知道两段明文可恢复 GHASH 的认证密钥，进而伪造任意消息的 tag；本题只利用机密性，未涉及伪造。
- **变体（CTR/ChaCha20）**：任何流密码/CTR 模式复用 nonce 都产生 `C1⊕C2=P1⊕P2`；ChaCha20-Poly1305 同样受影响。
- **变体（CBC 固定 IV）**：CBC 复用 IV 不会直接泄露明文异或，但会泄露相同明文前缀的相同密文块；需要结合位翻转/已知明文。
- **关联卡片**：[[crypto-aes-cbc-known-key-constraint-plaintext-forgery]]（另一种 AES 模式误用）、[[ctf-crypto-simon-period-measurement-gf2-nullspace]]（同一挑战中恢复 auxiliary 输入的前置步骤）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定密钥/模式复现）。
- **边界**：两段明文长度不同只能恢复重叠前缀；若 nonce 每次随机且不重复，攻击不成立；若已知明文不足，只能恢复对应位置；GCM tag 校验失败不代表明文不可恢复。

## 检测与防御

- **nonce 管理**：同一 key 下 nonce 必须唯一；使用 96-bit 随机 nonce 时注意生日界，或使用确定性计数器并持久化状态；密钥轮换可限制复用影响。
- **协议设计**：AEAD 的使用必须保证 nonce 唯一；不要把 nonce 交给不可信方控制；会话密钥分离，避免“同一 key 加密多段载荷”。
- **检测**：审计代码/流量中重复的 `(key, nonce)`；容器/协议中 nonce 字段重复、两段密文长度相同且同会话，都是强信号。
- **验证**：CTF/审计中看到 GCM 密文、公开 auxiliary/已知明文、重复 nonce 时，先尝试 `C1⊕C2⊕P1`；用文件头/格式校验确认。
