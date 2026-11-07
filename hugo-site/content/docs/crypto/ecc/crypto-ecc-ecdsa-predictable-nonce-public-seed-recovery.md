---
id: crypto-ecc-ecdsa-predictable-nonce-public-seed-recovery
title: ECDSA 可预测 nonce：由公开种子确定性派生 k 后直接恢复私钥
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-predictable-nonce-public-seed-key-recovery
tags:
- crypto
- ecc
- ecdsa
- nonce
- predictable
- private-key
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:32+08:00'
  notes: 已对照原文 ECDSA 题与 P-521/sha512(bias||i)/sha1 计算核对，公式与脚本一致；未在本地用题目签名文件复跑。
url: /docs/crypto/ecc/crypto-ecc-ecdsa-predictable-nonce-public-seed-recovery/
draft: false
kb_aliases:
- ECDSA 可预测随机数
- deterministic nonce 私钥恢复
- k = hash(seed||i) 攻击
- ECDSA known nonce
- 公开种子派生 nonce
- ECDSA 私钥恢复
---

## 一句话结论

如果 ECDSA 签名实现把 nonce `k` 用公开可推导的方式生成（例如 `k = Hash(固定字符串 || 消息序号) mod n`，或 `k = Hash(消息)`），攻击者拿到任意一条签名后就能重算出 `k`，再用 `d = (s*k - e) * r^{-1} mod n` 直接恢复私钥。

## 原理

- **ECDSA 签名方程**：`r = (k*G).x mod n`，`s = k^{-1}(e + d*r) mod n`，其中 `e = Hash(msg)`、`d` 为私钥、`n` 为基点阶、`k` 为一次性随机数。
- **k 已知即可解 d**：把方程乘以 `k` 得 `s*k = e + d*r`，移项即 `d = (s*k - e) * r^{-1} mod n`。不需要两条签名，也不需要 `r` 相同。
- **可预测 nonce 的成因**：实现者为了“确定性签名”用公开数据派生 `k`，例如 `k(i) = Hash("bias" || i)`、`k = Hash(msg)`、`k = Hash(timestamp)`、`k = Hash(username)`。只要派生输入可被攻击者重算，`k` 就不再是秘密。
- **与 RFC6979 的区别**：RFC6979 的确定性 nonce 是 `HMAC(私钥, 消息)`，输入包含私钥，攻击者不知道私钥就无法重算；而只用公开种子的“确定性”只是把随机数换成了可预测值，安全性归零。
- **示例参数**：NIST P-521 的阶为 521 bit，签名的 `r`、`s` 各占 66 字节；若实现把签名序列化为 `r||s`，需按 66 字节切分。哈希函数必须与签名端一致（示例用 SHA-1，私钥派生用 SHA-512），否则 `e` 计算错误会导致恢复失败。
- **为什么能验证**：恢复出的 `d` 满足 `d*G = Q`（公钥），可用来确认参数、哈希截断与字节序是否正确。

## 触发条件

- 目标使用 ECDSA，且 nonce 由公开数据确定性派生（固定种子、计数器、消息本身、时间戳等），或 nonce 被直接泄露。
- 攻击者能拿到至少一条 `(msg, r, s)` 签名与对应公钥/曲线参数。
- 知道签名端使用的哈希算法与签名序列化格式（r/s 字节长度、大小端）。
- `r` 在模 `n` 下可逆（正常签名均满足）。

## 利用步骤

1. 收集一条签名和对应消息，确认曲线阶 `n`、哈希算法、`r/s` 编码长度。
2. 按实现逻辑重算 nonce：如 `k = int(Hash(seed || index)) mod n`。
3. 计算消息摘要 `e = Hash(msg)`（按签名端实际哈希，必要时截断到 `n` 的位长）。
4. 计算 `d = ((s*k - e) * pow(r, -1, n)) % n`。
5. 用 `d*G == Q` 验证；若不等，检查哈希、字节序、`r/s` 切分和 `k` 是否取模。
6. 用恢复的私钥伪造签名、解密会话或登录目标系统。

## PoC

```python
from hashlib import sha1, sha512
from ecdsa import NIST521p

n = NIST521p.order
L = 66  # P-521 的 r/s 各 66 字节

# 一条签名：msg 为原始消息，sig 为 r||s
msg = bytes.fromhex("<message hex>")
sig = bytes.fromhex("<signature hex>")

i = msg[-1]                      # 示例中消息为 b"message-" + bytes([i])
k = int.from_bytes(sha512(b"bias" + bytes([i])).digest(), "big") % n
r = int.from_bytes(sig[:L], "big")
s = int.from_bytes(sig[L:], "big")
e = int.from_bytes(sha1(msg).digest(), "big")

d = ((s * k - e) * pow(r, -1, n)) % n
print(hex(d))

# 验证：ecdsa.SigningKey.from_string(long_to_bytes(d, 66), curve=NIST521p).verifying_key == 公钥
```

## 变体与关联

- 变体：`k = Hash(msg)`（不含私钥）时，攻击者可对任意已截获消息重算 `k`。
- 变体：`k` 由时间戳/递增计数器派生时，可在小范围枚举 `k` 并验证 `r` 是否匹配。
- 变体：`k` 只有部分泄露时，转为 partial nonce leak / HNP 格攻击。
- 关联卡片：[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]、[[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]、[[crypto-ecc-ecdsa-time-side-channel-hnp]]、[[crypto-ecc-ecdh-small-nonce-brute-shared-point-key]]。

## 检测与防御

- 检测：代码审计中搜索 `k = hash(...)`、`k = random(...)` 的可预测派生；检查签名是否出现重复 `r` 或可重算的 `k`。
- 检测：签名实现是否使用固定种子、消息序号、时间戳等公开输入生成 nonce。
- 防御：使用 RFC6979（HMAC-DRBG，输入包含私钥）或操作系统 CSPRNG 生成 `k`；优先使用 HSM/成熟库的签名接口。
- 防御：定期校验签名实现，禁止自研 ECDSA nonce 生成逻辑。
