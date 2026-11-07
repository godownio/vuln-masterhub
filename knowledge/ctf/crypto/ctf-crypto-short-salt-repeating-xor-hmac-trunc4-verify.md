---
id: ctf-crypto-short-salt-repeating-xor-hmac-trunc4-verify
title: 3 字节短盐循环 XOR + HMAC-SHA256 截断验证：已知前缀恢复盐
type: scenario
domain: ctf
path: ctf/crypto
technique: short-salt-repeating-xor-hmac-trunc4-verify
aliases:
- 短盐循环 XOR
- 3 字节 salt
- HMAC-SHA256 截断 4 字节
- BabyCrypto
- 已知前缀恢复盐
tags:
- ctf
- crypto
- xor
- salt
- hmac
- sha256
- known-prefix
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:53:39+08:00'
  notes: 已对照原文核对：flag_enc XOR 3 字节 salt 循环、已知前缀 grodno{ 恢复 salt、128 组 HMAC-SHA256 截断 4 字节全匹配验证、最终 flag 均一致；PoC 为原文脚本重写，未复跑。
---

## 一句话结论

当 `flag_enc = flag XOR (salt 循环重复)` 且 salt 只有 3 字节时，已知 flag 前缀 `grodno{` 即可直接解出 salt；再用数据集中 128 组 `HMAC-SHA256(key=salt, msg)[:4]` 全部匹配来验证 salt，最后用同一 salt 循环 XOR 解密 `flag_enc`。

## 原理

- **循环 XOR**：`C[i] = P[i] XOR salt[i % 3]`；已知前 3 个明文字节（如 `gro`）即可 `salt[i]=C[i]^P[i]`，得到 3 字节 salt。
- **前缀一致性**：用候选 salt 检查后续前缀字节 `C[i] XOR salt[i%3] == P[i]`；若一致，salt 基本确定。
- **MAC 验证**：数据集给出 128 组 `(message, mac)`，`mac=HMAC-SHA256(key=salt,msg)` 截断前 4 字节；用候选 salt 重算全部 MAC，若 128 条全匹配，说明 salt 正确（4 字节截断的偶然碰撞概率约 `2^-32`，128 条同时碰撞可忽略）。
- **解密**：`flag = flag_enc XOR salt`（循环重复）；本题得到 `grodno{Walter_put_your_salt_away_Walter}`。
- **为什么可行**：盐太短且直接当 HMAC key 使用；已知明文前缀泄露 key，MAC 数据集又提供了强验证 oracle；HMAC 本身安全，但 key 太短/可猜。
- **边界**：若 salt 长度未知，可枚举 1..N 并用前缀/MAC 验证；若 flag 前缀未知，可用频率/字典或 MAC oracle 逐步猜。

## 触发条件

- 题目给出 `flag_enc` 与一组 `(message, mac)`；说明/代码写明 `flag XOR salt 循环` 与 `HMAC-SHA256(key=salt)` 截断。
- salt 长度短（本题 3 字节）且 flag 前缀已知/可猜（如比赛 flag 格式）。
- MAC 截断长度足够（4 字节）且组数多，可做强验证。
- 能离线计算 HMAC-SHA256。

## 利用步骤

1. 从题目/代码确认 XOR 与 HMAC 参数：salt 长度、MAC 截断长度、消息编码。
2. 用已知 flag 前缀的前 `salt_len` 字节恢复 salt：`salt[i]=flag_enc[i]^prefix[i]`。
3. 用前缀后续字节检查 `flag_enc[i]^salt[i%len]==prefix[i]`，排除错误候选。
4. 对数据集中每条 `(message, mac)` 计算 `HMAC-SHA256(salt,msg)[:4]`，确认全部匹配。
5. 用 `flag_enc XOR salt` 循环解密，检查 `grodno{...}`/`flag{...}` 格式。
6. 若 salt 长度未知，枚举 1..16，重复 2–4，取全匹配者。

## PoC

```python
import json, hashlib

def hmac_sha256_trunc4(key: bytes, msg: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5c for b in key)
    inner = hashlib.sha256(ipad + msg).digest()
    return hashlib.sha256(opad + inner).digest()[:4]

def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

data = json.load(open("dataset.json"))
flag_enc = bytes.fromhex(data["flag_enc"])
prefix = b"grodno{"
salt = bytes(flag_enc[i] ^ prefix[i] for i in range(3))
print("salt =", salt.hex())

for item in data["dataset"]:
    assert hmac_sha256_trunc4(salt, item["message"].encode()) == bytes.fromhex(item["mac"])
print(xor_repeat(flag_enc, salt).decode())
```

说明：PoC 按原文 `dataset.json` 结构重写；实际字段名/编码需按题目调整。未在本机对附件复跑。

## 变体与关联

- **salt 长度未知**：枚举长度并用前缀/MAC 验证；也可用已知明文攻击逐字节恢复。
- **MAC 截断**：4/8/16 字节；截断越短，验证力越弱，需要更多组或已知前缀。
- **XOR 变体**：`flag XOR salt`、`flag XOR SHA256(salt)`、`flag XOR keystream`；按代码确认。
- **关联**：[[ctf-crypto-repeating-xor-key-known-plaintext-oracle]]（重复 XOR 已知明文/全零 oracle）、[[crypto-hash-sha256-length-extension-append-field]]（HMAC 构造错误）。

## 检测与防御

- **不要用短盐/短 key 直接做 HMAC key**：salt 应是随机 16+ 字节，HMAC key 应独立随机；短 key 可被已知明文/暴力恢复。
- **不要用 XOR 作为加密**：XOR 只是混淆；使用 AES-GCM/ChaCha20-Poly1305 等 AEAD。
- **检测**：CTF 中看到 `flag_enc` + 大量 `(message, mac)` 组合，优先怀疑短 key + 截断 MAC；真实系统审计硬编码短 salt/密钥。
