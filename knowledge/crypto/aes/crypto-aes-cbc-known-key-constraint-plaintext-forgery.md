---
id: crypto-aes-cbc-known-key-constraint-plaintext-forgery
title: 已知 AES-CBC KEY/IV 的明文条件伪造：按约束构造明文再加密通过校验
type: scenario
domain: crypto
path: crypto/aes
technique: aes-cbc-known-key-constraint-plaintext-forgery
aliases:
- AES-CBC 条件伪造
- 已知密钥加密
- 明文约束校验
- CBC 选择明文
- 固定 KEY/IV
tags:
- crypto
- aes
- cbc
- known-key
- chosen-plaintext
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:49:45+08:00'
  notes: 已对照原文核对；KEY/IV 公开、9 个位置约束、256 字节明文构造与本地加密流程一致
---

## 一句话结论

当服务端把 AES-CBC 的 KEY 与 IV 直接交给攻击者，并只检查解密后明文在若干固定位置的字节值时，攻击者不需要破解 AES：构造一个满足这些位置约束的 256 字节明文（其余位置填任意值），用同一 KEY/IV 做 CBC 加密，提交得到的密文即可通过校验并拿到 flag。

## 原理

- **AES-CBC 加密/解密**：`C_i = E_K(P_i ⊕ C_{i-1})`，`P_i = D_K(C_i) ⊕ C_{i-1}`，其中 `C_0 = IV`。只要 KEY 与 IV 已知，攻击者可以对任意明文 `P` 本地算出合法密文 `C`，服务端用同一组 KEY/IV 解密必然还原 `P`。
- **条件校验的弱点**：本题服务端读取 256 字节 base64 密文，解密后只检查 9 个固定索引 `8,30,41,63,67,91,104,122,143` 的 ASCII 值是否等于 `85,108,50,122,115,75,103,90,52`，其余字节不检查。攻击者构造明文时把这些位置写成目标值，其余位置随便填（本题填 `A`），即可满足全部条件。
- **为什么不需要 padding oracle/位翻转**：这里 KEY 和 IV 都是公开的，攻击者拥有加密能力，问题退化为“按已知明文生成密文”；位翻转攻击是在只知道 IV、不知道 KEY 时使用的另一类技巧。
- **边界**：如果服务端使用随机 IV 并在解密时从密文前缀读取 IV，攻击者仍可在本地加密后拼接该 IV（若协议允许）；如果服务端有 MAC/认证加密，或对密文做签名，则需要额外密钥，不能直接伪造。

## 触发条件

- 服务端/客户端源码、配置或二进制中泄露 AES-CBC 的 KEY 与 IV（本题直接在 task 源码中给出）。
- 服务端对攻击者提交的密文解密后只做位置约束检查，没有 MAC/认证、没有签名、没有服务端随机挑战。
- 密文长度固定（本题 256 字节），base64 严格解码能通过。
- 攻击者能连接服务并提交 base64 密文。

## 利用步骤

1. 从源码/配置提取 `KEY`、`IV`、`conditions` 字典。
2. 构造 256 字节 `m2`：默认填 `A`（0x41），把 `conditions` 中每个位置设为对应值。
3. 用 `AES.new(KEY, AES.MODE_CBC, IV).encrypt(bytes(m2))` 得到 256 字节密文，`base64.b64encode` 编码。
4. 连接服务，读到 `c2.encode('base64')=` 提示后提交 base64；服务端解密后 9 个位置全部匹配，打印 flag。
5. 本题得到 `0xGame{th15 15 my v1ct0ry}`；可用本地 `AES.decrypt` 复核每个位置。

## PoC

```python
from base64 import b64encode
from Crypto.Cipher import AES

KEY = bytes.fromhex("185608cdb3409b141aa6812757d41cc9")
IV = bytes.fromhex("2d1aed23dff9f1f2e30836642237a752")
conditions = {8: 85, 30: 108, 41: 50, 63: 122, 67: 115,
              91: 75, 104: 103, 122: 90, 143: 52}

m2 = bytearray(b"A" * 256)
for pos, val in conditions.items():
    m2[pos] = val

c2 = AES.new(KEY, AES.MODE_CBC, IV).encrypt(bytes(m2))
assert len(c2) == 256
payload = b64encode(c2).decode()
print(payload)
```

```python
# 验证：服务端会用同一 KEY/IV 解密
pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(c2)
assert all(pt[pos] == val for pos, val in conditions.items())
```

## 变体与关联

- **变体（只泄露 IV）**：若 KEY 未知、IV 已知且明文部分已知，可用 CBC 位翻转修改前一块密文，控制后一块明文的指定字节；需要已知明文或可预测明文。
- **变体（随机 IV）**：若 IV 随密文发送，攻击者可本地加密后替换前缀 IV；若 IV 由服务端保密且参与校验，则需要其他泄露。
- **变体（固定 key + ECB）**：无 IV、逐块独立，直接本地加密即可；与二进制中硬编码 key 的密文复现同类。
- **关联卡片**：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定 key/ECB 的密文复现）、[[crypto-aes-gcm-nonce-reuse-keystream-xor]]（另一种 AES 模式误用）、[[code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge]]（前端 AES-CBC 参数还原与请求伪造）。
- **边界**：服务端若有 HMAC/GCM tag/签名，伪造会失败；KEY/IV 若是会话级随机且不泄露，条件伪造不成立；密文长度/编码校验需满足。

## 检测与防御

- **密钥管理**：不要把对称密钥/IV 硬编码在客户端或可下载的源码中；客户端不应具备生成服务端可信密文的能力。
- **认证加密**：使用 AES-GCM/ChaCha20-Poly1305 等 AEAD，并校验 tag；或对密文做 HMAC/签名，防止攻击者构造任意密文。
- **服务端校验**：不要只检查解密明文的少数位置；使用服务端生成的随机挑战/会话绑定，避免重放和离线构造。
- **检测**：代码审计中搜索硬编码 `KEY`/`IV`、`AES.MODE_CBC`、对解密明文做索引比较的逻辑；CTF 中看到 KEY/IV 直接给出、只校验若干位置时，按本卡构造明文。
