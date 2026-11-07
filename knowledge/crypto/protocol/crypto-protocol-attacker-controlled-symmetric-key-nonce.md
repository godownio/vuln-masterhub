---
id: crypto-protocol-attacker-controlled-symmetric-key-nonce
title: 协议密钥替换：服务端使用攻击者提供的对称密钥与 nonce 加密敏感数据
type: scenario
domain: crypto
path: crypto/protocol
technique: protocol-attacker-controlled-symkey
aliases:
- 对称密钥替换
- attacker-controlled key
- nonce 替换
- 密钥协商缺失
- 用攻击者密钥加密 flag
tags:
- protocol
- key-substitution
- symmetric-crypto
- nonce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:24:56+08:00'
  notes: '已对照原文 Protocol Analysis 4 核对：Bob 接受请求中的 k:/d: 作为对称 key/nonce 加密 flag，攻击者用 /util/sym_decrypt 解出；PoC（含原文 symetric 拼写）一致；未实际运行。'
---

## 一句话结论

协议允许请求方在消息里直接指定对称加密的 key 与 nonce（例如 `k:<KEY>|d:<NONCE>`），服务端不做任何校验就用它加密敏感数据；攻击者自己生成 key/nonce，收到密文后用同一组参数解密，即可拿到明文。

## 原理

- 正常协议应由双方通过认证的密钥交换（或预共享的可信密钥）得到会话密钥；密钥材料不能由某一方在应用层消息里任意指定。
- 该协议中 Alice 的请求包含 `t:send me the flag encrypted under this symmetric key and nonce|k:<KEY>|d:<NONCE>`，Bob 直接采用消息中的 `k`、`d` 作为 AES（或等价对称算法）的密钥与 nonce 加密 flag。
- 攻击者伪造一条“来自 Alice”的请求，把 `k`、`d` 换成自己生成的值；Bob 返回密文后，攻击者用相同 key/nonce 解密。由于密钥完全由攻击者控制，加密不提供任何机密性。
- 即使协议有身份字段或简单的名字校验，只要密钥材料仍由请求方控制，攻击就成立；身份伪造与密钥替换是两个独立缺陷，常组合出现。
- 变体：服务端只接受 key ID，但 key ID 可指向攻击者预先注册的密钥；或 nonce 可预测/可复用，导致密钥流重用。

## 触发条件

- 协议消息包含 `key`、`nonce`、`iv`、`salt` 等密钥材料字段，服务端直接使用。
- 服务端不校验密钥是否由可信方生成、是否与发送者身份/会话绑定。
- 攻击者能伪造请求并获得加密结果。
- 加密算法与参数格式已知（key/nonce 长度、编码方式）。

## 利用步骤

1. 阅读协议，确认 Bob 接收的字段顺序与真实模板（注意服务端可能使用拼写错误或非文档化文案）。
2. 生成自己的对称 key 与 nonce（长度按算法要求，如 AES-256 key 32 字节、nonce 12 字节）。
3. 伪造 Alice 的请求，把 `k:`、`d:` 替换为自己的值，提交给 Bob。
4. 从 Bob 响应中提取密文（通常在 `d:` 字段）。
5. 调用协议提供的解密工具或本地实现，用同一 key/nonce 解密密文，得到 flag/敏感数据。
6. 若解密失败，检查字段顺序、编码（hex/base64）、nonce 长度与 AEAD tag 位置。

## PoC

```python
import secrets
import requests

BASE = "https://<protocol-host>"

r = requests.post(f"{BASE}/model/4", timeout=15)
r.raise_for_status()
conn_id = r.json()["conn_id"]

key_hex = secrets.token_hex(32)    # 32 字节 key
nonce_hex = secrets.token_hex(12)  # 12 字节 nonce

content = (
    "t:Hello|n:bob|t:this is|n:alice|"
    "t:send me the flag encrypted under this symetric key and nonce|"
    f"k:{key_hex}|d:{nonce_hex}"
)
r = requests.post(f"{BASE}/bob", json={"conn_id": conn_id, "content": content}, timeout=15)
r.raise_for_status()
bob_content = r.json()["content"]
cipher_hex = next(x[2:] for x in bob_content.split("|") if x.startswith("d:"))

r = requests.post(
    f"{BASE}/util/sym_decrypt",
    json={"conn_id": conn_id, "content": f"k:{key_hex}|d:{nonce_hex}|d:{cipher_hex}"},
    timeout=15,
)
r.raise_for_status()
print(r.json()["content"])
```

## 变体与关联

- 变体：只控制 nonce 时，若密钥固定且 nonce 可复用，可能导致 CTR/GCM 密钥流重用。
- 变体：服务端接受 key ID 而非原始 key，攻击者注册/猜测指向自己密钥的 ID。
- 变体：协议使用 RSA 公钥替换而非对称密钥，见公钥替换卡片。
- 关联：[[crypto-protocol-identity-field-spoofing-missing-sender-auth]]（身份伪造）、[[crypto-protocol-public-key-substitution-unbound-cert]]（公钥替换）、[[crypto-aes-gcm-nonce-reuse-keystream-xor]]（nonce 复用）。

## 检测与防御

- 防御：密钥必须来自认证的密钥交换或服务端可信存储，绝不接受请求方在应用层指定的原始密钥材料。
- 防御：使用 AEAD（AES-GCM/ChaCha20-Poly1305），把发送者、接收者、会话 ID 作为 AAD 绑定；nonce 由服务端或可信方生成并防重用。
- 检测：协议日志中出现客户端提供的 `key`/`nonce` 字段、同一密钥被多次使用、nonce 重复。
- 响应：确认密钥替换后，轮换相关密钥，审计所有使用该接口加密的敏感数据。
