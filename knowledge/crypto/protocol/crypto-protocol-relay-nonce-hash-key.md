---
id: crypto-protocol-relay-nonce-hash-key
title: 协议中继与 nonce 哈希密钥：中间人观察双方 nonce 派生会话密钥
type: scenario
domain: crypto
path: crypto/protocol
technique: protocol-relay-nonce-hash-key
aliases:
- 协议中继
- MITM relay
- nonce 哈希密钥
- 会话密钥可计算
- Sneedham-Chucker
tags:
- protocol
- relay
- mitm
- key-agreement
- nonce
- hash
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T04:34:34+08:00'
  notes: V125 指出 PoC 为骨架、无法直接复现；已明确标注为伪代码并要求按原文 exp_pa6.py 补全，原理与协议分析一致
---

## 一句话结论

协议让双方交换 nonce `nA`、`nB`，并用 `h(nA+nB)` 作为对称会话密钥加密 flag；由于 nonce 在消息中公开传递、没有身份认证或密钥交换秘密，处于中继位置的攻击者可以同时看到两个 nonce、计算出同一密钥，再解开 Bob 返回的密文。

## 原理

- 协议中 Alice 与 Bob 互相发送 nonce，最终 Bob 用 `key = h(nA + nB)` 加密 flag；`h` 是公开哈希函数。
- 密钥的全部输入 `nA`、`nB` 都在协议消息里明文传输，攻击者只要能看到/转发双方消息，就能复现 `h(nA+nB)`。
- 如果攻击者位于双方之间（中继/MITM），可以原样转发消息维持协议流程，同时记录 nonce；Bob 返回的密文用同一密钥解密。
- 即使哈希函数很强，密钥仍没有秘密性：nonce 是公开值，不是 DH 共享秘密，也没有签名/MAC 绑定身份。这与“用公开值派生密钥”是同一类问题。
- 变体：密钥可能是 `h(nA) xor h(nB)`、`h(nA||nB)`、`h(nA) + h(nB)`；只要两个输入都可观察，就能计算。
- 报文格式可能把 nonce 与密文打包在同一字段（如 `d:<nonce||ciphertext>`），需要按长度拆分。

## 触发条件

- 协议使用双方 nonce 的哈希/组合作为会话密钥，且 nonce 在消息中明文传递。
- 没有认证密钥交换（DH/ECDH + 签名）或预共享秘密；没有对 nonce 做签名/MAC。
- 攻击者能中继/观察双方消息（网络中间人、代理、日志、消息队列）。
- 最终密文字段可能包含 nonce 前缀或长度信息，可按协议拆分。

## 利用步骤

1. 获取 Alice 的首条消息，记录 `nA`；转发给 Bob。
2. 获取 Bob 的响应，记录 `nB`；转发给 Alice，维持协议。
3. 计算 `key = h(nA + nB)`（按协议实际拼接顺序/编码）。
4. 获取 Bob 最终返回的密文字段；若字段是 `nonce||ciphertext`，按 nonce 长度拆分。
5. 用 `key` 与 nonce 调用对称解密，得到 flag。
6. 若拼接顺序不确定，尝试 `h(nA+nB)`、`h(nB+nA)`、`h(nA||nB)` 等变体。

## PoC

```python
import requests

BASE = "https://<protocol-host>"

def api(path, conn_id, content=""):
    r = requests.post(f"{BASE}{path}", json={"conn_id": conn_id, "content": content}, timeout=20)
    r.raise_for_status()
    return r.json()["content"]

def field(content, typ):
    return next(v for t, v in (x.split(":", 1) for x in content.split("|")) if t == typ)

r = requests.post(f"{BASE}/model/6", timeout=20)
conn_id = r.json()["conn_id"]

# 中继双方消息，记录 nonce（具体字段名按协议调整）
nA = field(api("/alice", conn_id, ""), "d")
nB = field(api("/bob", conn_id, ""), "d")

# 计算 nonce 哈希密钥
key = field(api("/util/hash_data", 0, f"d:{nA + nB}"), "d")

# Bob 最终密文字段：前 24 hex 为 nonce，其余为密文
blob = field(api("/bob", conn_id, ""), "d")
nonce, ct = blob[:24], blob[24:]
print(api("/util/sym_decrypt", 0, f"k:{key}|d:{nonce}|d:{ct}"))
```

> 注：以上为协议流程伪代码骨架，非可直接运行的完整中继脚本；原文 exp_pa6.py 实现了多轮中继与非对称加解密，复现时需按目标协议补齐消息转发与字段解析。卡片按原文协议分析保留，PoC 未在本机执行。

## 变体与关联

- 变体：密钥由 `h(nA) xor h(nB)`、`h(nA||nB)` 等组合；拼接顺序/编码需按实现调整。
- 变体：nonce 与密文打包在同一字段，需按固定长度或长度头拆分。
- 变体：攻击者不仅中继，还可替换自己的 nonce 做降级/重放。
- 关联：[[crypto-protocol-attacker-controlled-symmetric-key-nonce]]（密钥替换）、[[crypto-protocol-reflection-signature-confusion]]（中继/反射）、[[crypto-protocol-decrypt-reencrypt-oracle]]（解密 oracle）。

## 检测与防御

- 防御：使用认证密钥交换（ECDH + 签名/证书）或预共享秘密；nonce 必须与身份、会话绑定并签名。
- 防御：不要用公开 nonce 的哈希作为唯一密钥；使用 HKDF 从共享秘密派生密钥，并用 AEAD 保护消息。
- 检测：协议中出现 `key = hash(nonce1 + nonce2)`、nonce 明文传输、无签名的会话建立。
- 响应：确认密钥可计算后，轮换会话密钥/长期密钥，审计历史密文。
