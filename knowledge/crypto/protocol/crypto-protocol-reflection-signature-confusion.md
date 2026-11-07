---
id: crypto-protocol-reflection-signature-confusion
title: 协议反射与中介攻击：证书和签名文本未绑定发送者导致双方互签
type: scenario
domain: crypto
path: crypto/protocol
technique: protocol-reflection-signature-confusion
aliases:
- 协议反射攻击
- 中介攻击
- mediation attack
- 签名文本未绑定
- 证书名字绑定缺陷
- 双方互签
tags:
- protocol
- reflection
- mediation
- signature
- certificate-binding
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:24:59+08:00'
  notes: 已对照原文 Protocol Analysis 7/8 核对：攻击者用自己证书 X 让 Alice 对 {X,nB,nA} 签名，再转给 Bob；反射变体（X=bob、nonce 顺序）与原文一致；confidence=medium 合理；未实际运行。
---

## 一句话结论

协议要求一方对 `{X, nX, nA}` 这类“身份 + 随机数”文本签名，但签名没有绑定接收者、方向或会话上下文；攻击者可以用自己的合法身份/证书 `X` 作为中介，让 Alice 对包含 Bob 随机数的文本签名，再把该签名原样转给 Bob，Bob 因只验证“Alice 的签名”而接受，最终交出 flag。

## 原理

- 协议中 Alice 接受 `pubX, X, certX, nX, {X, nX, nA}privX`：她验证 `certX` 与 `X` 的绑定，然后用私钥对 `{X, nX, nA}` 签名并返回 `{alice, nX, nA}privA`。
- 证书只保证“`certX` 对应的私钥持有者叫 `X`”，并不保证 `X` 是 Alice 以为的通信对象；攻击者可以为自己的名字 `X` 申请合法证书，从而满足 Alice 的格式要求。
- 更关键的是签名文本 `{X, nX, nA}` 没有包含“接收者是谁、签名用途、会话 ID、消息方向”。攻击者把 `nX` 设为 Bob 发来的随机数 `nB`，让 Alice 签出 `{alice, nB, nA}privA`，再转给 Bob；Bob 只检查签名者是 Alice、随机数是自己的 `nB`，于是接受。
- 反射变体：Bob 的最终校验只接受 `d:<nonce>|d:<sig>`，且实现可能校验的是 `bob` 这一路的签名文本；攻击者把 `X` 设为 `bob`，让 Alice 签出 `{bob, nB, nA2}privA`，再反射回 Bob，Bob 认为这是自己参与的消息。
- 本质是“签名语义不完整”：签名覆盖了名字和随机数，但没有覆盖“谁应该验证这条签名”“签名属于哪个协议/会话/方向”，导致签名可被跨上下文重放。

## 触发条件

- 协议使用“名字 + nonce + 签名”的消息格式，但签名不包含接收者、会话 ID、方向或协议标识。
- 服务端接受任意合法证书/身份作为中介 `X`，只校验证书与名字的绑定。
- 攻击者能获得自己的密钥对与证书，并能与 Alice、Bob 双方交互。
- 双方的 nonce 可以被攻击者选择/转发，且最终校验只检查签名与部分字段。

## 利用步骤

1. 获取 Alice 的首条消息 `pubA, alice, certA, nA`，原样转给 Bob。
2. Bob 返回 `pubB, bob, certB, nB, sigB`；记录 `nB`。
3. 生成攻击者密钥对 `(pubX, privX)`，为身份 `X` 申请证书 `certX`。
4. 用 `privX` 对 `{X, nB, nA}` 签名，构造 `pubX, X, certX, nB, {X,nB,nA}privX` 发给 Alice。
5. Alice 返回 `{alice, nB, nA}privA`；把它转给 Bob。
6. Bob 验证 Alice 的签名与 `nB` 后返回 flag；若失败，尝试反射变体：把 `X` 设为 `bob`/`alice`，或交换 nonce 顺序，观察 Bob 实际校验的文本。
7. 解析最终响应中的 flag。

## PoC

```python
import requests

BASE = "https://<protocol-host>"
ATTACKER = "mallory"

def api(path, conn_id, content=""):
    r = requests.post(f"{BASE}{path}", json={"conn_id": conn_id, "content": content}, timeout=20)
    r.raise_for_status()
    return r.json()["content"]

def field(content, typ):
    return next(v for t, v in (x.split(":", 1) for x in content.split("|")) if t == typ)

r = requests.post(f"{BASE}/model/7", timeout=20)
conn_id = r.json()["conn_id"]

# 1) Alice -> Bob
alice0 = api("/alice", conn_id, "")
pubA, nameA, certA, nA = [v for t, v in (x.split(":", 1) for x in alice0.split("|"))][:4]
bob1 = api("/bob", conn_id, alice0)
pubB, nameB, certB, nB = [v for t, v in (x.split(":", 1) for x in bob1.split("|"))][:4]

# 2) 攻击者身份 X + 证书
kp = api("/util/gen_asym_key_pair", 0, "")
keys = [v for t, v in (x.split(":", 1) for x in kp.split("|")) if t == "k"]
pubX, privX = keys[0], keys[1]
certX = field(api("/util/get_cert", 0, f"k:{pubX}|n:{ATTACKER}"), "d")

# 3) 让 Alice 对 {X, nB, nA} 签名
sigX = field(api("/util/asym_sign", 0, f"k:{privX}|t:n:{ATTACKER}|d:{nB}|d:{nA}"), "d")
msg_to_alice = f"k:{pubX}|n:{ATTACKER}|d:{certX}|d:{nB}|d:{sigX}"
alice2 = api("/alice", conn_id, msg_to_alice)

# 4) 把 Alice 的签名响应转给 Bob
print(api("/bob", conn_id, alice2))
```

## 变体与关联

- 变体：反射攻击，把 `X` 设为 `bob` 或 `alice`，让一方对另一方期望的文本签名。
- 变体：nonce 顺序交换、nonce 来源切换（对方 nonce / 自己 nonce），用于探测实现实际校验的字段。
- 变体：跨协议签名重用，同一密钥在多个协议中签相似文本，缺少域分离。
- 关联：[[crypto-protocol-public-key-substitution-unbound-cert]]（证书/公钥绑定）、[[crypto-protocol-identity-field-spoofing-missing-sender-auth]]（身份伪造）、[[crypto-protocol-decrypt-reencrypt-oracle]]（服务端 oracle）。

## 检测与防御

- 防御：签名文本必须包含发送者、接收者、会话 ID、方向、协议版本与用途，并做域分离（如 `sign("proto-v1", sender, receiver, session, nonce, data)`）。
- 防御：验证 `X` 必须是当前会话期望的对端身份，不接受任意合法证书作为中介；使用 TLS 通道绑定（channel binding）。
- 检测：日志中出现同一签名在不同会话/方向被重用、同一身份短时间内为多个对端签名、nonce 与签名文本不匹配。
- 响应：确认签名可重放后，轮换相关密钥，审计所有使用该签名格式的协议消息。
