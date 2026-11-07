---
id: crypto-protocol-public-key-substitution-unbound-cert
title: 协议公钥替换：服务端把敏感数据加密到消息中携带的攻击者公钥
type: scenario
domain: crypto
path: crypto/protocol
technique: protocol-public-key-substitution
tags:
- protocol
- public-key-substitution
- certificate-binding
- asymmetric-crypto
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:24:58+08:00'
  notes: '已对照原文 Protocol Analysis 5 核对：替换消息中最后一个 k: 公钥为攻击者 pubX，Bob 把 flag 加密给 pubX，privX 解密；PoC 一致；未实际运行。'
url: /docs/crypto/protocol/crypto-protocol-public-key-substitution-unbound-cert/
draft: false
kb_aliases:
- 公钥替换
- public key substitution
- 证书未绑定身份
- 加密给攻击者
- pubX 替换
---

## 一句话结论

协议中 Bob 根据消息里携带的公钥字段 `pubX` 决定把敏感数据加密给谁，却不校验证书链、不验证公钥与身份 `X` 的绑定；攻击者生成自己的密钥对，把消息中的公钥替换成自己的，Bob 就会把 flag 加密给攻击者。

## 原理

- 公钥密码只能保证“只有对应私钥持有者能解密”，前提是加密方使用的公钥确实属于预期的接收者。
- 该协议中 Alice 发送 `t:send the flag encrypted with this asymmetric key|k:<pubA>`，Bob 接收时接受任意 `k:<pubX>`，并把 flag 加密到 `pubX`；Bob 只看到消息里写着“this is alice”，但加密对象由 `pubX` 决定。
- 攻击者调用密钥生成接口得到 `(pubX, privX)`，伪造 Alice 的消息并把 `k:` 字段换成 `pubX`；Bob 返回 `{[FLAG]}pubX`，攻击者用 `privX` 解密。
- 证书/身份字段即使存在，如果没有做“证书链验证 + 名字匹配 + 公钥与身份绑定”，仍然可被替换；攻击者也可以为自己的身份 `X` 申请合法证书，再把它塞进消息。
- 与对称密钥替换的区别：这里攻击者控制的是非对称公钥，服务端用该公钥加密，攻击者用私钥解密；根因相同——加密对象由不可信输入决定。

## 触发条件

- 协议消息包含公钥/证书字段，服务端据此选择加密对象。
- 服务端不校验证书链、不验证公钥与声明身份/会话的绑定，或接受任意自签证书。
- 攻击者能生成密钥对并伪造请求。
- 服务端返回的密文格式与攻击者私钥匹配（同一算法/曲线/填充）。

## 利用步骤

1. 阅读协议，确认 Bob 使用消息中的哪个字段作为加密公钥。
2. 调用密钥生成接口或本地生成一对密钥 `(pubX, privX)`。
3. 获取 Alice 的真实首条消息模板（或按手册构造），把最后的公钥字段替换为 `pubX`，身份字段仍写 `alice`。
4. 提交给 Bob，得到加密后的 flag 密文。
5. 用 `privX` 调用解密接口或本地解密，得到 flag。
6. 若解密失败，检查公钥编码（PEM/hex/base64）、算法参数、密文是否包含 nonce/封装。

## PoC

```python
import requests

BASE = "https://<protocol-host>"

def api(path, conn_id, content=""):
    r = requests.post(f"{BASE}{path}", json={"conn_id": conn_id, "content": content}, timeout=15)
    r.raise_for_status()
    return r.json()["content"]

# 1) 新建实例
r = requests.post(f"{BASE}/model/5", timeout=15)
conn_id = r.json()["conn_id"]

# 2) 生成攻击者密钥对（协议返回两个 k: 字段：公钥、私钥）
kp = api("/util/gen_asym_key_pair", 0, "")
keys = [v for t, v in (x.split(":", 1) for x in kp.split("|")) if t == "k"]
pubX, privX = keys[0], keys[1]

# 3) 取 Alice 的真实消息，替换最后一个公钥字段
alice_msg = api("/alice", conn_id, "")
parts = alice_msg.split("|")
for i in range(len(parts) - 1, -1, -1):
    if parts[i].startswith("k:"):
        parts[i] = "k:" + pubX
        break
forged = "|".join(parts)

# 4) Bob 把 flag 加密给 pubX
bob_reply = api("/bob", conn_id, forged)
cipher = next(v for t, v in (x.split(":", 1) for x in bob_reply.split("|")) if t == "d")

# 5) 用 privX 解密
print(api("/util/asym_decrypt", 0, f"k:{privX}|d:{cipher}"))
```

## 变体与关联

- 变体：服务端校验证书但只校验“证书有效”，不校验名字与消息中的身份一致；攻击者为自己的名字申请证书即可。
- 变体：服务端接受 key ID/指纹，但 ID 可被替换为攻击者公钥的指纹。
- 变体：签名场景中替换验签公钥，导致攻击者伪造的签名被接受。
- 关联：[[crypto-protocol-attacker-controlled-symmetric-key-nonce]]（对称密钥替换）、[[crypto-protocol-identity-field-spoofing-missing-sender-auth]]（身份伪造）、[[crypto-protocol-reflection-signature-confusion]]（证书/签名绑定缺陷）。

## 检测与防御

- 防御：校验证书链、有效期、用途，并把公钥与声明身份/账号/会话绑定；优先使用经过认证的密钥交换（TLS、Signal、Noise）。
- 防御：对密钥字段做白名单/固定映射，不接受消息中任意公钥；使用证书固定（pinning）或 TOFU 时明确信任模型。
- 检测：协议日志中出现同一身份对应多个公钥、频繁更换公钥、自签证书、公钥字段与证书不匹配。
- 响应：确认公钥替换后，轮换相关密钥，审计所有使用该协议加密的敏感数据。
