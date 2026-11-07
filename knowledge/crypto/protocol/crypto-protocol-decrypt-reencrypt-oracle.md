---
id: crypto-protocol-decrypt-reencrypt-oracle
title: 协议解密/重加密 oracle：把服务端当作双层解密机
type: scenario
domain: crypto
path: crypto/protocol
technique: protocol-decrypt-reencrypt-oracle
aliases:
- 解密 oracle
- 重加密 oracle
- decrypt-reencrypt oracle
- 双层解密
- 服务端当解密机
tags:
- protocol
- oracle
- chosen-ciphertext
- re-encryption
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:01+08:00'
  notes: 已对照原文 Protocol Analysis 9 核对：Alice 对任意密文做两层解密并重加密给 pubX，攻击者先剥外层再喂内层拿 flag；PoC 的 unwrap 流程与原文一致；未实际运行。
---

## 一句话结论

协议中的 Alice 会接受任意“用 Alice 公钥加密的请求”，先用她的私钥解外层、再解内层，然后把明文重新加密给请求中指定的公钥 `X`；攻击者把 Bob 发给 Alice 的密文包装成合法请求喂给 Alice，就能逐层剥出 flag，相当于把 Alice 当成无限次解密/重加密 oracle。

## 原理

- 正常协议中，Alice 只应解密“来自预期对端、属于当前会话、格式符合预期”的密文；但该实现只要收到合法格式的请求，就会对任意密文执行两层解密，并把结果加密给 `X`。
- 请求格式类似 `pubX, X, certX, {{m}pubA, X}pubA, alice`：外层用 Alice 公钥加密，内层也是 Alice 公钥加密；Alice 解外层得到 `{m}pubA`，再解内层得到 `m`，最后用 `pubX` 加密 `m` 返回。
- 攻击者先让 Bob 生成 `{{FLAG}pubA, bob}pubA`（Bob 给 Alice 的密文），把它作为内层密文包进自己的外层请求发给 Alice；Alice 返回 `{FLAG}pubA`（加密给攻击者 `pubX`）。
- 攻击者用私钥 `privX` 解开外层，得到内层 `{FLAG}pubA`；再把它作为下一次请求的内层密文喂给 Alice，Alice 返回 `{FLAG}pubX`，攻击者解密得到 flag。
- 该攻击不破解 RSA，而是滥用“解密 + 重加密”这一服务能力；如果 Alice 还会对任意密文签名，同样可构成签名 oracle。
- 关键在于服务端没有把密文与“预期发送者/会话/用途”绑定，也没有限制嵌套层数或拒绝外来密文。

## 触发条件

- 服务端提供“解密后重新加密给指定公钥”的接口，且接受任意密文。
- 攻击者能构造合法的外层请求（自己的密钥对与证书），并能让 Alice 处理。
- 目标密文是嵌套结构（外层 + 内层），或攻击者可以通过多次调用逐层剥离。
- 服务端没有对密文来源、会话、嵌套深度做校验。

## 利用步骤

1. 获取 Alice 的首条消息，转给 Bob，得到 Bob 的外层密文 `{{FLAG}pubA, bob}pubA`。
2. 生成攻击者密钥对 `(pubX, privX)` 并为 `X` 申请证书。
3. 构造外层请求：把 Bob 的外层密文作为内层，用 Alice 公钥加密 `d:<bob_outer>|n:<X>`，发送给 Alice。
4. Alice 返回加密给 `pubX` 的结果；用 `privX` 解密，得到内层 `{FLAG}pubA`。
5. 把内层密文再次包装成请求发给 Alice，得到加密给 `pubX` 的 flag；解密即得明文。
6. 若响应有多层，重复“解一层、再喂一层”直到出现 flag 格式。

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

r = requests.post(f"{BASE}/model/9", timeout=20)
conn_id = r.json()["conn_id"]

alice0 = api("/alice", conn_id, "")
pubA = field(alice0, "k")
bob1 = api("/bob", conn_id, alice0)
bob_outer = [v for t, v in (x.split(":", 1) for x in bob1.split("|")) if t == "d"][1]

kp = api("/util/gen_asym_key_pair", 0, "")
keys = [v for t, v in (x.split(":", 1) for x in kp.split("|")) if t == "k"]
pubX, privX = keys[0], keys[1]
certX = field(api("/util/get_cert", 0, f"k:{pubX}|n:{ATTACKER}"), "d")

def unwrap(cipher):
    wrapped = field(api("/util/asym_encrypt", 0, f"k:{pubA}|t:d:{cipher}|n:{ATTACKER}"), "d")
    resp = api("/alice", conn_id, f"k:{pubX}|n:{ATTACKER}|d:{certX}|d:{wrapped}|n:alice")
    outer = [v for t, v in (x.split(":", 1) for x in resp.split("|")) if t == "d"][1]
    layer1 = api("/util/asym_decrypt", 0, f"k:{privX}|d:{outer}")
    inner = field(layer1, "d")
    return api("/util/asym_decrypt", 0, f"k:{privX}|d:{inner}")

print(unwrap(bob_outer))
```

## 变体与关联

- 变体：单层解密 oracle，直接返回明文而非重加密；可用选择密文攻击恢复目标。
- 变体：签名 oracle，服务端对任意消息签名，可伪造目标签名。
- 变体：嵌套层数更多，或每层使用不同密钥/算法，需要逐层识别。
- 关联：[[crypto-protocol-reflection-signature-confusion]]（签名/证书绑定）、[[crypto-rsa-lsb-parity-oracle]]（RSA 解密 oracle）、[[crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle]]（填充 oracle）。

## 检测与防御

- 防御：不要对任意密文执行解密/重加密；只解密来自预期对端、属于当前会话、格式与用途匹配的密文。
- 防御：把发送者、接收者、会话 ID、用途作为 AAD/签名覆盖范围；限制嵌套层数与请求频率；使用 OAEP 等安全填充。
- 检测：日志中出现大量“解密后重加密给不同公钥”的请求、同一密文被多次提交、嵌套密文、非预期公钥。
- 响应：确认 oracle 存在后下线相关接口，轮换密钥，审计历史解密请求。
