---
id: crypto-protocol-identity-field-spoofing-missing-sender-auth
title: 自定义协议身份字段伪造：只校验消息中的名字而不校验发送者
type: scenario
domain: crypto
path: crypto/protocol
technique: protocol-identity-field-spoofing
tags:
- protocol
- authentication
- identity-spoofing
- message-integrity
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:24:53+08:00'
  notes: '已对照原文 Protocol Analysis 1/2/3 核对：Bob 只检查消息内 n: 名字（alice/charlie），不验证发送者；缺席 Alice 时直接发首条消息即可拿 flag，PoC 与原文一致；未实际运行。'
url: /docs/crypto/protocol/crypto-protocol-identity-field-spoofing-missing-sender-auth/
draft: false
kb_aliases:
- 协议身份伪造
- name field spoofing
- 发送者身份未认证
- 缺席参与者攻击
- 自报家门绕过
---

## 一句话结论

自定义文本协议把发送者身份放在消息的 `n:`（name）字段里，服务端只检查“消息里写的是谁”，不验证消息实际来自哪个连接/进程，攻击者就能直接伪造一条“来自 Alice”的消息，让 Bob 执行只有 Alice 才能触发的动作（例如返回 flag）。

## 原理

- 协议消息是类型化字段拼接，例如 `t:Hello|n:bob|t:this is|n:alice|t:give me the flag`；服务端解析 `n:` 字段后认为发送者是 `alice`。
- 身份只存在于应用层数据中，没有与传输层身份（TLS 客户端证书、会话密钥、socket 对端）绑定，也没有对消息做签名/MAC。任何能向 `/bob` 提交内容的客户端都可以填任意 `n:` 值。
- 服务端的业务规则是“收到 Alice 的这条消息就返回 flag”，于是伪造消息即可触发；即使 Alice 根本不在线（缺席参与者），Bob 也只关心自己脚本里的 `recv` 条件是否匹配。
- 变体：Bob 可能检查消息里的名字必须是 `charlie`、`alice` 或某个角色；这仍然只是字符串比较，不构成认证。
- 该缺陷与加密无关：即使消息被加密，只要加密密钥对所有客户端可用，或服务端接受攻击者构造的密文，身份伪造仍然成立。

## 触发条件

- 协议消息包含自报的发送者名字/角色字段，服务端据此做授权或业务判断。
- 服务端不验证消息来源、没有签名/MAC、没有把身份绑定到会话。
- 攻击者能向服务端提交任意协议消息（直接 API、socket、消息队列等）。
- 目标动作由“收到某角色的特定消息”触发，而不是由不可伪造的凭据触发。

## 利用步骤

1. 抓取/阅读协议手册，确认消息字段格式与 Bob 的接收条件。
2. 创建会话，拿到 `conn_id` 或等价会话标识。
3. 构造一条 `n:` 字段写成目标角色（如 `alice`）的消息，内容匹配 Bob 的 `recv` 条件。
4. 提交给 `/bob` 或对应接收端，读取响应。
5. 从响应中提取敏感数据（flag、令牌、配置等）；若响应有加密，按协议继续处理。
6. 若名字被校验为其他角色，替换 `n:` 值重试；若 Alice 缺席，直接发送她“应该发”的第一条消息即可。

## PoC

```python
import requests

BASE = "https://<protocol-host>"

# 1) 创建实例/会话
r = requests.post(f"{BASE}/model/1", timeout=15)
r.raise_for_status()
conn_id = r.json()["conn_id"]

# 2) 伪造 Alice 的身份字段，直接发给 Bob
payload = {
    "conn_id": conn_id,
    "content": "t:Hello|n:bob|t:this is|n:alice|t:give me the flag",
}
r = requests.post(f"{BASE}/bob", json=payload, timeout=15)
r.raise_for_status()

content = r.json()["content"]
print(content)
for item in content.split("|"):
    if "{" in item and "}" in item:
        print("FLAG:", item.split(":", 1)[1])
```

## 变体与关联

- 变体：服务端要求名字为 `charlie` 或其他角色，直接替换 `n:` 字段即可。
- 变体：Alice 不在线/不发送时，Bob 仍然接受伪造的第一条消息（缺席参与者）。
- 变体：消息被简单加密但密钥公开或可协商，攻击者加密伪造消息后同样通过。
- 变体：协议使用 JSON/XML 而非 `|` 分隔，身份字段换成 `sender`、`from`、`role` 等。
- 关联：[[crypto-protocol-attacker-controlled-symmetric-key-nonce]]（密钥替换）、[[crypto-protocol-public-key-substitution-unbound-cert]]（公钥替换）、[[crypto-protocol-reflection-signature-confusion]]（签名/证书绑定缺陷）。

## 检测与防御

- 防御：不要在应用层信任自报身份；用 mTLS、签名消息、会话绑定或服务端侧身份映射来认证发送者。
- 防御：对每条消息做 MAC/签名，签名覆盖发送者、接收者、会话 ID、序号与消息体，防止伪造和重放。
- 检测：服务端日志中出现同一会话内多个不同 `n:` 身份、来自非预期来源的角色消息、缺少签名/MAC 的敏感操作。
- 响应：确认身份伪造后，审计该接口的所有历史操作，轮换被泄露的凭据，并为协议补上认证与消息完整性。
