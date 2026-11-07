---
id: mobile-alter-lte-user-plane-aes-ctr-dns-tamper
title: aLTEr：LTE 用户面 AES-CTR 可塑性篡改 DNS 查询，把目标 IP 改成攻击者 IP
type: scenario
domain: mobile
path: mobile
technique: alter-lte-user-plane-aes-ctr-malleability
tags:
- mobile
- lte
- cellular
- aes-ctr
- malleability
- dns
- user-plane
- mitm
- protocol
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:17:39+08:00'
  notes: 已对照原文与截图核对：LTE 用户面 EEA 加密无 EIA、AES-CTR 可塑性 C'=C⊕(P⊕P')、relay 篡改 DNS dest_ip 8.8.8.8 的原理均一致；原文无直接可执行 PoC；关联中 crypto-protocol-* 为通配占位链接（非严重问题）；未实际运行。
url: /docs/mobile/mobile-alter-lte-user-plane-aes-ctr-dns-tamper/
draft: false
kb_aliases:
- aLTEr
- LTE 用户面篡改
- AES-CTR malleability
- EEA 加密无 EIA
- DNS 查询比特翻转
- 4G 中间人
- relay 攻击
---

## 一句话结论

LTE 用户面用 AES-CTR（EEA）加密但不做完整性保护（EIA 只保护控制面）；AES-CTR 是流密码、具有可塑性，攻击者在伪基站与合法基站之间做 relay，截获已知明文的 DNS 查询后，把密文与“原 IP ⊕ 恶意 IP”掩码异或，就能在不知道密钥的情况下把 `dest_ip=8.8.8.8` 改成攻击者 IP，终端收到被篡改的 DNS 响应/连接。

## 原理

- LTE 分层安全：NAS 层在 NAS SMC 后受保护，RRC（AS 层）在 AS SMC 后受保护；但用户面（IP 层）只做 EEA 加密，**不做 EIA 完整性保护**（标准中用户面完整性保护 UPIP 是 5G 才引入的可选项）。
- AES-CTR 把计数器加密成密钥流，再与明文异或：`C = P ⊕ KS`。它没有认证，攻击者不需要密钥，只要知道/猜到明文片段，就能构造 `C' = C ⊕ (P ⊕ P')`，解密后得到 `P'`；这就是可塑性（malleability）。
- 攻击者作为 UE 与合法 eNodeB 之间的 relay：转发用户面数据，但在 DNS 查询经过时修改密文。例如原查询 `dest_ip = 8.8.8.8`，攻击者想改成 `attacker_ip`，计算 `mask = 8.8.8.8 ⊕ attacker_ip`，对相应密文字节异或 mask，接收端解密后就是攻击者 IP。
- DNS 查询是理想目标：格式固定、目标 IP 字段位置可预测、明文可猜；篡改后终端可能连接到恶意 DNS/服务器，或收到伪造响应。其他已知明文协议（HTTP Host、TLS SNI 等）也可作为变体。
- 该攻击不破坏加密算法本身，而是利用“加密但无完整性”的组合缺陷；根因是 LTE 用户面安全模型只保证机密性、不保证完整性。
- 5G NSA 控制面锚定 LTE，用户面仍可能继承；5G SA 的 UPIP 可缓解，但取决于运营商/终端是否启用。

## 触发条件

- 目标使用 LTE/5G NSA 用户面，且未启用用户面完整性保护（UPIP）。
- 攻击者能在 UE 与合法 eNodeB 之间做 relay（伪基站/中间人），并能截获/修改用户面密文。
- 攻击者知道或能猜测目标明文片段（如 DNS 查询的固定字段、目标 IP）。
- 目标协议对完整性不敏感（DNS 无 DNSSEC、应用无 TLS/DoH 等），篡改后能产生实际影响。
- 仅限授权安全测试/研究环境。

## 利用步骤

1. 部署 relay/伪基站，使目标 UE 的用户面流量经过攻击者；保持与合法 eNodeB 的转发，避免断链。
2. 识别目标流量与明文结构（如 DNS 查询的 `dest_ip` 字段位置）。
3. 计算掩码 `mask = P_original ⊕ P_malicious`，对密文对应字节异或，转发修改后的密文。
4. 终端解密得到被篡改的明文，向攻击者 IP 发起 DNS/连接；攻击者返回伪造响应或直接接管。
5. 若目标使用 DNSSEC/DoH/TLS，篡改会被发现或无法生效；改用其他已知明文协议或降级路径。

## PoC

文章给出的是原理图与异或公式，没有可直接执行的 PoC；核心计算：

```text
原始明文:  DNS Query: dest_ip = 8.8.8.8
密文字节:  E3 A7 0B 91 ...        (AES-CTR)
掩码:      mask = 8.8.8.8 XOR attacker_ip
篡改后密文: C' = C XOR mask
终端解密:  DNS Query: dest_ip = attacker_ip
```

Python 伪代码：

```python
def flip_ip(ciphertext: bytes, offset: int, old_ip: bytes, new_ip: bytes) -> bytes:
    mask = bytes(a ^ b for a, b in zip(old_ip, new_ip))
    out = bytearray(ciphertext)
    for i, m in enumerate(mask):
        out[offset + i] ^= m
    return bytes(out)
```

## 变体与关联

- **协议变体**：DNS、HTTP Host/URI、TLS SNI、明文应用协议；凡是已知明文且无完整性保护的字段都可尝试。
- **位置变体**：UE↔eNodeB 空口 relay、回传链路、伪基站；需要保持链路不断。
- **防御变体**：5G UPIP、DNSSEC、DoH/DoT、应用层 TLS、证书固定。
- **关联**：[[mobile-lte-rrc-redirect-downgrade-gsm]]（LTE 控制面降级）；[[mobile-gsm-fake-bts-downgrade-sms-injection]]（2G 伪基站）；[[crypto-protocol-*]]（协议可塑性/中间人相关卡）。
- **边界**：启用 UPIP、DNSSEC/DoH、应用层端到端加密，或攻击者无法维持 relay/不知道明文时，本路径失效。

## 检测与防御

- **检测**：用户面流量异常重传/时延、DNS 响应 IP 与查询不符、TLS 证书/SNI 异常、同一 UE 的流量路径突变；网络侧可检测 relay 特征。
- **防御**：启用 5G UPIP；部署 DNSSEC/DoH/DoT；应用层使用 TLS 并校验证书；终端/网络侧监控异常 DNS 与用户面完整性。
- **加固**：运营商在 5G SA 中默认开启用户面完整性保护；终端优先使用加密 DNS；对高风险业务使用端到端加密。
- **合规**：仅可在授权实验室/屏蔽环境研究，遵守无线电管理与法律。
