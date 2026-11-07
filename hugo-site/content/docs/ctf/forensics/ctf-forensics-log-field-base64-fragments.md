---
id: ctf-forensics-log-field-base64-fragments
title: 日志异常字段中的分段 Base64 提取拼接还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: log-field-base64-fragment-concat
tags:
- ctf
- forensics
- log-analysis
- base64
- data-fragmentation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:31:39+08:00'
  notes: 已对照原文核对：server.log 中 packet anomaly detected id=... 与 backup failed code=... 异常字段、分片 Zmxh/Z3tP/YmZ1/c2Nh/dGVk/VHJ1dGh9 按序拼接为 ZmxhZ3tPYmZ1c2NhdGVkVHJ1dGh9、Base64 解码得 flag{ObfuscatedTruth}、提交 VishwaCTF{ObfuscatedTruth} 均一致。未验证点：无日志附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-log-field-base64-fragments/
draft: false
kb_aliases:
- Fragmented Evidence
- 日志分段 Base64
- id/code 字段提取
- 日志隐写
---

## 一句话结论

当系统日志里混入多条 `packet anomaly detected id=...`、`backup failed code=...` 等异常记录，且字段值只含 Base64 字符时，按时间顺序提取这些值并拼接，再做 Base64 解码，即可还原被拆碎藏进日志的 flag。

## 原理

- 出题人把 Base64 字符串切成多段，分别塞进日志的 `id=`、`code=` 等字段，使每段看起来像普通错误码/ID。
- Base64 字符集为 `A-Za-z0-9+/=`，与十六进制/数字 ID 相比有明显特征；按出现顺序拼接后仍是合法 Base64。
- 解码后的明文可能带外层 `flag{...}`，按题目要求替换为比赛前缀即可。
- 该方法依赖“分片顺序 = 日志时间顺序”，不需要理解日志语义。

## 触发条件

- 日志中存在多处异常字段，字段值长度/字符集与普通日志不符。
- 分片按时间顺序拼接后能 Base64 解码为可打印文本。
- 可能存在干扰分片，需要按可打印性/前缀筛选。

## 利用步骤

1. 通读日志，标记所有 `id=`、`code=` 等异常字段。
2. 用正则提取字段值，按出现顺序拼接。
3. Base64 解码，检查是否得到 `flag{...}` 或比赛前缀。
4. 若有干扰分片，尝试不同子集/顺序，按解码结果可打印性筛选。
5. 按题目要求转换外层格式。

## PoC

```python
import base64, re

data = open("server.log", encoding="utf-8").read()
parts = re.findall(r'id=([A-Za-z0-9+/=]+)', data)
parts += re.findall(r'code=([A-Za-z0-9+/=]+)', data)
b64 = "".join(parts)
print(base64.b64decode(b64).decode())
```

## 变体与关联

- 字段名可换成 `trace=`、`session=`、`err=`；编码可换成 Base32/Base58/hex。
- 分片可能乱序，需要按时间戳或序号排序。
- 关联：[[ctf-forensics-soc-dns-tunnel-base32-pat-exfil]]（日志/流量中的编码外带）、[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（多层编码）。

## 检测与防御

- 这是 CTF 取证题型；防御上可对日志字段做长度/字符集校验，避免把用户可控数据原样写入日志。
- 检测：日志中大量字段值只含 Base64 字符且长度固定、拼接后可解码。
