---
id: ctf-forensics-ja3-flow-fragment-timestamp-reassembly
title: JA3 与目的 IP 过滤日志分片：按时间戳拼接 5 字符载荷
type: scenario
domain: ctf
path: ctf/forensics
technique: ja3-flow-fragment-timestamp-reassembly
tags:
- ctf
- forensics
- ja3
- tls
- log-analysis
- fragment-reassembly
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:12+08:00'
  notes: 已对照原文 The Step After the PCAP 核对：Dst IP 45.76.123.45 + JA3 d2b4... 过滤、按时间戳拼接 5 字符分片均一致；未实际运行。
url: /docs/ctf/forensics/ctf-forensics-ja3-flow-fragment-timestamp-reassembly/
draft: false
kb_aliases:
- JA3 流量分片
- TLS 指纹过滤
- 日志分片按时间拼接
- Payload Fragment
- 同目的 IP 同 JA3
---

## 一句话结论

网络取证日志中混有大量不同流量的记录，每条记录包含时间戳、目的 IP、TLS JA3 哈希与 5 字符载荷分片；用“同一目的 IP + 同一 JA3”筛出目标流，再按时间戳升序把分片拼接，即可还原外带数据/flag。

## 原理

- JA3 是 TLS ClientHello 的指纹（版本、密码套件、扩展、曲线、点格式的 MD5），同一恶意客户端/工具通常保持稳定 JA3；结合目的 IP/端口可把目标 C2 流从噪声中分离。
- 日志按 Flow Record 分块，每块含 `Timestamp`、`Dst IP`、`TLS JA3 Hash`、`Payload Fragment` 等字段；载荷被切成固定长度（示例 5 字符）分片，分散在不同记录中。
- 同一流的分片按时间戳排序后拼接即可还原完整载荷；不同流可能共享目的 IP 但 JA3 不同，或共享 JA3 但目的 IP 不同，需同时约束。
- 若时间戳相同，需用 Flow Record 编号、包序号或分片偏移作为次级排序键；若分片有丢失/重复，需按序号去重。
- 这是“流量指纹 + 分片重组”的通用取证方法，适用于 DNS/HTTP/TLS 外带、C2 分段传输等场景。

## 触发条件

- 日志/PCAP 中含 TLS 元数据（JA3/JA3S）与载荷分片字段。
- 目标流与噪声流在目的 IP、JA3、SNI、User-Agent 等维度上可区分。
- 分片按时间/序号可排序，且拼接后呈现可识别格式（flag、Base64、JSON 等）。
- 分片长度固定或可由字段推断。

## 利用步骤

1. 解析日志为结构化记录（时间戳、flow ID、目的 IP、JA3、payload fragment）。
2. 按目的 IP + JA3（可加 SNI/端口）过滤出候选流，统计分片数量与时间跨度。
3. 按时间戳升序排序；时间戳重复时用 flow ID/包序号/分片偏移排序。
4. 拼接所有分片，检查开头/结尾是否符合 flag、Base64、JSON 等格式。
5. 若拼接结果乱序，尝试按 flow ID 分组、按包序号排序，或反转分片顺序。
6. 提取 flag/外带数据。

## PoC

```python
import re
import pathlib
import pandas as pd

text = pathlib.Path("network_forensics.log").read_text(encoding="utf-8")
blocks = text.split("------------------------------------------------------------")
rows = []
for b in blocks:
    if "Dst IP: 45.76.123.45" in b and "Payload Fragment:" in b:
        ts = re.search(r"Timestamp:\s*(.+)", b)
        ja3 = re.search(r"TLS JA3 Hash:\s*(.+)", b)
        frag = re.search(r"Payload Fragment:\s*(.+)", b)
        flow = re.search(r"--- Flow Record #(\d+)", b)
        if ts and ja3 and frag:
            rows.append((ts.group(1).strip(), int(flow.group(1)) if flow else 0,
                         ja3.group(1).strip(), frag.group(1).strip()))

df = pd.DataFrame(rows, columns=["ts", "flow", "ja3", "frag"])
df["dt"] = pd.to_datetime(df["ts"].str.replace(" UTC", "", regex=False))
df = df.sort_values(["dt", "flow"])
target = df[df["ja3"] == "d2b4c6a8f0e1d3c5b7a9f2e4d6c8b0a1"]
print("".join(target["frag"]))
```

## 变体与关联

- 变体：用 JA3S、SNI、HTTP User-Agent、DNS 查询名、TLS 证书指纹替代 JA3。
- 变体：分片长度可变，需按长度/偏移字段重组；分片可能乱序、重复或丢失。
- 变体：载荷经过 Base64/hex/压缩，拼接后需再解码。
- 关联：[[ctf-forensics-http-beacon-gate-php-dns-c2-extraction]]（HTTP 信标外带）、[[ctf-forensics-soc-dns-tunnel-base32-pat-exfil]]（DNS 隧道分片）、[[ctf-forensics-tcp-urgent-pointer-covert-channel]]（TCP 字段隐写）。

## 检测与防御

- 检测：同一 JA3 高频访问同一目的 IP、固定长度小分片、非浏览器 JA3、异常 SNI。
- 防御：部署 JA3/JA3S 指纹与威胁情报匹配；对未知 JA3 的出站 TLS 做审计；DLP 检测分片外带。
- 响应：确认恶意流后阻断目的 IP/域名，提取全部分片还原外带数据，排查主机。
