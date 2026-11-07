---
id: ctf-forensics-icmp-echo-payload-concatenation
title: ICMP Echo Request payload 顺序拼接还原隐蔽文本
type: scenario
domain: ctf
path: ctf/forensics
technique: icmp-echo-payload-concatenation
tags:
- forensics
- pcap
- icmp
- covert-channel
- stego
- scapy
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:48:15+08:00'
  notes: 已对照原文代码与图11核对：过滤 ICMP type=8、按包序拼接 load，36 个 Echo Request payload 还原 flag；MAX_PKTS=72 与原文一致；未复跑 pcap
url: /docs/ctf/forensics/ctf-forensics-icmp-echo-payload-concatenation/
draft: false
kb_aliases:
- ICMP payload 隐写
- Echo Request 数据拼接
- ping 隐蔽信道
- Scapy 提取 ICMP 载荷
---

## 一句话结论

当 pcap 中的 ICMP Echo Request 每个包只携带一小段 ASCII 数据时，按包序把所有 `icmp.load` 拼接起来再按 UTF-8 解码，就能还原被拆分的 flag/密钥；这是最直接的 ICMP payload 隐蔽信道，不需要改 TTL/ID/序列号等头部字段。

## 原理

- ICMP Echo Request（type 8）允许携带任意 payload；正常 `ping` 通常填充固定模式或时间戳，但攻击者可以把秘密文本拆成多段，分别放进每个请求的 payload。
- 抓包文件保留每个包的原始 payload 和顺序；解析时过滤 `ICMP` 且 `type == 8`，取 `load`，按 `frame.number` 顺序拼接，即可重建原始字节流。
- 与 TTL 隐写不同：TTL 每包只承载 1 bit，需要 8 个包一个字符；payload 拼接每包可以承载数十到上千字节，容量大得多，但更容易被 DPI/载荷检测发现。
- 为什么顺序重要：TCP 有序列号可重排，ICMP 没有；抓包顺序通常就是发送顺序，若存在多流/多主机，需要按源/目的或 payload 前缀分组后再拼接。
- 如果拼接结果不可读，可能是每段带长度/序号头、做了 base64/XOR、或 payload 被填充；先看十六进制和字符串特征，再尝试去头/解码。

## 触发条件

- 有 pcap/pcapng，包含 ICMP Echo Request，且 payload 不是标准 ping 填充模式（如全 0x00/0x41/时间戳）。
- 秘密文本被拆成多段，段数/每段长度可识别；包序稳定，或可按序列号/源地址分组。
- 抓包包含完整的请求；若只有响应，Echo Reply（type 0）也可能携带同样 payload，需要相应调整过滤。

## 利用步骤

1. 用 `tshark` 或 Scapy 统计 ICMP 包：类型、数量、payload 长度、payload 前几个字节。
   ```bash
   tshark -r capture.pcap -Y "icmp.type == 8" -T fields -e frame.number -e data.data
   ```
2. 过滤 `type == 8`（Echo Request），按 `frame.number` 排序；若存在多个源/目的，按 `ip.src`/`ip.dst` 分组。
3. 取每个包的 `icmp.load`（Scapy）或 `data.data`（tshark），按顺序 `b"".join()`。
4. 先尝试 `decode("utf-8")`；若失败，尝试 latin-1、hex 解码、base64 解码，或检查是否有每段长度头/序号头。
5. 在拼接结果中搜索 `flag{`、`key`、`http` 等特征；若文本被反转/异或，按题目提示处理。
6. 若 pcap 很大，可先限制前 N 个包（示例只取前 72 个包，因为有效载荷集中在前段），或按 payload 长度/前缀筛选。

## PoC

```python
from scapy.all import rdpcap, ICMP

pkts = rdpcap('stealthy.pcap')
blob = b''
for pkt in pkts:
    if ICMP in pkt and pkt[ICMP].type == 8:          # Echo Request
        payload = bytes(pkt[ICMP].payload)
        if payload:
            blob += payload

print(blob)
print(blob.decode('utf-8', errors='replace'))
```

```bash
# tshark 等价提取（按包序）
tshark -r stealthy.pcap -Y "icmp.type == 8" -T fields -e data.data
```

## 变体与关联

- 变体：使用 Echo Reply（type 0）承载数据；过滤条件改为 `type == 0`，或请求/响应都取。
- 变体：每段带 2/4 字节序号或长度头，需要先解析头再按序号排序/截断。
- 变体：payload 先做 base64/XOR/RC4 再放入 ICMP；先按编码/密钥还原，再拼接。
- 变体：不用 payload，而用 ICMP 的 ID、序列号、TTL、checksum 或时间间隔编码；参考 [[ctf-forensics-icmp-ttl-bit-stego]]。
- 关联卡片：[[ctf-forensics-icmp-ttl-bit-stego]]（TTL 二值隐写）、[[pentest-c2-ipv4-reserved-bit-udp-covert-channel]]（IP 头保留位信道）、[[ctf-forensics-http-beacon-gate-php-dns-c2-extraction]]（HTTP/DNS 隐蔽信道）。
- 边界：如果 pcap 只包含部分包、payload 被截断，或包序在合并多个抓包点时错乱，需要按序列号/时间戳重建；如果 payload 是加密的，需先获得密钥。

## 检测与防御

- 检测：统计 ICMP payload 长度/熵/字符分布；正常 ping 的 payload 多为固定填充，若出现大量可打印 ASCII、base64 字符或递增序号，属于异常。
- 防御：不需要 ICMP 的环境直接封禁/限速；对出站 ICMP payload 做 DPI 与大小限制；监控同一源短时间内大量同长度 ICMP 请求。
- 分析侧：先看 `strings`/十六进制，再决定拼接/解码顺序；不要直接执行 payload 中的任何内容。
