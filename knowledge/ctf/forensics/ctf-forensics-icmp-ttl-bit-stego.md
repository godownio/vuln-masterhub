---
id: ctf-forensics-icmp-ttl-bit-stego
title: ICMP TTL 隐写：64/65 映射二进制位还原 ASCII
type: scenario
domain: ctf
path: ctf/forensics
technique: icmp-ttl-bit-stego
aliases:
- TTL 隐写
- ICMP TTL stego
- TTL 二进制信道
- 64/65 隐写
tags:
- forensics
- pcap
- icmp
- ttl
- stego
- covert-channel
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:29+08:00'
  notes: 已对照原文与图06核对：pcap 以 ICMP Echo Request 为主、TTL 仅 64/65、266 包（64 出现 145 次、65 出现 121 次）、64→0/65→1 按包序拼 bit 每 8 位转字节、解出 kashiCTF{ttl_stego_is_evil} 均一致。未验证点：无 pcap 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

当一份 pcap 几乎全是 ICMP Echo Request、且 IPv4 TTL 只在 64 和 65 之间切换时，可以把 64 映射为 0、65 映射为 1，按抓包顺序拼成 bit 流，每 8 位转一个字节，即可还原隐藏的 ASCII/Base32 文本。

## 原理

- TTL 是 IPv4 头的 1 字节字段，正常主机/路由器会使用 64、128、255 等默认值；同一段单一 ICMP 流量中只在两个相邻值之间来回切换，通常不是网络行为，而是人为编码。
- 选取两个可区分的 TTL 值作为二进制符号（如 64=0、65=1），按包序号读取即可得到一条隐蔽信道；ICMP Echo Request 的 payload 可以保持正常，检测方只看 payload 时难以发现。
- 每 8 个 bit 组成一个字节；若字节流不可读，可尝试反向映射（64=1/65=0）、LSB-first、跳过前导包或先做 Base32/Base64 解码。
- 为什么可行：TTL 在每跳会被路由器减 1，但同一局域网/同一路径上通常稳定；攻击者只需控制发包主机的初始 TTL，接收端按到达 TTL 解码。跨路由时需保证路径稳定或改用其他字段。
- 该手法容量低（每包 1 bit），但胜在隐蔽；适合短 flag/密钥外带。

## 触发条件

- 有 pcap，流量以 ICMP Echo Request/Reply 为主，包数量足够承载目标文本（每字符 8 包）。
- TTL 只出现两种可区分值（或可按阈值二值化），且顺序稳定。
- 发送端/接收端对 TTL 的映射规则已知或可猜测；跨路由时 TTL 可能被中间设备改写。

## 利用步骤

1. 用 tshark 提取每个 ICMP 包的 TTL 与序号：
   ```bash
   tshark -r capture.pcapng -Y "icmp" -T fields -e frame.number -e ip.ttl
   ```
2. 统计 TTL 取值分布；若只有两个值（如 64/65），分别映射为 0/1。
3. 按 frame.number 排序，拼接 bit 串；每 8 位转字节。
4. 尝试两种映射和两种位序（MSB/LSB first），观察可读文本。
5. 若结果是 Base32/Base64，继续解码；若开头有噪声，尝试偏移 0-7 位对齐。
6. 用得到的 flag/密钥完成后续题目。

## PoC

```bash
tshark -r capture.pcapng -Y "icmp" -T fields -e frame.number -e ip.ttl > ttl.txt
```

```python
vals = []
for line in open("ttl.txt"):
    parts = line.split()
    if len(parts) >= 2:
        vals.append(int(parts[1]))

lo, hi = min(vals), max(vals)
bits = "".join("1" if v == hi else "0" for v in vals)
for off in range(8):
    data = bytes(int(bits[i:i+8], 2) for i in range(off, len(bits) - 7, 8))
    print(off, data[:120])
```

说明：PoC 为原文思路的结构化复现，未在本机执行；原文 266 个 ICMP 包、TTL 64 出现 145 次、65 出现 121 次，解码得到 `kashiCTF{ttl_stego_is_evil}`。

## 变体与关联

- 变体（字段）：IP ID、TCP initial window、TCP timestamp、UDP 长度、ICMP sequence 等也可做二进制/多进制信道；原理相同。
- 变体（编码）：每包 1 bit 改为多 bit（多个字段组合）、曼彻斯特编码、差分编码；需先做分布与自相关分析。
- 关联：[[pentest-c2-ipv4-reserved-bit-udp-covert-channel]]（IPv4 保留位隐蔽信道）；[[ctf-forensics-soc-dns-tunnel-base32-pat-exfil]]（DNS 隧道外带）；[[ctf-forensics-tcp-urgent-pointer-covert-channel]]（TCP 紧急指针信道）。
- 边界：TTL 被中间路由器改写、两种值不唯一、包乱序/丢包、或流量混合其他协议时，需要先过滤/排序/纠错。

## 检测与防御

- 检测：单一 ICMP 流量中 TTL 只在两个相邻值间切换；TTL 分布与正常主机/路径不符；ICMP payload 与 TTL 序列存在相关性。
- 防御：网络侧对 ICMP 做速率限制与异常 TTL 监控；统一/规范化 TTL（部分防火墙可重置）；禁止不必要的主机间 ICMP。
- 取证：保存原始 pcap，按 frame.number 排序；对 bit 流做偏移/位序/映射的穷举，并记录解码参数。
