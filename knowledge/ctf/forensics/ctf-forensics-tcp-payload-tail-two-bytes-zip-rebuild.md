---
id: ctf-forensics-tcp-payload-tail-two-bytes-zip-rebuild
title: TCP 载荷末两字节十六进制拼接重建 ZIP：另一条流量里的明文口令解压取 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: tcp-payload-tail-bytes-hex-concat-zip-rebuild
aliases:
- 工业控制协议流量分析2
- TCP 末两字节拼接
- ZIPDATA 流量
- pcap 重建压缩包
- 流量内明文口令
tags:
- ctf
- forensics
- pcap
- tcp
- file-carving
- zip
- ics
- traffic-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:24+08:00'
  notes: 已对照原文与图21-23核对：每条 TCP 载荷取 payload[-2:] 转 HEX 拼接，xxd -r -p 还原 ZIP；过滤 normol 得 PW:password:MMS12345；解压得 flag{6a46756d-df7e-4b66-87e4-1b2661676e40}。未复跑脚本。
---

## 一句话结论

工控流量题里，自定义协议把 ZIP 文件按 TCP 报文切分，每条报文载荷的最后 2 字节就是文件的一段；按抓包顺序对每个 TCP 载荷取 `payload[-2:]` 转十六进制并拼接，写入 `hex.txt` 后用 `xxd -r -p` 还原 ZIP；另一条“正常”流量中以明文出现 `PW:password:MMS12345`，用该口令解压即得 flag。

## 原理

- 题目自定义了一个工控风格协议：正常流量之外，有若干报文携带 `ZIPDATA` 字段，文件字节被放在每条 TCP 载荷的固定位置（本题为最后 2 字节）。
- 文件雕刻思路：既然每条报文只贡献 2 字节，按抓包顺序把这些字节转成十六进制串并拼接，就能得到完整文件的十六进制表示；`xxd -r -p`/`bytes.fromhex` 还原二进制后检查 `PK\x03\x04` 文件头，即可确认是 ZIP。
- 口令来源：同一 pcap 的“正常”流量/另一条流中包含 `PW:password:MMS12345` 这样的明文字段；用 `strings`/Wireshark 过滤 `normol`（原文拼写）或 `password` 即可找到。口令明文传输是工控协议常见的弱设计。
- 若拼接结果不以 `PK` 开头，说明取的字段/偏移不对：应先看载荷结构，确认数据字段是末 2 字节、前 N 字节还是某个分隔符之后；也需按 TCP 流/序号排序，避免乱序。
- 拿到 ZIP 后直接解压（可能还需口令），读取内部 flag 文件；本题口令即流量中的明文，属于“文件传输 + 口令明文”的完整链。

## 触发条件

- CTF 工控/流量题，pcap 中存在自定义协议或 TCP 承载的文件分片（如 `ZIPDATA` 标记）。
- 每条报文的数据字段长度固定、位置固定（本题为末 2 字节），按顺序拼接可还原文件。
- 文件头/尾可识别（ZIP 的 `PK\x03\x04`、`PK\x05\x06`）。
- 解压口令在流量中以明文或可解码形式出现（本题 `PW:password:MMS12345`）。
- 若报文乱序，需要按 TCP 流序号/时间排序后再拼接。

## 利用步骤

1. Wireshark 打开 pcap，过滤 `tcp`，观察自定义协议字段（如 `ZIPDATA`）与每条载荷结构，确认文件数据所在偏移。
2. 用 Scapy 遍历 TCP 报文，按抓包顺序取每条 `payload[-2:]`，转大写十六进制并拼接，写入 `hex.txt`。
3. `xxd -r -p hex.txt output.zip`（或 `bytes.fromhex` 写文件），检查 `PK` 文件头；若不对，调整偏移/排序。
4. 用 `strings`/Wireshark 搜索 `password`、`PW`、`normol` 等关键字，找到明文口令 `MMS12345`。
5. `unzip -P MMS12345 output.zip`，读取解压出的 flag 文件，得到 `flag{6a46756d-df7e-4b66-87e4-1b2661676e40}`。

## PoC

原文提取脚本：

```python
from scapy.all import rdpcap, TCP

packets = rdpcap("111.pcap")
hex_str = ""

for pkt in packets:
    if pkt.haslayer(TCP) and hasattr(pkt[TCP], "payload"):
        raw = bytes(pkt[TCP].payload)
        if len(raw) >= 2:
            # 取倒数两个字节并转成大写十六进制
            hex_str += raw[-2:].hex().upper()

with open("hex.txt", "w") as f:
    f.write(hex_str)

print(f"拼接完成，共 {len(hex_str) // 2} 字节，已保存到 hex.txt")
```

```bash
# 还原 ZIP
xxd -r -p hex.txt output.zip
unzip -l output.zip

# 在流量里找口令（原文：过滤 normol 后发现 PW:password:MMS12345）
strings 111.pcap | grep -iE "password|PW:|normol"

# 解压
unzip -P MMS12345 output.zip
```

```text
flag{6a46756d-df7e-4b66-87e4-1b2661676e40}
```

## 变体与关联

- 变体（字段偏移）：数据可能在载荷首 N 字节、末 N 字节、或某个分隔符之后；先用少量报文对比文件头，确定正确偏移。
- 变体（协议）：Modbus 功能码 3/16 的寄存器数据、ICMP echo 载荷、CAN 末字节等都可承载文件分片；见关联卡。
- 变体（口令）：明文口令可能被 URL/Base64/十六进制编码；先 `strings` 再按常见编码解码。
- 关联：[[ctf-forensics-modbus-read-register-pdf-carve-password-hidden-text]]（Modbus 功能码 3 重建 PDF）、[[ctf-forensics-icmp-echo-payload-concatenation]]（ICMP 载荷拼接）、[[ctf-forensics-can-repeated-frame-trailing-byte-covert-channel]]（CAN 末字节隐蔽信道）。
- 边界：若报文乱序或数据字段不固定，简单 `[-2:]` 拼接会失败；若 ZIP 口令不在流量中，需要另行爆破。

## 检测与防御

- 这是 CTF 取证解法；对工控安全的启示是：自定义/TCP 协议可能被用来分片传输任意文件，且口令常以明文出现在正常流量中。
- 检测：对 pcap 做文件头/尾扫描（`PK`、`%PDF`、`\x89PNG`）、载荷熵分析和固定偏移字段提取；监控异常的大文件分片传输与明文口令字段。
- 防御：工控协议加密/认证（TLS/VPN、Modbus Security），禁止明文口令；网络分区与流量基线；对异常 TCP 载荷做 DPI 与告警。
