---
id: ctf-forensics-hexlines-wrpcap-tcpstream-jpeg
title: 每行一包的十六进制文本重组 pcapng：scapy wrpcap 还原后追踪 TCP 流，把载荷里的 JFIF 段导出为图片
type: scenario
domain: ctf
path: ctf/forensics
technique: hexlines-wrpcap-tcpstream-jpeg-extract
aliases:
- No Shark?
- 十六进制文本转 pcap
- wrpcap 重组流量包
- 每行一个 hex 包
- 追踪 TCP 流导出 JPEG
- JFIF 载荷取证
tags:
- ctf
- forensics
- pcap
- hex
- scapy
- tcp-stream
- jpeg
- traffic-reassembly
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:27:47+08:00'
  notes: 已对照原文核对：每行一段 hex 逐行 unhexlify + scapy wrpcap 成 pcapng、Wireshark 追踪 TCP 流、载荷 FF D8 FF E0 ... JFIF 开头导出为 jpg 均与原文脚本与截图(08.png)一致；PoC 已去掉原文本机绝对路径，改为相对文件名，路径合法。未验证点：未重建流量包；flag 仅写 irisctf{...} 占位未抄原文值。
---

## 一句话结论

当取证题只给一个「每行一段十六进制」的文本文件时，先按行 `unhexlify` 得到原始字节，用 scapy 的 `wrpcap` 把它们写成 pcapng，再在 Wireshark 里追踪 TCP 流：如果流载荷以 `JFIF` 开头就是 JPEG 字节流，把载荷导出（raw）后改名/补全即可得到图片，图片里的文字就是 flag。

## 原理

- **每行即一个完整帧**：这类题目把整段流量按「一个数据包一行」的十六进制导出，行内是完整的链路层帧（含以太网/IP/TCP 头）。逐行 `binascii.unhexlify` 后按顺序喂给 `wrpcap`，即可重建原始抓包；包顺序与时间线由文件行序决定。
- **为什么能直接还原**：hex 导出是无损的字节级复制，只要每行没有混入注释/空行，重组后的 pcap 与原始流量在字节层面等价，Wireshark 可正常解析并重组 TCP 流。
- **为什么是图片**：TCP 流重组后，载荷开头出现 `JFIF\0`（JPEG File Interchange Format 标识，紧跟在 `FF D8` SOI 之后）就说明服务端把一张 JPEG 按 TCP 传输；把该流保存为原始字节（Follow → TCP Stream → Show data as Raw → Save as）即可得到可打开的图片，无需再用流量工具解码。
- **与直接 hex→图片的区别**：本题必须保留「包边界」做 TCP 重组（可能分片、可能混有其它流），不能把所有行拼接成一个连续字节串；先成 pcap 再按流导出才能拿到完整、顺序正确的图片。

## 触发条件

- 取证附件是纯文本，每行一段十六进制字节（可能是完整帧，也可能是单包载荷）。
- 环境可用 Python + scapy（`wrpcap`）以及 Wireshark/tshark。
- 流量中包含承载文件的 TCP 会话（本例为 JPEG）。

## 利用步骤

1. 先肉眼判断文本结构：是否每行长度一致、有无非 hex 字符；若每行是完整帧（含 `001122334455` 一类 MAC 与 `0800` 类型），可直接成包。
2. 逐行去空白、`unhexlify`，收集成字节列表，跳过无法解码的行。
3. 用 `wrpcap('output.pcapng', packets)` 写出文件（scapy 会按扩展名与内容写 pcap/pcapng）。
4. 用 Wireshark 打开，先看协议层次与流数量；对可疑 TCP 流右键 Follow → TCP Stream。
5. 在流窗口把显示模式切到 Raw（或 `Show data as: Raw`），Save as 导出字节；若开头是 `FF D8 FF E0 ... JFIF`，把文件后缀改成 `.jpg` 打开。
6. 图片中读取 flag；若载荷被截断，检查是否有其它流或需要从 pcap 里导出 HTTP 对象（File → Export Objects）。

## PoC

```python
from scapy.all import *
import binascii

with open("oshark.txt", "r") as f:
    hex_data = [line.strip() for line in f if line.strip()]

packets = []
for packet_hex in hex_data:
    try:
        packets.append(binascii.unhexlify(packet_hex))
    except binascii.Error as e:
        print(f"Error decoding hex: {e}")

if packets:
    wrpcap("output.pcapng", packets)
    print("Successfully created output.pcapng")
```

Wireshark 侧的关键观察（原文截图）：

```text
Follow TCP Stream -> 载荷开头: FF D8 FF E0 ... JFIF ......... C ...
显示模式切 Raw 并保存 -> 得到可用图片浏览器打开的 .jpg
```

图片自带文本：`irisctf{...}`。PoC 未在本机执行。

## 变体与关联

- **单包载荷而非完整帧**：若每行只有 TCP/应用层载荷，需要自己补以太网/IP/TCP 头（或用 `scapy` 构造 `Ether()/IP()/TCP()/Raw()`，按序填入 payload 与递增 seq），再用 `wrpcap`。
- **其它容器**：载荷可能不是 JPEG 而是 PNG（`89 50 4E 47`）、ZIP（`50 4B 03 04`）、7z 等；按魔数判断，导出方式相同。
- **无 Wireshark 环境**：可用 `tshark -r out.pcapng --export-objects http,dir` 或 `tcpflow`/`follow` 脚本直接按流落盘。
- **关联**：[[ctf-forensics-hex-png-stream-qr-chain-base64]]（同为「十六进制文本 → 二进制图片」，但那条不需要重组 pcap）、[[ctf-forensics-pcap-shell-history-base64-nc-image-exfil]]（pcap 中提取图片的另一路径）、[[ctf-forensics-tcp-payload-tail-two-bytes-zip-rebuild]]（同样按流序拼接载荷）。
- **边界**：行内混有行号/偏移/注释、或字节被截断（每行只给前 N 字节）时无法完整还原；帧序错乱或丢包会导致 TCP 重组失败，需要按 seq 手工拼接。

## 检测与防御

- 本卡是取证侧技巧，不涉及目标加固；对应的检测视角是「流量中通过 TCP 明文传输图片/文件」——在真实环境中可用 DLP/流量还原（HTTP 对象导出、SMB 文件还原）来发现此类外传。
- 若作为蓝队复盘：对含 `JFIF`/`PK`/`%PDF` 等魔数的长连接载荷做提取，比对文件哈希与已知样本。
