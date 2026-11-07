---
id: ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb
title: PCAP 噪声分层取口令：组播 Base64 口令 + HTTP JSON AES ZIP + RGB-LSB 位流
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-multicast-noise-password-aes-zip-rgb-lsb
tags:
- ctf
- forensics
- pcap
- tshark
- multicast
- base64
- zip
- aes
- lsb
- png
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:06+08:00'
  notes: 已对照原文与图01-05核对：io,phs/conv,ip 显示 1500 UDP 组播噪声 + 9 TCP/HTTP 帧；组播 Base64 解出 ShengDongJiXi@36-1-6（图02）；HTTP JSON instruction 为 Base64 AES ZIP；解出 PNG 按 RGB LSB 得 ISCC{w1d3vf1c4t10no_1s_th3_k3y_t0_fvM1ct0Try}（图04/05），均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb/
draft: false
kb_aliases:
- 组播噪声藏口令
- SSDP 组播噪声
- Base64 口令候选
- HTTP instruction AES ZIP
- RGB LSB 位流
- 喧宾夺主的信号
---

## 一句话结论

先用协议统计把上千个组播噪声包与极少量 TCP/HTTP 指令流分开；组播 payload 中可打印的 Base64 片段解出 ZIP 口令，HTTP POST JSON 的 `instruction` 字段是 Base64 的 AES 加密 ZIP，解出的 PNG 按像素顺序提取 RGB 三通道最低位并按 8 bit 打包，即可恢复 flag。

## 原理

- **噪声层与指令层分离**：组播包数量大、目的地址固定、payload 看似随机，但其中夹带可打印 Base64；真正的控制指令只在极少的 HTTP 会话里。先做 `io,phs`/`conv,ip` 统计可以把分析量从上千包收缩到个位数会话。
- **口令筛选**：对整份 pcap 做 `strings` 后按 Base64 字符集和长度筛候选，再要求解码结果可打印、含字母数字与至少一个特殊符号（`@-_!#$%^&*`），并按出现次数排序；动态附件会换口令，但规则不变。
- **AES ZIP**：ZIP 的 AES 加密需要口令，`7z` 或 `pyzipper` 都可解；JSON 字段只是 Base64 包装。
- **RGB-LSB**：内层 PNG 很小、颜色数极少，说明 RGB 通道只在最低位抖动；按行优先读取 `R,G,B` 的 bit 并每 8 位大端打包，字节流开头通常直接出现 `ISCC{`。

## 触发条件

- pcap 中同一源持续向组播地址发送大量 UDP，另有极少量 TCP/HTTP 会话。
- HTTP 请求体是 JSON，某字段为长 Base64；解码后是 ZIP/压缩包。
- 解出的图片尺寸小、颜色单一，具备 LSB 隐写特征。

## 利用步骤

1. `tshark -r capture.pcapng -q -z io,phs` 与 `-z conv,ip`，确认噪声流与指令流的包数/字节数。
2. `strings -a capture.pcapng | rg '^[A-Za-z0-9+/=]{20,}$' | sort | uniq -c | sort -nr`，对候选做 Base64 解码并按可打印规则筛选口令。
3. `tshark -Y 'http.request.method=="POST"' -T fields -e http.file_data | xxd -r -p > body.json`，`jq -r '.instruction' | base64 -d > instruction.zip`。
4. 用恢复出的口令 `7z x -p<password> instruction.zip`，得到内层 PNG。
5. 用 PIL 按像素顺序读取 RGB 最低位，按 8 bit 打包为字节流；正则匹配 flag。
6. 动态附件下不要硬编码口令或 flag，口令从当前 pcap 恢复，flag 从当前图片提取。

## PoC

```python
import base64, re, string, binascii
from collections import Counter
from PIL import Image

def password_candidates(blob):
    counter = Counter()
    for token in re.findall(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{20,128}(?![A-Za-z0-9+/=])", blob):
        try:
            decoded = base64.b64decode(token, validate=True)
        except binascii.Error:
            continue
        text = decoded.decode("ascii", "ignore")
        if 6 <= len(text) <= 96 and all(c in string.printable for c in text) \
           and sum(c.isalnum() for c in text) >= max(4, len(text)//3) \
           and any(c in text for c in "@-_!#$%^&*"):
            counter[text] += 1
    return [v for v, _ in counter.most_common()]

def rgb_lsb_bytes(path):
    img = Image.open(path).convert("RGB")
    bits = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = img.getpixel((x, y))
            bits += [r & 1, g & 1, b & 1]
    out = bytearray()
    for i in range(0, len(bits)//8*8, 8):
        v = 0
        for bit in bits[i:i+8]:
            v = (v << 1) | bit
        out.append(v)
    return bytes(out)
```

## 变体与关联

- **口令载体变体**：Base64 片段可能在 UDP payload 任意偏移、DNS TXT、ICMP、TCP 保留字段；也可能用 hex/Base32 而非 Base64。
- **压缩包变体**：ZIP 可能是 ZipCrypto 而非 AES，口令可先做已知明文攻击；也可能是 7z/RAR。
- **LSB 变体**：通道顺序可能为 BGR、只取单通道、列优先或从右下角开始；字节流可能先有长度头或 XOR 掩码。
- **关联卡片**：[[ctf-forensics-tcp-urgent-pointer-covert-channel]]（TCP 字段隐写）、[[ctf-forensics-png-lsb-column-major-scan-order]]（LSB 扫描顺序）、[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（嵌套压缩包口令链）。
- **边界**：若组播 payload 被加密或压缩，需先解密；若图片经过有损压缩，LSB 不可用。

## 检测与防御

- **CTF 验证**：先确认协议统计能分离出两类流量，再验证口令候选能成功解 ZIP，最后确认 LSB 字节流以 flag 前缀开头。
- **防御**：限制 SSDP/组播在边界内的传播；对出网流量做 DLP 与高熵/Base64 片段检测；图片上传统一重编码；终端监控异常 ZIP 解密与临时文件。
- **检测信号**：固定目的组播地址的高频小包、payload 中高比例可打印字符、HTTP JSON 内嵌大块 Base64。
