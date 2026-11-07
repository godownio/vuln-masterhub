---
id: ctf-forensics-pcap-custom-base64-tcp-protocol
title: HTTP 内嵌 pyc + 自定义 Base64 TCP 协议：tshark 提取 3333 流量还原命令输出
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-custom-base64-tcp-protocol-pyc
tags:
- ctf
- forensics
- pcap
- tshark
- custom-base64
- tcp
- pyc
- protocol-reverse
- command-execution
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T20:13:50+08:00'
  notes: 已对照原文核对（含11张图片）；未复跑 tshark；自定义64字符表、解码函数、3333 端口与 flag 输出均有图文印证
url: /docs/ctf/forensics/ctf-forensics-pcap-custom-base64-tcp-protocol/
draft: false
kb_aliases:
- 自定义 Base64 协议
- pyc 泄露协议
- tshark data.data 提取
- TCP 3333 流量解密
- HTTP 对象导出 pyc
- 换表 Base64 流量
---

## 一句话结论

流量包的 HTTP 响应里带了一个 `2.cpython-37.pyc`，反编译后得到服务端协议：监听 3333、把收到的数据用自定义 64 字符表做 6-bit 编码/解码、执行命令后把输出用同一张表编码回传。用 `tshark` 导出 3333 端口的 `data.data`，按泄露的字母表解码，就能还原服务端执行过的命令与输出（含 flag）。

## 原理

- **HTTP 对象泄露源码**：pcap 的 HTTP 会话中传输了 `.pyc` 文件（Python 3.7 字节码）。Wireshark 的“导出 HTTP 对象”或 `tshark --export-objects http,<dir>` 可取出；用 `uncompyle6`/`decompyle3`（对应 Python 3.7）反编译得到源码。
- **自定义 Base64 编码**：源码定义
  ```python
  CUSTOM_BASE64_CHARS = 'LMNOPQRSTUVWxyzabcdefghijklmnopqrstuvw0123456789+/XYZABCDEFGHIJK'
  ```
  编码时把数据转成二进制串，按 6 bit 一组查表；不足 6 的倍数补 `'0'`。解码时按字符查索引、拼回 6-bit 串、`rstrip('0')` 去掉尾部补零、再按 8 bit 切字节。它不是标准 Base64（没有 `=` 填充，字母表也是换过的），所以不能直接用标准 Base64 解码。
- **服务端协议**：`socket.bind(('0.0.0.0', 3333))`，`accept()` 后循环 `recv(1024)`；`custom_base64_decode(data)` 得到命令字符串，`subprocess.run(command, shell=True, capture_output=True, text=True)` 执行，`custom_base64_encode(stdout+stderr)` 回传。因此 3333 端口上的双向流量都是这种自定义编码。
- **流量提取**：`tshark -r capture.pcap -Y "tcp.port==3333" -T fields -e data.data` 把每个 TCP 包的 payload 以十六进制输出；把十六进制转回字节、按流方向拼接，再按自定义字母表解码，即可还原命令与输出。TCP 可能分片，需要按 stream/方向重组或把所有 `data.data` 顺序拼接后解码。
- **为什么可行**：协议没有加密/认证，只有一层换表编码；pyc 又直接泄露了字母表与执行逻辑。拿到字母表后，编码只是可逆的 6-bit 映射，不需要密钥。

## 触发条件

- 抓包中包含 HTTP 传输的 `.pyc`/源码/配置文件，或能通过其他方式获得协议实现。
- 目标协议使用固定自定义字母表的 6-bit/Base64 变体，且没有额外加密/压缩。
- 3333 端口流量完整（握手后的数据包未被截断），或能按 TCP 流重组。
- 服务端会把命令输出用同一编码回传；若只编码请求不编码响应，则只能还原命令，不能直接拿输出。

## 利用步骤

1. 用 Wireshark 打开 pcap，筛选 `http`，导出对象；或 `tshark --export-objects http,out`，找到 `.pyc`。
2. 确认 Python 版本（magic/文件名 `cpython-37`），用对应反编译器得到源码；提取自定义字母表、端口、编码/解码函数、命令执行逻辑。
3. 用 `tshark -r capture.pcap -Y "tcp.port==3333" -T fields -e data.data > out.hex` 导出 3333 端口 payload。
4. 把 hex 转字节；按 TCP stream/方向重组（或顺序拼接后尝试解码），用自定义字母表解码。
5. 检查解码结果中的命令、stdout/stderr；若一次解码不完整，按包边界/流方向分段解码，或先解请求再解响应。
6. 提取 flag/敏感输出；用源码中的 `custom_base64_encode` 反向验证（把明文编码回流量）以确认字母表和分组正确。

## PoC

```python
ALPHABET = 'LMNOPQRSTUVWxyzabcdefghijklmnopqrstuvw0123456789+/XYZABCDEFGHIJK'

def custom_b64_decode(s: str) -> bytes:
    bits = ''.join(format(ALPHABET.index(c), '06b') for c in s)
    bits = bits.rstrip('0')
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if chunk:
            out.append(int(chunk, 2))
    return bytes(out)

# 1) tshark -r capture.pcap -Y "tcp.port==3333" -T fields -e data.data > out.hex
hex_data = ''.join(open("out.hex").read().split())
raw = bytes.fromhex(hex_data)
# 2) 按实际 TCP 流分段；下面假设 raw 是单个方向拼接后的编码文本
text = raw.decode("latin-1")
print(custom_b64_decode(text))
```

案例解码出的输出中包含 `flag{e34f1743c79af05fe922317bd44aaed1}`。

## 变体与关联

- **字母表变体**：换表 Base64、6-bit/5-bit 编码、加 `=` 填充或去掉填充、大小写/数字重排；先确认分组位数，再写 encode/decode 闭环。
- **多层编码**：自定义 Base64 外再套 XOR/RC4/zlib/gzip；按源码中的调用顺序逆序解，必要时用明文格式/magic 校验。
- **协议方向**：请求与响应可能使用不同字母表/不同密钥；按 TCP stream 区分方向，不要把所有 payload 混在一起。
- **流量重组**：大输出会跨多个 TCP 段；按 `tcp.stream` 和 seq 排序重组，或使用 Wireshark 的 Follow TCP Stream 导出原始字节。
- **关联：换表 Base64 逆向**。`ctf/reverse` 下已有自定义 Base64 表 + XOR 的逆向卡；本卡是“从 pcap + pyc 还原协议”的取证版本。
- **关联：HTTP 对象导出**。CTF 取证常从 HTTP 导出二进制/源码；本卡把导出对象、pyc 反编译、协议解码串成一条链。

## 检测与防御

- **取证流程**：先 `capinfos`/`tshark -q -z io,phs` 看协议层次；再导出 HTTP 对象；对未知 TCP 端口用 `Follow TCP Stream` 看是否有可打印/编码文本。
- **协议识别**：统计字符集与 6-bit 分组特征；用已知明文（如命令提示符、`flag{`）反推字母表映射。
- **防御/设计**：不要用自定义编码代替加密/认证；远程命令执行接口必须鉴权、参数化、限制命令白名单；不要在 HTTP 中传输服务端源码/字节码。
- **检测**：监控非标准端口上的可打印 6-bit 编码流量；对 `subprocess`/`shell=True` 服务端行为告警；限制出站/入站非业务端口。
