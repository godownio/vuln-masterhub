---
id: defense-forensics-http-segmented-response-jpeg-carve
title: Wireshark 从 HTTP 分段响应重组导出 JPEG：FF D8/FF D9 截取 + binascii 还原图片
type: scenario
domain: defense
path: defense/forensics
technique: pcap-http-reassembled-pdu-jpeg-extract
aliases:
- TCP segment of a reassembled PDU
- HTTP 响应还原 JPEG
- pcap 图片提取
- binascii a2b_hex 还原图片
- 网页版微信抓包图片
tags:
- forensics
- pcap
- wireshark
- http
- tcp-reassembly
- jpeg
- traffic-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V584
  verified_at: '2026-11-12T13:59:38+08:00'
  notes: 已对照原文（3780 字符）与全部 34 张截图逐项核对：HTTP/1.1 200 OK (JPEG JFIF image)、6 段 TCP segment of a reassembled PDU 共 8474 字节、载荷 FF D8/FF D9、binascii.a2b_hex 写盘与还原图（群头像）一致。验证中修正了案例来源描述：JPEG 还原实际发生在 iOS 端微信刷新列表的明文 HTTP 图片 GET（网页版微信登录/同步/上传接口走 short.weixin.qq.com HTTP:80），原文并非只限网页版；相应调整了触发条件与步骤中 Content-Type 的表述。dedup 候选（TLS keylog、Web 入侵时间线、hexlines-wrpcap-jpeg）均不同链。未本机复跑抓包与代码。
---

## 一句话结论

在 pcap 中定位一条响应体为 JPEG 的 HTTP 200 OK（Wireshark 显示 `HTTP/1.1 200 OK (JPEG JFIF image)`），它常被 TCP 拆成多个 `TCP segment of a reassembled PDU`；Wireshark 重组后把载荷按十六进制复制，按 JPEG 的 `FF D8` 文件头与 `FF D9` 文件尾截取，再用 `binascii.a2b_hex` 写盘即可还原出可打开的图片。原文案例中，微信客户端（网页版登录/同步与 iOS 端刷新列表）的部分业务走明文 HTTP:80，抓包可直接看到响应并还原图片数据。

## 原理

- **HTTP 大响应会被 TCP 分段**：单段 TCP 通常受 MSS 限制（常见 1440/1460 字节），大于该值的 HTTP 响应体被拆成多段发送；Wireshark 把后续段标记为 `TCP segment of a reassembled PDU`，在最后一段的响应报文中完成重组。
- **为什么能还原**：HTTP 响应体在承载层是无损字节流；只要抓包完整，把重组后的 payload 按字节取出就是原始文件。JPEG 以 `FF D8`（SOI）开始、`FF D9`（EOI）结束，据此可从载荷中截出准确的文件边界。
- **hex 转换路径**：Wireshark 以 hex 显示载荷时每字节两位十六进制；复制 `FF D8 ... FF D9` 的十六进制串，`binascii.a2b_hex` 转回字节写入文件即可；也可以用 Follow HTTP/TCP Stream 直接保存 Raw，或 `tshark --export-objects http,<dir>` 导出。
- **明文 HTTP 的前提**：原文案例里网页版微信的登录二维码、消息同步、上传图片等请求走 `short.weixin.qq.com` 的 HTTP:80（UA 为 `MicroMessenger Client`）；iOS 端微信刷新列表时的图片 GET 也是明文 HTTP（响应为 `HTTP/1.1 200 OK (JPEG JFIF image)`）。因此同一网络内抓包能看到明文响应；其他接口使用 TLS/mmtls 加密（iOS 端业务包为 mmtls），加密流量不能按同样方法直接还原，需按实际会话区分。
- **边界**：TLS/mmtls 加密流量、抓包丢段（TCP 重组不完整）、分块传输或压缩编码时需要额外处理，均不能按原始 hex 直接还原。

## 触发条件

- 已取得包含目标会话的 pcap（本机抓包、端口镜像、同一局域网嗅探等），且会话完整。
- 图片通过明文 HTTP 传输（案例为网页版微信部分业务及 iOS 端微信图片 GET）；HTTPS/mmtls 会话不适用。
- 响应为单张完整 JPEG，未被截断；Content-Type 或载荷魔数能识别为图片。
- 环境具备 Wireshark/tshark 与 Python（binascii）。

## 利用步骤

1. 用 `http` 过滤定位响应：找 `200 OK` 且响应体为 JPEG（Wireshark 标注 `JPEG JFIF image` 或 Content-Type 为 `image/jpeg`）的报文，注意其前方的 `TCP segment of a reassembled PDU` 分段。
2. 右键 Follow → HTTP Stream（或 TCP Stream），确认载荷开头为 `FF D8`、结尾为 `FF D9`。
3. 将显示模式切到 Hex/Raw，复制从 `FF D8` 到 `FF D9` 的十六进制串（或直接 Save as Raw）。
4. 用 Python 将 hex 串 `binascii.a2b_hex` 后以二进制写入 `.jpg`。
5. 打开图片校验；若显示不全，检查是否漏掉分段或流中混有多个响应（按 Content-Length/流边界切分）。
6. 也可直接用 `tshark --export-objects http,outdir` 或 File → Export Objects → HTTP 批量导出。

## PoC

原文 Python 片段（把 hex 串写入图片文件）：

```python
import binascii
filepath = "a.jpg"
payload = "FF D8 ... FF D9"  # 从重组后的 HTTP 响应载荷复制的十六进制串
f = open(filepath, "ab")
f.write(binascii.a2b_hex(payload.encode()))
f.close()
```

## 变体与关联

- **直接导出**：Wireshark 的 Export Objects → HTTP 或 `tshark --export-objects` 能自动完成重组与落盘，适合批量处理。
- **其他文件类型**：按魔数截取，PNG（`89 50 4E 47`）、ZIP（`50 4B 03 04`）、PDF（`%PDF`）等同样可从响应载荷还原。
- **加密流量**：TLS 会话需要密钥日志（SSLKEYLOGFILE）或内存取密钥；mmtls 等私有协议需专门分析。
- **关联卡片**：[[ctf-forensics-hexlines-wrpcap-tcpstream-jpeg]]（十六进制文本先重组 pcap 再导出 JPEG）、[[ctf-forensics-smtp-pcap-mime-attachment-reassembly]]（SMTP 附件重组）。

## 检测与防御

- 敏感图片/文件应通过 TLS 传输并启用 HSTS，避免明文 HTTP 暴露内容。
- 蓝队可用 DLP/流量还原对明文 HTTP 中的图片、文档传输做审计；对 `JFIF`/`PNG` 等魔数的长响应提取并比对哈希。
- 企业网络可对明文 HTTP 上传/下载图片行为做基线告警，尤其是办公网内的即时通讯网页版流量。
