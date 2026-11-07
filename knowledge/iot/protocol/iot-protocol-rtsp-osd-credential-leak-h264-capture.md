---
id: iot-protocol-rtsp-osd-credential-leak-h264-capture
title: RTSP 公开流 OSD 泄露 Base64 凭据：抓取维护流并用 H.264 解包读 flag
type: scenario
domain: iot
path: iot/protocol
technique: rtsp-osd-credential-leak-h264-capture
aliases:
- RTSP OSD 泄露
- 摄像头 OSD 凭据
- RTSP-over-TCP
- H.264 depacketization
- gortsplib
- sprop-parameter-sets
tags:
- iot
- rtsp
- camera
- osd
- credential-leak
- h264
- rtp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:55+08:00'
  notes: 已对照原文「摄像头信息探查」核对：公开流 OPTIONS/DESCRIBE 得 gortsplib 与 H.264 sprop-parameter-sets；录制抽帧 OCR 得 diag-user=b64:c3ZjX3N5bmM=(svc_sync)、diag-pass=b64:TlZSLTc3LXJvdGFOZQ=(NVR-77-rotate)、diag-path=b64:ZmFjdG9yeS1kZWJ1Zy05ZjZhMmI=(factory-debug-9f6a2b)，维护流 Basic 认证后 RTSP-over-TCP、interleaved=0-1，按单NAL/STAP-A/FU-A 重组并解码得 flag{hidden_rtsp_feed_single_port}，与原文一致。未验证点：未持附件复跑；无版本/CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

当智能摄像头公开一个 RTSP 流、且画面 OSD 状态栏循环显示诊断字段时，录制/OCR 其中的 `diag-user`、`diag-pass`、`diag-path` 等 Base64 字段即可恢复维护流的 Basic 认证凭据与路径；再用 RTSP-over-TCP 抓取维护流，按 RTP 负载拆出 H.264 NAL（单 NAL/STAP-A/FU-A）并解码，即可读到画面中的 flag。

## 原理

- **RTSP 会话**：`OPTIONS` 获取能力，`DESCRIBE` 返回 SDP（含 H.264 `sprop-parameter-sets` 的 SPS/PPS），`SETUP` 指定 `Transport: RTP/AVP/TCP;unicast;interleaved=0-1`，`PLAY` 开始推流；TCP 交错模式下 RTP 包以 `$` + channel + 2 字节长度开头。
- **OSD 泄露**：摄像头在视频画面叠加状态栏（OSD），可能包含诊断字段；这些字段不是 RTSP 响应头，而是像素内容，需要录制多帧并用 OCR/人工识别。本题 OSD 循环刷新，单帧可能只显示部分字段，录制 60 秒并按 1fps 抽帧可覆盖全部状态。
- **Base64 字段**：`diag-user=b64:...`、`diag-pass=b64:...`、`diag-path=b64:...` 解码得到 `svc_sync`、`NVR-77-rotate`、`factory-debug-9f6a2b`；维护流 URL 为 `rtsp://host:port/factory-debug-9f6a2b`，Basic 认证用 `svc_sync:NVR-77-rotate`。
- **H.264 RTP 拆包**：RTP 负载类型 96 的 H.264 有三种封装：
  - 单 NAL：`payload[0]&0x1f` 在 1..23，直接是一个 NAL；
  - STAP-A：`payload[0]&0x1f == 24`，后续是 `[2 字节长度][NAL]` 序列；
  - FU-A：`payload[0]&0x1f == 28`，`payload[1]` 的 S/E 位表示分片开始/结束，重组为 `[(indicator&0xe0)|(header&0x1f)] + payload[2:]`。
- **为什么成立**：公开流只保护了维护流路径/凭据，但 OSD 把凭据显示在公开画面里；拿到凭据后维护流可正常 DESCRIBE/PLAY，视频中的 flag 可直接帧解码。
- **边界**：OSD 可能只短暂显示/被遮挡，需要多帧；维护流可能需要 Basic/Digest 认证；H.264 可能加密（SRTP）或使用不同 payload type。

## 触发条件

- 目标摄像头/RTSP 服务暴露公开流，且 SDP 可读；公开流画面包含 OSD 诊断字段。
- OSD 字段经过 Base64/简单编码，可离线解码；维护流路径/凭据可从 OSD 恢复。
- 维护流使用 Basic/Digest 认证，且凭据有效；RTSP-over-TCP 可用（UDP 可能被防火墙阻断）。
- 有 RTSP 客户端/脚本与 H.264 解码器（OpenCV/ffmpeg）。
- 目标在授权测试范围内。

## 利用步骤

1. 对公开流发 `OPTIONS`/`DESCRIBE`，确认服务端（如 `gortsplib`）、SDP 与 H.264 track。
2. 录制公开流 60 秒以上，按 1fps 抽帧；对帧做 OCR/人工查看，收集所有不同 OSD 状态。
3. 提取 `diag-user=b64:...`、`diag-pass=b64:...`、`diag-path=b64:...` 并 Base64 解码；得到维护流路径与 Basic 凭据。
4. 对维护流发 `DESCRIBE`（带 `Authorization: Basic ...`），确认 200 与 SDP；`SETUP` 用 `RTP/AVP/TCP;unicast;interleaved=0-1`，`PLAY`。
5. 解析 `$` 交错 RTP 包：跳过 12 字节 RTP 头与 CSRC/扩展，按单 NAL/STAP-A/FU-A 重组 NAL；把 SPS/PPS（来自 `sprop-parameter-sets`）与 NAL 写入 `.h264`。
6. 用 ffmpeg/OpenCV 解码，查看维护画面中的 flag；本题为 `flag{hidden_rtsp_feed_single_port}`。

## PoC

OSD 字段解码：

```python
import base64
for v in ("c3ZjX3N5bmM=", "TlZSLTc3LXJvdGFOZQ=", "ZmFjdG9yeS1kZWJ1Zy05ZjZhMmI="):
    print(base64.b64decode(v).decode())
# svc_sync
# NVR-77-rotate
# factory-debug-9f6a2b
```

RTSP-over-TCP 关键流程（伪代码）：

```python
# 1) OPTIONS/DESCRIBE 公开流，拿 SDP 与 sprop-parameter-sets
# 2) 用 Basic 凭据 DESCRIBE 维护流
# 3) SETUP: Transport: RTP/AVP/TCP;unicast;interleaved=0-1
# 4) PLAY；读取 $ + channel + len + RTP packet
offset = 12 + (packet[0] & 0x0f) * 4
if packet[0] & 0x10:                      # RTP 扩展
    offset += 4 + int.from_bytes(packet[offset+2:offset+4], "big")
payload = packet[offset:]
kind = payload[0] & 0x1f
if 1 <= kind <= 23:
    nals = [payload]                      # 单 NAL
elif kind == 24:                          # STAP-A
    nals, pos = [], 1
    while pos + 2 <= len(payload):
        size = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        nals.append(payload[pos:pos+size]); pos += size
elif kind == 28:                          # FU-A 重组
    ...
# 每个 NAL 前加 00 00 00 01，连同 SPS/PPS 写入 .h264
```

## 变体与关联

- **变体（Digest 认证）**：维护流要求 Digest 时，从 401 `WWW-Authenticate` 取 nonce/realm，按 MD5 计算 response。
- **变体（UDP/RTP）**：用 UDP 收 RTP，需处理丢包/乱序；TCP 交错更稳定。
- **变体（SRTP/加密）**：若流加密，需要密钥/漏洞；OSD 仍可能泄露凭据。
- **关联卡片**：[[iot-protocol-hartip-command9-quadrant-covert-channel]]（工控协议隐蔽信道）、[[iot-protocol-rtps-dds-writer-spoofing]]（实时协议）、[[pentest-recon-image-metadata-comment-hidden-path-hydra]]（公开信息泄露路径）。
- **边界**：OSD 可能不显示凭据；维护流可能仅内网/需 VPN；H.264 封装可能是非标准 payload type；OCR 误差需人工复核。

## 检测与防御

- **关闭公开流/OSD 敏感字段**：不要把用户名、密码、维护路径、固件版本等诊断信息叠加到公开画面；生产环境关闭 debug OSD。
- **认证与网络**：维护流使用强随机凭据 + Digest/TLS（RTSPS）；限制来源 IP/VPN；不要在 URL 中放可猜测路径。
- **检测**：监控公开 RTSP 流的 OSD 内容（OCR/模板匹配）；审计 `DESCRIBE/SETUP/PLAY` 与 Basic 认证失败；定期更换维护凭据。
- **响应**：发现 OSD 泄露后立即更换凭据、关闭公开流、检查是否已被抓取维护流。
