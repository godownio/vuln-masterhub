---
id: iot-protocol-nfc-digital-key-relay-attack
title: NFC 数字钥匙中继攻击：NFCgate tag/reader + 中继服务器延长通信距离
type: scenario
domain: iot
path: iot/protocol
technique: nfc-digital-key-relay-attack
tags:
- iot
- automotive
- nfc
- relay
- apdu
- nfcgate
- digital-key
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:08:57+08:00'
  notes: 已对照原文与6张图核对：NFCgate 双机 relay、server.py 5566、192.168.137.1、APDU/SW 示例与原文一致。核对中发现卡片把 reader/tag 放置位置写反（原文与图02：reader 手机贴近车主手机/卡片读取，tag 手机贴近车辆 NFC 感应区），已修正一句话结论、触发条件、步骤4/5与PoC；原理段原表述正确。原文未标记受影响版本；frontmatter 无 sources/source_url。未验证点：本库未复跑车辆中继。
url: /docs/iot/protocol/iot-protocol-nfc-digital-key-relay-attack/
draft: false
kb_aliases:
- NFC 中继攻击
- NFC Relay Attack
- 数字钥匙中继
- NFCgate
- 车联网中继
- APDU 中继
---

## 一句话结论

车规 NFC 数字钥匙的读卡器只验证卡片对 APDU 挑战的密码学响应，不验证“卡片是否真的在几厘米内”；攻击者用两台手机（NFCgate，一台 reader 模式贴近车主手机/卡片读取，一台 tag 模式贴近车辆 NFC 感应区被车辆读取）加一台中继服务器，把 APDU 请求/响应实时转发，就能在远距离解锁车辆。

## 原理

- NFC 有三种模式：卡模拟（Tag/Card Emulation）、读卡器（Reader/Writer）、点对点（P2P）。车辆数字钥匙通常由车辆作为 reader 发射射频场、给手机/卡片供电，并通过 APDU 做权限验证。
- 正常流程：卡片靠近 → 车辆 RF 场激活卡片 → REQA/ATQA 防冲突 → SELECT/SAK 选卡 → RATS/ATS 协商参数 → C-APDU（挑战/认证）→ R-APDU（响应）→ 验证通过开门。
- 中继攻击把短距离链路拆成两段：`tag1 <-> reader2 <-> 服务器 <-> tag2 <-> reader1`。攻击者手机1 模拟车辆读卡器贴近受害者的手机/卡片，手机2 模拟卡片贴近车辆 reader，服务器转发两端的 APDU 字节；车辆看到的仍是“合法卡片”的响应，因此开门。
- 关键点：NFC 协议本身没有距离绑定/测距；只要 APDU 交互在时间窗口内完成，车辆无法区分“卡片在 4cm 内”还是“信号经服务器绕了很远”。示例可在 1–2 秒内完成开门。
- APDU 结构：C-APDU = CLA/INS/P1/P2/Lc/Data/Le；R-APDU = Data/SW1 SW2。`00 A4 04 00` 为 Select File（选择应用）；`80`/`84` 开头为行业标准/私有（GlobalPlatform）；`6A82` = File Not Found，`90 00` = Success。
- 防御核心是距离/时延检测：UWB 的 ToF/安全时间戳可测出中继时延；严格 FWT（<20ms）并禁用 WTX；MFA/生物识别；钥匙运动传感器静止休眠。

## 触发条件

- 目标车辆使用 NFC 数字钥匙（CCC 规范），且未部署 UWB/距离绑定/严格时延检测。
- 攻击者能在车主手机/卡片附近放置一台 NFCgate 手机（reader 模式），同时在车辆 NFC 感应区放置另一台（tag 模式）。
- 两台手机与中继服务器网络可达（同一热点/互联网），NFCgate 已安装并授予 Xposed/Root 权限。
- 车辆未要求额外生物识别/手机解锁确认，或该确认可被绕过。

## 利用步骤

1. 准备两台安装 NFCgate 的 Android 手机（需 Xposed）、一台电脑作为中继服务器。
2. 电脑开热点，两台手机连接；运行 `python3 server.py`，确认监听 `0.0.0.0:5566`。
3. 两台手机在 NFCgate Settings 中设置服务器 IP（如 192.168.137.1）与端口 5566。
4. 回到主界面选择 Relay Mode：手机1 设为 reader（贴近车主手机/卡片），手机2 设为 tag（贴近车辆 NFC 感应区）。
5. 先锁车；把 reader 手机靠近车主手机 NFC 感应区，tag 手机靠近车辆 NFC 感应区。
6. 两端自动开始 APDU 中继；观察车辆是否解锁。若成功，记录时间、APDU 日志与状态字（如 9000）。
7. 分析 APDU 交互（CLA/INS/P1/P2、SW1 SW2），理解认证流程；测试结束恢复车辆状态。

## PoC

```text
# 服务器
python3 server.py
# [server] NFCGate server listening on ('0.0.0.0', 5566)

# 手机端 NFCgate
# Settings: Hostname = 192.168.137.1, Port = 5566
# Relay Mode: Phone1 = Reader（靠近车主手机/卡片）
#             Phone2 = Tag   （靠近车辆 NFC）

# APDU 示例
C-APDU: 00 A4 04 00 ...   # Select File / 选择应用
R-APDU: 6A 82             # File Not Found
R-APDU: 90 00             # Success
```

## 变体与关联

- 变体：BLE/UWB 数字钥匙中继；中继链路可走互联网，距离不受限。
- 变体：自定义硬件（NFC 读卡器 + 卡片模拟器）替代两台手机。
- 变体：先中继完成认证，再重放/伪造后续 APDU（若协议无计数器）。
- 关联：[[iot-protocol-can-arbitration-id-discovery-spoofing]]（CAN 伪造）、[[iot-protocol-can-replay-candump-canplayer]]（CAN 重放）、[[web-generic-auth-iot-nfc-lock-predictable-signature-factory-mode]]（NFC 锁签名缺陷）。

## 检测与防御

- 防御：UWB ToF/安全测距、严格 FWT（<20ms）并禁用 WTX、MFA/生物识别、钥匙运动传感器静止休眠。
- 防御：车辆端检测异常时延/信号强度/距离，要求手机解锁确认；NFC 协议加入距离绑定或挑战-响应时间戳。
- 检测：NFC 认证时延异常、信号强度与距离不一致、同一卡片短时间内异地使用。
- 响应：确认中继后轮换数字钥匙/证书，升级 UWB/时延检测，审计解锁日志。
