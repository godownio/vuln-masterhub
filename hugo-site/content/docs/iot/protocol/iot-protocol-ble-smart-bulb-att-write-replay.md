---
id: iot-protocol-ble-smart-bulb-att-write-replay
title: BLE 智能灯泡 GATT 协议逆向与重放：nRF Sniffer 抓 ATT Write 后直接控制开关
type: scenario
domain: iot
path: iot/protocol
technique: ble-gatt-att-write-replay
tags:
- iot
- ble
- gatt
- att
- replay
- nrf-sniffer
- smart-home
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:24:33+08:00'
  notes: 已对照原文与19张图核对：nRF52832 Sniffer 连接前抓包、CONNECT_IND/Follow、btatt 过滤、Write handle 0x0012、Service 9fdc9c81-fffe-51a1-e511-5a38c414c2f9、Write 特征 ac7bc836-6b69-74b6-d64c-451cc52b476e、Read/Notify/WriteNoResponse、16 字节报文 0e...0405020180/0e...0406020181、最后字节 0/1 控制开关、nRF Connect 重放均与图14-19一致。已修正卡片原文照抄的“第 7 个字节”为“第 13 个字节”（16 字节报文逐字节计数，变化字节为 05/06/07...）。未验证点：未在本机抓包/重放；原文未给灯泡型号/固件版本。
url: /docs/iot/protocol/iot-protocol-ble-smart-bulb-att-write-replay/
draft: false
kb_aliases:
- nRF Sniffer
- nRF52832
- BLE 重放
- GATT
- ATT Write
- LifeSmart 智能灯泡
- 智能家居重放
---

## 一句话结论

用 nRF52832 Sniffer + Wireshark 在连接建立前抓 BLE 空口包，按 `btatt` 过滤 ATT 交互，定位 Write Request 的 handle 0x0012 与特征值 UUID；开关灯指令是固定 16 字节 ATT Write，只有最后一个字节 0/1 决定状态，中间递增字节不被校验；用 nRF Connect 直接重放捕获到的 Write Request 即可在未安装原厂 App 的情况下控制灯泡。

## 原理

- **BLE 空口抓包**：BLE 有 3 个广播信道（37/38/39）和 37 个数据信道（0-36），连接后按跳频算法每秒切换数百次；普通蓝牙网卡只能看到自己参与的连接，nRF Sniffer 先捕获 `CONNECT_IND` 锁定设备，再跟随跳频把 ATT 数据送给 Wireshark。
- **ATT/GATT**：连接后应用层数据由 ATT 承载；Write Request（0x12）/Write Response、Read Request（0x14）/Read Response、Handle Value Notification（0x16）是常见交互。GATT 用 handle 和 characteristic UUID 区分服务/特征值。
- **本题设备**：Service UUID `9fdc9c81-fffe-51a1-e511-5a38c414c2f9`；Write Characteristic `ac7bc836-6b69-74b6-d64c-451cc52b476e`（Properties: WRITE）；Read `c4c617ea-...`；Notify `628c711d-...`；另有 Write No Response `4039ddf0-...`。
- **指令格式**：捕获到的 Write Request value 为 16 字节：
  - 关灯：`0e000000000000000000000405020180`
  - 开灯：`0e000000000000000000000406020181`
  多次对比发现第 13 个字节（`04/05/06/...`，从 1 计数）只是 App 端递增计数，设备不校验；最后一个字节 `00`/`01` 才是开关状态。
- **重放**：协议没有 nonce、时间戳、会话标识、challenge-response，也不要求链路层加密/配对绑定；把捕获的 Write Request 通过 nRF Connect 写到同一 handle/characteristic 即可复现控制。
- **影响**：未授权者可在蓝牙范围内开关灯/改变状态；若协议还控制亮度/颜色/场景，同样可重放。

## 触发条件

- 目标 BLE 设备使用 GATT Write/Write Without Response 下发控制指令。
- 指令中没有随机数、时间戳、会话/序列号校验，或校验可预测。
- 设备未强制 BLE Link Layer Encryption/配对绑定，或攻击者能在配对前/后抓包重放。
- 有 nRF52832/nRF Sniffer 等支持跟随跳频的抓包硬件，或能在手机端 Hook GATT 写入。

## 利用步骤

1. 安装 Wireshark（勾选 Npcap/USBPCap）、CP210x 驱动、nRF Sniffer extcap 插件；Wireshark 以管理员运行。
2. 在建立连接前启动 Sniffer 抓包；选择目标设备（如 `BULB-7CEC79FD0915`），捕获 `CONNECT_IND` 后跟随跳频。
3. 用 `btatt` 过滤 ATT 包；操作 App 开/关灯，观察 Write Request/Write Response、Read、Notification。
4. 对比多次开关的 Write Request value，找固定前缀/后缀与变化字节；本题确认最后字节 0/1 控制开关，第 13 字节是无效递增。
5. 记录 Write handle（0x0012）和 characteristic UUID；在 nRF Connect 中连接设备，向同一 characteristic 写入捕获的 16 字节。
6. 观察灯泡状态变化；若成功，说明无重放防护。可进一步枚举亮度/颜色等指令。

## PoC

```text
抓包过滤：btatt
Write handle: 0x0012
Service UUID: 9fdc9c81-fffe-51a1-e511-5a38c414c2f9
Write characteristic: ac7bc836-6b69-74b6-d64c-451cc52b476e

关灯：0e 00 00 00 00 00 00 00 00 00 00 04 05 02 01 80
开灯：0e 00 00 00 00 00 00 00 00 00 00 04 06 02 01 81
```

nRF Connect：连接目标 → 选择 Write characteristic → 写入上述 16 字节（New value → Write）。

## 变体与关联

- **写入方式变体**：Write Request（有响应）vs Write Without Response；Notify/Read 可能泄露状态。
- **协议变体**：固定指令、递增计数器、校验和、XOR/加密；先对比多次操作找变化字段。
- **防护变体**：nonce/时间戳/会话、challenge-response、链路层加密/配对绑定、特征值权限。
- **关联卡片**：[[iot-protocol-someip-sd-stopoffer-spoof-tp-command]]（无认证控制协议）、[[iot-protocol-rtps-dds-writer-spoofing]]（身份伪造/重放）、[[iot-protocol-hartip-command9-quadrant-covert-channel]]（工控协议字段）。
- **边界**：若设备要求配对/绑定、链路层加密、或指令含不可预测 nonce，直接重放会失败；需要进一步逆向密钥/协议。

## 检测与防御

- **协议**：控制指令加入随机 nonce/时间戳/会话 ID，设备端校验一次性/时效；使用 challenge-response；敏感操作要求配对绑定与链路层加密。
- **GATT 权限**：Write characteristic 设置认证/加密权限，不要对未配对连接开放。
- **检测信号**：同一 16 字节 Write 被重复发送；未配对设备收到控制指令；GATT 特征值权限过宽。
- **测试建议**：抓包要在连接前开始；用 `btatt` 过滤；多次对比找变化字段；重放时注意 handle/characteristic 一致。
