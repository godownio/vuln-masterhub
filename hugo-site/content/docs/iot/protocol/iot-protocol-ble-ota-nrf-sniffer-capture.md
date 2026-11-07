---
id: iot-protocol-ble-ota-nrf-sniffer-capture
title: BLE 空口抓包：nRF Sniffer + Wireshark 跟踪 CONNECT_IND 与跳频
type: scenario
domain: iot
path: iot/protocol
technique: ble-ota-nrf-sniffer-capture
tags:
- iot
- ble
- bluetooth
- ota
- nrf-sniffer
- wireshark
- sniffing
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:07:56+08:00'
  notes: 已对照原文与全部14张图核对：nRF52840/E104-BT5040UA、固件 V3.0 与 nrfutil v4 不匹配、Wireshark nRF Sniffer 插件、目标 MAC d0:62:2c:cd:99:42 与 CONNECT_IND/LL 控制 PDU/ATT MTU 均与截图一致；frontmatter 无 sources/source_url。未验证点：本库未复跑空口抓包。
url: /docs/iot/protocol/iot-protocol-ble-ota-nrf-sniffer-capture/
draft: false
kb_aliases:
- BLE 空口抓包
- OTA Sniffing
- nRF Sniffer
- nRF52840
- CONNECT_IND
- 蓝牙跳频抓包
---

## 一句话结论

BLE 空口抓包用 nRF52840 抓包板（nRF Sniffer 固件）配合 Wireshark，先监听 37/38/39 广播信道，选中目标设备 MAC 后捕获 `CONNECT_IND`，按其中的跳频参数跟随数据信道，即可抓到连接后的完整 BLE 通信（PHY/LL/ATT），与 Android HCI 抓包互补。

## 原理

- BLE 使用 2.4–2.485GHz ISM 频段，共 40 个信道：37/38/39 为广播信道，0–36 为数据信道；连接建立后设备按跳频算法在数据信道间跳变。
- 空口抓包（OTA Sniffing）抓的是空气中传播的射频包，能看到 PHY/LL 层（广播、CONNECT_IND、LL 控制 PDU、ATT 数据），不接触交互双方设备。
- 只监听广播信道只能看到广播包；要抓连接后的数据，必须在 Wireshark/nRF Sniffer 中选中目标设备 MAC，捕获 `CONNECT_IND`，从中解析 Hop Increment/Channel Map 等参数，跟随跳频轨迹。
- 示例：选中 `Xiaomi Smart Band 8 9942`（public MAC `d0:62:2c:cd:99:42`），Wireshark 先显示 ADV_IND，绑定手机后出现 `CONNECT_IND`，随后是 `LL_FEATURE_REQ/RSP`、`LL_LENGTH_REQ/RSP`、`LL_VERSION_IND`、ATT Exchange MTU 等。
- 空口抓包的应用数据可能被 BLE 链路层加密（配对后），没有 LTK 时只能看到密文；HCI 抓包则能看到手机 Host 侧明文，两者互补。
- 常见坑：抓包板固件版本必须与 Wireshark 插件版本一致（示例固件 V3.0 vs nrfutil `ble-sniffer bootstrap` v4 不匹配）；Wireshark 右下角配置/Profile 选择会影响显示（Default vs nRF Sniffer profile）。

## 触发条件

- 有 nRF52840 抓包板（如 E104-BT5040UA）或兼容的空口抓包设备，烧录 nRF Sniffer 固件。
- Wireshark 安装 nRF Sniffer for Bluetooth LE 插件，版本与固件匹配。
- 目标 BLE 设备在附近广播/连接，攻击者能在射频范围内被动监听。
- 目标连接未使用仅配对密钥可解的加密，或已有 LTK/配对信息。

## 利用步骤

1. 给抓包板烧录 nRF Sniffer 固件（如 `sniffer_pca10056_xxxxxx.hex`），确认版本与 Wireshark 插件一致。
2. 插入抓包板，Wireshark 中启用 `nRF Sniffer for Bluetooth LE` 接口工具栏，刷新接口列表，选择对应 COM 口。
3. 开始抓包，先观察 37/38/39 广播信道上的 `ADV_IND`/`ADV_NONCONN_IND`。
4. 在设备下拉框中选择目标设备 MAC（如 `d0:62:2c:cd:99:42`），或在过滤器中指定。
5. 触发目标设备与手机绑定/连接；在 Wireshark 中搜索 `CONNECT_IND`，确认捕获到连接建立。
6. 让 nRF Sniffer 跟随连接跳频，观察后续 LL 控制 PDU 与 ATT 数据；按需过滤 `btle`/`btatt`/`btl2cap`。
7. 若看不到连接后数据，检查 MAC 是否选对、固件/插件版本、Wireshark Profile、设备是否使用随机地址/扩展广播。

## PoC

```text
# Wireshark + nRF Sniffer 操作序列
1. 插入 nRF52840 抓包板（nRF Sniffer 固件 V3.0）
2. Wireshark -> 捕获 -> 刷新接口列表 -> nRF Sniffer for Bluetooth LE COMx
3. 开始捕获，观察 ADV_IND
4. Device 选择目标 MAC（如 d0:62:2c:cd:99:42）
5. 手机与设备绑定，Ctrl+F 搜索 CONNECT_IND
6. 观察 LL_FEATURE_REQ/RSP、LL_LENGTH_REQ/RSP、LL_VERSION_IND、ATT Exchange MTU
7. 过滤 btatt / btl2cap / btle 分析业务数据
```

## 变体与关联

- 变体：其他空口抓包设备（Ubertooth、Ellisys、乐鑫/ Nordic 开发板）；BLE 5 扩展广播/长包需对应固件。
- 变体：目标使用随机 MAC/隐私模式时，需要先通过广播特征/IRK 关联设备。
- 变体：连接加密且无 LTK 时，只能看 LL 控制/长度/版本，业务数据为密文；需结合 HCI 抓包或配对窃取。
- 关联：[[iot-protocol-ble-android-hci-btsnoop-capture]]（HCI 抓包）、[[iot-protocol-ble-smart-bulb-att-write-replay]]（BLE 重放）、[[iot-protocol-nfc-digital-key-relay-attack]]（NFC 中继）。

## 检测与防御

- 检测：BLE 设备附近存在异常嗅探器（被动监听难以发现）；监控异常连接/配对、随机 MAC 变化。
- 防御：BLE 配对加密、应用层认证/加密、MAC 随机化、连接参数与密钥保护；敏感指令不要只依赖链路层加密。
- 响应：确认空口泄露后，轮换配对密钥/LTK，审计异常绑定与连接记录。
