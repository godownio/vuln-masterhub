---
id: iot-protocol-ble-android-hci-btsnoop-capture
title: Android BLE HCI 抓包：btsnoop_hci 日志提取与 Wireshark 分析
type: scenario
domain: iot
path: iot/protocol
technique: android-ble-hci-btsnoop-capture
tags:
- iot
- ble
- bluetooth
- hci
- btsnoop
- android
- wireshark
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:07:55+08:00'
  notes: 已对照原文与全部14张图核对：HCI 日志开关、重启蓝牙、/data/misc/bluetooth/logs 与旧版 /sdcard 路径、btsnoop 导出命令均与原文一致；frontmatter 无 sources/source_url。未验证点：本库未在真机复跑抓包。
url: /docs/iot/protocol/iot-protocol-ble-android-hci-btsnoop-capture/
draft: false
kb_aliases:
- BLE HCI 抓包
- btsnoop_hci.log
- 蓝牙 HCI 日志
- Android 蓝牙抓包
- btsnoop
---

## 一句话结论

Android 开发者选项中的“启用蓝牙 HCI 信息收集日志”会把手机 Host 与蓝牙 Controller 之间的 HCI 数据写入 `btsnoop_hci.log`；导出该文件用 Wireshark 打开，即可看到 App 层最原始的 BLE 明文应用数据，绕过空口链路的加密，是分析智能手环/门锁/车钥匙等 BLE 设备的第一步。

## 原理

- BLE 协议栈分三层：Controller（PHY/LL，负责 2.4GHz 收发/跳频）、Host（L2CAP/SMP/GAP/GATT，运行在手机 CPU）、Application（业务逻辑）。
- App 发出的指令先在 Host 生成明文数据，再经 HCI 交给 Controller；Controller 负责打包、加密、调频后从天线发出。
- HCI 抓包抓的是 Host↔Controller 之间的数据，因此能看到 App 层明文（ATT/GATT 读写、L2CAP 数据），但看不到 PHY/LL 的空口细节；OTA 空口抓包则相反，能看到 PHY/LL 但应用数据可能被链路层加密。
- Android 8+ 日志路径为 `/data/misc/bluetooth/logs/btsnoop_hci.log`；Android 7 及以前常见 `/sdcard/btsnoop_hci.log`。
- 开启 HCI 日志后必须关闭并重新打开蓝牙，日志才开始记录；操作 App 后导出日志，Wireshark 可直接解析 btsnoop 格式并显示 BLE/ATT 协议。
- 该方法的局限：需要 Root/ADB 访问日志目录；部分厂商 ROM 可能裁剪 HCI 日志功能；只能看到本机 Host 侧数据，无法看到其他设备之间的空口流量。

## 触发条件

- 测试手机已 Root，能访问 `/data/misc/bluetooth/logs` 或 `/sdcard`。
- Android 开发者选项可用，且 ROM 保留“启用蓝牙 HCI 信息收集日志”。
- 目标 BLE App 在手机上运行，攻击者能操作 App 触发业务指令。
- 需要分析 BLE 应用层明文/协议字段。

## 利用步骤

1. 打开“关于手机”，连续点击版本号开启开发者模式。
2. 在“开发者选项”中开启“启用蓝牙 HCI 信息收集日志”。
3. 关闭并重新打开手机蓝牙（关键步骤，否则不记录）。
4. 操作目标 App（绑定/开锁/读数据等），触发 BLE 通信。
5. `adb shell` → `su` → `cd /data/misc/bluetooth/logs` → `ls`，找到 `btsnoop_hci_*.log`。
6. `cp` 到 `/sdcard/`，`adb pull` 到本地；用 Wireshark 打开，过滤 `btatt`/`btl2cap`/`bthci` 分析。
7. 若路径不存在，检查 Android 版本/ROM，尝试 `/sdcard/btsnoop_hci.log` 或厂商日志目录。

## PoC

```bash
adb shell
su
cd /data/misc/bluetooth/logs
ls
cp btsnoop_hci_*.log /sdcard/
exit
adb pull /sdcard/btsnoop_hci_*.log .
# Wireshark 打开，过滤 btatt / btl2cap / bthci
```

## 变体与关联

- 变体：Android 7 及以前路径为 `/sdcard/btsnoop_hci.log`；部分 ROM 需 `setprop persist.bluetooth.btsnooplogmode full`。
- 变体：iOS/其他 OS 有类似 HCI 日志/包抓取工具。
- 变体：HCI 日志看不到空口跳频/连接参数，需要配合 OTA 抓包。
- 关联：[[iot-protocol-ble-ota-nrf-sniffer-capture]]（空口抓包）、[[iot-protocol-ble-smart-bulb-att-write-replay]]（BLE 重放）、[[iot-protocol-nfc-digital-key-relay-attack]]（NFC 中继）。

## 检测与防御

- 检测：设备开启开发者选项/HCI 日志、`btsnoop_hci.log` 生成、ADB Root 访问。
- 防御：企业设备禁用开发者选项/USB 调试；App 对敏感指令做应用层加密/认证，避免仅依赖链路层加密。
- 响应：确认 HCI 日志泄露后，轮换 BLE 配对准密钥/绑定信息，审计异常绑定。
