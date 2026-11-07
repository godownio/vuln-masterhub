---
id: iot-vehicle-bluetooth-hid-keyboard-spoofing
title: 车机蓝牙 HID 键盘仿冒：未授权配对后模拟按键控车与 PIN/密钥爆破
type: scenario
domain: iot
path: iot/vehicle
technique: vehicle-bluetooth-hid-keyboard-spoofing
aliases:
- 蓝牙键盘控车
- hi_my_name_is_keyboard
- HID 键盘仿冒
- 车机蓝牙未授权配对
- 蓝牙按键重放
- 蓝牙 PIN 爆破
tags:
- iot
- vehicle
- automotive
- bluetooth
- hid
- keyboard-injection
- unauthorized-pairing
- input-injection
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:42:57+08:00'
  notes: 已对照原文与图片30/32/34核对：hi_my_name_is_keyboard、Device Class 0x002540、L2CAP 19/17、按键重放一致；PoC 未复跑。
---

## 一句话结论

车机蓝牙作为 HID Host 允许无确认/无白名单地配对键盘设备时，攻击者用蓝牙网卡和 `hi_my_name_is_keyboard` 把自己伪装成蓝牙键盘，扫描到车机 MAC 后配对，即可向车机界面注入按键：切换页面、操作空调等车控功能，并可通过按键重放或爆破 PIN 进一步扩大影响。

## 原理

- **HID 键盘是被信任的输入设备**：车机把蓝牙键盘当作本地输入，按下按键产生的 HID report 直接进入系统输入队列，等价于有人在触摸屏/物理键盘上操作；系统不会区分“真键盘”和“攻击者伪造的键盘”。
- **配对策略过宽**：若车机处于可发现/可配对状态，且 HID Host 对键盘类设备不要求 PIN 确认、不做已配对设备白名单，攻击者可在蓝牙范围内发起配对并被接受；`bluetoothctl` 扫描可见车机 MAC 与设备信息。
- **工具自动化**：`hi_my_name_is_keyboard` 项目用蓝牙网卡注册 HID 键盘（Device Class `0x002540`），建立 L2CAP HID Control/Interrupt 通道，按脚本发送按键序列；原文日志显示成功连接 HID Control（L2CAP 19）与 HID Interrupt（L2CAP 17），并发送 payload。
- **为什么能控车**：车机 UI 的车控功能（空调、媒体、设置等）可以通过键盘方向键/回车导航触发；攻击者只需知道界面布局或通过截屏/观察反馈调整按键序列。
- **扩展**：按键可被录制重放；也可用于在车机输入框中尝试 PIN、ADB 授权码、root 密码等，形成“蓝牙键盘爆破”。

## 触发条件

- 目标车机蓝牙可被发现/配对，启用 HID Host（支持蓝牙键盘）。
- 配对过程无用户确认、无 PIN 显示确认，或攻击者可诱导用户确认。
- 车机 UI 的车控功能可通过键盘导航触达，且攻击者在蓝牙有效距离内。
- 攻击者具备支持 HCI 的蓝牙网卡（原文使用 BT+AC4600 类网卡）与 Linux 环境。

## 利用步骤

1. 用 `bluetoothctl` 或 `hcitool` 扫描，记录车机 MAC 地址与名称。
2. 克隆并运行 `hi_my_name_is_keyboard`，把本机注册为 HID 键盘设备（Device Class 0x002540），配置目标 MAC。
3. 发起配对/连接，确认 HID Control 与 HID Interrupt 通道建立（日志中出现 L2CAP 19/17 connected）。
4. 发送按键序列（方向键、Tab、Enter、音量/空调快捷键等），观察车机界面响应，逐步定位目标功能。
5. 录制成功操作序列做重放；或针对 PIN/密码输入框做字典/枚举尝试。
6. 记录配对信息与操作日志作为证据；测试结束解除配对并恢复车机设置。

## PoC

```bash
# 扫描车机蓝牙
bluetoothctl
[bluetooth]# scan on
# 记录目标 MAC，例如 00:60:37:41:32:2C

# 克隆工具并按项目说明配置目标 MAC 与按键脚本
git clone https://github.com/marcnewlin/hi_my_name_is_keyboard.git
cd hi_my_name_is_keyboard
# 运行项目脚本，注册 HID 键盘并连接目标（具体命令以项目 README 为准）
```

```text
# 原文日志关键行（示意）
connected to HID Control (L2CAP 19) on target
connected to HID Interrupt (L2CAP 17) on target
payload has been transmitted; disconnecting Bluetooth HID client
```

说明：原文在模拟车机上完成配对与按键发送，未展示具体按键序列与车控结果视频；工具用法以项目 README 为准，故 confidence 定为 medium。

## 变体与关联

- 变体：设备类别可伪装成键盘、鼠标、多媒体遥控器；鼠标可点击 UI，遥控器可触发媒体/音量快捷键。
- 变体：配对成功后保持长期连接，作为隐蔽的“无线键盘后门”；或结合按键重放绕过一次性 PIN。
- 变体：若车机同时暴露 ADB/串口，蓝牙键盘可用于输入授权码或触发调试菜单。
- 关联：[[iot-vehicle-camera-debug-console-20000-unauth]]（同一车机攻击面）、[[pentest-initial-access-usb-hid-keyboard-injection-powershell-scheduled-task]]（USB HID 键盘注入，原理同为 HID 输入信任）、[[mobile-android-apk-ble-native-modified-rc4-vin]]（车机 BLE 通信逆向）。
- 限制：需要蓝牙有效距离与可配对状态；量产车常要求配对确认或隐藏 HID Host，利用前需实测。

## 检测与防御

- 修复：车机默认关闭 HID Host 或要求配对确认/PIN；维护已配对设备白名单，拒绝未知键盘类设备。
- 加固：车控功能增加二次确认/驾驶员在场校验；敏感设置（ADB、恢复出厂、钥匙配对）要求物理操作或账号认证。
- 检测：车机蓝牙日志出现异常键盘设备配对、HID Control/Interrupt 连接后短时间内大量按键；UI 在无人操作时自行导航；配对列表出现未知设备。
- 响应：解除可疑配对、清理已配对列表、检查是否通过键盘输入开启过调试/ADB 功能。
