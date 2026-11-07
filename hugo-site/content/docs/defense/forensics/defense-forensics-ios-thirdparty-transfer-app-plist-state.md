---
id: defense-forensics-ios-thirdparty-transfer-app-plist-state
title: iOS 第三方文件传输 App 取证：Paprika（com.estmob.paprika）偏好 plist 设备标识与状态枚举判定传输方向
type: scenario
domain: defense
path: defense/forensics
technique: ios-thirdparty-transfer-app-prefs-forensics
tags:
- ios
- forensics
- plist
- file-transfer
- paprika
- mobile
- data-exfiltration
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:39+08:00'
  notes: 已对照原文与图24-30核对；修正bundle归属（com.estmob.paprika为Paprika，SHAREit为com.lenovo.anyshare，原文将二者分列）；deviceId/deviceName/SEND_PAPRIKA/Samsung对端一致；未复跑。
url: /docs/defense/forensics/defense-forensics-ios-thirdparty-transfer-app-plist-state/
draft: false
kb_aliases:
- 第三方快传 App 取证
- Paprika 取证
- com.estmob.paprika
- group.com.estmob.paprika.plist
- iOS 文件传输 App 取证
- PAPRIKA_STATE 枚举
---

## 一句话结论

iOS 第三方文件传输 App（本例 bundle `com.estmob.paprika`，即 Paprika 文件传输 App；同检材另见 `com.lenovo.anyshare`/SHAREit 与 AirDrop）把本机身份写在 App Group 偏好 plist `group.com.estmob.paprika.plist`：`deviceId`、`deviceName`、`kPN` 等键可确定发送设备；传输记录中的二进制状态枚举（如 `SEND_PAPRIKA`、`PAPRIKA_STATE_TRANSFERRING`、`PAPRIKA_DETAILED_STATE_FINISHED_SUCCESS`）可判定是“发送/标准模式”还是其他模式，再结合对端设备名即可确定发送方/接收方与传输方向。

## 原理

- iOS 应用数据位于 `var/mobile/Containers/Data/Application/<UUID>/`；应用可通过 App Group 共享偏好 plist，路径通常是 `Library/Preferences/group.<bundle-id>.plist`。该 plist 不随应用删除立即消失，常保留设备名、设备 ID、迁移标记与统计计数。
- `com.estmob.paprika` 的偏好中包含 `deviceId`（本例 `3836403626142`）、`deviceName`（本例 `Apple iPhone11,6`）、`kPN`（产品名，本例 `iPhone`）、`kSTA`、`migrated`、`migratedDB`、`myDeviceDiscoverable`、`accumulativeTransferCount`（本例 2）等键；这些值足以把一次传输记录绑定到本机。
- 传输记录/状态数据（二进制 plist、SQLite 或自定义序列化）中保留状态枚举字符串：`PAPRIKA_DETAILED_STATE_TRANSFERRING_START_NEW_FILE`、`PAPRIKA_DETAILED_STATE_FINISHED_SUCCESS`、`PAPRIKA_STATE_TRANSFERRING`、`PAPRIKA_STATE_FINISHED`。出现 `SEND_PAPRIKA` 一类状态说明走的是 Paprika 标准发送模式，而非 `DIRECT`、`CLOUD`、`BLUETOOTH` 模式。
- 传输方向不能只看状态名：要用本机 `deviceId`/`deviceName` 与传输记录中的对端设备名（本例对端 `Samsung SM-G930F`）比较；本机是发送端时状态为 SEND，接收端则出现接收/完成状态。
- 文件类型可由传输记录中的文件名/扩展名判断（本例为屏幕截图）；与相册、聊天记录交叉可确认外发内容。
- 这类 App 常见于跨平台“换机/快传”，也是数据外带的便捷通道；取证价值在于恢复“谁把什么文件传给了哪台设备、何时、用什么模式”。

## 触发条件

- 已获得 iOS 全盘镜像/备份，包含第三方 App 的 Data 容器与 App Group 偏好。
- 目标 App 已安装并实际使用过文件传输（`accumulativeTransferCount` 大于 0，或存在传输历史记录）。
- 偏好 plist/状态数据未被删除或覆盖；二进制 plist 可用 strings/十六进制工具读取枚举。
- 需要回答“哪个 App 传输了文件、本机是发送方还是接收方、发给了什么设备、用了什么模式”。
- 取证已获授权并保持证据链。

## 利用步骤

1. 定位应用容器：在镜像中按 bundle id 搜索 `com.estmob.paprika`，通常位于 `var/mobile/Containers/Data/Application/<UUID>/`；通过 `Library/Preferences/` 下的 plist 与应用元数据确认 bundle。
2. 读取 App Group 偏好：

```text
.../Library/Preferences/group.com.estmob.paprika.plist
```

用 `plutil -p` 或取证工具查看 `deviceId`、`deviceName`、`kPN`、`accumulativeTransferCount`、`myDeviceDiscoverable` 等键。
3. 在容器内（Preferences、Documents、Library/Application Support 以及相关数据库）搜索传输历史；按文件名、时间、对端设备名筛选。
4. 对二进制 plist/数据库做 `strings` 或十六进制搜索，提取 `PAPRIKA_*` 状态枚举；本例解出 `PAPRIKA_DETAILED_STATE_TRANSFERRING_START_NEW_FILE`、`PAPRIKA_DETAILED_STATE_FINISHED_SUCCESS`、`PAPRIKA_STATE_TRANSFERRING`、`PAPRIKA_STATE_FINISHED`，并出现 `SEND_PAPRIKA`，判定为标准发送模式。
5. 读取传输记录的对端设备名（本例 `Samsung SM-G930F`），与本机 `deviceName` 对比，确认本机是发送方（状态为发送/完成，且对端为接收设备）。
6. 结合文件名/扩展名判断内容类型（本例为屏幕截图），并与照片库、聊天记录的时间线交叉验证。
7. 记录 plist 哈希、键值截图、状态字符串偏移与解析结果，报告中注明“枚举语义由字符串推断”的限制。

## PoC

```bash
# 查看 App Group 偏好
plutil -p group.com.estmob.paprika.plist | grep -iE "device|transfer|kPN|kSTA"

# 提取传输状态枚举（二进制 plist/数据库均可）
strings -a group.com.estmob.paprika.plist | grep -i PAPRIKA
```

原文检材中偏好显示：`deviceId = 3836403626142`、`deviceName = Apple iPhone11,6`、`accumulativeTransferCount = 2`；传输记录状态枚举包含 `SEND_PAPRIKA` 与 `PAPRIKA_STATE_FINISHED`，对端设备为 `Samsung SM-G930F`，据此判定本机为发送方、采用 Paprika 标准模式传输了一个屏幕截图文件。本卡未在本库复跑，App 不同版本的 plist 键名与状态枚举可能变化。

## 变体与关联

- 同类 App：SHAREit、Zapya、Send Anywhere、LocalSend 等均会在偏好/数据库中保存设备 ID、设备名、传输历史与状态枚举；可套用同一思路，但键名与路径不同。
- 传输模式变体：`DIRECT`、`CLOUD`、`BLUETOOTH` 等模式的状态字符串不同，需结合枚举定义判断，不能仅凭“出现 SEND”就认定发送。
- 关联卡：iOS 照片库 AirDrop 溯源（`defense-forensics-ios-photos-sqlite-airdrop-origin`）；iOS Wi-Fi 取证（`defense-forensics-ios-wifi-plist-nsdate-first-join`）；iOS 备份口令与 plist（`defense-forensics-ios-encrypted-backup-pin-bruteforce-plist`）。
- 注意：偏好 plist 的 `deviceName` 是应用记录的设备名，可能因换机/迁移与应用实际名称不一致；需与系统设备名、序列号/UDID 交叉验证。

## 检测与防御

- 取证规范：复制 App 容器时保留 `Library/Preferences` 全部 plist 与 `-wal/-shm` 文件；对 plist/数据库计算哈希；用只读方式解析。
- 解释限制：状态枚举来自二进制数据，需结合 App 版本/反编译或官方文档确认语义；报告中区分“直接键值证据”与“枚举推断”。
- 隐私合规：传输历史可能包含文件名、联系人/设备名等个人数据，最小化提取并脱敏。
- 防御视角：企业通过 MDM 限制或禁用第三方快传/文件传输 App，使用 DLP 监控大文件外发；终端侧记录 App 安装与网络行为，便于事件溯源。
- 事件响应：发现可疑外发时，结合 Wi-Fi/BSSID、传输时间、对端设备名与文件哈希还原数据流向，并评估是否需要通知数据主体。
