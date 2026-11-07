---
id: defense-forensics-ios-wifi-plist-nsdate-first-join
title: iOS Wi-Fi 取证：com.apple.wifi-private-mac-networks.plist 的 NSDate 首连时间与 SSID/热点名还原
type: scenario
domain: defense
path: defense/forensics
technique: ios-wifi-plist-nsdate-forensics
aliases:
- iOS Wi-Fi 取证
- com.apple.wifi-private-mac-networks.plist
- DeviceIdentityFetchDate
- 苹果 NSDate 换算
- 首次连接 Wi-Fi 时间
- 热点名称取证
tags:
- ios
- forensics
- wifi
- plist
- nsdate
- ssid
- mobile
- timeline
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:37+08:00'
  notes: 已对照原文与图14/18/42-46核对；NSDate 768535172.735564→2025-05-10 09:59:32 GMT+8；热点名=设备名iPhone；未复跑plist解析。
---

## 一句话结论

iOS 备份/全盘中的 `var/preferences/SystemConfiguration/com.apple.wifi-private-mac-networks.plist` 记录已扫描/连接的网络（SSID、BSSID、私密 MAC）以及 `DeviceIdentityInfo` 里的 `DeviceIdentityFetchDate`；该值是 Apple NSDate（自 2001-01-01 00:00:00 UTC 起的秒数），加上纪元即可换算首次连接时间（本例 `2025-05-10 09:59:32` GMT+8）。iOS 没有独立“热点名”配置，个人热点 SSID 就是设备名（本例 `iPhone`）。

## 原理

- iOS 将 Wi-Fi 配置保存在 `SystemConfiguration` 目录下的多个 plist：`com.apple.wifi.plist`、`com.apple.wifi-networks.plist.backup`、`com.apple.wifi-private-mac-networks.plist` 等。后者保存使用“私密 Wi-Fi 地址”（随机 MAC）的网络列表，数组元素包含 `BSSID` 与关联信息。
- 每个已加入网络还带 `DeviceIdentityInfo`（base64 包裹的 JSON/binary 数据），其中 `DeviceIdentityFetchDate` 表示设备在该网络首次取回网络身份的时间。取证工具/解析脚本把它作为“首次连接该 SSID 的时间”使用；本例值为 `768535172.735564`。
- Apple 的 NSDate 以 2001-01-01 00:00:00 UTC 为 0 点，换算公式为 `UTC = 2001-01-01 00:00:00 + 秒数`。`768535172.735564` 秒对应 UTC `2025-05-10 01:59:32`，即 GMT+8 `2025-05-10 09:59:32`；若把 NSDate 当作 Unix 时间（1970 纪元）会得到错误年份。
- Wi-Fi 记录同时保存 SSID、最后连接时间、BSSID/MAC、加密类型、信号强度等；网络密码（iOS 称“登入金钥”）也在 plist/钥匙串相关记录中，可用于还原连接配置。
- 个人热点：iOS 不允许单独设置“热点名”，热点 SSID 随设备名（设置-通用-关于本机-名称）变化，因此热点名称可从设备名属性/偏好 plist 得到；本例设备名为 `iPhone`，热点名即 `iPhone`。
- 时间线价值：首次/最后连接时间可与行程、聊天、照片 EXIF 交叉定位设备位置与使用时段；SSID 与 BSSID 还能关联路由器/场所。

## 触发条件

- 已获取 iOS 全盘镜像或未加密/已解密的备份，能读取 `var/preferences/SystemConfiguration/` 下的 plist。
- 需要回答“连接过哪些 Wi-Fi、首次/最后连接时间、SSID/BSSID、密码、热点名”等问题。
- plist 未被删除或覆盖；`com.apple.wifi-networks.plist.backup` 可作为补充证据。
- 具备 plist 解析工具（plutil、PlistEdit Pro、取证工具）与 NSDate 换算脚本。
- 取证已获授权并保持证据完整性。

## 利用步骤

1. 在镜像/备份中定位 Wi-Fi 配置文件：

```text
var/preferences/SystemConfiguration/com.apple.wifi-private-mac-networks.plist
var/preferences/SystemConfiguration/com.apple.wifi.plist
var/preferences/SystemConfiguration/com.apple.wifi-networks.plist.backup
var/preferences/SystemConfiguration/preferences.plist
```

2. 用 `plutil -p` 或取证工具查看结构：`List of scanned networks with private mac` 数组、每个网络的 `BSSID`，以及 `DeviceIdentityInfo` 字段。
3. 解码 `DeviceIdentityInfo`（base64 → JSON/二进制 plist），取出 `DeviceIdentityFetchDate`。
4. 按 Apple 纪元换算：`datetime(2001,1,1) + timedelta(seconds=768535172.735564)` → UTC `2025-05-10 01:59:32` → GMT+8 `2025-05-10 09:59:32`。脚本示例：

```python
from datetime import datetime, timedelta, timezone
apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
utc = apple_epoch + timedelta(seconds=768535172.735564)
print(utc.isoformat(), utc.astimezone(timezone(timedelta(hours=8))).isoformat())
```

5. 枚举所有网络记录，按最后连接时间排序，区分已连接与仅扫描；本例检材连接过 2 个网络（`iPhone(2)`、`wanchai`），最早的非热点连接为 `2025-04-15 19:29:29`，SSID 为 `wanchai`，并可从记录中读出对应的登入金钥（以 base64 形式保存）。
6. 热点名：读取设备名/偏好设置（本例设备名 `iPhone`），确认热点 SSID 与设备名一致；不要把“热点名”当作独立的 plist 键。
7. 交叉验证：用最后连接时间与照片 EXIF、聊天记录、Safari 历史比对；对关键记录计算文件哈希并截图存档。

## PoC

```bash
# 列出 Wi-Fi 相关 plist 并查看内容
plutil -p com.apple.wifi-private-mac-networks.plist
plutil -p com.apple.wifi.plist
```

```python
from datetime import datetime, timedelta, timezone

def nsdate_to_local(seconds, tz_hours=8):
    base = datetime(2001, 1, 1, tzinfo=timezone.utc)
    utc = base + timedelta(seconds=float(seconds))
    local = utc.astimezone(timezone(timedelta(hours=tz_hours)))
    return utc, local

print(nsdate_to_local(768535172.735564))
# (2025-05-10 01:59:32+00:00, 2025-05-10 09:59:32+08:00)
```

原文检材中该值对应首次连接 `CMHK` 的时间 `2025-05-10 09:59:32`（GMT+8）；另一检材 `FUNG_CC` 的最早非热点连接为 `wanchai`（`2025-04-15 19:29:29`）。本卡方法未在本库复跑，且不同 iOS 版本 plist 键名/位置可能变化。

## 变体与关联

- 键名变体：部分版本把网络列表放在 `com.apple.wifi.plist` 或 `com.apple.wifi-networks.plist.backup`，需同时检查；`DeviceIdentityFetchDate` 可能位于 base64 包裹的嵌套数据中。
- 时间变体：其他 plist 字段可能是 Unix 时间或字符串时间，不能一律按 NSDate 处理；先确认键的类型与单位。
- 关联卡：iOS 备份口令/plist 提取（`defense-forensics-ios-encrypted-backup-pin-bruteforce-plist`）；iOS 照片库溯源（`defense-forensics-ios-photos-sqlite-airdrop-origin`）。
- 注意：SSID/BSSID 与密码属于敏感信息，报告中按需脱敏；BSSID 的随机化与私密 MAC 功能会影响“同一路由器”的关联判断。

## 检测与防御

- 取证规范：对 plist 及其所在目录做哈希；同时提取 `com.apple.wifi.plist` 与备份文件，避免单一文件被系统重写导致缺失；记录解析工具版本与换算脚本。
- 时间解释：明确标注 NSDate 纪元（2001-01-01 UTC）与展示时区（GMT+8），报告中保留原始秒数与换算结果，便于复核。
- 数据校验：用多个字段（最后连接时间、BSSID、SSID 大小写）交叉验证；对“首次连接”结论注明依据字段，避免把扫描记录误判为连接记录。
- 隐私合规：Wi-Fi 密码、位置与 BSSID 属于个人数据，最小化提取并脱敏；证据移交保持链式保管。
- 防御视角：企业可通过 MDM 限制个人热点与不受控 Wi-Fi，终端日志集中采集 SSID/BSSID 以支持事件溯源。
