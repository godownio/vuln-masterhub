---
id: defense-forensics-ios-encrypted-backup-pin-bruteforce-plist
title: iOS 加密备份口令离线爆破与 plist/sysdiagnose 元数据提取：4 位 PIN、序列号与蓝牙 MAC
type: scenario
domain: defense
path: defense/forensics
technique: ios-encrypted-backup-pin-bruteforce-plist-forensics
tags:
- ios
- forensics
- backup
- plist
- bruteforce
- sysdiagnose
- mobile
- password-recovery
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T02:03:53+08:00'
  notes: 已对照原文第17-24题与图44-53核对：Recover File Password 对 Manifest.plist 爆破 4 位数字，10,000 候选、3 分 26 秒命中 1111；Manifest.plist Date=2026-09-23T07:02:50Z、SerialNumber=FD2W71HJCMO、IsEncrypted=true；sysdiagnose 中 bluetooth_status.txt 的 MAC=00:A5:3B:82:06:E0，BatteryBDC/*.csv、mobile_installation.log.1、powerlog_*.PLSQL 均存在且对应电量/安装/解锁记录。卡片与原文一致；未复跑爆破与解析（无备份/日志附件）；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/defense/forensics/defense-forensics-ios-encrypted-backup-pin-bruteforce-plist/
draft: false
kb_aliases:
- iOS 备份密码爆破
- iTunes 备份口令恢复
- Manifest.plist 解密
- 4 位备份密码
- iOS 手机取证
- sysdiagnose 取证
---

## 一句话结论

iOS 的 iTunes/Finder 加密备份把密钥包裹在 `Manifest.plist` 的 BackupKeyBag 中，备份口令只用于解包；若用户把备份口令设成 4 位数字，攻击者/取证方可以在离线环境穷举 10,000 种组合恢复口令，解密备份后从 plist 与 sysdiagnose 日志中提取备份时间、设备序列号、蓝牙 MAC、应用安装/电量/解锁记录。

## 原理

- iOS 备份目录通常包含 `Manifest.plist`、`Info.plist`、`Status.plist` 与大量哈希命名文件。`Manifest.plist` 的 `IsEncrypted` 为 `true` 时，备份文件用备份口令派生的密钥加密，`BackupKeyBag` 保存包裹后的类密钥。
- 备份口令由用户在 iTunes/Finder 中单独设置，和设备解锁密码不是同一个；它可以是 4 位数字，也可以是复杂密码。4 位数字只有 10,000 种组合，离线爆破成本极低；复杂口令则不可行。
- 口令恢复工具（如 Recover File Password、iphone-dataprotection 等）读取 `Manifest.plist`，对候选口令做 KDF 并尝试解包 BackupKeyBag；命中后即可用该口令解密备份文件。
- 解密后可读取的元数据包括：备份日期（`Manifest.plist`/`Status.plist`）、设备名称/型号/产品类型/iOS 版本/序列号/UDID（`Info.plist`/`Manifest.plist`）、已安装应用与文件清单。
- 设备 sysdiagnose 日志（`sysdiagnose_*.tar`）还包含 `logs/Bluetooth/BluetoothCoreCapture/bluetooth_status.txt`（蓝牙 Power/MAC Address）、`logs/BatteryBDC/*.csv`（电池充电记录）、`logs/MobileInstallation/mobile_installation.log`（应用安装时间）、`powerlog_*.PLSQL`（电量/屏幕/解锁事件）等；两者结合可还原设备使用时间线。
- 本例中备份口令为 `1111`，工具在约 3 分 26 秒内分析 10,000 个候选后命中；随后从 plist/日志读出备份日期 `2026-09-23 07:02:50`、序列号 `FD2W71HJCMO`、蓝牙 MAC `00:A5:3B:82:06:E0` 等。

## 触发条件

- 已获取 iOS 备份目录（iTunes/Finder 备份或取证镜像中的备份）。
- 备份为加密备份（`Manifest.plist` 中 `IsEncrypted=true`），且口令为弱口令（如 4 位数字）。
- 有可离线运行的口令恢复工具与足够算力；4 位数字通常几分钟内完成。
- 已获取设备 sysdiagnose 或备份内的日志文件，用于提取元数据。
- 取证/分析已获授权，遵守隐私与合规要求。

## 利用步骤

1. 定位备份目录：找到 `Manifest.plist`、`Info.plist`、`Status.plist`；用 `plutil -p Manifest.plist` 查看 `IsEncrypted`、`BackupKeyBag`、`Date`、`Lockdown` 等字段。
2. 确认口令策略：若题目/线索表明是 4 位数字，直接穷举 0000–9999；若不是，先评估字典/规则。
3. 离线爆破：用 Recover File Password 等工具加载 `Manifest.plist`，选择 4 位数字掩码，运行至命中（本例 `1111`，约 3 分 26 秒、10,000 候选）。
4. 解密备份：用恢复出的口令在 iTunes/Finder 或取证工具中解密备份；导出 `Info.plist`、`Manifest.plist`、应用数据与日志。
5. 提取元数据：`plutil -p` 或 Python `plistlib` 读取备份日期、设备型号、iOS 版本、序列号、UDID；从 sysdiagnose 的 `bluetooth_status.txt` 读蓝牙 MAC，从 `mobile_installation.log` 读应用安装时间，从 `powerlog_*.PLSQL`/`BatteryBDC/*.csv` 读电量、充电与屏幕解锁事件。
6. 时间线关联：把备份时间、安装时间、首次解锁、充电 100% 时间等按 UTC/UTC+8 统一，交叉验证设备活动。
7. 记录与保全：对原始备份与 plist 计算哈希，保留解密前后副本，记录工具版本与口令恢复日志。

## PoC

```bash
# 查看备份清单（macOS）
plutil -p Manifest.plist | grep -E 'IsEncrypted|Date|Serial|Product|BuildVersion'
plutil -p Info.plist   | grep -E 'Device Name|Product Type|Product Version|Serial Number|Unique Identifier'

# 查看 sysdiagnose 中的蓝牙状态
tar -tf sysdiagnose_*.tar | grep -i bluetooth
tar -xOf sysdiagnose_*.tar '*/bluetooth_status.txt'
# 输出示例：
# Power        : On
# MAC Address  : 00:A5:3B:82:06:E0

# 查看应用安装日志
tar -xOf sysdiagnose_*.tar '*/mobile_installation.log.1' | grep -i 'Installed'
```

```python
import plistlib
with open("Manifest.plist", "rb") as f:
    m = plistlib.load(f)
print(m.get("IsEncrypted"), m.get("Date"), m.get("Lockdown", {}).get("SerialNumber"))
```

口令爆破使用支持 iTunes 备份的工具（如 Recover File Password）加载 `Manifest.plist`，设置 4 位数字掩码；PoC 未在本机执行，工具与耗时因环境而异。

## 变体与关联

- 变体：备份口令为 6 位数字、生日、字典词；可用掩码/字典/规则扩展，但复杂度上升。
- 变体：iCloud 备份与本地备份的密钥体系不同；本卡针对本地 iTunes/Finder 加密备份。
- 变体：即使备份未加密，`Manifest.plist`/`Info.plist` 与 sysdiagnose 仍可提供设备序列号、安装记录与日志；加密只保护文件内容。
- 关联卡片：[[defense-forensics-chromium-artifact-offline-decrypt]]（离线解析加密应用数据）、[[mobile-android-sqlcipher-static-key-derivation]]（Android 应用数据库静态解密）、[[defense-forensics-sqlcipher-im-db-memory-key-extraction]]（SQLCipher 内存密钥提取）。
- 注意：备份口令恢复只适用于用户设置的弱备份口令；设备锁屏密码、Secure Enclave 保护的密钥不在本卡范围。

## 检测与防御

- 防御：iOS 备份使用强字母数字口令，避免 4/6 位数字；不要在不受信任的电脑上勾选“加密备份”并保存口令。
- 防御：企业环境用 MDM 限制本地备份/要求加密与强口令；备份介质加密并限制访问；定期轮换备份口令。
- 检测（取证侧）：备份目录存在 `Manifest.plist` 且 `IsEncrypted=true`；`BackupKeyBag` 结构完整；sysdiagnose 含 `bluetooth_status.txt`、`powerlog_*.PLSQL`、`mobile_installation.log`。
- 检测（防御侧）：监控对备份目录的批量读取/复制；对异常的口令恢复工具运行、CPU 长时间满载等行为告警。
- 响应：确认备份泄露范围，评估其中个人信息/凭据，按合规流程通知与轮换相关账号；加强备份口令策略。
