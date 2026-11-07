---
id: defense-forensics-localsend-config-precise-timestamp
title: LocalSend 传输时间取证：GUI 只显示到分钟时从 settings.json/FlutterSharedPreferences 取秒级时间戳
type: scenario
domain: defense
path: defense/forensics
technique: localsend-config-history-timestamp
aliases:
- LocalSend 取证
- 局域网传输记录
- settings.json receive_history
- FlutterSharedPreferences 取证
- GUI 时间精度不足
- 秒级时间戳恢复
tags:
- forensics
- localsend
- flutter
- configuration
- timestamp
- file-transfer
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:06:39+08:00'
  notes: 已对照原文与图片 35-39 核对；Research.tar (1) 历史、settings.json 的 timestamp 换算 UTC+8 后 2026-07-10 14:38:03 一致
---

## 一句话结论

LocalSend 的传输历史界面只把时间显示到分钟，但 Windows 端 `settings.json` 与 Android 端 `FlutterSharedPreferences.xml` 中保存了带时区/毫秒的完整时间戳；案例中界面显示 `2026-07-10 14:38`，配置里对应 `2026-07-10T06:38:03.8...Z`（UTC），换算本地时区后得到精确答案 `2026-07-10 14:38:03`。

## 原理

- LocalSend 是 Flutter 应用，Windows 版配置在 `%USERPROFILE%\scoop\apps\localsend\<version>\settings.json`（或其他安装方式的对应目录），Android 版在 `/data/user/0/org.localsend.localsend_app/shared_prefs/FlutterSharedPreferences.xml`。
- 配置中的 `flutter.receive_history` 是一个 JSON 字符串数组，每个元素包含 `fileName`、`fileSize`、`senderAlias`、`timestamp`、`path`、`savedToGallery` 等字段；`timestamp` 是带时区的 ISO 8601 时间（通常为 UTC），精度到毫秒/秒。
- 界面层为了简洁只渲染到分钟，导致“界面时间”与“配置文件时间”不一致；取证时应以配置/数据库中的原始时间戳为准，并做 UTC→本地时区换算。
- Android 端的历史可能因删除、清理或应用未同步而不完整；若 Windows 端配置仍在，优先从 Windows 端恢复。案例中 Android 端历史没有目标文件，而 Windows 端 `settings.json` 保留了对应记录。
- 文件快捷方式（`Recent/*.lnk`）的创建时间可能早于/晚于传输完成时间，只能作为辅助线索，不能替代配置中的业务时间戳。

## 触发条件

- 目标主机安装了 LocalSend（Windows/Linux/macOS/Android），且配置/历史未被清除。
- 能读取应用安装目录、用户配置目录或手机应用私有目录/备份。
- 已知待查文件名或大致时间范围，用于在 `receive_history` 中定位记录。
- 需要按检材原始时区回答时，知道系统时区设置（案例为 UTC+8）。

## 利用步骤

1. 定位 LocalSend 安装/配置目录：Windows 常见 `scoop/apps/localsend/<version>/settings.json`；Android 为应用私有目录下的 `shared_prefs/FlutterSharedPreferences.xml`。
2. 在配置中搜索目标文件名（如 `Research.tar`），截取对应 `receive_history` 元素。
3. 读取 `timestamp` 字段的完整 ISO 8601 值，确认时区（`Z` 表示 UTC）。
4. 按检材时区换算为本地时间；案例 UTC `06:38:03` + 8 小时 = `14:38:03`。
5. 与界面显示、文件系统时间、`.lnk` 快捷方式时间交叉验证；若不一致，以配置中的业务时间戳为主，并记录差异原因。
6. 固定 `settings.json`/XML 文件哈希与记录行号，形成证据链。

## PoC

```json
// settings.json 中的 receive_history 元素（案例，节选）
{
  "fileName": "Research.tar (1)",
  "fileSize": 32490960,
  "senderAlias": "wang phone",
  "timestamp": "2026-07-10T06:38:03.8...Z",
  "path": "C:\\Users\\Wang\\Downloads\\Research.tar (1)",
  "savedToGallery": false
}
```

```bash
# Windows：在 settings.json 中定位目标文件并提取时间戳
rg -n -C 3 'Research.tar' "$USERPROFILE/scoop/apps/localsend/1.17.0/settings.json"

# Android 备份：查看 FlutterSharedPreferences.xml 中的接收历史
rg -n -C 2 'receive_history|Research.tar' FlutterSharedPreferences.xml

# 时间换算（UTC -> UTC+8）
python -c "from datetime import datetime,timezone,timedelta; print(datetime.fromisoformat('2026-07-10T06:38:03.800+00:00').astimezone(timezone(timedelta(hours=8))))"
```

说明：案例答案为 `2026-07-10 14:38:03`（UTC+8）；界面仅显示 `2026-07-10 14:38`。

## 变体与关联

- 变体：其他 Flutter 桌面应用也使用 `shared_preferences`/`settings.json` 保存历史，界面可能截断精度；取证时优先读原始配置。
- 变体：Android 端 `FlutterSharedPreferences.xml` 中的历史可能缺少已删除记录，需同时检查 Windows 端、日志、下载目录与文件系统时间。
- 变体：传输记录中的 `senderAlias`（如 `wang phone`）可用于关联发送设备，结合手机端 LocalSend 配置确认同一文件。
- 关联：[[defense-forensics-obsidian-livesync-config-credential-recovery]]（同为应用配置取证）、[[defense-forensics-multisource-timeline-log-clear]]（多源时间线）。

## 检测与防御

- 防御：对传输历史中的敏感文件名/路径做清理；在共享设备上定期清除 LocalSend 历史与下载目录。
- 防御：应用层显示时间不应作为唯一审计依据，日志/配置应保留完整时间戳与时区。
- 检测：取证时检查 LocalSend 安装目录、`settings.json`、`FlutterSharedPreferences.xml`、下载目录与 `Recent/*.lnk`；对文件名做全盘搜索。
- 响应：固定配置与文件时间证据，注意 UTC/本地时区换算；若涉及敏感文件外传，结合网络日志与接收端记录还原传输链路。
