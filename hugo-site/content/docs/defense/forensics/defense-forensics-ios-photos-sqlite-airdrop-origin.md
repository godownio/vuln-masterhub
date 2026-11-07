---
id: defense-forensics-ios-photos-sqlite-airdrop-origin
title: iOS 照片库 Photos.sqlite 溯源：ZASSET 关联导入来源判定 AirDrop、原始文件名与拍摄 App
type: scenario
domain: defense
path: defense/forensics
technique: ios-photos-sqlite-import-origin-forensics
tags:
- ios
- forensics
- photos
- sqlite
- airdrop
- exif
- quicktime
- timeline
- mobile
cve: []
severity: medium
confidence: medium
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/defense/forensics/defense-forensics-ios-photos-sqlite-airdrop-origin/
draft: false
kb_aliases:
- Photos.sqlite 取证
- ZASSET 查询
- ZIMPORTEDBYBUNDLEIDENTIFIER
- AirDrop 传输取证
- iOS 照片原始文件名
- com.apple.sharingd
- QuickTime software 元数据
---

## 一句话结论

在 iOS 全盘/备份镜像里，`Photos.sqlite` 的 `ZASSET` 与 `ZADDITIONALASSETATTRIBUTES` 通过 `ZADDITIONALATTRIBUTES = Z_PK` 关联；`ZIMPORTEDBYBUNDLEIDENTIFIER` 记录资产由哪个 bundle 导入，值为 `com.apple.sharingd` 即为 AirDrop 接收，配合 `ZFILENAME`/`ZUNIFORMTYPEIDENTIFIER` 和文件时间可确定传输的文件与时刻；再用聊天记录或 QuickTime 的 `com.apple.quicktime.software` 元数据，可还原被重命名前的原始文件名和拍摄/处理 App。

## 原理

- `Photos.sqlite` 是 iOS 照片库的 Core Data 数据库。`ZASSET` 每行代表一个照片/视频资产，`ZADDITIONALASSETATTRIBUTES` 保存该资产的附加属性（导入来源、原始文件名、导入时间等），两者通过 `ZASSET.ZADDITIONALATTRIBUTES` 指向 `ZADDITIONALASSETATTRIBUTES.Z_PK` 关联。
- `ZADDITIONALASSETATTRIBUTES.ZIMPORTEDBYBUNDLEIDENTIFIER` 是“由哪个应用/服务导入”的 bundle id：`com.apple.sharingd` 是 AirDrop 的守护进程，因此该值等于 `com.apple.sharingd` 的资产就是从 AirDrop 接收的文件；`com.apple.mobileslideshow`/相机等则是本机拍摄或照片 App 导入。
- `ZASSET.ZFILENAME` 是照片库中的文件名（通常被重命名为 `IMG_xxxx`），`ZUNIFORMTYPEIDENTIFIER` 给出 UTI（如 `com.apple.quicktime-movie` 表示视频），两者结合可判断传输文件类型。
- 文件时间（取证件中的修改/导入时间）对应 AirDrop 开始/完成传输的时刻；相册中的“屏幕快照”是独立的媒体子类型/分类，可按该分类统计；`cloudCache`/`idMapping` 等云端缓存记录则反映曾同步到 iCloud 的资产数量。
- 照片进入相册后常被重命名，原始文件名可能只保留在来源应用（微信/WhatsApp 等）的文件记录或系统文件中；把照片库时间线与聊天附件按同一时刻、大小/哈希对齐，就能恢复原名（本例 `IMG_0079.JPG` 对应原始 `5005.JPG`，同一时刻还有一条即时通讯图片消息）。
- 对视频/实况照片，QuickTime 元数据中的 `com.apple.quicktime.software` 键记录生成该文件的 App 名称；图片本身没有水印时，可用同风格、同时间段的 MOV 文件反推拍摄 App（本例为 `infltr`）。

## 触发条件

- 已获得 iOS 全盘镜像、iTunes/Finder 备份或取证工具解析后的文件系统（`Photos.sqlite` 可读；加密备份需先解密）。
- 具备 SQLite 查询能力或支持原生数据库解析的取证工具（如火眼、DB Browser for SQLite）；能读取关联的应用数据目录（聊天附件、Preferences 等）。
- 需要回答“某文件是否经 AirDrop 传入、原文件名是什么、由哪个 App 产生、何时传入”等问题。
- 取证过程已获授权，并保证镜像哈希与证据链完整。

## 利用步骤

1. 定位照片库数据库：全盘镜像通常在 `var/mobile/Media/PhotoData/Photos.sqlite`；备份中为 `HomeDomain/Library/Photos/...` 下的数据库。先做 `PRAGMA integrity_check;` 并记录哈希。
2. 确认 AirDrop 导入数量：

```sql
SELECT COUNT(*) AS AirDrop_Total
FROM ZASSET AS a
JOIN ZADDITIONALASSETATTRIBUTES AS aa
  ON a.ZADDITIONALATTRIBUTES = aa.Z_PK
WHERE aa.ZIMPORTEDBYBUNDLEIDENTIFIER = 'com.apple.sharingd';
```

3. 列出 AirDrop 传入的文件名与类型：

```sql
SELECT a.ZFILENAME, a.ZUNIFORMTYPEIDENTIFIER, aa.ZIMPORTEDBYBUNDLEIDENTIFIER
FROM ZASSET AS a
JOIN ZADDITIONALASSETATTRIBUTES AS aa
  ON a.ZADDITIONALATTRIBUTES = aa.Z_PK
WHERE aa.ZIMPORTEDBYBUNDLEIDENTIFIER = 'com.apple.sharingd';
```

本例结果为 1 条：`IMG_0084.MOV`、`com.apple.quicktime-movie`、`com.apple.sharingd`，即只通过 AirDrop 传输了一个视频文件。
4. 读取该资产的修改/导入时间：原文取证工具显示 `IMG_0084` 对应记录修改时间为 `2025-04-20 16:46:30`，作为开始传送时间。注意 Core Data 时间戳以 2001-01-01 UTC 为纪元，若直接查库需做 `2001-01-01 + 秒数` 换算并按 GMT+8 呈现。
5. 统计截图与 iCloud 资产：按相册的“屏幕快照”分类/媒体子类型过滤，本例 15 张；查看 `cloudCache`、`idMapping` 等云端缓存表，本例各 90 条，对应 90 个曾存到 iCloud 的图片。不同 iOS 版本的内部表名可能不同，以实际 schema 为准。
6. 恢复原始文件名：在文件系统/聊天应用数据中搜索同一时间点（本例 `2025-04-16 16:14:35`）的文件记录，发现照片 `IMG_0079.JPG`、文件 `5005.JPG` 与一条即时通讯图片消息同时出现，结合大小/哈希确认 `5005.JPG` 为原始文件名。
7. 判定拍摄 App：用 010 Editor/exiftool/ffprobe 查看 MOV 的 QuickTime metadata，搜索 `com.apple.quicktime.software`；本例得到 `infltr`。对无元数据的 GIF（`IMG_0057.GIF`、`IMG_0062.GIF`），用风格相同、同时间段的 MOV 推断由同一 App 拍摄/生成。
8. 将上述证据（SQL 查询结果、文件哈希、时间线、元数据截图）写入取证报告，区分“直接证据”和“推断”（例如由相邻视频推断 GIF 来源属于推断）。

## PoC

最小查询链（SQLite）：

```sql
-- 1) 哪些资产由 AirDrop 导入
SELECT a.ZFILENAME, a.ZUNIFORMTYPEIDENTIFIER, aa.ZIMPORTEDBYBUNDLEIDENTIFIER
FROM ZASSET AS a
JOIN ZADDITIONALASSETATTRIBUTES AS aa
  ON a.ZADDITIONALATTRIBUTES = aa.Z_PK
WHERE aa.ZIMPORTEDBYBUNDLEIDENTIFIER = 'com.apple.sharingd';

-- 2) 数量
SELECT COUNT(*) FROM ZASSET AS a
JOIN ZADDITIONALASSETATTRIBUTES AS aa
  ON a.ZADDITIONALATTRIBUTES = aa.Z_PK
WHERE aa.ZIMPORTEDBYBUNDLEIDENTIFIER = 'com.apple.sharingd';
```

QuickTime 软件标识（等价于原文 010 Editor 手工查看）：

```bash
exiftool -G1 -a target.MOV | grep -i "software\|quicktime"
# 或在 010 Editor 中搜索 ASCII "com.apple.quicktime.software"
```

原文 `Photos.sqlite` 的 AirDrop 查询返回 `IMG_0084.MOV`；截图计数 15、iCloud 图片 90、原始文件名 `5005.JPG` 均来自同一检材的取证工具统计与时间线关联。该方法未在本库复跑，且不同 iOS 版本的表结构可能变化。

## 变体与关联

- 来源 bundle 变体：`com.apple.mobileslideshow`（照片 App/相机胶卷）、`com.apple.MobileSMS`（信息附件）、微信/WhatsApp 等第三方 App 导入；把 `ZIMPORTEDBYBUNDLEIDENTIFIER` 换成目标 bundle 即可统计其他来源。
- 文件类型变体：`ZUNIFORMTYPEIDENTIFIER` 可区分 `public.jpeg`、`public.heic`、`com.apple.quicktime-movie` 等；实况照片需同时看图片与 MOV 配对。
- 删除恢复：`Photos.sqlite` 的 freelist/空闲页可能保留已删除资产记录，见 `ctf-forensics-sqlite-freeblock-linked-list-page-xor`。
- 关联卡：iOS 备份口令与 plist 元数据（`defense-forensics-ios-encrypted-backup-pin-bruteforce-plist`）；iOS Wi-Fi 记录与首连时间（`defense-forensics-ios-wifi-plist-nsdate-first-join`）。
- 注意：本卡是取证/溯源方法，不是攻击手法；对时间戳、文件名与哈希的结论应交叉验证，避免把工具分类名当作数据库字段名。

## 检测与防御

- 取证规范：镜像前后计算 SHA-256；用只读方式挂载/复制数据库（同时复制 `-wal`、`-shm`，否则可能丢失最新记录）；在报告中记录查询语句与工具版本。
- 证据解释：区分“导入时间”“修改时间”“创建时间”三种语义，Core Data 的 2001 纪元与 Unix 1970 纪元不可混用；时区统一换算为 GMT+8 或 UTC 并在报告中注明。
- 数据完整性：对 `Photos.sqlite` 执行 `PRAGMA integrity_check`；对可疑记录用文件哈希与来源应用附件交叉验证，避免仅凭文件名推断。
- 隐私与合规：移动设备取证涉及个人数据，需授权、最小化提取，敏感内容脱敏；证据移交保持链式保管记录。
- 防御视角：企业可对 AirDrop 与第三方文件传输 App 做 MDM 限制，减少敏感文件经非受管通道进出；终端 DLP 记录外发文件名/类型以便事后溯源。
