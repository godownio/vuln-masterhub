---
id: ctf-forensics-thumbs-db-deleted-image-thumbnail-recovery
title: Thumbs.db 缩略图缓存恢复已删除图片：从磁盘镜像提取 Explorer 缩略图流
type: scenario
domain: ctf
path: ctf/forensics
technique: thumbs-db-deleted-image-thumbnail-recovery
tags:
- ctf
- forensics
- windows
- thumbs-db
- thumbnail-cache
- deleted-file
- disk-image
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:24:32+08:00'
  notes: 已对照原文 MISC5 与图24-25核对：镜像 Images 目录原图 0 被删、Thumbs.db 经 Thumbs Viewer 查看缩略图读出 image_in_thumbnail；未验证点：未在原始镜像上复跑 Thumbs Viewer。
url: /docs/ctf/forensics/ctf-forensics-thumbs-db-deleted-image-thumbnail-recovery/
draft: false
kb_aliases:
- Thumbs.db 取证
- 缩略图恢复
- 删除图片恢复
- Thumbs Viewer
- Windows 缩略图缓存
- thumbcache 解析
---

## 一句话结论

当图片目录中的原图被删除但目录里仍留有隐藏的 `Thumbs.db` 时，用 Thumbs Viewer 等工具解析 Explorer 缩略图缓存，可以直接导出已删除图片的缩略图；若 flag 写在原图上，看缩略图即可读出，无需恢复原始文件。

## 原理

- Windows Explorer 为加速目录预览，会把图片/视频的缩略图缓存起来。旧版 Windows（XP/2003 时代及兼容实现）在图片所在目录生成隐藏系统文件 `Thumbs.db`，它是一个 OLE 复合文档（Compound File Binary），包含 `Catalog` 目录项与若干按索引编号的缩略图数据流（常见为 JPEG 小图）。
- Vista 之后大量场景改用集中式 `thumbcache_*.db`（位于用户 `AppData\Local\Microsoft\Windows\Explorer`），但目录级 `Thumbs.db` 在网络共享、旧系统、兼容模式或特定应用中仍会出现。
- 缩略图与原文件是两份独立数据：删除原图只会删掉目录项/数据区，缓存条目要等到 Explorer 重建缓存、磁盘清理或用户手动清除才会消失。因此 `Thumbs.db` 能保留“曾经存在过哪些图片”以及低分辨率内容。
- 缩略图通常只有几十到几百像素，足以辨认原图中的文字/二维码/大面积色块；如果 flag 是直接画在图片上的，缩略图往往可读。分辨率过低时可放大、增强对比度或做 OCR。
- 该技巧也适用于真实取证：`Thumbs.db`/`thumbcache` 可证明某目录曾被浏览、某图片曾存在，即使原文件已被删除。

## 触发条件

- 拿到磁盘镜像、目录副本或用户配置文件，且原图片已被删除/不可读。
- 目标目录存在 `Thumbs.db`（需开启“显示隐藏的系统文件”），或用户 `Explorer` 目录存在 `thumbcache_*.db`。
- 缩略图内容包含目标信息（flag、文件名、画面细节）。
- 缓存未被清理工具重建/删除。

## 利用步骤

1. 挂载/浏览镜像，定位图片目录（如 `Images/`），检查隐藏文件 `Thumbs.db`；同时看 `C:\Users\<user>\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db`。
2. 用 Thumbs Viewer 打开 `Thumbs.db`：工具会列出每个条目的索引、大小、修改时间与所属系统，选中条目即可预览/导出缩略图。
3. 若是 Vista+ 的集中式缓存，用 thumbcache 解析工具选择 `thumbcache_*.db`；不同文件对应不同尺寸（16/32/48/96/256/1024 等）。
4. 导出可疑缩略图，按内容筛选（flag 文本、二维码、截图、文档预览）；对低分辨率图放大、调对比度、二值化或 OCR。
5. 若缩略图不足以读出，继续从 `$MFT`/`$I30` 索引、回收站（`$Recycle.Bin`）、未分配空间或文件系统日志恢复原图；`Thumbs.db` 的条目名/修改时间可作为恢复线索。
6. 记录缓存文件的哈希、条目列表与导出图片的哈希，形成证据链。

## PoC

```python
# 仅枚举 Thumbs.db（OLE 复合文档）中的流，确认缓存结构
import olefile

ole = olefile.OleFileIO("Thumbs.db")
for entry in ole.listdir():
    print("/".join(entry), ole.get_size(entry))
```

```text
工具流程（图形界面）：
1. 打开 Thumbs Viewer；
2. File -> Open 选择 Thumbs.db；
3. 在列表中按大小/修改时间浏览条目；
4. 选中条目 -> 预览/导出为 PNG/JPEG；
5. 对导出图做 OCR/放大检查。
```

说明：`Thumbs.db` 的流命名与缩略图格式随 Windows 版本/实现变化，实际解析优先用专用工具；PoC 只做流枚举，未在原文镜像上复跑。

## 变体与关联

- **集中式 thumbcache**：`thumbcache_*.db` 使用不同的容器格式（含 SRUM/索引），需用 thumbcache 专用解析器；同一张图可能存在于多个尺寸文件。
- **网络共享**：远程目录的 `Thumbs.db` 可能由访问者的客户端生成，能反映“谁浏览过什么”，但内容属于客户端缓存。
- **缓存清理**：磁盘清理、隐私工具、Explorer 重建会删除条目；若 `Thumbs.db` 被删除，可从未分配空间/文件系统日志恢复。
- **关联**：[[ctf-forensics-ntfs-mft-slack-ads-flag-segments]]（NTFS 元数据恢复）、[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（删除文件簇恢复）、[[ctf-forensics-ext4-image-unallocated-strings-residual]]（未分配空间残留）、[[ctf-misc-broken-docx-zip-mtime-thumbnail-stego]]（文档缩略图隐写）。

## 检测与防御

- 隐私：`Thumbs.db`/`thumbcache` 会在本机留下曾浏览图片的低分辨率副本；敏感目录应关闭缩略图缓存（组策略 `DisableThumbnailCache`/`DisableThumbnailCacheOnNetwork`）或定期清理。
- 取证：排查“图片被删除但缩略图仍在”的场景时，优先保留 `Thumbs.db`、`thumbcache_*.db` 与 `$MFT`，不要先运行磁盘清理。
- 检测：CTF 中看到镜像里图片目录缺号（如 `0.png` 被删）但存在 `Thumbs.db`，应优先检查缓存；真实环境中可把 `Thumbs.db` 作为目录浏览/文件存在性的辅助证据。
