---
id: defense-forensics-ventoy-log-partition-history
title: Ventoy 日志取证：从 log.txt 恢复删除分区大小与启动介质制作完成时间
type: scenario
domain: defense
path: defense/forensics
technique: ventoy-log-partition-history
aliases:
- Ventoy 启动盘取证
- Ventoy log.txt
- 删除分区大小
- 启动介质制作时间
- bootable media 取证
tags:
- forensics
- ventoy
- bootable-media
- log-analysis
- partition
- timestamp
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:06:40+08:00'
  notes: 已对照原文与图片 33-34 核对；Partition 3 size 499775438848、最后 OK 2026/07/10 15:21:13 一致
---

## 一句话结论

Ventoy 在安装/制作启动介质时会把分区删除、格式化、写入引导镜像等操作写入安装目录下的 `log.txt`；案例中从日志的 `Partition 3 (... size: 499775438848) delete it` 恢复出被删除的最大分区大小 499775438848 字节，并以最后一次 `OK` 对应的时间 `2026/07/10 15:21:13` 作为制作完成时间。

## 原理

- Ventoy 制作启动盘时需要重新分区、格式化并写入引导镜像，其安装程序会记录详细日志（案例路径为 `scoop/apps/ventoy/1.16/log.txt`）。
- 日志行包含时间戳、操作类型、分区号、偏移、大小、盘符等字段，例如：
  - `Partition 3 (offset: 332398592, size: 499775438848) delete it`
  - `Delete this partitions success`
  - `Formatting Part1 exFAT ...`、`Writing Boot Image ...`、`VentoyPlugin ...`
- 通过筛选 `delete` 行并按 `size` 排序，可恢复被删除分区中容量最大的一个；通过筛选一次制作流程末尾的 `OK` 行，可确定该次制作结束时间。
- 日志中的时间是本地时间（案例格式 `2026/07/10 15:21:13`），题目要求按检材原始时区回答，因此通常无需 UTC 换算，但需确认日志记录时区。
- 若日志被清理，可从 Ventoy 安装目录的 `Ventoy2Disk.ini`、`log.txt` 备份、分区表残留、文件系统创建时间等辅助恢复。

## 触发条件

- 目标主机安装了 Ventoy（常见于 `scoop/apps/ventoy/<version>`、`Program Files\Ventoy` 或便携目录）。
- 安装目录下保留 `log.txt` 或类似日志文件。
- 需要回答“删除了哪些分区/最大分区多大”“最后一次制作何时完成”等问题。
- 取证环境可读取文本日志，具备基本 grep/awk/PowerShell 处理能力。

## 利用步骤

1. 定位 Ventoy 安装目录与 `log.txt`，记录文件大小、修改时间与哈希。
2. 搜索 `delete`/`Delete` 行，提取每行的分区号、偏移与 `size` 字段。
3. 将 `size` 转为整数排序，取最大值；案例最大值为 `499775438848` 字节（约 465GB）。
4. 搜索一次制作流程的结束标志（如 `OK`、`Ventoy2Disk` 完成、`Writing Boot Image` 后的收尾行），取最后一条对应时间。
5. 如有多个制作批次，按时间分段，确认“最后一次”对应的批次，避免把历史操作当成当前结果。
6. 与分区表、文件系统创建时间、USB 设备连接记录交叉验证，固定证据。

## PoC

```bash
# 1) 定位日志
find /path/to/scoop/apps/ventoy -iname 'log.txt' -o -iname '*.log'

# 2) 提取删除分区及大小（案例）
rg -n 'delete it|Delete this partitions' log.txt
# Partition 3 (offset: 332398592, size: 499775438848) delete it

# 3) 取最大 size（awk 示例）
rg -o 'size: [0-9]+' log.txt | awk -F': ' '{print $2}' | sort -n | tail -1
# 499775438848

# 4) 查看制作流程末尾的 OK 时间（案例）
rg -n 'OK|Writing Boot Image|Formatting Part' log.txt | tail -20
# 2026/07/10 15:21:13  OK
```

```powershell
# PowerShell 等价：提取 delete 行的 size 并排序
Select-String -Path .\log.txt -Pattern 'delete it' |
  ForEach-Object { if ($_.Line -match 'size:\s*(\d+)') { [int64]$matches[1] } } |
  Sort-Object -Descending | Select-Object -First 1
```

说明：案例答案为最大删除分区 `499775438848` 字节、最后完成时间 `2026/07/10 15:21:13`；日志格式可能随 Ventoy 版本变化，需按实际行调整正则。

## 变体与关联

- 变体：Rufus、balenaEtcher、Ventoy2Disk 等启动盘工具也会留下日志/配置；Rufus 的 `rufus.ini`、Etcher 的日志目录可作为替代证据。
- 变体：日志被删除时，可通过分区表残留（被删除分区的 offset/size）、文件系统创建时间、`$MFT` 中 `$UsnJrnl` 记录恢复操作痕迹。
- 变体：多块 U 盘/多次制作时，需按日志批次和设备序列号区分，避免张冠李戴。
- 关联：[[defense-forensics-localsend-config-precise-timestamp]]（应用配置时间戳取证）、[[defense-forensics-multisource-timeline-log-clear]]（多源时间线）。

## 检测与防御

- 防御：启动盘制作完成后清理 `log.txt` 与安装目录中的设备信息；对敏感介质使用后做安全擦除。
- 防御：企业环境限制普通用户制作可启动介质，记录 USB 设备接入与写操作审计。
- 检测：主机上出现 Ventoy/Rufus/Etcher 安装目录与日志；USB 存储设备接入后的分区表大幅变更；日志中出现 `delete it`、`Writing Boot Image` 等关键词。
- 响应：保留日志原件与哈希；按时间批次还原分区操作与制作时间，结合设备序列号确认对应介质。
