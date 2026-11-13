---
id: ctf-forensics-volatility-mftparser-deleted-file-recover
title: Volatility2 mftparser 从内存镜像恢复已删除文件：$MFT 记录常驻 $DATA 直接读出删除文本 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: volatility-mftparser-deleted-file-recovery
tags:
- forensics
- memory
- volatility
- mftparser
- ntfs
- deleted-file
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:32:58+08:00'
  notes: 已对照原文 12559 全文与 49 张图核对：Lab4 用 mftparser 从 $MFT 记录恢复已删除 Users\SlimShady\Desktop\Important.txt，输出 $FILE_NAME/$DATA 段与 ctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3} 均与图27一致；常驻 $DATA 原理与约 700 字节阈值表述合理；PoC 命令与 grep 思路可复现。查重 top 候选（screenshot 桌面恢复、Volatility3 二次转储等）均非同链，无重复。CTF 靶场无产品版本，affected_versions 保持省略。未实际运行 Volatility。
url: /docs/ctf/forensics/ctf-forensics-volatility-mftparser-deleted-file-recover/
draft: false
kb_aliases:
- mftparser 恢复删除文件
- 内存 MFT 取证
- 删除文件内容恢复
- $DATA 常驻属性
---

## 一句话结论

Windows 内存镜像中缓存着 NTFS 的 `$MFT` 记录；用 Volatility2 的 `mftparser` 解析后，已删除文件若内容小于约 700 字节（常驻在 MFT 记录的 `$DATA` 属性内），其原始内容仍直接出现在解析输出里，`cat` 的只是磁盘上已不存在的文件。

## 原理

- NTFS 的每个文件在 `$MFT` 中有记录（FILE record），小文件的内容不单独分配簇，而是以**常驻（resident）`$DATA` 属性**内嵌在 MFT 记录里；删除文件只会把记录标记为空闲并更新位图，内容在记录被覆盖前仍然存在。
- `$MFT` 本身是打开着的系统元文件，其内容会映射/缓存到内存；因此内存镜像里可以通过 Volatility `mftparser` 扫描到文件记录，包括已删除项与它们的常驻内容。
- 解析输出会显示 `$FILE_NAME`（文件名、父目录、时间戳）与 `$DATA`（hex + ASCII）两部分；对删除文件重点看文件名为空/带删除标记但 `$DATA` 仍有内容的记录。
- 非驻留文件（大于常驻阈值）的内容在磁盘簇中，内存 MFT 只能恢复文件名、大小、时间与数据运行（runlist），需要磁盘镜像才能取内容；因此本手法对“小文本文件”最有效。
- 与磁盘取证的区别：不需要磁盘镜像，内存里的 `$MFT` 缓存已足够恢复小文件；也解释了为什么“被删除的重要 txt”能在只拿到内存镜像时找回。

## 触发条件

- 已获取 Windows 内存镜像且 profile 匹配；
- 目标文件较小（内容常驻在 MFT 记录中）、所在卷的文件系统为 NTFS；
- 文件删除后 MFT 记录未被新文件覆盖。

## 利用步骤

1. `imageinfo` 确定 profile。
2. 运行 `mftparser`，输出保存到文件（量很大）。
3. 搜索目标文件名或已知关键字；同时浏览“文件名异常/已删除”的 `$FILE_NAME` 条目。
4. 在对应 `$DATA` 段读取 hex/ASCII 内容，拼接得到文件正文。

## PoC

```bash
python2 vol.py -f MemoryDump.raw imageinfo
python2 vol.py -f MemoryDump.raw --profile=Win7SP1x64 mftparser > mft.txt
grep -n -A 40 "Important.txt" mft.txt
```

输出中 `$DATA` 段（示例）：

```
$DATA
0000000000: 69 0d 0a 0d 0a ...  ct...f1...
...
0000000080: ...  d0$3...Goo d_work.?
```

按 ASCII 列读出即可得到类似 `ctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}` 的完整内容。

## 变体与关联

- 变体：文件被删除但目录项仍残留时，`$FILE_NAME` 的父目录与时间戳可用于时间线；结合 `$LogFile`/USN 记录可还原重命名/删除顺序。
- 变体：非驻留文件改用磁盘镜像的 MFT 解析或 `ntfsundelete`；内存 MFT 的 runlist 可帮助定位磁盘上的数据簇。
- 关联：[[ctf-forensics-ntfs-logfile-rename-timeline-recovery]]——NTFS 日志重命名时间线。
- 关联：[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]——FAT16 删除文件簇恢复。
- 关联：[[defense-forensics-volatility3-secondary-dump-process-memmap-dll-dumpfiles]]——Volatility3 的其它转储能力。

## 检测与防御

- 该卡为取证手法；对攻击方，删除小文件并不能从内存镜像中抹除内容。
- 防御/响应：敏感文件避免小文本形式落盘；事件响应先做内存镜像；处置时对 `$MFT` 记录覆盖与安全擦除有正确预期。
