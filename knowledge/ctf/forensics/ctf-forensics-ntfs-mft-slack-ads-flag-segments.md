---
id: ctf-forensics-ntfs-mft-slack-ads-flag-segments
title: NTFS 镜像元数据取证：UTF-16LE 文件名残留 + MFT slack + ADS 恢复分段 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: ntfs-mft-slack-ads-flag-segments
aliases:
- Journaling
- evidence.001
- flagsegment
- tasks.txt:source
- NTFS ADS
- MFT slack
tags:
- forensics
- ntfs
- mft
- ads
- usn
- strings
- disk-image
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:34+08:00'
  notes: 已对照原文核对：UTF-16LE strings 提取 flagsegment 片段、unc0v3rs/notetoself 重命名残留、gsegment_4lter3d 截断补全、tasks.txt 正文 part 5、tasks.txt:source ADS 与最终 flag 均一致；卡片补齐了原文 exp 中 egrep 未闭合的引号。未验证点：无镜像附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

对 NTFS 镜像直接跑 `strings -a -el` 搜 `flagsegment`，可以从 MFT/文件名残留中拿到多段 flag；相邻旧文件名揭示重命名关系，`tasks.txt` 的正文提示“part 5”，而 `tasks.txt:source` 这个 ADS 里藏着最后一段，按语义排序即得完整 flag。

## 原理

- **NTFS 元数据残留**：文件名在 MFT 记录中以 UTF-16LE 保存；删除/重命名后，旧文件名可能残留在 MFT slack、目录索引或 USN journal 中。`strings -el` 能直接扫出这些宽字符。
- **重命名痕迹**：`flagsegment_unc0v3rs.txt` 与 `notetoself.txt` 紧邻出现，说明前者可能是后者的旧名；`gsegment_4lter3d` 少了前缀，是 MFT slack/被截断的 resident data，按同题固定前缀补全为 `flagsegment_4lter3d`。
- **ADS（Alternate Data Stream）**：NTFS 文件可以有多个命名数据流，`tasks.txt:source` 不会出现在普通目录列表里，但内容仍在卷上；本题最后一段 `flagsegment_3fd19982505363d0` 就藏在 `tasks.txt` 的 `source` 流附近。
- **顺序线索**：`tasks.txt` 正文写着 “find out where part 5 is...”，明确最后一段是 part 5；前四段按语义拼成 “unusual uncovers altered files” 的 leetspeak，得到 `u5njOurn@l unc0v3rs 4lter3d f1les`。
- **结果**：`texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}`。

## 触发条件

- 拿到 NTFS 磁盘镜像/分区镜像（MBR/GPT 或 raw）。
- 镜像中残留文件名、MFT slack、USN journal 或 ADS。
- 题目提示分段/顺序，或 flag 格式可帮助排序。
- 能用 `strings -el`、Autopsy、`fls`/`icat`、`ntfs-3g` 等工具读取元数据。

## 利用步骤

1. 解压证据包，确认镜像分区结构（`file`、`fdisk -l`、`mmls`）。
2. 对镜像跑 `strings -a -el evidence.001 | grep flagsegment`，收集所有片段。
3. 对相邻/截断的字符串做补全：缺前缀的按同题模式补，紧邻旧文件名的判断为重命名残留。
4. 找 `tasks.txt` 等提示文件，读取正文确定分段顺序/part 编号。
5. 检查 ADS：挂载后 `dir /r`、`Get-Content -Stream source`，或用 `fls -r`/`icat` 读命名流。
6. 按语义/编号排序拼接，套 flag 格式提交。

## PoC

```bash
unzip evidence.zip
strings -a -el evidence.001 | grep flagsegment
strings -a -el evidence.001 | egrep 'notetoself|monitor\.log|tasks\.txt|source'
```

典型输出：

```text
flagsegment_u5njOurn@l
flagsegment_unc0v3rs.txt
flagsegment_4lter3d
flagsegment_f1les.txt
flagsegment_3fd19982505363d0
```

ADS 读取（Windows 挂载后）：

```powershell
dir /r tasks.txt
Get-Content -Path tasks.txt -Stream source
```

Linux `ntfs-3g` 挂载后可用 `getfattr -d tasks.txt` 查看命名流 xattr（具体名称以挂载实现为准）。

## 变体与关联

- **残留位置变体**：MFT slack、目录索引、USN journal、`$LogFile`、卷影副本、未分配空间。
- **隐藏方式变体**：ADS、短文件名（8.3）、备用文件名、硬链接、稀疏文件。
- **工具变体**：Autopsy、`fls`/`icat`（Sleuth Kit）、`ntfs-3g`、`strings -el`、`bulk_extractor`。
- **关联卡片**：[[ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt]]（NTFS/EWF 恢复）、[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（删除文件恢复）、[[ctf-forensics-wsl-ext4-vhdx-offline-inspect]]（虚拟磁盘取证）。
- **边界**：若镜像被安全擦除/全盘加密、或文件名/ADS 已被覆盖，strings 可能找不到；需要按 MFT 记录/USN 日志做结构化恢复。

## 检测与防御

- **防御**：敏感数据不要以文件名/ADS 形式落盘；使用全盘加密；删除后擦除 MFT slack/未分配空间；关闭/轮转 USN journal。
- **检测信号**：文件名中出现 `flagsegment`/`part` 等分段模式；`dir /r` 发现异常 ADS；USN journal 中出现重命名/删除记录。
- **CTF 技巧**：先宽字符 strings 扫全局，再看相邻关系和截断补全，最后用提示文件定顺序。
