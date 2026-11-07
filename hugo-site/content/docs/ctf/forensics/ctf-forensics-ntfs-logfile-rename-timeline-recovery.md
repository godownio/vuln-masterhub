---
id: ctf-forensics-ntfs-logfile-rename-timeline-recovery
title: NTFS $LogFile 重命名时间线：从 USN/RENAME 记录恢复分段 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: ntfs-logfile-rename-timeline-recovery
tags:
- forensics
- ntfs
- logfile
- usn-journal
- rename
- timeline
- disk-image
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:12+08:00'
  notes: 已对照原文 NTFS 一节核对：$LogFile 提取、LogFileParser 输出 ntfs.db、RENAME 查询与数字转字节解码一致（本地复算 5 个数字得 0xGame{Y0u_H@vE_nnAsTered_NTF3!!!}）；已修正 LogFileParser 为 C# 工具的调用表述；未复跑镜像。
url: /docs/ctf/forensics/ctf-forensics-ntfs-logfile-rename-timeline-recovery/
draft: false
kb_aliases:
- NTFS LogFile 取证
- $LogFile 重命名分析
- LogFileParser 恢复文件名
- USN RENAME 时间线
- NTFS 日志分析
---

## 一句话结论

NTFS 的 `$LogFile` 记录文件创建、删除、重命名、权限与大小变化等元数据操作（不记录文件内容）；从 VHD/磁盘镜像中提取 `$LogFile`，用 LogFileParser 解析成 SQLite/CSV 后，按 `lf_LSN` 排序查询 `lf_UsnJrlReason LIKE '%RENAME%'`，可从“数字.txt → 字母.dat”等前后文件名恢复隐藏数据，再把数字按大端转字节即可拼出 flag。

## 原理

- **$LogFile 的作用**：NTFS 是日志文件系统，`$LogFile` 保存事务日志以保证崩溃一致性；它记录元数据变更（文件创建/删除、重命名、权限、大小、目录结构），但不记录文件的实际内容。
- **为什么能恢复重命名历史**：一次重命名会产生日志事务，记录中包含旧文件名、新文件名、USN 原因（如 `RENAME_OLD_NAME`/`RENAME_NEW_NAME`）和时间戳；即使文件后来被删除或改名，日志中仍保留操作序列。
- **LSN 的顺序性**：`lf_LSN`（Log Sequence Number）是日志记录的绝对顺序，值越大越新；按 LSN 排序可还原“先改了什么、后改了什么”。
- **USN 字段**：LogFileParser 会把 `$UsnJrnl` 相关字段并入 `LogFile` 表，包括 `lf_UsnJrlFileName`、`lf_UsnJrlTimestamp`、`lf_UsnJrlReason`、`lf_UsnJrlMFTReference` 等；对重命名事件，`lf_FileName` 会同时保留前后名字，便于配对。
- **数据恢复方式**：本题把 flag 的每一段编码成数字文件名（如 `13643046854681979.txt`），重命名后变成字母名（`.dat`）；日志中同时能看到数字名和字母名，提取数字后用 `num.to_bytes((num.bit_length()+7)//8, 'big')` 转回 ASCII 即可。
- **提取途径**：Autopsy 挂载 VHD 后直接导出 `$LogFile`；或用 7z 打开 VHD，按正确路径找到 `$LogFile`（隐藏系统文件，需显示隐藏/系统文件）；再用 LogFileParser 生成 CSV 与 SQLite 数据库。

## 触发条件

- 拿到 NTFS 卷/VHD/整盘镜像，`$LogFile` 未被清空或覆盖。
- 关键操作是元数据级（重命名、创建、删除、权限变更），而非仅文件内容变化。
- 能运行 Autopsy/7z 提取 `$LogFile`，并能运行 LogFileParser（或等价解析器）。
- 攻击者/出题人把信息编码进文件名或重命名序列，且未做日志清除。

## 利用步骤

1. 识别镜像：`file`/`fdisk -l` 确认 VHD/磁盘格式与分区。
2. 提取 `$LogFile`：
   - Autopsy 挂载 VHD，浏览到根目录，导出 `$LogFile`；
   - 或 7z 打开 VHD，显示隐藏/系统文件，定位 `$LogFile` 并解压。
3. 用 LogFileParser 解析：把 `$LogFile` 放到工具目录，按 README 运行；输出目录会生成 `ntfs.db` 与多个 CSV（如 FileNames）。
4. 打开数据库：`sqlite3 ntfs.db`，`.tables`、`.schema LogFile` 查看字段。
5. 查询重命名事件：
   ```sql
   SELECT lf_UsnJrlTimestamp, lf_UsnJrlReason, lf_FileName
   FROM LogFile
   WHERE lf_UsnJrlReason LIKE '%RENAME%'
   ORDER BY lf_LSN;
   ```
6. 从结果中配对旧/新文件名，提取数字名；按时间顺序或语义顺序拼接。
7. 将数字转为字节并解码，得到 flag 分段。

## PoC

```bash
# 用 jschicht/LogFileParser（C# 工具，非 Python 脚本）解析 $LogFile，
# 按该工具 README 指定输入文件与输出目录；解析后在输出目录得到 ntfs.db 与 CSV
sqlite3 ./out/ntfs.db

# SQL：按 LSN 看重命名时间线
SELECT lf_UsnJrlTimestamp, lf_UsnJrlReason, lf_FileName
FROM LogFile
WHERE lf_UsnJrlReason LIKE '%RENAME%'
ORDER BY lf_LSN;
```

```python
def num_to_string(num):
    n = (num.bit_length() + 7) // 8
    return num.to_bytes(n, "big").decode("utf-8", errors="ignore")

numbers = [
    13643046854681979,
    6426765720352224837,
    6876554908428166514,
    28539333146592819,
    555819389,
]
print("".join(num_to_string(n) for n in numbers))
```

说明：PoC 为原文流程的最小化复现，未在本机执行；原文通过 LogFileParser 的 SQLite 数据库查询 RENAME 记录，恢复出数字文件名并转回 flag。

## 变体与关联

- 变体（日志源）：`$UsnJrnl:$J` 直接解析 USN 记录；`$MFT` 的 `$FILE_NAME` 属性留存的旧文件名；`$LogFile` 与 USN 交叉验证。
- 变体（工具）：MFTECmd、UsnJrnl2Csv、Autopsy、FTK Imager、LogFileParser；不同工具字段名不同，但 LSN/时间戳/原因/文件名的语义一致。
- 变体（编码）：数字转字节、文件名按时间/字典序拼接、扩展名藏位、ADS 藏内容。
- 关联：[[ctf-forensics-ntfs-mft-slack-ads-flag-segments]]（MFT slack/ADS 恢复）；[[ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt]]；[[ctf-forensics-windows-sam-system-offline-ntlm-mask-crack]]。
- 边界：`$LogFile` 被清除/覆盖、卷被格式化、关键操作只改内容不改元数据、或镜像不完整时，日志无法提供线索；`$LogFile` 写入需要 SYSTEM 权限并绕过文件系统驱动，篡改难度较高。

## 检测与防御

- 检测：`$LogFile`/USN 中出现大量短周期 RENAME、数字名与随机名交替、批量创建/删除；与文件系统实际目录不一致的重命名历史；异常时间戳。
- 防御：开启并保护 USN 日志/安全日志，集中采集到 SIEM；限制本地管理员与 SYSTEM 级工具；对关键目录做文件完整性监控；保留足够日志轮转周期；发现日志被清空时触发告警。
