---
id: ctf-forensics-ext4-image-unallocated-strings-residual
title: ext4 镜像未分配块 strings 残留：恢复口令、密钥与明文 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: ext4-image-unallocated-strings-residual
aliases:
- ext4 镜像 strings 取证
- 未分配块残留
- 删除文件明文恢复
- 磁盘镜像关键字挖掘
tags:
- forensics
- disk-image
- ext4
- strings
- unallocated
- deleted-file
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:31+08:00'
  notes: 已对照原文核对：ext4 镜像 KASHI_LEDGER、strings 命中 decoy_ledger_*、stage2_ledger.enc/txt、ritual_words.txt、ritual_index_notes.md、ward_scans、聊天记录、stage2 JSON（ghat-manjari-copper-owl、AES salt/key/iv）以及未覆盖块中的明文 flag kashiCTF{ledger_ashes_remember_every_ritual} 均一致；卡片对 decoy 的排除逻辑与原文一致。未验证点：无镜像附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

拿到 ext4 文件系统镜像时，先对整个镜像做 `strings -a`，往往能直接从已删除文件/未分配块中恢复文件名、口令规则、聊天记录、JSON 配置和明文 flag；再用文件系统解析工具按路径验证，即可还原完整证据链。

## 原理

- ext4 删除文件时通常只清除 inode 的块指针/位图，数据块本身不会立即擦除；这些块进入未分配池，直到被新数据覆盖。`strings` 会扫描整个镜像（包括元数据区、日志区、未分配块），把连续可打印字符输出。
- 文件内容、文件名（目录项）、邮件/聊天记录、JSON 配置等往往以明文或可识别编码存在；即使文件已删除，残留仍可能包含关键口令、AES key/IV、flag。
- `strings` 是无结构扫描，可能命中大量噪声/诱饵；需要结合文件名、上下文关键字（flag、pass、key、secret、stage、decoy）和文件系统解析结果交叉验证。
- 为什么可行：取证镜像包含完整块设备，未分配块没有被清零；CTF 出题人常故意把答案放在删除文件/未分配块中，考察“不要只看当前目录”的意识。

## 触发条件

- 获得 ext4（或其他未加密）文件系统镜像，且有读取权限。
- 关键数据曾以明文写入且未被覆盖/清零；文件系统未启用安全删除/加密。
- 能运行 `strings`、`grep`、`debugfs`/`fls`/`icat` 等工具。

## 利用步骤

1. `file image.img` 确认文件系统类型；`strings -a image.img | less` 或重定向到文件。
2. 用关键字过滤：`grep -Ei 'flag|pass|key|secret|stage|decoy|token|iv|salt'`；记录可疑文件名、邮件、笔记、JSON。
3. 用 `debugfs -R 'ls -l /' image.img`、`fls -r image.img` 或 `icat` 按 inode 提取当前/删除文件；对照 strings 中的文件名。
4. 对疑似加密文件，结合 strings 中泄露的 key/IV/salt/口令规则解密；对疑似明文直接读取。
5. 识别诱饵：文件名含 `decoy`、内容互相矛盾、聊天记录明确说“false/decoy”的，先排除。
6. 用多处证据交叉验证（邮件规则 + 笔记 + 聊天 + JSON），确认最终口令/flag 后提交。

## PoC

```bash
file kashi_ritual_ledger.img
strings -a kashi_ritual_ledger.img > strings.txt
grep -Ei 'flag|pass|key|secret|stage|decoy|token|iv|salt' strings.txt | head -100

# 按文件系统结构查看/提取（示例）
debugfs -R 'ls -l /' kashi_ritual_ledger.img
debugfs -R 'cat /path/to/file' kashi_ritual_ledger.img
```

说明：PoC 为原文流程的结构化复现，未在本机执行；原文通过 strings 直接恢复了邮件口令规则、`ritual_words.txt`、聊天中的 AES 参数、stage2 JSON 以及未分配块中的明文 flag。

## 变体与关联

- 变体（工具）：`binwalk`/`foremost`/`scalpel` 按文件头 carving；`sleuthkit` 的 `fls/icat` 按 inode 恢复删除文件；`extundelete`/`ext4magic` 尝试恢复。
- 变体（文件系统）：NTFS 的 `$MFT`/`$UsnJrnl`、FAT 的目录项、APFS/HFS+ 的元数据；未分配块残留原理类似。
- 关联：[[ctf-forensics-wsl-ext4-vhdx-offline-inspect]]（ext4.vhdx 挂载与 bash_history）；[[defense-forensics-core-dump-secret-extraction]]（strings/字节搜索提取秘密）；[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（删除文件簇恢复）。
- 边界：镜像被加密、未分配块被清零/TRIM、关键数据从未落盘、或 strings 只命中诱饵时，需要更深的文件系统/日志分析。

## 检测与防御

- 检测：镜像中出现大量已删除文件名、口令/密钥/聊天记录残留；`decoy` 文件与真实线索并存；未分配块含高熵/明文敏感数据。
- 防御：敏感数据落盘前加密；删除时使用安全擦除/全盘加密；启用 TRIM/定期清零未分配块；不要把密钥与密文放在同一镜像。
- 取证：对镜像做只读挂载/哈希校验，保留原始镜像；记录 strings 命中位置与文件系统路径，形成证据链。
