---
id: ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip
title: SNOW 空白隐写 + binwalk 尾随 ZIP + ZipCrypto 明文攻击
type: scenario
domain: ctf
path: ctf/forensics
technique: snow-whitespace-binwalk-known-plaintext-zip
tags:
- ctf
- forensics
- stego
- snow
- whitespace
- binwalk
- zip
- known-plaintext
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:00:44+08:00'
  notes: 已对照原文『人类联合之高塔』与图14-17核对：EXIF key:amiya、尾部空格/制表符 SNOW.EXE -C -p amiya 1.txt 解出 'Great ideals but through selfless struggle and sacrifice to achieve.'（图14）、用该口令解压后 binwalk 发现尾随 ZIP（图15）、解出 Sarkaz.zip 与 Civilight_Eterna_ruined.zip（图16）、两者 Civilight_Eterna_ruined.png CRC32 均为 F1BD250E（图17）、明文攻击。卡片 SNOW 参数、binwalk/foremost、bkcrack -C/-c/-p/-k/-U 流程与12+字节已知明文边界均正确。未在本机复跑；无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip/
draft: false
kb_aliases:
- SNOW 隐写
- 空白隐写
- 制表符空格隐写
- binwalk 尾随文件
- ZipCrypto 明文攻击
- bkcrack
---

## 一句话结论

当图片的 EXIF/元数据给出密码、且文件尾部有大量空格/制表符时，先把尾部空白提取为文本并用 SNOW（`-C -p <密码>`）解出隐藏口令；用该口令解压后，若图片尾部还被 binwalk 发现附加 ZIP，而两个 ZIP 中存在 CRC32 相同的已知文件，可用 ZipCrypto 明文攻击（bkcrack）恢复密钥并解密。

## 原理

- **SNOW 空白隐写**：SNOW 把数据编码为行尾的空格/制表符（及换行）模式，肉眼看不出；`SNOW.EXE -C -p password file.txt` 从文本中提取隐藏消息。密码来自 EXIF/题目提示（本题 `key:amiya`）。
- **binwalk 尾随文件**：PNG/JPEG 等格式在 IEND/EOI 后可以附加任意数据；`binwalk`/`foremost` 能识别尾部的 ZIP/RAR/PNG 等 magic，并提取。
- **ZipCrypto 明文攻击**：ZipCrypto 使用 12 字节密钥流 + CRC 校验；若攻击者已知归档中某个文件的明文（≥12 字节，通常需要更多以提高唯一性），可用 `bkcrack -C cipher.zip -c plain.txt -p plain.txt` 恢复内部密钥，再用 `bkcrack -k <keys> -U decrypted.zip plain.txt` 解密。本题两个 ZIP 中包含同一个 PNG（CRC32 相同），一个 ZIP 可解/已知明文，另一个用其做明文攻击。
- **为什么成立**：ZipCrypto 的密钥流只依赖密码与文件内容，已知明文可恢复密钥流/内部密钥；同一文件出现在两个归档中时，已知明文可直接复用。
- **边界**：WinZip AES（method 99）不适用 ZipCrypto 明文攻击；bkcrack 需要至少 12 字节已知明文（8 字节密钥流 + 4 字节 CRC 校验），实际建议更长/唯一。

## 触发条件

- 图片/文本尾部有大量空格/制表符，EXIF/提示给出密码；SNOW 可提取隐藏消息。
- 解压后的图片/文件尾部被 binwalk/foremost 识别出追加的 ZIP/RAR。
- 两个 ZIP 中存在 CRC32 相同/内容已知的文件（本题 `Civilight_Eterna_ruined.png`），或能从其他来源获得明文。
- ZIP 使用传统 ZipCrypto（method 8 或 0 + 加密标志），不是 WinZip AES。

## 利用步骤

1. 读图片 EXIF/元数据，记录 `key`/密码提示（本题 `amiya`）。
2. 用 010 查看文件尾部，确认有空格/制表符；把尾部空白提取到 `1.txt`（保留空格/制表符/换行）。
3. 运行 `SNOW.EXE -C -p "amiya" 1.txt`，得到隐藏口令（本题为一句英文）。
4. 用该口令解压外层 ZIP，得到提示图片；`binwalk`/`foremost` 扫描图片，发现尾随 ZIP/RAR 并提取。
5. 解压后得到两个 ZIP；比较文件列表/CRC32，找到相同/已知明文的 PNG。
6. 用 `bkcrack` 明文攻击解出另一个 ZIP 的密钥，解密得到 flag。

## PoC

```bash
# 1) SNOW 提取（Windows）
SNOW.EXE -C -p "amiya" 1.txt

# 2) binwalk 尾随文件
binwalk -e suspicious.png
foremost -i suspicious.png -o out

# 3) ZipCrypto 明文攻击（bkcrack）
bkcrack -C Sarkaz.zip -c Civilight_Eterna_ruined.png -p known.png
# 得到 key 后解密
bkcrack -C Sarkaz.zip -k <key1> <key2> <key3> -U decrypted.zip Civilight_Eterna_ruined.png
```

## 变体与关联

- **变体（其他空白隐写）**：SNOW、StegoSuite、行尾空格编码、零宽字符；先看文件尾部/文本行尾。
- **变体（尾随文件）**：PNG IEND 后、JPEG EOI 后、PDF EOF 后；binwalk/foremost/`010` 模板。
- **变体（明文攻击）**：两个 ZIP 同文件、已知压缩包内文档模板、可下载的公开文件；bkcrack 需要 12+ 字节明文。
- **关联卡片**：[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（ZIP 嵌套/CRC 重叠）、[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（ZIP 伪加密/头修复）、[[ctf-forensics-office-doc-password-office2john-hashcat]]（Office 密码）。
- **边界**：AES ZIP 不适用；已知明文不足/不唯一时攻击失败；SNOW 密码错误会输出乱码/无输出；尾随数据可能被压缩/加密。

## 检测与防御

- **CTF 识别**：EXIF 给密码 + 尾部空白 → SNOW；图片尾随 magic → binwalk；两个 ZIP 同 CRC 文件 → 明文攻击。
- **数据安全**：不要用 ZipCrypto 保护敏感归档；使用 AES-256 + 强密码；不要在归档中保留可公开获取的明文文件。
- **检测**：文件尾随数据扫描、ZIP 加密算法识别（method 99 vs 8）、异常空白字符密度；DLP 可检测 SNOW 类隐写。
