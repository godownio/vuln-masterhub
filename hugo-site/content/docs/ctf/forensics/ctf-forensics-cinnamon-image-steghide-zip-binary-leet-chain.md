---
id: ctf-forensics-cinnamon-image-steghide-zip-binary-leet-chain
title: 图片隐写多阶段链：EXIF ROT13 提示 → steghide 取加密 zip → john 爆破 → 二进制 leet 口令
type: scenario
domain: ctf
path: ctf/forensics
technique: image-steghide-zip-binary-leet-chain
tags:
- ctf
- forensics
- stego
- image
- exiftool
- rot13
- steghide
- zip
- john
- leet
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:19:30+08:00'
  notes: 已对照原文核对：EXIF ROT13 提示、scortisoara->fpbegvfbnen、john 得 tudorvianu、leet 5c0r71504r4 与 flag 一致；原文正文/代码块 steghide 口令不一致已在卡内注明，未复跑
url: /docs/ctf/forensics/ctf-forensics-cinnamon-image-steghide-zip-binary-leet-chain/
draft: false
kb_aliases:
- Cinnamon
- cinnamon.jpg
- steghide extract
- tryme.zip
- john rockyou
- scortisoara leet
- 5c0r71504r4
- 多阶段隐写
---

## 一句话结论

图片 `cinnamon.jpg` 的 EXIF/元数据给出 ROT13 提示，猜测主题词 `scortisoara`（罗马尼亚语“肉桂”）并 ROT13 得到 steghide 口令，提取出加密 `tryme.zip`；用 john + rockyou 爆破 zip 口令 `tudorvianu`，解压得到 `tryme` 二进制；程序提示“之前遇到过这个密码”且要求 leet 形式，把 `scortisoara` 转成 `5c0r71504r4` 输入即得 flag。

## 原理

- **元数据提示**：`exiftool` 可读出图片注释/描述中的 ROT13 提示（如“在名字上做 ROT13”）；主题词需结合文件名/题目名（cinnamon → 罗马尼亚语 `scortisoara`）猜测。
- **steghide**：JPEG 可用 steghide 以口令隐藏/提取数据；提取时若口令正确会得到内嵌文件（示例 `tryme.zip`）。口令通常是题目主题词的变换（原文正文用 ROT13 后的 `fpbegvfbnen`，代码块示例用 `cinnamon`，存在两种写法，需按实际提示尝试）。
- **zip 口令爆破**：`tryme.zip` 加密，用 `zip2john` 提取哈希后 `john --wordlist=rockyou.txt` 得到 `tudorvianu`；`unzip -P tudorvianu` 解出二进制。
- **二进制口令推理**：`tryme` 要求输入密码，提示“童话英雄需通过三次考验”“CarPl”（罗马尼亚语老师 Carmen Pleșa 的梗）以及“之前已经遇到过这个密码”；联想前面反复出现的主题词 `Scorțișoară`，按 leet 规则转成 `5c0r71504r4`（s→5, o→0, i→1, a→4）输入。
- **为什么成立**：多阶段题把同一主题词用不同编码/变换贯穿各阶段；每阶段的口令提示都指向主题词，只是编码不同（ROT13/leet/大小写）。这一致性是解题的关键线索。
- **可复用方法**：先读元数据/注释，再按文件名/题目名猜主题词，尝试常见变换（ROT13、leet、大小写、拼音）作为 steghide/zip/程序口令；每阶段产物继续用 `file`/`strings`/`binwalk` 分析。

## 触发条件

- 题目给出一张图片（JPEG/PNG）并暗示“藏了东西”；可能有元数据/注释提示。
- 图片可用 steghide/outguess/binwalk 等工具检测到嵌入数据。
- 嵌入数据可能是加密 zip/二进制；口令由主题词变换得到。
- 允许使用 john/hashcat 做离线 zip 爆破，且词典/提示足够。

## 利用步骤

1. `exiftool cinnamon.jpg` 读元数据/注释，寻找 ROT13/凯撒/主题词提示；`binwalk`/`steghide info` 确认是否嵌入数据。
2. 按文件名/题目名猜主题词（cinnamon → `scortisoara`），尝试原词、ROT13（`fpbegvfbnen`）、大小写等作为 steghide 口令。
3. `steghide extract -sf cinnamon.jpg -p "<口令>"` 提取内嵌文件（示例 `tryme.zip`）。
4. `zip2john tryme.zip > zip.hash`，`john --wordlist=rockyou.txt zip.hash` 得到 zip 口令（示例 `tudorvianu`），`unzip -P tudorvianu tryme.zip`。
5. 运行 `tryme`，阅读提示；把主题词转 leet（`5c0r71504r4`）作为密码输入。
6. 程序输出 flag；若提示不明确，用 `strings`/反编译查看期望密码格式，或枚举 leet 变体。

## PoC

```bash
#!/bin/bash
# 1) 元数据提示 -> steghide 口令（示例两种写法）
exiftool cinnamon.jpg
steghide extract -sf cinnamon.jpg -p "cinnamon"        # 或 -p "fpbegvfbnen"

# 2) 加密 zip 爆破
zip2john tryme.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
unzip -P tudorvianu tryme.zip

# 3) 二进制要求 leet 主题词
echo "5c0r71504r4" | ./tryme | grep -o "Vianu_CTF{[^}]*}"
```

输出：

```text
Vianu_CTF{1l_1ub1m_p3_5c0r71504r4}
```

原文正文称 steghide 口令为 `scortisoara` 的 ROT13 `fpbegvfbnen`，代码块示例写 `-p "cinnamon"`，两者存在不一致；zip 口令 `tudorvianu` 由 john 得到，二进制口令 `5c0r71504r4` 为 `scortisoara` 的 leet 形式。PoC 未在本机复跑。

## 变体与关联

- 隐写工具变体：steghide、outguess、zsteg、binwalk、foremost；不同工具口令/格式不同。
- 口令变换变体：ROT13、leet、大小写、拼音、摩斯、Base64；同一主题词在不同阶段用不同变换。
- 载荷变体：zip/rar/7z、可执行文件、另一张图片；每层继续用 `file`/`strings`/`binwalk`。
- 关联：[[ctf-forensics-deepsound-audio-stego-extract]]（音频隐写链）、[[ctf-misc-jpeg-segment-metadata-stego]]（JPEG 元数据）、[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（嵌套压缩链）。
- 边界：图片未嵌入数据、口令提示不足、zip 使用强口令时，爆破/提取不可行。

## 检测与防御

- 检测：CTF 中图片元数据异常、steghide 检测到嵌入数据、图片尾部有 zip/压缩包结构。
- 防御：真实场景不要用图片隐写保存敏感信息；上传图片应剥离 EXIF/注释并重新编码；对加密压缩包使用强口令。
- 加固：DLP 检测图片中的嵌入文件/异常元数据；限制 steghide 等工具在企业环境的使用。
