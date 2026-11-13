---
id: ctf-misc-png-zip-filename-base64-zero-width-aes-chain
title: PNG 伪装 JPG + 内嵌加密 ZIP + 文件名 Base64 作密码 + 零宽隐写取 AES 密钥
type: scenario
domain: ctf
path: ctf/misc
technique: png-zip-filename-base64-zero-width-aes
aliases:
- 图片内嵌加密 ZIP
- 文件名 base64 密码
- 零宽隐写取 key
- PNG 改宽高
- AES ECB 解密图片
- easy00aes
tags:
- ctf
- misc
- stego
- png
- zip
- zero-width
- aes
- image-repair
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:33:55+08:00'
  notes: 已对照原文与20图核对：正文明确 jpg 实为 PNG、内嵌加密 ZIP、密码为文件名 YXNkZHNh 的 Base64(asddsa)、解出 key.txt/flag.jpg、PNG 宽高被改；图13 拉伸/修复后显示 Base64 密文（1eu4+X0r...）；图14 零宽工具 Hidden Text=adsadwadsadad；图15 AES ECB/pkcs7padding/128位/key=adsadwadsadad 解密得 DASCTF{aac827d3d8e496ad844f2fef2f663090d}。卡片参数与截图一致。affected_versions 留空正确（CTF题）。dedup 报告判 new，related 的 Aztec 码密码、图片尾部伪加密ZIP、PNG IHDR CRC 爆破等为不同载体/步骤，非同链，保留。未验证点：ZIP 分离与宽高修复过程无截图，仅正文描述；Base64 密码 YXNkZHNh 仅见正文文字。
---

## 一句话结论

一张后缀为 `.jpg` 的图片实际是 PNG，内部/尾部藏有加密 ZIP；压缩包密码来自文件名 `YXNkZHNh` 的 Base64 解码（`asddsa`），解出 `key.txt` 与 `flag.jpg` 后，`key.txt` 的零宽字符隐写给出 AES 密钥，修复被篡改的 PNG 宽高即可看到密文，再用 AES-128-ECB 解密得到 flag。

## 原理

- **文件头识别**：扩展名不可信；PNG 头为 `89 50 4E 47`。用 `file`/010 确认真实类型后再选分离工具。
- **图片内嵌 ZIP**：PNG 的 IEND 之后或 IDAT 块之间可附加 ZIP（`50 4B 03 04`）；`binwalk -e`/`foremost` 按偏移切出。
- **密码来源**：题目把 zip 文件名（或提示串）设为 `YXNkZHNh`，Base64 解码得 `asddsa`，直接作为解压密码——CTF 中常见“密码藏在文件名/注释/元数据”的套路。
- **零宽隐写**：`key.txt` 正常内容是可读文本，另混入 U+200B/U+200C 等不可见字符；用零宽隐写解码工具按二进制/五进制还原出隐藏的 AES 密钥（本例 `adsadwadsadad`）。
- **PNG 宽高修复**：题目修改了 PNG IHDR 的宽/高字段使图片显示异常；按实际像素数据长度重算宽高（或直接用脚本爆破合理尺寸）后，图片中显示 Base64 密文字符串。
- **AES 解密**：密文为 Base64，密钥 13 字节按 128 位补零/取 MD5 等方式处理（按题目工具设定），模式 ECB + PKCS7，解密得 flag。

## 触发条件

- CTF 附件为图片，但文件头与后缀不符或 `binwalk` 发现内嵌压缩包。
- 压缩包加密且密码可从文件名/元数据/注释推导。
- 解出文件含不可见字符或图片尺寸异常。
- 有 AES 密文与可推导密钥。

## 利用步骤

1. `file`/010 确认真实类型；`binwalk`/`foremost` 分离内嵌 ZIP。
2. 对 ZIP 文件名/注释做 Base64/ROT13 等常见编码尝试，得到解压密码。
3. 解压得到 `key.txt`、`flag.jpg`；用零宽隐写工具解码 `key.txt` 得 AES 密钥。
4. 用 PNG 宽高修复工具/脚本修正 `flag.jpg`，读取其中的 Base64 密文。
5. 用 AES-128-ECB + PKCS7 解密（CyberChef 或脚本），得到 flag。

## PoC

```bash
file easy00aes.jpg          # 实际为 PNG
binwalk -e easy00aes.jpg    # 分离出 zip
echo YXNkZHNh | base64 -d   # asddsa，作为 zip 密码
# 零宽隐写解码 key.txt -> adsadwadsadad
# 修复 PNG 宽高后读取密文：
# 1eu4+X0rAE79+rZQBxhAG7t85wcd20u0VfupQJx1H0Hm6HVnHQoLM...
# AES-128-ECB / PKCS7 / key=adsadwadsadad -> DASCTF{...}
```

## 变体与关联

- 变体：ZIP 伪加密（改 general purpose bit flag）而非真密码；嵌套 ZIP/PCZ。
- 变体：密码来源为图片 EXIF、注释、文件名反转、Base32。
- 变体：零宽隐写的二进制/五进制映射；PNG/BMP/PPM 宽高篡改修复。
- 关联：[[ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz]]（图片尾部 ZIP + 伪加密）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（零宽隐写）、[[ctf-misc-bmp-header-size-repair]]（图片尺寸修复）。
- 边界：ZIP 真加密且密码不可推导、隐写内容被压缩/加密、AES 密钥/模式未知时需继续爆破或从题目提示获取。

## 检测与防御

- 本卡为 CTF 解题思路，不涉及防御；出题时可把密码与密钥分散到不同载体（文件名、零宽、图片修复）提高层次。
