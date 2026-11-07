---
id: ctf-misc-jpeg-steghide-exif-elf-xor-pseudo-zip
title: JPEG 尾部 Base64 01 串 + EXIF 备注口令 steghide 提取：伪加密 ZIP 修复与 ELF 逐位 XOR 求压缩包口令
type: scenario
domain: ctf
path: ctf/misc
technique: jpeg-steghide-exif-elf-xor-pseudo-zip-chain
tags:
- ctf
- misc
- stego
- jpeg
- steghide
- exif
- pseudo-encryption
- zip
- elf
- xor
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:35:44+08:00'
  notes: 已对照原文 misc2 与 img14-26 核对：JPEG 尾部 Base64 解码得 64 位 01 串、EXIF 备注 jzxcvb123 作 steghide 口令得 test.zip、test 伪加密修复、ELF .rodata 64 位 01 串逐位 XOR（s[i]-48）、两串异或=HELLo123（已脚本复算）、flag DASCTF{qwe789qwe789} 一致。未验证点：steghide 与伪加密修复未复跑。
url: /docs/ctf/misc/ctf-misc-jpeg-steghide-exif-elf-xor-pseudo-zip/
draft: false
kb_aliases:
- steghide 隐写
- EXIF 备注作为口令
- 伪加密 ZIP 修复
- ELF 逐位 XOR 求密钥
- 图片尾部 Base64 01 串
- 你的人生需要翻转
---

## 一句话结论

一张 JPEG 的尾部藏着 Base64 编码的 64 位 01 串，EXIF 备注里藏着字符串 `jzxcvb123`，配合题目提示“斯蒂格德会帮助你”把它当作 steghide 口令，可提取出 test.zip；zip 内 test 是伪加密的 ELF，其 main 用 `.rodata` 中另一段 64 位 01 串对输入逐位 XOR，把两段 01 串异或得到 `HELLo123`，即为 zip 内 flag.txt 的口令。

## 原理

- **图片尾部附加数据**：JPEG 以 `FFD9` 结束，之后可追加任意字节；本题在 `x.jpeg` 尾部放了一串 Base64，解码后得到 64 位二进制字符串。这类附加数据不会被图片查看器显示，但用 010/`tail` 可发现。
- **EXIF 备注作为隐写口令**：图片属性“备注”字段为 `jzxcvb123`；题目提示“你的人生需要翻转，斯蒂格德会帮助你的”中的“斯蒂格德”即 steghide，提示把备注字符串作为 `steghide extract -sf x.jpeg` 的 passphrase，提取出 `test.zip`。
- **伪加密 ZIP**：test.zip 中 `test` 文件的本地文件头/数据区加密标志被置位，但中央目录未加密（或反之），属于“伪加密”；用伪加密修复工具修改标志位即可正常解出 ELF，不需要真实口令。
- **ELF 逐位 XOR**：test 的 main 读取输入字符串 s，对每个字符执行 `v8[i] = key[i % 64] ^ (s[i] - 48)`，再与目标字节比较；`.rodata` 中的 64 位 01 串就是 key。因为输入是 01 字符，`s[i]-48` 即 0/1。
- **两段 01 串异或得口令**：把图片尾部解码出的 64 位串与 ELF 的 64 位 key 逐位异或，得到 8 个字节 `01001000 01100101 01001100 01001100 01101111 00110001 00110010 00110011` = `HELLo123`，正好是 test.zip 中 flag.txt 的口令。
- **根因**：这是 CTF 谜题的多层信息隐藏，不是软件漏洞；复用价值在于“图片元数据/尾部数据 → steghide → 伪加密修复 → ELF 常量 XOR → 压缩包口令”的排查顺序。

## 触发条件

- CTF misc 题提供图片，尾部/元数据可能有附加信息。
- 环境有 steghide（需要口令）、010 Editor/xxd、伪加密修复工具（如随波逐流）、IDA。
- zip 同时包含可执行文件与加密文本，且可执行文件中的常量与图片尾部数据长度一致（提示 XOR 关系）。

## 利用步骤

1. 用 010/`xxd` 查看 JPEG 头部与尾部；在 `FFD9` 后提取 Base64 串并解码，得到 64 位 01 串。
2. 查看 EXIF/文件属性“备注”，得到 `jzxcvb123`；结合提示“斯蒂格德”判断为 steghide 口令。
3. 执行 `steghide extract -sf x.jpeg`，输入口令，得到 `test.zip`。
4. 用伪加密修复工具检查 test.zip：若 `test` 的加密标志与中央目录不一致，修复后解出 ELF。
5. 用 IDA 分析 ELF 的 main：找到 `.rodata` 中的 64 位 01 串，确认 XOR 逻辑 `out[i]=key[i%64]^(input[i]-48)`。
6. 把图片尾部 01 串与 ELF key 逐位异或，得到 ASCII 口令 `HELLo123`。
7. 用该口令解压 test.zip 中的 flag.txt，得到 flag。

## PoC

```bash
# 1. 提取图片尾部 Base64 并解码为 01 串
tail -c 200 x.jpeg | base64 -d

# 2. EXIF 备注（Windows 属性或 exiftool）
exiftool x.jpeg | grep -i comment   # jzxcvb123

# 3. steghide 提取
steghide extract -sf x.jpeg         # passphrase: jzxcvb123 -> test.zip

# 4. 伪加密修复（随波逐流/zip 工具），解出 test 与 flag.txt

# 5. IDA 查看 test 的 main 与 .rodata 64 位 key
# 6. 两段 01 串异或
python -c "a='1100111011100101000110111101000010001011001010110110001001100110'; b='1000011010100000010101111001110011100100000110100101000001010101'; print(''.join('1' if x!=y else '0' for x,y in zip(a,b)))"
# 0100100001100101010011000100110001101111001100010011001000110011 -> HELLo123
```

原文用该口令解压得到 `flag.txt`：`DASCTF{qwe789qwe789}`。

## 变体与关联

- 隐藏位置变体：JPEG 尾部、EXIF Comment/UserComment、PNG tEXt/iTXt、文件属性、缩略图。
- 提取工具变体：steghide、outguess、zsteg、binwalk、foremost；口令可能来自图片元数据、题目提示或另一层编码。
- ZIP 变体：伪加密、ZipCrypto 弱口令、明文攻击、嵌套 zip；先修复标志位再考虑爆破。
- 密钥恢复变体：ELF/PE 常量与图片尾部数据等长，逐位/逐字节 XOR、加减、RC4 等；先找长度一致的常量。
- 关联卡片：[[ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz]]、[[ctf-misc-jpeg-segment-metadata-stego]]、[[ctf-misc-png-trailing-data-lcg-xor-base62]]、[[ctf-reverse-elf-stack-constants-xor-hidden-flag]]。
- 边界：若 steghide 口令错误会直接失败；伪加密修复只对标志位错位有效，真实加密仍需口令/爆破。

## 检测与防御

- 这是 CTF 解题流程，不涉及生产系统防御；企业侧对应风险是“图片/文档元数据泄露敏感信息”。
- 对外发布图片前剥离 EXIF/注释、缩略图与尾部附加数据；使用 `exiftool -all=` 或图像库重新编码。
- 文件上传/处理服务应限制文件尾随数据、校验图片真实结构，避免把附加内容当作合法数据。
- 压缩包加密应使用真实加密（AES/ZipCrypto）并保护口令，不要依赖伪加密标志位。
