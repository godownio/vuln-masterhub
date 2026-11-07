---
id: ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz
title: 图片尾部附加 ZIP 链：foremost 分离 + 伪加密修复 + PCZ 嵌套 ZIP 取 BMP flag
type: scenario
domain: ctf
path: ctf/misc
technique: image-appended-zip-pseudo-encryption-nested-pcz
tags:
- ctf
- misc
- stego
- zip
- foremost
- pseudo-encryption
- pcz
- jpeg
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/ctf/misc/ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz/
draft: false
kb_aliases:
- JPG 尾部 ZIP
- foremost 分离
- ZIP 伪加密
- PCZ 嵌套压缩包
- BMP flag
- 图片多语义
---

## 一句话结论

一张能正常打开的 JPG，如果在 `FF D9` 之后还跟着 `50 4B 03 04`，它同时是一个 ZIP。用 010/binwalk 确认尾部 ZIP 偏移，`foremost` 或按偏移切出压缩包；若解压提示密码，先检查本地文件头的 general purpose bit flag 是否只是伪加密（bit0 被置位），清零后即可解压得到 `.PCZ`。PCZ 本身又是 ZIP，重复一次“改后缀/伪加密修复”，即使 CRC 校验报错也能浏览目录，最终在 `bmp/` 下的图片里读取 flag。

## 原理

- **文件格式多语义**：JPEG 以 `FF D8` 开头、`FF D9` 结尾；解析器读到 EOI 就停止，后面的字节被忽略。攻击者/出题人把 ZIP 直接追加在 EOI 后，图片查看器正常显示，压缩软件按 `PK` 魔数也能识别。
- **ZIP 伪加密**：ZIP 本地文件头偏移 6-7 是 general purpose bit flag，bit0 表示加密；某些题只把 bit0 置 1（常见 `09 00`/`01 00`），但数据并未真正加密，也没有正确密码校验。把 bit0 清零（或让 WinRAR 修复）即可解压。
- **PCZ 还是 ZIP**：`.PCZ` 是某组态软件的工程包扩展名，本质仍是 ZIP（`PK\x03\x04`）；改名为 `.zip` 或用 7-Zip 直接打开即可。它可能再次带伪加密标志。
- **CRC 错误不等于不可读**：伪加密/头部修复后，中央目录记录的 CRC 可能与数据不一致，解压器会报 CRC 错误；但 ZIP 是流式/按偏移读取，很多工具仍能列出并提取文件。优先看目录结构和文件内容，不要因 CRC 报错放弃。
- **为什么成立**：ZIP 的目录/本地头自描述，伪加密只改标志位；图片解析器忽略尾随数据；多层容器只是重复同一套识别/修复流程。

## 触发条件

- 图片能正常打开，但 `binwalk`/`foremost` 报告尾部有 ZIP，或十六进制在 EOI 后出现 `PK\x03\x04`。
- ZIP 打开提示密码，但本地头 bit0 置位、数据段没有真正加密特征（method 不是 99/AES）。
- 解压得到 `.PCZ`/其它后缀，文件头仍是 `PK\x03\x04`。
- 需要从多层容器中取最终文件（图片/文本/flag）。

## 利用步骤

1. 用 010/`xxd` 查看图片尾部：找 `FF D9` 后的 `50 4B 03 04`，记录偏移。
2. `foremost -i flag.jpg -o out` 或 `binwalk -e flag.jpg` 分离尾部 ZIP；也可用 `dd if=flag.jpg of=out.zip bs=1 skip=<offset>`。
3. 用 7-Zip/WinRAR 打开 ZIP；若提示密码，定位本地头偏移 6-7 的标志位，把 `09 00`/`01 00` 改为 `00 00`（只清 bit0，保留其它必要位），同步检查中央目录。
4. 解压得到 `天然气运维系统.PCZ`；`file`/`xxd` 确认它是 ZIP，改名为 `.zip` 或用 7-Zip 直接打开。
5. 若再次提示密码，重复伪加密修复；忽略 CRC 错误，浏览目录结构。
6. 在 `bmp/` 等目录中找图片，用图片查看器/StegSolve 查看，读取 flag 或继续隐写分析。
7. 保留每一层的哈希与偏移，便于复现和证明容器关系。

## PoC

```bash
# 1) 找尾部 ZIP 偏移
binwalk flag.jpg
# 2) 分离（foremost 或按偏移 dd）
foremost -i flag.jpg -o out
# 3) 伪加密修复：把本地头 bit0 清零（示意，实际用 010/脚本）
python - <<'PY'
data = bytearray(open("out/zip/00001479.zip", "rb").read())
# 本地头签名 50 4B 03 04 后偏移 6-7 为 flag
assert data[:4] == b"PK\x03\x04"
data[6] &= ~0x01
open("fixed.zip", "wb").write(data)
PY
# 4) 解压 PCZ，再按 ZIP 处理
7z x fixed.zip
file 天然气运维系统.PCZ
```

说明：不同 ZIP 版本的标志位/中央目录位置可能不同；修改前备份，优先用 WinRAR“修复压缩文件”自动处理。

## 变体与关联

- 变体：PNG/GIF/BMP 尾部附加 ZIP；或在图片 EXIF/comment 中藏 Base64 压缩包。
- 变体：ZIP 真加密（ZipCrypto/AES），需要密码爆破/已知明文攻击；伪加密修复无效。
- 变体：多层嵌套（ZIP→PCZ→ZIP→图片），每层重复识别魔数/修复标志。
- 关联：[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（ZIP 本地头损坏与伪加密修复的详细字节级方法）；[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（嵌套 ZIP/CRC 链）；[[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]（binwalk 尾随 ZIP + 明文攻击）。

## 检测与防御

- 检测：文件类型与扩展名不一致；图片 EOI 后仍有数据；`binwalk`/`foremost` 报告尾随归档。
- 检测：ZIP 本地头 bit0 置位但压缩方法/数据不符合真加密；中央目录与本地头标志不一致。
- 防御：上传/邮件网关做文件类型嗅探与多语义检测，不只按扩展名；对图片做重编码以剥离尾随数据。
- 防御：解压前用沙箱/只读环境；对嵌套容器递归扫描，不要只检查第一层。
