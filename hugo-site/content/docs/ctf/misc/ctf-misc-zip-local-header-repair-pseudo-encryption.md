---
id: ctf-misc-zip-local-header-repair-pseudo-encryption
title: ZIP 本地文件头损坏与伪加密修复：补 50 4B 03 04 + 清零加密标志位
type: scenario
domain: ctf
path: ctf/misc
technique: zip-local-header-repair-pseudo-encryption
tags:
- ctf
- misc
- zip
- file-format
- pseudo-encryption
- header-repair
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:00:39+08:00'
  notes: 已对照原文ez_zip题与图02/03核对：图02的010高亮字节确为缺失后补回的前三字节 50 4B 03（其后 04 14 00 未高亮），说明本题只缺前3字节而非完整4字节魔数；原卡按补 50 4B 03 04 四字节写会让残余 04 重复，已在卡内修正结论/原理/步骤/PoC（区分 04 14 00 开头补 PK\x03 与其它情况补四字节）。伪加密部分：本地头偏移 4-5 为 14 00、6-7 为 09 00（bit0 置位），WinRAR 修复后解压得到 sdpcsec{n1ce_da1_fu!}，与图04一致。未在本机复跑；CTF题无组件版本。
url: /docs/ctf/misc/ctf-misc-zip-local-header-repair-pseudo-encryption/
draft: false
kb_aliases:
- ZIP 文件头修复
- 伪加密
- 504B0304
- 14000900
- WinRAR 修复
- ez_zip
---

## 一句话结论

当 ZIP 文件打不开时，先用十六进制确认本地文件头缺失的是哪几个字节（如本题文件以 `04 14 00` 开头，仅缺前三字节 `50 4B 03`），按缺失长度补齐为 `50 4B 03 04`（ZIP 魔数）；补回后若提示需要密码，再检查本地文件头偏移 6-7 的通用标志位（如 `09 00` 中的 bit0）是否为“伪加密”；把加密标志清零或让 WinRAR 修复，即可在不爆破密码的情况下解压。

## 原理

- **ZIP 本地文件头**：`50 4B 03 04`（`PK\x03\x04`）+ version + general purpose bit flag + compression method + mod time/date + CRC32 + compressed/uncompressed size + filename length + extra length + filename + extra + data。文件头缺失/截断时，解压器无法识别归档。补头时必须只补缺失的字节：若文件以 `04 14 00 ...` 开头，说明只缺前三字节 `50 4B 03`，补三字节即可；盲目补四字节会把残余的 `04` 重复一次。
- **伪加密**：ZIP 的“加密”由 general purpose bit flag 的 bit0 表示；有些题目只把这个 bit 置 1（常见字节 `09 00` 或 `01 00`），但没有真正加密数据/没有正确密码校验。把该 16 位标志清零（`00 00`），或让 WinRAR/7-Zip 的“修复”功能重写本地头，即可直接解压。
- **为什么能修**：ZIP 是自描述的；本地文件头/中央目录记录提供偏移与长度，补回魔数/清除标志位后，解压器按正常结构读取数据。若数据本身被真正加密（ZipCrypto/AES），清零标志位只会得到乱码，需要密码/明文攻击。
- **注意**：不能把中央目录的加密标志与本地头混淆；两边都要一致。修改后建议用 `unzip -t`/7-Zip 测试完整性。

## 触发条件

- ZIP 文件无法打开/提示损坏；十六进制显示开头不是 `50 4B 03 04` 或前几字节缺失。
- 补头后能打开但提示密码；本地文件头 general purpose bit flag 的 bit0 为 1（如 `09 00`），但数据可能未真正加密。
- 有 010 Editor/WinRAR/7-Zip 等工具；能修改字节。
- 目标不是 WinZip AES/强加密（method 99 + extra 0x9901），否则伪加密不成立。

## 利用步骤

1. 用 010/`xxd` 查看文件头；若文件以 `04 14 00 ...` 开头（缺前 3 字节），在开头补 `50 4B 03` 三字节，使文件以 `50 4B 03 04` 开头；其他截断情况按实际缺失长度补齐，注意不要重复已有字节。
2. 打开 ZIP；若提示密码，定位本地文件头偏移 6-7 的 general purpose bit flag。
3. 把 `09 00`/`01 00` 等改为 `00 00`（清除 bit0 加密标志；保留 bit3 data descriptor 等必要位时只清 bit0）。
4. 同步检查中央目录对应字段；或用 WinRAR“修复压缩文件”自动处理。
5. 重新解压；若仍失败，说明是真实加密，转 ZipCrypto/AES 爆破或明文攻击。
6. 本题补头 + WinRAR 修复后直接得到 flag。

## PoC

```python
from pathlib import Path

data = Path("flag.zip").read_bytes()
if not data.startswith(b"PK\x03\x04"):
    if data.startswith(b"\x04\x14\x00"):   # 仅缺前 3 字节：补 PK\x03，避免重复 04
        data = b"PK\x03" + data
    else:                                  # 其它截断情况按四字节魔数补齐
        data = b"PK\x03\x04" + data
    Path("flag_fixed.zip").write_bytes(data)

# 伪加密：把本地文件头 offset 6-7 的 bit0 清零（示例，按实际偏移调整）
raw = bytearray(Path("flag_fixed.zip").read_bytes())
flag = int.from_bytes(raw[6:8], "little") & ~1
raw[6:8] = flag.to_bytes(2, "little")
Path("flag_pseudo_fixed.zip").write_bytes(raw)
```

```bash
unzip -t flag_pseudo_fixed.zip   # 验证完整性
```

## 变体与关联

- **变体（中央目录损坏）**：EOCD/中央目录偏移错误时，用 `zip -FF`/WinRAR 修复；或手工按本地头扫描重建。
- **变体（真实 ZipCrypto）**：`bkcrack` 明文攻击（已知至少 12 字节明文）；或 ARCHPR 掩码/字典爆破。
- **变体（WinZip AES）**：method 99 + extra 0x9901，需要密码/掩码爆破，不能靠清标志位。
- **关联卡片**：[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（ZIP 嵌套/CRC 重叠）、[[ctf-forensics-office-doc-password-office2john-hashcat]]（Office 密码爆破）、[[web-generic-file-upload-zip-entry-nul-windows-truncation]]（ZIP 条目名截断）。
- **边界**：补头位置/长度必须正确；清除标志位后若 CRC/大小不匹配，可能仍需修复中央目录；真实加密不能伪修复。

## 检测与防御

- **CTF 识别**：ZIP 打不开先看魔数；能打开但要密码且标志位为 `09 00`，先试伪加密修复。
- **文件完整性**：真实场景用 `unzip -t`、哈希校验；不要信任来源不明的 ZIP。
- **安全**：伪加密不是安全机制；敏感归档使用真实加密（AES-256）+ 强密码，并校验完整性。
