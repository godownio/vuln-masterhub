---
id: ctf-forensics-bkcrack-d-raw-inflate-nested-zip
title: bkcrack -d 解出的条目仍是 raw deflate：Raw Inflate 还原内层 ZIP 后再处理口令
type: scenario
domain: ctf
path: ctf/forensics
technique: bkcrack-d-raw-inflate-nested-zip
tags:
- ctf
- forensics
- zip
- zipcrypto
- bkcrack
- deflate
- raw-inflate
- nested-zip
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:02:34+08:00'
  notes: 已对照 90749 原文核对：bkcrack -d 只解密不 deconcatenate 压缩层、method 8 输出 raw deflate、CyberChef Raw Inflate/zlib -15、method 字段偏移 8-9 与 10-11、内层 2 字节口令枚举、zpaq 尾提示均与原文一致。未复跑。
url: /docs/ctf/forensics/ctf-forensics-bkcrack-d-raw-inflate-nested-zip/
draft: false
kb_aliases:
- bkcrack -d 输出乱码
- raw inflate 还原 zip
- CyberChef Raw Inflate
- zlib.decompress -15
- 嵌套 ZIP 解压
- bkcrack 解密后仍是压缩流
---

## 一句话结论

`bkcrack -d` 只去掉 ZipCrypto 加密层，写出条目的原始数据；如果该条目的压缩方法是 deflate（method 8），输出就是一段 **raw deflate 流**，不是可直接打开的 ZIP。用 `zlib.decompress(data, -15)`（或 CyberChef 的 Raw Inflate）解压后，才会得到内层 ZIP；若内层 ZIP 还有短口令，再按 2 字节 65536 组合穷举或继续 bkcrack。

## 原理

- **ZIP 条目的两层处理**：写入 ZIP 时，文件先按压缩方法压缩（method 8 = deflate，method 0 = store），再对压缩后的字节做加密（ZipCrypto/AES）。读取时顺序相反：先解密，再解压。
- **bkcrack 的职责**：bkcrack 通过已知明文攻击恢复 ZipCrypto 的内部 key，然后用 key 解密条目数据。它只处理加密层，不知道也不负责解压；`-d <file>` 把解密后的字节原样写出。
- **为什么是 raw deflate**：ZIP 使用的 deflate 是“裸” deflate，不带 zlib 头（`78 9c` 等）和 Adler-32 尾；因此不能用普通的 `zlib.decompress(data)`（默认期望 zlib 包装），而要用 `zlib.decompress(data, -15)`（负 windowBits 表示 raw deflate）。CyberChef 的 “Raw Inflate” 操作等价。
- **store 条目**：如果 method=0，`-d` 输出就是原文件，直接可用；判断依据是 ZIP 本地头偏移 8-9 / 中央目录偏移 10-11 的 compression method 字段。
- **嵌套链**：解出内层 ZIP 后，它可能仍带密码（如本题 2 字节口令）或另一层压缩；可以继续用 `zipfile` 暴力枚举、bkcrack、或其它解压工具。注意嵌套层不一定是 ZIP，也可能是 zpaq/7z 等，文件尾/头部的提示也要检查。
- **与 `-U` 的区别**：`bkcrack -U` 会按条目信息重建一个解密后的 ZIP（通常更省事）；`-d` 是裸数据导出，适合需要手工处理压缩流/嵌套格式的场景。两者都可能需要后续解压，具体以 bkcrack 版本行为为准。

## 触发条件

- 已用 bkcrack 恢复 key，并用 `-d` 导出了条目数据。
- 导出的数据不以 `PK\x03\x04` 开头、`file`/`unzip` 无法识别，但 ZIP 头显示 compression method=8。
- 目标条目原本是一个压缩过的文件（如内层 ZIP、文本、图片），而不是 store。
- 需要继续分析内层数据（嵌套 ZIP、口令、隐写等）。

## 利用步骤

1. 在 ZIP 本地头偏移 8-9（或中央目录偏移 10-11）确认 compression method；8=deflate，0=store。
2. 用 bkcrack 解密并导出：
   ```bash
   bkcrack -C purezip.zip -c "secret key.zip" -k e63af7cc 55ef839d dc10b922 -d 1.bin
   ```
3. 先尝试 `file 1.bin`、`unzip -l 1.bin`；若提示不是 ZIP/数据，进入 raw inflate。
4. Python 解压：
   ```python
   import zlib
   raw = open("1.bin", "rb").read()
   out = zlib.decompress(raw, -15)   # raw deflate；若报错可试 zlib.decompress(raw)
   open("inner.zip", "wb").write(out)
   ```
   或在 CyberChef 中对输入做 `Raw Inflate`，把输出保存为文件。
5. 检查输出是否以 `PK\x03\x04` 开头；是则用 `unzip -l`/7-Zip 查看内层条目。
6. 若内层 ZIP 有口令且很短（如 2 字节），用 `zipfile` 枚举 0x00–0xFF × 0x00–0xFF；更长或字符集受限时用 bkcrack `-r`/字典。
7. 若内层是其它格式（zpaq/7z/RAR），按对应工具处理；注意检查文件尾部是否有题目提示（本题在 zpaq 文件尾给出“密码是 md5(明文密钥, 3 字节)”的提示）。

## PoC

```bash
# 1) bkcrack 解密条目，输出裸数据
bkcrack -C purezip.zip -c "secret key.zip" -k e63af7cc 55ef839d dc10b922 -d 1.bin

# 2) raw inflate 还原内层 ZIP
python - <<'PY'
import zlib
raw = open("1.bin", "rb").read()
open("inner.zip", "wb").write(zlib.decompress(raw, -15))
PY

unzip -l inner.zip
```

2 字节口令穷举（原文思路，逐个候选重新打开 zip，避免状态污染）：

```python
import zipfile

for i in range(256):
    for j in range(256):
        pwd = bytes([i, j])
        try:
            with zipfile.ZipFile("inner.zip", "r") as fz:
                fz.extractall(pwd=pwd)
            print("password:", pwd)
            raise SystemExit
        except Exception:
            continue
```

## 变体与关联

- **method 0（store）**：`-d` 输出即原文件，不需要 inflate；先看压缩方法再决定。
- **zlib 包装流**：若数据以 `78 9c`/`78 01`/`78 da` 开头，可能是 zlib 包装，使用 `zlib.decompress(data)`；ZIP 正常是 raw deflate，用 `-15`。
- **`-U` 重建 ZIP**：不想手工 inflate 时可让 bkcrack `-U` 生成解密后的归档；但嵌套/异常条目仍可能需要手工处理。
- **短口令**：2 字节直接穷举；更长可用 bkcrack `-r <len> <charset>` 或字典/掩码。
- **嵌套格式**：zpaq/7z/RAR 等按各自工具解；文件尾提示、注释、额外字段都可能是下一层线索。
- **关联**：[[ctf-forensics-pkzip-key-schedule-reverse-password]]（由 key 反推密码）、[[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]（bkcrack 明文攻击）、[[ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt]]（ZipCrypto 流解密）。

## 检测与防御

- **CTF 识别**：bkcrack `-d` 输出打不开、但 ZIP 方法是 deflate → 先 raw inflate；不要误以为解密失败。
- **工具使用**：解密和压缩是两层，任何“解密后仍是乱码”的问题都要先确认压缩方法；`zlib.decompress(..., -15)` 与 CyberChef Raw Inflate 是常用手段。
- **安全**：ZipCrypto 本身不安全；敏感归档使用 AES-256，且不要把已知明文文件放入归档，以免 key 被恢复后整包失守。
