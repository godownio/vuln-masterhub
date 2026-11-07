---
id: ctf-forensics-zipcrypto-png-header-known-plaintext-bkcrack
title: ZipCrypto 已知明文攻击：用 PNG 文件头 16 字节 bkcrack 恢复密钥
type: scenario
domain: ctf
path: ctf/forensics
technique: zipcrypto-png-header-known-plaintext-bkcrack
aliases:
- bkcrack PNG 文件头明文攻击
- ZipCrypto known plaintext PNG
- 已知 PNG 头解 ZIP
- bkcrack -C -c -p
- zip 明文攻击 89504E47
tags:
- ctf
- forensics
- zip
- zipcrypto
- bkcrack
- known-plaintext
- png
- password-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:23+08:00'
  notes: 已对照原文与图 14 核对：ZipCrypto Store、PNG 头 16 字节、bkcrack -C/-c/-p、-k 导出 flag.txt 一致；未复跑附件。
---

## 一句话结论

ZipCrypto 加密 ZIP 中若包含 PNG 图片，而该条目使用 Store（method 0）保存，则文件开头的 16 字节固定为 PNG 签名 + IHDR 块名 `89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52`；把这 16 字节作为已知明文，用 `bkcrack -C <zip> -c <entry> -p <header>` 即可恢复 ZipCrypto 的 3 个内部密钥，再用 `-k` 解密条目或 `-U` 重打包，读出 flag。

## 原理

- **ZipCrypto 的流式密钥**：传统 ZIP 加密（ZipCrypto）维护 3 个 32 位密钥，加密时先生成 12 字节加密头，再对压缩数据逐字节异或 keystream。已知足够长的连续明文可以反推出 3 个密钥；bkcrack 用 Z 值归约把搜索空间压到可计算范围。
- **为什么 PNG 头可用**：PNG 文件前 8 字节是固定魔数 `89 50 4E 47 0D 0A 1A 0A`，随后是第一个数据块 `IHDR` 的长度 `00 00 00 0D` 和类型 `49 48 44 52`，共 16 字节完全固定；正常 PNG 都相同，因此是天然的已知明文。
- **必须区分 Store 与 Deflate**：bkcrack 的已知明文针对的是 ZIP 条目实际加密的字节。Store 模式下加密的就是原文件，PNG 头直接可用；Deflate 模式下加密的是压缩后的数据，压缩流开头并不是 PNG 头（`89 50...`），此时需要已知压缩流片段或改用其他方法。原文用 `bkcrack -L` 确认两个条目都是 `ZipCrypto Store`，才直接用 PNG 头攻击。
- **偏移与长度**：已知明文必须在条目内的正确偏移处。PNG 头位于文件偏移 0，因此不需要 `-o`；bkcrack 会从条目起点开始匹配。已知明文至少 8 字节，通常 12 字节以上更稳；本题 16 字节足够。
- **恢复密钥后的两种用法**：`-U <newzip> <password>` 用恢复的密钥把 ZIP 重打包并设置新密码，之后正常解压；`-c <entry> -d <out>` 直接解密该条目到文件，无需知道原密码。
- **为什么能成功**：ZipCrypto 元数据（含 CRC32）明文存储，加密流本身可被已知明文攻击；PNG 头固定且可预测，攻击者无需知道原密码即可恢复内部密钥。

## 触发条件

- ZIP 使用传统 ZipCrypto 加密（不是 AES-256/WinZip AES），且目标条目压缩方式为 Store，或能获得 Deflate 压缩流中的已知明文片段。
- ZIP 内含 PNG 等具有固定文件头的文件，且该文件在压缩包中的偏移/长度可知。
- 能运行 bkcrack（或等价工具），并有足够 CPU 时间（取决于已知明文字节数与数据量）。
- 已知明文至少 8 字节（bkcrack 要求），12 字节以上成功率更高。

## 利用步骤

1. 查看压缩包结构：`bkcrack -L attachment.zip`，确认加密方式 `ZipCrypto`、压缩方式 `Store`（或 `Deflate`）、条目名与大小。
2. 构造已知明文文件：`echo 89504E470D0A1A0A0000000D49484452 | xxd -r -ps > pngheader`。
3. 执行攻击：`bkcrack -C attachment.zip -c huiliyi.png -p pngheader`，等待输出 `Keys: <k1> <k2> <k3>`。
4. 用密钥解密：
   - 重打包：`bkcrack -C attachment.zip -k <k1> <k2> <k3> -U flag.zip 123456`，再用 `123456` 解压；
   - 或直接导出：`bkcrack -C attachment.zip -k <k1> <k2> <k3> -c flag.txt -d flag.txt && cat flag.txt`。
5. 若条目是 Deflate 且导出后是 raw deflate 流，用 `zlib.decompress(data, -15)` 或 CyberChef Raw Inflate 解压。

## PoC

```bash
# 1. 确认加密/压缩方式
bkcrack -L attachment.zip
# 0 ZipCrypto Store e7b7038a 80 92 flag.txt
# 1 ZipCrypto Store 04a6dc2d 10149855 10149867 huiliyi.png

# 2. 生成 16 字节 PNG 已知明文
echo 89504E470D0A1A0A0000000D49484452 | xxd -r -ps > pngheader

# 3. 已知明文攻击
bkcrack -C attachment.zip -c huiliyi.png -p pngheader
# Keys: cdc564be 5675041f 719adb56

# 4. 解密
bkcrack -C attachment.zip -k cdc564be 5675041f 719adb56 -c flag.txt -d flag.txt
cat flag.txt
```

说明：PoC 为原文命令的最小化复现，未在本机执行；原文用上述 16 字节 PNG 头恢复了 3 个密钥，并直接导出 `flag.txt`。

## 变体与关联

- 变体（已知明文来源）：ZIP 内两个压缩包存在 CRC32 相同的同一文件；已知 JSON/XML 开头、固定文件头（PDF、ZIP、ELF）、明文日志；短文件的 CRC32 爆破/反转结果。
- 变体（压缩方式）：Store 直接用原文件头；Deflate 需要已知压缩流片段，或先通过 CRC32 恢复短文件内容再作为已知明文。
- 变体（工具）：bkcrack `-U` 重打包、`-d` 裸导出、`-o` 指定偏移；pkcrack 等老工具。
- 关联：[[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]（bkcrack 已知文件明文攻击）；[[ctf-forensics-bkcrack-d-raw-inflate-nested-zip]]（`-d` 输出 raw deflate 的后续处理）；[[ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt]]（已知密码解密 ZipCrypto 流）；[[ctf-misc-crc32-four-byte-preimage-gf2-linear]]（CRC32 短文件明文恢复）；[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]。
- 边界：AES 加密 ZIP、条目使用 Deflate 且无已知压缩流、已知明文不足 8 字节或偏移不对、密码/密钥派生复杂度超出工具能力时，bkcrack 不适用。

## 检测与防御

- 检测：压缩包内出现 Store 的 PNG/固定头文件；攻击者反复调用 bkcrack（CPU 占用高）或生成 `pngheader` 等已知明文文件；短时间内对同一 ZIP 多次解密尝试。
- 防御：使用 AES-256 ZIP 加密（如 7-Zip/WinZip AES）替代 ZipCrypto；使用强密码与密钥派生；避免在加密压缩包中放入可预测内容作为已知明文；对敏感归档使用专用加密容器并限制分发。
