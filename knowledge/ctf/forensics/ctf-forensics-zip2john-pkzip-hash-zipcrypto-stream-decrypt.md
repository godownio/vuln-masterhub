---
id: ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt
title: zip2john $pkzip$ 哈希 + 已知密码：直接解密 ZipCrypto 流恢复压缩包内容
type: scenario
domain: ctf
path: ctf/forensics
technique: zip2john-pkzip-hash-zipcrypto-stream-decrypt
aliases:
- zip2john
- $pkzip$ 哈希
- pkzip hash
- ZipCrypto 流解密
- 从哈希恢复压缩包内容
- zip2john2zip
- 已知密码解 ZIP
tags:
- ctf
- forensics
- zip
- zipcrypto
- pkzip
- zip2john
- known-password
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:49:53+08:00'
  notes: 已对照原文与全部 14 张图核对：$ 字段解析（parts[-2]）、ZipCrypto 三键算法、12 字节加密头丢弃、示例恢复出 Welcome to the V&N family 均吻合；PoC 按原文脚本重写，未在本机执行
---

## 一句话结论

`zip2john` 会把 ZipCrypto 加密的 ZIP 条目转换成 `$pkzip$...$` 哈希，其中包含一段原始加密数据；只要已知密码（爆破、泄露或从 C2 流量中拿到），即使没有原 ZIP 文件，也能按 ZipCrypto 的三键算法用密码生成 keystream、解密哈希里的密文，丢弃前 12 字节加密头，恢复该条目的明文。

## 原理

- **zip2john 的产物**：John/hashcat 需要可比较的哈希，zip2john 会把 ZIP 的加密条目、CRC、压缩/未压缩大小、加密数据等打包成 `$pkzip$` 格式；例如
  `...:$pkzip$1*2*2*0*25*19*2d251cff*0*42*0*25*61e5*<加密hex>*$/pkzip$:...`
  其中最后一个 `*` 字段（脚本里的 `parts[-2]`）就是该条目的加密数据。
- **ZipCrypto 三键算法**：传统 ZIP 加密维护三个 32 位 key：
  - 初始 `key0=0x12345678`、`key1=0x23456789`、`key2=0x34567890`；
  - 每读入一个密码字节：`key0 = crc32(key0, byte)`，`key1 = (key1 + (key0 & 0xff)) * 0x08088405 + 1`，`key2 = crc32(key2, key1 >> 24)`；
  - 每字节 keystream：`temp = (key2 & 0xffff) | 3`，`((temp * (temp ^ 1)) >> 8) & 0xff`；
  - 解密：`plaintext = ciphertext ^ keystream`，然后用明文字节更新三个 key。
- **12 字节加密头**：ZipCrypto 在文件数据前先加密 12 字节随机头（用于校验密码），解密后必须丢弃这 12 字节，后面的才是条目内容；脚本中的 `[12:]` 就是做这件事。
- **为什么哈希能恢复内容**：`$pkzip$` 哈希里保留了足够的加密数据（通常是一个条目的一段），而 ZipCrypto 是对称流式加密；知道密码就能重建 keystream，不需要原 ZIP 的本地文件头/目录。若条目使用 deflate 压缩，解密后还需 `zlib.decompress(..., -15)` 才能得到原始文件。
- **与明文攻击的区别**：本文是“已知密码”直接解；若不知道密码但有已知明文（如 ZIP 中已知文件），可用 ZipCrypto 明文攻击恢复 key，再解其他条目；两者都依赖 ZipCrypto 的弱设计。

## 触发条件

- 拿到 `zip2john` 生成的 `$pkzip$` 哈希（通常来自 CTF 附件/取证镜像）。
- 已知该 ZIP 的密码：爆破成功、从流量/配置/笔记中泄露，或题目直接给出。
- ZIP 使用传统 ZipCrypto 加密，而非 AES/ZipCrypto-AES；哈希中包含加密数据。
- 条目数据未被额外加密/分卷；若为 deflate，需要对应解压。

## 利用步骤

1. 生成哈希：`zip2john target.zip > ziphash`；查看是否以 `$pkzip$` 开头（ZipCrypto）还是 `$zip2$`/AES 标记。
2. 获得密码：用 `john --wordlist=... ziphash`、`hashcat -m 17200/17210/17220/17225` 爆破，或从流量/配置/题目提示中取得。
3. 解析哈希：按 `:$pkzip$` 与 `*$/pkzip$` 切出主体，按 `*` 分割，取倒数第二个字段作为加密数据 hex（字段位置可能随 zip2john 版本变化，需打印确认）。
4. 用密码初始化 ZipCrypto 三键，逐字节解密；丢弃前 12 字节加密头。
5. 若条目是 deflate 压缩，用 raw deflate 解压；若是 store，直接得到文件内容。
6. 校验 CRC/文件头，确认恢复内容正确；必要时对多个条目重复。

## PoC

最小 ZipCrypto 流解密（按原文脚本重写，未在本机执行）：

```python
def crc32_byte(crc, b):
    crc = (crc ^ b) & 0xffffffff
    for _ in range(8):
        crc = ((crc >> 1) ^ 0xedb88320) if (crc & 1) else (crc >> 1)
    return crc & 0xffffffff

def decrypt_zipcrypto(data, password):
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

    def update(b):
        nonlocal k0, k1, k2
        k0 = crc32_byte(k0, b)
        k1 = (((k1 + (k0 & 0xff)) * 0x08088405) & 0xffffffff) + 1 & 0xffffffff
        k2 = crc32_byte(k2, (k1 >> 24) & 0xff)

    for b in password:
        update(b)

    out = bytearray()
    for c in data:
        t = (k2 & 0xffff) | 3
        ks = (((t * (t ^ 1)) & 0xffff) >> 8) & 0xff
        p = c ^ ks
        out.append(p)
        update(p)
    return bytes(out)

# 从 $pkzip$ 哈希取加密数据（字段位置需按实际哈希确认）
h = open("ziphash").read().strip()
body = h.split(":$pkzip$")[1].split("*$/pkzip$")[0] + "*"
enc = bytes.fromhex(body.split("*")[-2])

plain = decrypt_zipcrypto(enc, b"<password>")[12:]   # 丢弃 12 字节加密头
print(plain)
```

原文示例中恢复出的内容为 `Welcome to the V&N family`；具体哈希字段、密码与是否 deflate 需按题目调整。

## 变体与关联

- 变体：密码未知时先用 john/hashcat 爆破；有已知明文时改用 ZipCrypto 明文攻击恢复 key。
- 变体：ZIP 使用 AES-256（WinZip AES）时 `$pkzip$` 不适用，需要 `$zip2$` 哈希与对应模式。
- 变体：多条目 ZIP 需分别解析每个条目的哈希/加密数据；分卷 ZIP 需先合并。
- 关联：[[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]（ZipCrypto 明文攻击）、[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（ZipCrypto 嵌套链）、[[defense-forensics-vshell-config-aes-cbc-traffic-aes-gcm-decrypt]]（从 C2 流量中取得 ZIP 密码的上一阶段）。
- 边界：哈希不完整/条目被截断、密码错误（前 12 字节校验失败）、AES ZIP、deflate 未解压时会得到乱码。

## 检测与防御

- CTF 识别：拿到 `$pkzip$` 哈希时优先尝试已知密码/字典；注意 12 字节加密头与 deflate。
- 防御：不要使用传统 ZipCrypto，改用 AES-256 ZIP 或 7z/age 等现代加密；使用强密码并避免在流量/配置中明文传输；压缩包加密不能替代传输层加密。
- 取证：保留原始哈希与 ZIP，记录 zip2john/hashcat 版本与密码来源；恢复内容后用 CRC 校验完整性。
