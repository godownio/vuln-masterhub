---
id: code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt
title: CryptoAPI SHA1 派生 40 位 RC4 密钥解密恶意样本配置：CryptDeriveKey 0x280011 参数与离线复现
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: cryptapi-sha1-rc4-config-decrypt
aliases:
- CryptDeriveKey 0x280011
- CALG_RC4 配置解密
- CryptoAPI RC4
- SHA1 派生 RC4 密钥
- 恶意样本配置解密
- Hancitor 配置
- CyberChef RC4 解密
tags:
- reverse
- obfuscation
- string-encryption
- cryptoapi
- rc4
- sha1
- cryptderivekey
- config-extraction
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:41:40+08:00'
  notes: 已对照原文与截图核对：sub_10001CB7 将 unk_10004018 的 0x2000 字节复制到堆缓冲并调 sub_10002131(...,&pbData,8u)；CryptoAPI 序列 CryptAcquireContextA(PROV_RSA_FULL,CRYPT_VERIFYCONTEXT)→CryptCreateHash(CALG_SHA1)→CryptHashData(8字节)→CryptDeriveKey(CALG_RC4,0x280011)→CryptDecrypt 与卡一致；种子 C5 8B 00 15 7F 8E 92 88，实测 SHA1=11f668918f469d61362f3aacc9f93117d2a1096b，前5字节 11f668918f；CyberChef RC4 解出 1910_nsw + newnucapi.com/gintlyba.ru/stralonz.ru 的 /8/forum.php，与卡一致。未验证点：未本机运行样本，仅复算 SHA1；无产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

恶意样本用 Windows CryptoAPI 把内置 `pbData` 种子做 SHA1，再以 `CryptDeriveKey(CALG_RC4, 0x280011)` 派生密钥、`CryptDecrypt` 原地解密配置；`0x280011` 的高 16 位 `0x28` 表示 40 位（5 字节）RC4 密钥、低 16 位 `0x11` 为 `CRYPT_EXPORTABLE|CRYPT_NO_SALT`，因此用 `pbData` 的 SHA1 前 5 字节作为 RC4 密钥即可离线还原 C2 配置。

## 原理

- 样本把配置密文放在 `.data`/`.rdata` 的固定偏移（原文为 `unk_10004018`，长度 0x2000），运行时复制到堆缓冲区后原地解密，避免配置以明文形式出现在磁盘和静态字符串中。
- 解密函数按固定顺序调用 CryptoAPI：
  1. `CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)`：创建临时加密上下文，不使用持久密钥容器。
  2. `CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)` + `CryptHashData(hHash, pbData, 8, 0)`：对 8 字节种子做 SHA1。
  3. `CryptDeriveKey(hProv, CALG_RC4, hHash, 0x280011, &hKey)`：从 SHA1 哈希派生 RC4 密钥。
  4. `CryptDecrypt(hKey, 0, TRUE, 0, 密文, &长度)`：原地解密；RC4 是流密码，密文与明文等长。
- 关键在 `CryptDeriveKey` 的 `dwFlags = 0x280011`：
  - 高 16 位 `0x28 = 40`：密钥长度 40 位，即 5 字节；
  - 低 16 位 `0x11 = CRYPT_EXPORTABLE(0x1) | CRYPT_NO_SALT(0x10)`：密钥可导出且不使用盐；
  - 因此实际 RC4 密钥就是 `SHA1(pbData)` 的前 5 字节，不存在额外的盐或 KDF 迭代。
- 这是“配置/字符串加密”的常见低成本实现：算法标准、参数硬编码、密文与种子都在样本内，逆向者只要识别 API 序列和 flag 就能离线解密，不需要运行样本。
- 原文样本的种子为 8 字节 `C5 8B 00 15 7F 8E 92 88`，SHA1 为 `11f668918f469d61362f3aacc9f93117d2a1096b`，取前 5 字节 `11 f6 68 91 8f` 作为 RC4 密钥，解密 0x2000 字节后得到以 `1910_nsw` 开头、`|` 分隔的多个 C2 URL。

## 触发条件

- 样本为 PE（32/64 位均可），导入表包含 `CryptAcquireContextA/W`、`CryptCreateHash`、`CryptHashData`、`CryptDeriveKey`、`CryptDecrypt` 组合。
- 存在固定偏移的大块高熵数据，运行时被复制到堆缓冲区并传给 `CryptDecrypt`。
- `CryptDeriveKey` 的算法为 `CALG_RC4`（0x6801），flag 为 `0x280011`（或其他高位指定密钥长度、低位带 `CRYPT_NO_SALT` 的组合）。
- 种子 `pbData` 与长度在调用点可见（常见 8/16/32 字节）。

## 利用步骤

1. 在 IDA 中定位 `CryptDecrypt` 调用，回溯其 `hKey` 来源至 `CryptDeriveKey`，记录算法 ID 与 `dwFlags`。
2. 回溯 `CryptHashData` 的 `pbData` 与 `dwDataLen`，从数据段读取种子字节。
3. 回溯密文缓冲区来源：通常是 `memcpy`/`datacopy` 从 `unk_xxx` 复制固定长度到 `HeapAlloc` 的缓冲区。
4. 解析 flag：`key_bits = flags >> 16`，`key_bytes = key_bits // 8`；确认低 16 位是否含 `CRYPT_NO_SALT`。
5. 按 `SHA1(seed)[:key_bytes]` 得到 RC4 密钥，用标准 RC4 解密整段密文（或按 CyberChef：From Hex → SHA1 → 取前 5 字节 hex 作为 RC4 Passphrase → RC4 解密）。
6. 取输出中的可打印前缀（遇 `\0` 截断），提取 C2 域名/URL、构建号、开关等配置。
7. 将配置与网络行为交叉验证（域名解析、User-Agent、POST 路径），确认解密正确。

## PoC

CyberChef 复现（原文做法）：

```text
输入 Hex:      C58B00157F8E9288
操作 1 From Hex
操作 2 SHA1            -> 11f668918f469d61362f3aacc9f93117d2a1096b
取前 5 字节 hex:       11f668918f
操作 3 RC4，Passphrase 填 11f668918f（Hex），Input/Output 均为 Hex/Latin1
输入 0x2000 字节密文 -> 明文: 1910_nsw http://newnucapi.com/8/forum.php|http://gintlyba.ru/8/forum.php|http://stralonz.ru/8/forum.php|
```

等价的 Python 复现：

```python
import hashlib
from Crypto.Cipher import ARC4

seed = bytes.fromhex("C58B00157F8E9288")
key = hashlib.sha1(seed).digest()[:5]          # 0x28 -> 40-bit RC4 key

with open("config.bin", "rb") as f:
    ciphertext = f.read()

plain = ARC4.new(key).decrypt(ciphertext)      # CryptoAPI CALG_RC4, no salt
print(plain.split(b"\x00", 1)[0].decode("latin1"))
```

说明：`Crypto.Cipher.ARC4` 为标准 RC4，与 CryptoAPI 在 `CRYPT_NO_SALT` 下的流密钥一致；若样本在 `CryptDecrypt` 前对缓冲区做了额外异或/分包，需要按实际代码调整。

## 变体与关联

- 变体：密钥长度由 flag 高位决定（如 `0x0080`=128 位、`0x0100`=256 位），取 SHA1/SHA256 前 16/32 字节。
- 变体：`CryptDeriveKey` 使用 `CALG_AES_256` 等分组算法时，需按 CryptoAPI 的派生规则生成 key/IV，不能直接套用“哈希前 N 字节”。
- 变体：不落盘只在内存解密时，可在 `CryptDecrypt` 返回后下断点，从缓冲区直接读取明文；或用 Frida hook `CryptDecrypt` 打印入参/出参。
- 关联：[[code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump]]（同一 Hancitor 样本的脱壳与 PE 修复流程）；[[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]（同为恶意样本的静态数据还原）；[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（轻量字符串混淆的还原思路）。
- 关联：40 位 RC4 密钥空间很小，但本场景不需要暴力破解——种子和派生参数都在样本内，直接重算即可。

## 检测与防御

- 检测（分析侧）：导入表中同时出现 `CryptAcquireContext`、`CryptCreateHash`、`CryptDeriveKey`、`CryptDecrypt`，且 `CryptDeriveKey` 使用 `CALG_RC4` 与 `CRYPT_NO_SALT`，是配置加密的高置信特征；结合高熵 `.data` 与固定偏移拷贝。
- 检测（防御侧）：监控进程调用 CryptoAPI 解密自身数据段后立即发起网络请求的行为链；对含 `CALG_RC4` 的二进制可用 YARA 匹配 API 组合与 flag 常量。
- 防御：该手法只是提高静态分析成本，不构成安全边界；敏感配置应使用平台级密钥管理或服务端下发，避免把长期密钥与密文一起打包。
- 响应：提取配置后封禁 C2 域名/IP，更新检测规则；若样本使用相同种子派生多份配置，检查同家族其他变体。
