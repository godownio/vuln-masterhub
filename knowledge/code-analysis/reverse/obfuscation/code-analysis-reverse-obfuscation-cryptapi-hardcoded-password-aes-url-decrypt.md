---
id: code-analysis-reverse-obfuscation-cryptapi-hardcoded-password-aes-url-decrypt
title: 加载器硬编码口令 + CryptoAPI AES-256-CBC 加密下载 URL：.rdata 无明文 C2，分析时用同一 password 派生密钥即可还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: cryptapi-hardcoded-password-aes-url-static-decrypt
aliases:
- CryptDeriveKey CALG_AES_256 URL 加密
- 硬编码 password 派生 AES key
- 加密下载地址 loader
- WinINet URL 静态加密
- CryptEncrypt CBC 零 IV
tags:
- reverse
- obfuscation
- string-encryption
- cryptoapi
- aes
- wininet
- loader
- ioc-extraction
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:52:36+08:00'
  notes: 已对照原文核对：EncryptDecryptUrl 的 CryptAcquireContext(PROV_RSA_AES,CRYPT_VERIFYCONTEXT)、CryptCreateHash(CALG_SHA_256)、CryptHashData(password,8)、CryptDeriveKey(CALG_AES_256, CRYPT_EXPORTABLE 或 256<<16)、CryptSetKeyParam(KP_MODE=CBC 与 KP_IV 全零 16 字节)、CryptEncrypt 与 CryptDecrypt 的末参 TRUE，以及按 wchar_t 长度处理明文、下载前先解密再 InternetOpenUrlW，均与正文一致；已修正 Python 还原片段里先 rstrip 零字节再去 padding 会吃掉 UTF-16 高位 0x00 的问题，改为按末字节截断 padding。本次核对未读取图片；离线脚本与 CryptDeriveKey 等价 SHA256 摘要截断到 32 字节这一简化假设均未实测；未编译原程序。
---

## 一句话结论

加载器把下载地址在编译期用 `CryptDeriveKey`（口令 `password` 经 SHA-256 派生）得到 AES-256 密钥、`CryptEncrypt` 以 CBC + 全零 IV 加密后硬编码进程序，运行时再用同一口令派生密钥 `CryptDecrypt` 还原字符串后交给 `InternetOpenUrlW`；这样 `.rdata` 里搜不到 C2 域名，但因为是**自带口令的对称加密**，分析者照抄同一段派生代码（或按「SHA-256(password) 前 32 字节 + 零 IV + CBC」离线复算）就能在几分钟内还原出真实 URL。

## 原理

- **派生链固定**：`CryptAcquireContext(PROV_RSA_AES, CRYPT_VERIFYCONTEXT)` → `CryptCreateHash(CALG_SHA_256)` → `CryptHashData(("password",8))` → `CryptDeriveKey(CALG_AES_256, hHash, CRYPT_EXPORTABLE | (256<<16))`。CryptoAPI 的派生算法是「哈希值截断/填充到密钥长度」，因此**口令 + 哈希算法 + 目标算法**唯一确定密钥，不需要样本里的其它数据。
- **加密模式**：`CryptSetKeyParam(KP_MODE, CRYPT_MODE_CBC)` 加 `KP_IV` 全零 16 字节。零 IV + 固定口令 ⇒ 同一明文每次加密结果相同（确定性），这也意味着密文可离线比对、可用 CyberChef/自写脚本直接解。
- **为什么能免静态特征**：明文字符串（`http://…/shellcode.exe`）不再出现在 `.rdata`，只以 `\x..` 密文数组或宽字符密文串形式存在；字符串扫描（`strings`、YARA 的 URL 正则、`grep -a http`）都拿不到 C2。
- **代价**：密钥完全由硬编码口令决定，逆向者在 `CryptHashData` 的 `CryptHashData(hHash, (BYTE*)"password", 8, 0)` 处一眼就能拿到口令；即使口令被拆分成多段/异或，也只是提高一点成本。这不是「密钥协商」，而是可逆的静态混淆。
- **宽字符陷阱**：示例把 `wchar_t` 缓冲区直接 `CryptEncrypt`（长度按 `url.length()*sizeof(wchar_t)`），密文里混着 UTF-16 的高零字节，解密后按 `wchar_t` 还原即可；离线复算时要注意按字节处理而不是按字符。

## 触发条件

- 加载器为 Windows 原生程序，使用 CryptoAPI（`advapi32!CryptAcquireContext` 等导入）与 WinINet/WinHTTP（`InternetOpenUrlW`）组合。
- 下载地址在编译期加密后硬编码，运行时才解密；口令也硬编码在样本里。
- 分析者能静态定位 `CryptHashData` 的口令与 `CryptDecrypt` 后的使用点（通常紧接 `InternetOpenUrl`）。

## 利用步骤

1. 静态定位加密 API 组合：导入表/字符串里出现 `CryptAcquireContext`、`CryptCreateHash`、`CryptHashData`、`CryptDeriveKey`、`CryptEncrypt`/`CryptDecrypt`，同时伴随 `InternetOpenUrlW` —— 典型「加密字符串 + 下载执行」加载器。
2. 在 `CryptHashData(hHash, pData, cbData, 0)` 处读出口令字节与长度（示例为 `"password"`, 8 字节）。
3. 确认 `CryptDeriveKey` 的 algid（示例 `CALG_AES_256`）、`CryptSetKeyParam(KP_MODE/KP_IV)` 的模式与 IV（示例 CBC + 全零），记录 `CryptEncrypt`/`CryptDecrypt` 的最后一个参数是否为 `TRUE`（决定是否补 padding）。
4. 取密文缓冲（`memcpy` 进 `pbBuffer` 的那块静态数据）与长度，按其是宽字符还是字节串确定元素宽度。
5. 离线复算：`key = SHA256("password")[:32]`，AES-256-CBC + 零 IV 解密（去掉 PKCS#7 padding），按 UTF-16LE 解释得到 URL。
6. 用还原出的 URL 做 IOC 关联（域名/IP 归属、证书、同族样本），并回填到样本行为分析中。

## PoC

```c
/* 样本侧（编译期加密 / 运行期解密共用同一函数） */
HCRYPTPROV hProv; HCRYPTKEY hKey; HCRYPTHASH hHash; DWORD mode = CRYPT_MODE_CBC;
BYTE iv[16] = {0};
CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
CryptHashData(hHash, (BYTE*)"password", 8, 0);                     /* 硬编码口令 */
CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE | (256 << 16), &hKey);
CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
CryptSetKeyParam(hKey, KP_IV, iv, 0);                              /* 全零 IV */
CryptDecrypt(hKey, NULL, TRUE, 0, pbBuffer, &dwDataLen);            /* 还原 URL */
```

```python
# 分析侧离线还原（无需运行样本）
import hashlib
from Crypto.Cipher import AES

key = hashlib.sha256(b"password").digest()[:32]      # CryptDeriveKey(CALG_AES_256, SHA256)
ct  = open("url_cipher.bin", "rb").read()            # memcpy 进 pbBuffer 的静态密文
pt  = AES.new(key, AES.MODE_CBC, b"\x00"*16).decrypt(ct)
pt  = pt[: len(pt) - pt[-1]]                         # 按末字节去 PKCS#7 padding（勿先 rstrip 零字节，会吃掉 UTF-16 高位 0x00）
print(pt.decode("utf-16-le", errors="replace"))      # 宽字符 URL
```

```text
验证点：解出的字符串应为 http(s)://…/<payload>.exe 形态；若为乱码，检查是否漏了 UTF-16 解释或 padding 处理。
```

## 变体与关联

- **只换算法不换结构**：把 `CALG_AES_256` 换成 `CALG_RC4` 或 `CALG_3DES`，或把 SHA-256 换成 SHA-1/MD5，口令仍硬编码；分析步骤不变（读口令 → 复算派生 → 解密）。
- **口令分段/异或**：口令在多个全局变量里拼出、或与常量异或后再 `CryptHashData`，静态看要跟一次数据流；`CryptDeriveKey` 的 algid 高 16 位（如 `0x28` 表示 40 位 RC4 密钥）也会泄露密钥长度。
- **只加密 URL 的一部分**：只混淆域名、保留路径，字符串扫描仍能看到路径片段，可据此猜完整 URL。
- 关联：[[code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt]]（同为 CryptoAPI 派生解密，那条是 RC4-40 解配置、本条是 AES-256 解 URL）、[[code-analysis-reverse-obfuscation-pe-data-section-xor-decode-embedded-pe]]（另一种「静态数据运行时还原」）、[[code-analysis-reverse-anti-debug-desktop-artifact-keying-drive-count-shortcut]]（同一样本族的反沙箱前置门）。

## 检测与防御

- 检测：`CryptAcquireContext` + `CryptDeriveKey` + `InternetOpenUrl` 同一函数的组合是「加密 URL 下载器」的高置信度签名；抓 `CryptDecrypt` 之后立刻 `InternetOpenUrlW` 的调用序列。
- 分析/取证：不必动态跑，静态取「口令 + 算法 + 模式 + IV + 密文」四项即可离线还原，把结果作为 C2 IOC 入库；对同一家族批量跑该脚本。
- 沙箱侧：对「导入 CryptoAPI 与 WinINet 但无明文 URL」的样本重点观察 DNS/TLS SNI，因为解密后必然发起真实连接。
- 投放侧：这类混淆只是提高静态成本；真正的隐蔽应结合环境键控、分阶段下发与域名前置，而不是单一硬编码对称加密。
