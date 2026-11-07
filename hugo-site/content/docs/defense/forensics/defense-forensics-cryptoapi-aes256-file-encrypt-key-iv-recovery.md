---
id: defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery
title: CryptoAPI AES-256 文件加密样本：SHA-256 派生密钥与 CryptSetKeyParam 取 IV 后离线解密
type: scenario
domain: defense
path: defense/forensics
technique: cryptoapi-aes256-sha256-derive-key-iv-recovery
tags:
- defense
- forensics
- windows
- cryptoapi
- aes-256
- cryptderivekey
- cryptencrypt
- iv
- ransomware
- reverse
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T16:59:23+08:00'
  notes: 已对照原文与图片44-51核对：CryptDeriveKey 0x6610、CryptSetKeyParam KP_IV、种子 SHA-256 与 IV=3037... 解密得 恭喜；已复算 SHA-256(种子)=BAD9AE9D6038... 与图51一致；未复跑样本。
url: /docs/defense/forensics/defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery/
draft: false
kb_aliases:
- CryptoAPI AES-256 文件加密分析
- CryptDeriveKey CALG_AES_256
- CryptSetKeyParam KP_IV 取 IV
- AES-256-CBC 加密文件解密
- CryptEncrypt 样本取证
- 桌面文件加密样本密钥提取
---

## 一句话结论

Windows 文件加密样本通过 CryptoAPI 的 `CryptDeriveKey(CALG_AES_256)` 从 SHA-256 哈希对象派生 AES-256 密钥、用 `CryptSetKeyParam(KP_IV)` 设置 IV；在动态调试中对这两个调用下断点取出 32 字节种子与 16 字节 IV，再对种子做一次 SHA-256 即可还原密钥并离线解密被加密文件。

## 原理

- **加密 API 序列**：样本 `encrypt.dll` 的加密函数依次调用 `CryptAcquireContext` → `CryptCreateHash(CALG_SHA_256, 0x800C)` → `CryptHashData(hHash, seed, 32, 0)` → `CryptDeriveKey(hProv, CALG_AES_256, 0x6610, hHash, 0, &hKey)` → `CryptSetKeyParam(hKey, KP_IV, iv, 0)` → `CryptEncrypt(hKey, 0, 1, 0, data, &len, blockSize)`。
- **密钥为什么等于 SHA-256(种子)**：`CryptDeriveKey` 用哈希对象 `hHash` 派生会话密钥；当 `Algid=CALG_AES_256` 时，派生结果就是该哈希对象的摘要（SHA-256 输出 32 字节，正好是 AES-256 密钥长度）。样本先 `CryptHashData` 喂入 32 字节“初始密钥/种子”，所以最终 AES 密钥 = `SHA-256(seed)`，而不是种子本身。
- **IV 来源**：`CryptSetKeyParam` 的 `dwParam=KP_IV(1)`，`pbData` 指向 16 字节 IV。样例中 IV 为 ASCII 字符串 `0701080109091001`，十六进制 `30373031303830313039303931303031`。
- **模式与填充**：CryptoAPI 默认 `CryptEncrypt` 对 AES 使用 CBC 模式；样本按块加密并在最后一块做填充。实际离线解密时按 AES-256-CBC 处理即可还原明文。
- **为什么断点能拿到**：密钥和 IV 必须以明文形式传给 CryptoAPI，无法只靠静态字符串还原；在 `CryptDeriveKey` 处可看到 32 字节哈希输入/输出，在 `CryptSetKeyParam` 处可直接 dump `pbData` 指向的 16 字节 IV。x64 调用约定下关注 `rcx/rdx/r8/r9` 与栈上第 5 个参数，按断点实际寄存器取值。
- **样例结果**：用种子 `3C2389B9D7E04885B5F85D6A30BFCCB8B0D2AD65B31330C02F65F8A9F654AB9A` 做 SHA-256 得到 AES 密钥，配合上述 IV 解 `FD024B893B591699FB17ACE051118518`，明文为 `恭喜`。

## 触发条件

- 已取得加密样本（原生 DLL 或调用它的宿主程序），并能对其动态调试。
- 样本使用 CryptoAPI 的 `CryptDeriveKey` + AES-256，且密钥材料在运行时可见（非硬件保护/非 DPAPI 封装）。
- 有至少一组已知明文/密文或完整密文文件用于验证解密结果。

## 利用步骤

1. 静态确认导入表包含 `advapi32.dll` 的 `CryptAcquireContext`、`CryptCreateHash`、`CryptHashData`、`CryptDeriveKey`、`CryptSetKeyParam`、`CryptEncrypt`。
2. 在 `CryptDeriveKey` 下断点，确认 `Algid=0x6610`（CALG_AES_256），dump 哈希输入/输出，记录 32 字节种子。
3. 在 `CryptSetKeyParam` 下断点，筛选 `dwParam=1`（KP_IV），dump `pbData` 指向的 16 字节 IV。
4. 对种子做 SHA-256 得到 32 字节 AES 密钥。
5. 用 AES-256-CBC + IV 解密密文文件，验证明文；若样本按块处理，注意去掉 PKCS#7 填充。

## PoC

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

seed = bytes.fromhex(
    "3C2389B9D7E04885B5F85D6A30BFCCB8B0D2AD65B31330C02F65F8A9F654AB9A"
)
key = hashlib.sha256(seed).digest()          # 32 字节 AES-256 密钥
iv = bytes.fromhex("30373031303830313039303931303031")
ciphertext = bytes.fromhex("FD024B893B591699FB17ACE051118518")

plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
print(unpad(plain, AES.block_size).decode("utf-8"))
# 输出：恭喜
```

## 变体与关联

- 变体：`CALG_AES_128`/`CALG_AES_192` 时摘要截断到对应长度；`CALG_RC4` 时无 IV。
- 变体：用 `CryptGenKey` 生成随机密钥并用 `CryptExportKey` 导出，密钥需从内存/注册表/配置中另行提取。
- 变体：密钥材料经 DPAPI 或非对称公钥封装，无法仅靠 `CryptDeriveKey` 断点还原。
- 关联卡片：[[defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery]]、[[code-analysis-reverse-windows-cng-bcrypt-rc4-md5]]、[[code-analysis-reverse-windows-api-hook-hidden-aes-branch]]、[[pentest-c2-dotnet-singlefile-embedded-dll-delegate-loader]]。

## 检测与防御

- 检测：样本导入 `CryptDeriveKey` + `CryptEncrypt`，或进程对大量文件执行加密并追加 `.enc` 等扩展名。
- 检测：动态调试时在 `CryptDeriveKey`/`CryptSetKeyParam` 处出现固定 32 字节种子与 16 字节 IV，可作为家族特征。
- 检测：文件内容熵突增、原文件被删除/覆盖、桌面与文档目录出现批量重命名。
- 防御：备份与卷影副本；EDR 监控 CryptoAPI 批量加密行为；限制未知 DLL 加载；对关键目录启用只读/受控写入。
