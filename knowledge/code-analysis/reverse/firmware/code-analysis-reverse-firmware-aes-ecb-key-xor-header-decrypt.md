---
id: code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt
title: 固件升级包 AES-128-ECB 解密：16 字节 passwd 与 4 字节 xor_key 派生密钥
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: firmware-aes-ecb-key-xor-header-decrypt
aliases:
- libupgradeFirmware.so
- 固件解密
- AES ECB
- xor_key 派生
- binwalk 二次提取
- 升级包解密
tags:
- firmware
- aes
- ecb
- reverse
- binwalk
- key-derivation
- squashfs
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:28+08:00'
  notes: 已对照原文与图54-56核对；AES-128-ECB、40字节头、result[14]=0与libupgradeFirmware.so一致；PoC用占位密钥，未复跑。
---

## 一句话结论

固件升级包常见结构是“明文头 + AES 加密的镜像”。用 binwalk 提取文件系统后，在升级相关 `libupgradeFirmware.so` 中定位 `fw_decrypt`/`AES_set_decrypt_key`：它把 16 字节 `passwd` 与 4 字节 `xor_key` 循环异或派生 AES-128 密钥，对 40 字节头之后的密文做 AES-ECB 解密，并把头部某字节清零。按同样的密钥派生写脚本解密，再 binwalk 二次提取，即可拿到可分析的 SquashFS 文件系统。

## 原理

- **升级包格式**：很多 IoT 固件升级包不是直接 SquashFS，而是“自定义头（含版本/长度/CRC）+ 加密镜像”。`binwalk` 能识别出内部的 zImage/LZO/gzip/SquashFS，但加密段无法直接解。
- **密钥派生**：库函数里通常有静态 `passwd[16]` 和 `xor_key[4]`；`key[i] = passwd[i] ^ xor_key[i % 4]` 把 16 字节每个字节与 4 字节密钥循环异或，得到真正的 AES-128 key。这种“常量数组 + 简单异或”是可静态还原的。
- **AES-ECB**：`AES_set_decrypt_key(key, 128, &aes)` + `AES_ecb_encrypt(in, out, &aes, AES_DECRYPT)`（某些实现函数名仍是 `encrypt` 但传入解密 key/标志）；ECB 按 16 字节块独立解密，不需要 IV。
- **头部处理**：前 40 字节是明文头，直接复制；第 14 字节可能被清零（版本/标志位），以匹配解密后镜像的校验；密文长度按 16 字节对齐，尾部 padding 可忽略。
- **为什么成立**：固件要在设备上解密，密钥必须存在于设备端；静态分析升级库即可拿到派生逻辑。ECB 没有 IV/认证，解密是确定性的。

## 触发条件

- 拿到固件升级包/ROM，`binwalk` 能看到 SquashFS/zImage 但无法直接挂载，或中间有高熵段。
- 文件系统内有升级/校验相关库（如 `libupgradeFirmware.so`），导出 `fw_decrypt`/`AES_*` 符号。
- 库中存在静态 key 数组或可推导的密钥派生。
- 目标是恢复文件系统做漏洞分析/取证，而非破解签名。

## 利用步骤

1. `binwalk -e old.rom` 或在 `binwalk old.rom` 输出中确认 zImage、LZO、gzip、SquashFS 偏移；提取出文件系统。
2. 在提取目录中 `grep -r "decrypt"`，定位 `libupgradeFirmware.so` 等升级库。
3. 用 IDA/Ghidra 打开库，找 `fw_decrypt`/`AES_set_decrypt_key`/`AES_ecb_encrypt` 调用；记录 `passwd`、`xor_key`、头部长度（如 40）、头部清零偏移。
4. 按 `key[i] = passwd[i] ^ xor_key[i % 4]` 派生 16 字节 AES key。
5. 读取升级包：`header = data[:40]`，`cipher = data[40:]`（截断到 16 的倍数）；AES-ECB 解密；可选去 PKCS#7 padding。
6. 复制头部并按要求清零字节（如 `result[14] = 0`），拼上解密数据写出 `decrypted.rom`。
7. 对 `decrypted.rom` 再次 `binwalk`，得到 SquashFS 并挂载/提取；用文件哈希/版本字符串验证解密正确。

## PoC

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 从 libupgradeFirmware.so 静态数组中读取
passwd  = bytes.fromhex("...16 bytes...")
xor_key = bytes.fromhex("...4 bytes...")
key = bytes(passwd[i] ^ xor_key[i % 4] for i in range(16))

data = open("new.rom", "rb").read()
header, cipher = data[:40], data[40:]
cipher = cipher[:len(cipher) // 16 * 16]

plain = AES.new(key, AES.MODE_ECB).decrypt(cipher)
try:
    plain = unpad(plain, 16)
except ValueError:
    pass

out = bytearray(header)
out[14] = 0
out += plain
open("decrypted.rom", "wb").write(out)
```

说明：`passwd`/`xor_key` 需按实际库填写；若解密结果不是 SquashFS，检查是否 AES-CBC（找 IV）、字/字节序、header 长度或 padding 方式。

## 变体与关联

- 变体：AES-CBC/CTR，需要 IV/nonce；密钥可能是 SHA256(passwd) 或 PBKDF2。
- 变体：密钥不静态存储，而是从设备 ID/OTP/证书派生；需要动态调试或读 OTP。
- 变体：升级包有签名/CRC 校验，解密后仍需修复头部或绕过校验。
- 关联：[[code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery]]（自定义包 AES KDF 字段恢复）；[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（SquashFS 提取与仿真）；[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定 key/ECB 识别）。

## 检测与防御

- 检测：升级包中出现高熵段 + 明文头；设备端库存在静态 key/xor 派生；固件版本/哈希异常。
- 防御：升级包使用签名 + AEAD（AES-GCM/ChaCha20-Poly1305），密钥放 TEE/安全区，避免静态可提取。
- 防御：校验升级包完整性与来源；关闭调试接口；对固件做安全启动与回滚保护。
- 防御：分析侧保留原始包与解密脚本，确保取证可复现；不要在生产设备上直接刷入修改后的固件。
