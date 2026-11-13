---
id: code-analysis-reverse-firmware-audiocodes-hardcoded-des3-password-decrypt
title: AudioCodes 固件 libac_des3.so 硬编码 3DES 密钥/IV：逆向 decrypt_string 解密设备存储口令（CVE-2023-22957）
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: audiocodes-hardcoded-des3-decrypt-string
aliases:
- CVE-2023-22957
- AudioCodes 硬编码密钥
- decrypt_string 3DES
- libac_des3.so 密钥提取
- SYSS-2022-052
- AudioCodes 口令解密
tags:
- firmware
- reverse
- audiocodes
- des3
- hardcoded-key
- crypto
- cve-2023-22957
cve:
- CVE-2023-22957
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: AudioCodes C450HD UC 3.4.6.604.1（原文测试版本）
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:44:02+08:00'
  notes: 已对照原文与截图核对：libaq201.so引用libac_des3.so的decrypt_string、花括号/引号剥离(strncmp "{" / "}")、base64_decode后des3_crypt(图14)、三次DES_set_key_unchecked+DES_ede3_cbc_encrypt(图12)、key偏移0x10fb8首字节60 40 75 FB(图16)、IV偏移0x10fb0首字节A3 A4..35 CB(图15)、dd提取命令与PyCryptodome PoC、密文VvlZOp5/5pM=解密为system，均与原文一致；CVE-2023-22957=SYSS-2022-052映射正确。affected_versions为原文测试版本(图28 /etc/release UC_3.4.6.604.1)，非受影响区间。dedup候选为OA skey/Android UDID等不同产品3DES硬编码，非同链。
---

## 一句话结论

AudioCodes 设备的密码字段以 Base64+Triple DES 存储，而密钥和 IV 硬编码在固件 `/lib/libac_des3.so` 中：逆向 `decrypt_string`/`des3_crypt` 可定位 24 字节密钥（偏移 0xfb8）与 8 字节 IV（偏移 0xfb0），用 PyCryptodome 的 `DES3.new(KEY, MODE_CBC, IV)` 即可把配置/重定向服务里拿到的密文还原成明文口令（CVE-2023-22957，SYSS-2022-052）。

## 原理

- 设备固件未加密，可从厂商门户下载，或用 SSH+管理员口令拿到 root 后直接取文件系统。`/lib/libaq201.so` 中很多功能依赖 `/lib/libac_des3.so` 导出的 `decrypt_string`，这是加密例程的入口。
- `decrypt_string(char *param_1, ...)`：先用 `strncmp(param_1, "{\"", 2)` 去掉 JSON 包装的花括号/引号，取出中间的 Base64 串（`strncpy` 到栈缓冲），再 `base64_decode`，最后调用 `des3_crypt(...)`。
- `des3_crypt` 内部依次调用 OpenSSL 的 `DES_set_key_unchecked` 三次（分别用 24 字节 key 的 3 个 8 字节片段生成 key schedule），再调用 `DES_ede3_cbc_encrypt(input, output, size, ks1, ks2, ks3, ivec, enc)`，即标准 3DES-CBC。
- 密钥与 IV 是硬编码的全局数据：Ghidra 里 `des3_crypt` 的密钥指针指向 `00010fb8`（24 字节，原文前四字节 `60 40 75 FB`），IV 指针指向 `00010fb0`（8 字节，原文前几字节 `A3 A4 .. 35 CB ..`）。按调用约定确认参数后即可 `dd` 提取。
- 因为密钥/IV 全设备相同，任何拿到密文的人都能离线解密；密文出现在配置文件、以及无需认证即可访问的配置/重定向服务响应里（如 `ems_server/user_password={"VvlZOp5/5pM="}`），两者组合即明文凭据泄露。

## 触发条件

- 目标为使用该硬编码密钥的 AudioCodes 固件（原文 C450HD UC 3.4.6.604.1）。
- 攻击者能获得设备固件（官方下载或已 root 的文件系统）以提取密钥/IV。
- 攻击者能获得至少一段密文：配置文件、备份、或可未授权访问的配置服务响应（SYSS-2022-053）。
- 密文使用同一 3DES-CBC 密钥/IV 加密（静态 IV）。

## 利用步骤

1. 下载对应型号固件（或从设备 root shell 取 `/lib/libac_des3.so`）。
2. 用 Ghidra 反编译 `decrypt_string`/`des3_crypt`，确认 `DES_ede3_cbc_encrypt` 的参数顺序与密钥/IV 指针。
3. 按偏移提取密钥和 IV：
   `dd skip=$((0xfb8)) count=24 if=libac_des3.so of=key.bin bs=1`；`dd skip=$((0xfb0)) count=8 if=libac_des3.so of=iv.bin bs=1`。
4. 用 Python 脚本对 Base64 密文做 3DES-CBC 解密。
5. 对配置文件中 `auth_password`、`ems_server/user_password` 等字段批量解密，得到明文口令后登录设备/服务。

## PoC

```python
#!/usr/bin/env python3
import sys, base64
from Crypto.Cipher import DES3
from binascii import unhexlify

KEY = unhexlify('604075fb########################################')  # libac_des3.so +0xfb8, 24 字节
IV  = unhexlify('a3a4####35cb####')                              # libac_des3.so +0xfb0, 8 字节

def decrypt(ciphertext):
    ct = base64.b64decode(ciphertext)
    pt = DES3.new(KEY, DES3.MODE_CBC, iv=IV).decrypt(ct)
    print(pt.decode('utf-8'))

decrypt(sys.argv[1])
```

```text
$ python3 poc.py VvlZOp5/5pM=
plain text password: system
```

密钥/IV 原文做了打码，需按目标固件实际偏移提取。

## 变体与关联

- 变体：同一密钥/IV 可能覆盖设备管理员口令、SIP 认证口令、EMS 服务器口令等多种字段；静态 IV 意味着相同明文得到相同密文，可做比对识别。
- 变体：密文获取路径包括未授权配置/重定向服务响应（SYSS-2022-053）和固件/配置备份文件。
- 关联：[[code-analysis-reverse-firmware-audiocodes-config-evp-bytestokey-decrypt]]——同一设备的配置文件加密使用另一套硬编码口令 + `EVP_BytesToKey`（CVE-2023-22956）。
- 关联：[[iot-zoom-ztp-mac-claim-malicious-firmware-takeover]]——拿到明文口令后可配合 ZTP 劫持链扩大控制面。

## 检测与防御

- 防御：密钥必须唯一化并按设备硬件秘密派生（如 eFuse/TPM），不能全设备共享硬编码密钥；静态 IV 改为随机 IV 随密文存储。
- 防御：口令字段使用带认证的加密（AES-GCM 等）并做完整性保护；配置服务必须鉴权且不返回加密凭据。
- 检测：固件中搜索硬编码密钥/IV 与 3DES 常量；配置分发接口未授权访问与批量下载告警。
- 检测：设备配置文件中出现 Base64 口令字段时，检查是否可由已知固件密钥解密（离线验证），命中即视为高危。
