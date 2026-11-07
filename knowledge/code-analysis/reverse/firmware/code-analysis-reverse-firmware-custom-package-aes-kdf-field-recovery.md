---
id: code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery
title: 自定义固件包 NOE-FWP 逆向：updater KDF 解 AES-256-CBC 载荷，恢复 Feistel/Digest/校验和三处被抹字段
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: custom-firmware-package-aes-kdf-field-recovery
aliases:
- 升级程序里的秘密
- NOE-FWP 固件包
- firmware.pkg 解密
- updater 0x40341c KDF
- Feistel 6 轮 model 还原
- RFC2617 Digest response 重算
- 32 位字求和 0xFFFFFFFF
tags:
- ics
- firmware
- package-format
- aes-256-cbc
- kdf
- feistel
- digest-auth
- checksum
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:43+08:00'
  notes: 对照 工控232：NOE-FWP 头布局、updater KDF、F1 Feistel/F2 Digest/F3 字求和、最终 AES 一致
---

## 一句话结论

工控固件包 `NOE-FWP` 的载荷用 AES-256-CBC 加密，密钥由 `updater` 内嵌的 EC 公钥 DER 与固定串经自定义 rotl/xor KDF 派生；解开内部 TAR 后，再分别用 6 轮 Feistel（model）、RFC2617 Digest 重算（日志口令）与“全文件 32 位字求和等于 0xFFFFFFFF”（固件校验码）恢复三处被抹字段，拼接后 SHA-256 派生最终密钥解密 flag。

## 原理

- `firmware.pkg` 是自定义格式（魔数 `NOE-FWP`），载荷 AES-256-CBC 加密。头部布局：0x28–0x37 为 IV；0x38–0x57 为载荷密文 SHA-256；0x58–0x77 为明文 SHA-256；0x78 为 CRC32。解包时先用头部校验值验证解密结果。
- 密钥派生在 `updater` 的 0x40341c：`.rodata` 0x7d4900 处 91 字节 EC 公钥 DER 拼接 `NOE77101-UPD` 做 SHA-256 得到 h；KDF 循环
  `t = rotl32((h[i] ^ state[j]) + i − 0x61C88647, (i % 13) + 3)`，
  `state[j] = t`，
  `state[(j+3)&7] = (t + state[(j+3)&7]) ^ 0xA5A5A5A5`；
  最后把 state 按小端拼成 32 字节，再拼 `PKGKEY` 做 SHA-256 得到 AES 密钥。
- 解密后得到内部 TAR（91 个文件），包含 `fw.ini`、`http_request.log`、`umconfig.txt`、`NOE77101.bin`，分别对应三处被抹信息 F1/F2/F3。
- **F1（model）**：`fw.ini` 的 `Model=3796b22fb830c11a` 被改写；`webcfg.jar` 的 `aw.class` 做还原——校验 model 恰 16 个 hex 字符、解成 8 字节、由 version 派生轮密钥（k=1831565813 起迭代）、做 6 轮 Feistel（常量表从 0x9E3779B9 起的六个常量，轮函数含 rotl/雪崩/异或常量），得 `F1=7403e45edabec0c1`。
- **F2（Digest response）**：`http_request.log` 中 `ctf` 用户的 Digest response 被抹空；按 RFC2617 用 `umconfig.txt` 的 `password_hex`（口令 123456）重算：
  `HA1=MD5("ctf:NOE77101:123456")=b57d1b27fc798ec12c870121f194d0d8`，
  `HA2=MD5("GET:/secure/index.htm")`，
  `response=MD5(HA1:nonce:nc:cnonce:qop:HA2)`，得 `F2=7af6f1ea58a09971763652608b70d670`。
- **F3（固件校验码）**：`NOE77101.bin` 头 0x0c 的 32 位校验码被抹。前 900 字节是文件头，0x384 起是 zlib 压缩固件（约 4.7MB PowerPC 代码）；解压后字符串暴露校验规则——整个文件按 32 位字求和必须等于 `0xFFFFFFFF`。文件长 996352 字节即 249088 个字，校验码位置先置 0 求和得 `0xd6f288b9`，校验码 = `0xFFFFFFFF − 0xd6f288b9 = 0x290d7746`。
- 最终 `material = F1+F2+F3`（小写 hex 拼接）`7403e45edabec0c17af6f1ea58a09971763652608b70d670290d7746`，SHA-256 为密钥、IV 为 `NOE77101_FLAG_IV`，对 48 字节 `flag.enc` 做 AES-256-CBC 解密去 PKCS7 填充。

## 触发条件

- 拿到固件包、升级程序（含 KDF/校验逻辑）与待解密的 `flag.enc`。
- 包格式/头部字段可通过逆向确定；载荷加密密钥由程序内常量与固定串派生。
- 内部文件包含可恢复的元数据（版本、日志、配置、固件镜像）。
- 有足够信息重算 Digest/校验和（口令、HTTP 请求、字求和规则）。

## 利用步骤

1. 解析 `NOE-FWP` 头部：IV、密文 SHA-256、明文 SHA-256、CRC32。
2. 逆向 `updater` 的 KDF（0x40341c），提取 EC 公钥 DER、`NOE77101-UPD`、`PKGKEY` 与 rotl/xor 常量，复现密钥。
3. AES-256-CBC 解密载荷，校验明文 SHA-256/CRC32，解 TAR 得到内部文件。
4. F1：反编译 `aw.class`，复现 6 轮 Feistel 与轮密钥派生，由 `fw.ini` 的 model/version 还原正确 model。
5. F2：从 `umconfig.txt` 取口令，按 RFC2617 重算 `HA1/HA2/response`。
6. F3：解析固件头，按“32 位字求和 = 0xFFFFFFFF”规则求校验码；可用解压后的字符串/代码交叉确认。
7. 拼接 F1+F2+F3，SHA-256 派生密钥，AES-256-CBC 解密 `flag.enc`。

## PoC

```python
# 1) 头部解析
iv = pkg[0x28:0x38]
ct_sha = pkg[0x38:0x58]
pt_sha = pkg[0x58:0x78]
crc32 = pkg[0x78:0x7c]

# 2) KDF（按 updater 0x40341c 复现）
h = hashlib.sha256(ec_pub_der + b"NOE77101-UPD").digest()
state = [0] * 8
j = 0
for i, b in enumerate(h):
    t = rotl32(((b ^ state[j]) + i - 0x61C88647) & 0xffffffff, (i % 13) + 3)
    state[j] = t
    k = (j + 3) & 7
    state[k] = (t + state[k]) ^ 0xA5A5A5A5
    j = (j + 1) & 7
key = hashlib.sha256(struct.pack("<8I", *state) + b"PKGKEY").digest()
plain = AES.new(key, AES.MODE_CBC, iv).decrypt(pkg[0x80:])
```

```python
# F3：全文件 32 位字求和 = 0xFFFFFFFF
words = struct.unpack("<%dI" % (len(fw) // 4), fw)
checksum = (0xFFFFFFFF - (sum(words) & 0xFFFFFFFF)) & 0xFFFFFFFF

# 最终密钥
material = (F1 + F2 + ("%08x" % checksum)).encode()
key = hashlib.sha256(material).digest()
flag = unpad(AES.new(key, AES.MODE_CBC, b"NOE77101_FLAG_IV").decrypt(open("flag.enc","rb").read()), 16)
```

## 变体与关联

- 变体：包格式可换成厂商自定义头 + zlib/LZMA/AES；KDF 可换成 PBKDF2/Argon2/自定义轮函数；校验规则可从固件字符串或反编译代码恢复。
- 变体：Feistel/Digest/校验和三处字段可独立求解，也可用明文哈希/CRC 交叉验证。
- 关联：[[code-analysis-reverse-firmware-8051-eeprom-protocol-mac]]（固件内密码逻辑逆向）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件解包/模拟）。
- 边界：需要 `updater` 未加壳/可反编译；KDF 常量与 EC 公钥必须完整；固件压缩算法/字序需确认；缺失口令时 Digest 无法重算。

## 检测与防御

- 检测：固件包头部含多组 SHA-256/CRC 但无签名；升级程序内嵌固定 KDF 常量与公钥；内部文件含明文口令/日志；固件校验仅为简单字求和。
- 修复：固件包使用签名（RSA/ECDSA）与 AEAD；密钥由安全启动/HSM 管理，不硬编码 KDF 常量；元数据字段加 MAC；校验和升级为加密哈希/签名。
- 加固：升级程序混淆/加壳与完整性校验；限制固件包与升级工具的获取；对内部文件最小化敏感信息；定期轮换包密钥。
