---
id: code-analysis-reverse-firmware-openssl-salted-extract-dictionary-bruteforce
title: OpenSSL 加密 IoT 固件的提取与字典爆破：binwalk 定位 offset/salt，openssl enc -d -aes-256-cbc -pbkdf2 逐字典试解，成功后再 binwalk 提取
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: openssl-salted-firmware-extract-dictionary-bruteforce
aliases:
- binwalk OpenSSL encryption
- 固件 openssl 加密提取
- Salted__ 固件解密
- openssl enc 字典爆破
- rockyou 爆破固件密码
- binwalk 无法提取
tags:
- iot
- firmware
- openssl
- binwalk
- bruteforce
- rockyou
- aes-256-cbc
- pbkdf2
- salted
- extraction
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:28:16+08:00'
  notes: 已对照原文与4张图核对：binwalk 报 516/0x204 OpenSSL salted salt 0x3F67045AE470EEE1、skip=516 截取保留 Salted__ 头、openssl enc -d -aes-256-cbc -salt -pbkdf2 -S salt 逐字典试解、返回码判定、命中 000000 后 binwalk 见 Zlib 签名均一致；图03输出文件名为 kksk.bin 与正文 decrypt.bin 不一致属原文小差异不影响方法；与既有固件/OpenSSL salted 卡非同链；dup-scan(11-08)早于建卡未涉及；原文无受影响版本；未复跑脚本
---

## 一句话结论

厂商用 OpenSSL 加密最新 IoT 固件后，binwalk 只会报 `OpenSSL encryption, salted, salt: 0x...` 而无法继续提取；此时按 binwalk 给出的偏移截取加密段（保留 `Salted__` 头），用 `openssl enc -d -aes-256-cbc -salt -pbkdf2 -S <salt> -pass pass:<候选>` 对字典逐条试解，以 openssl 返回码判定是否命中，成功后再对解密产物跑 binwalk，就能看到 zlib/squashfs 等可提取内容。

## 原理

- **binwalk 为什么只报不解**：带 `-salt` 的 `openssl enc` 输出格式是 8 字节魔数 `Salted__` + 8 字节随机 salt + 密文。binwalk 的签名扫描能认出这个结构并给出偏移与 salt，但不持有口令，无法派生密钥，所以只报告 `OpenSSL encryption, salted` 就停止，后续文件系统签名（squashfs、zlib 等）都在密文里不可见。
- **口令是唯一缺口**：OpenSSL 解密所需的一切（算法、salt、KDF）都能从命令行/binwalk 得到或枚举，缺的只有口令；厂商常用弱口令或默认口令（本例为 `000000`），因此字典攻击可行。
- **返回码即判定器**：`openssl enc -d` 在口令错误时解密失败（bad decrypt/填充校验失败）返回非 0；口令正确时返回 0 并写出明文。脚本每试一个口令检查 `returncode == 0`，命中即停止，无需人工看输出。
- **参数必须与加密侧一致**：`-aes-256-cbc` 与 `-pbkdf2` 是脚本假定的算法/KDF；若试遍字典都失败，应换 `-aes-128-cbc`/`-des3`/`-rabbit`，或去掉 `-pbkdf2` 改用 OpenSSL 旧版 `EVP_BytesToKey` 派生再试。binwalk 只保证 salt 与偏移，算法需自行确认。
- **偏移的含义**：binwalk 报的 516 是加密段起始（0x204），前 516 字节通常是未加密头部。从该偏移原样截取到文件尾，正好保留 `Salted__`+salt+密文，openssl 才能识别盐值；用 `-S <hex salt>` 显式指定 binwalk 报出的 salt 后，即使截取位置有偏差也可纠正。

## 触发条件

- `binwalk -eM <固件>` 输出含 `OpenSSL encryption, salted, salt: 0x...`，且能读到十进制/十六进制偏移与 8 字节 salt（16 个十六进制字符）。
- 本地有 openssl 命令行与可用字典（如 `/usr/share/wordlists/rockyou.txt`）；固件口令为弱口令/默认口令。
- 加密算法与 KDF 可枚举尝试（典型为 AES-256-CBC + `-pbkdf2`）。

## 利用步骤

1. 运行 `binwalk -eM <firmware>.bin`，记录 `DECIMAL`（如 516）与 `salt`（如 `3F67045AE470EEE1`）。
2. 从该偏移截取到文件尾，得到裸 OpenSSL 密文段（保留文件开头 8 字节 `Salted__` 与 salt）。
3. 可选：`xxd` 确认截取段前 8 字节为 `Salted__`，salt 位于其后 8 字节。
4. 遍历字典，每个口令执行一次 `openssl enc -d -aes-256-cbc -salt -pbkdf2 -S <salt> -pass pass:<口令> -in enc.bin -out out.bin`，返回码 0 即命中，打印口令。
5. 对 `out.bin` 重新 `binwalk -eM`，确认出现 zlib/squashfs 等签名并正常提取文件系统。

## PoC

最小脚本（提取 + 字典试解）：

```python
import subprocess, sys

def extract(src, skip, dst):
    with open(src, "rb") as f, open(dst, "wb") as o:
        f.seek(skip)
        while chunk := f.read(4096):
            o.write(chunk)

def try_decrypt(pw, enc, out, salt):
    cmd = ["openssl", "enc", "-d", "-aes-256-cbc",
           "-in", enc, "-out", out,
           "-salt", "-pbkdf2", "-pass", f"pass:{pw}", "-S", salt]
    return subprocess.run(cmd, capture_output=True).returncode == 0

extract("firmware.bin", 516, "encrypted.bin")       # offset 来自 binwalk
for pw in open("/usr/share/wordlists/rockyou.txt", "rb").read().splitlines():
    pw = pw.decode("utf-8", "ignore").strip()
    if try_decrypt(pw, "encrypted.bin", "decrypt.bin", "3F67045AE470EEE1"):
        print("Password found:", pw)
        break
```

本例实际输出 `Password found: 000000`；随后 `binwalk -eM decrypt.bin` 可看到大量 `Zlib compressed data`，正常提取。

## 变体与关联

- 变体：字典失败时先换算法/ KDF 组合（AES-128-CBC、DES3、Rabbit；`-pbkdf2` 与默认 `EVP_BytesToKey`），再做更大字典；也可用 hashcat/john 的 OpenSSL 格式离线加速。
- 变体：若厂商脚本把口令硬编码在升级程序/so 中，先逆向升级逻辑取口令比爆破更快；同类“固件升级包解密”思路见 [[code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt]]。
- 关联：`Salted__` 结构、`U2FsdGVkX1` base64 特征与 `EVP_BytesToKey`/`-pbkdf2` 两种 KDF 的判别见 [[ctf-crypto-nibble-charmap-hex-md5-sequence-openssl-salted]]。
- 关联：解密后若得到打包文件系统，按 [[code-analysis-reverse-firmware-openwrt-squashfs-jffs2-overlay]] 等方式提取 overlay。

## 检测与防御

- 分析侧信号：binwalk 只报 `OpenSSL encryption, salted` 且后面没有任何文件系统签名；`Salted__` 魔数出现在固件某个偏移；厂商固件版本更新后突然无法提取，通常就是加了 OpenSSL 加密。
- 防守侧：不要用 `openssl enc -salt` 加弱口令保护固件，这只能挡住 binwalk 的自动提取；使用每设备唯一密钥 + 认证加密（AEAD），密钥放安全存储；升级包做签名校验。
- 局限：强口令 + 未知算法/KDF 时字典攻击无效；本流程只解决“加密段可被识别且口令可猜”的情况。
