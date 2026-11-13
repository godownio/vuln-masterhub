---
id: iot-hardware-tapo-config-des-ecb-model-version-hash-key
title: Tapo 摄像头配置分区离线解密：型号/固件版本字符串经 Java 风格 hash（h=31h+c mod 0x7fffffff）得 4cfdad81，作 DES-ECB 密钥用 openssl 解密 uc_conf
type: scenario
domain: iot
path: iot/hardware
technique: tapo-config-des-ecb-model-string-hash-key
aliases:
- Tapo 配置解密
- TC60 配置分区
- uc_convert 离线解密
- Java String.hashCode 密钥派生
- DES-ECB 配置解密
- TC100 TC200 密钥
- openssl des-ecb
tags:
- iot
- hardware
- firmware
- config-decryption
- des-ecb
- key-derivation
- model-string
- tapo
- camera
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:54:03+08:00'
  notes: '已对照原文与25图核对：图22 xxd flashdump.bin|grep C60 出现 TC60/TC60_4.0/''TC60 4.0''；图23 哈希程序对 ''TC60 4.0'' 输出 KEY: 4cfdad81（h=(c+31h)%0x7fffffff，跳过反斜杠且长度>0xb 截止）；openssl enc -d -des-ecb -nopad -K 3463666461643831（即 ASCII ''4cfdad81'' 的十六进制）与原文一致；图24 binwalk test.bin 在 24(0x18) 与 65560(0x10018) 报 Zlib compressed data；图25 解密配置含 config server ''rtsp'' port ''554''、media_encrypt enabled ''on''、root username ''admin'' passwd。同族 C100 2.0/C200 1.0 与原文一致。dedup top（OpenSSL salted 固件、Android MD5+时间窗 DES、AudioCodes、USB 加密盘 hash32shift）均非同链。原文无版本标记，未设 affected_versions。未在本环境复现。'
---

## 一句话结论

Tapo 摄像头（TC60，TC100/TC200 同族）的 config 分区用 DES-ECB 加密，密钥不是随机值，而是由**型号 + 硬件/固件版本字符串**（本例 `"TC60 4.0"`）经 Java `String.hashCode` 风格的循环 `h = (c + 31*h) mod 0x7fffffff` 计算出的 32 位值 `0x4cfdad81`；把该值的 ASCII 字节 `34 63 66 64 61 64 38 31` 作为 DES key，`openssl enc -d -des-ecb -nopad -K 3463666461643831 -in mtdblock3.bin` 即可离线解出 `uc_conf` 配置（rtsp 端口、media_encrypt、root/admin 口令哈希等）。

## 原理

- **配置加密与设备内解密**：设备把配置数据加密存放在 config 分区；固件自带 `uc_convert` 工具，在 root shell 下执行 `uc_convert -t 0` 会在 `/tmp/etc/uc_conf/` 生成解密后的配置目录（`user_management` 等），说明解密逻辑与密钥都在设备上。
- **同族研究给出密钥来源**：TC200 研究项目发现密钥是型号/硬件版本字符串（如 `"C200 1.0"`），TC100 论文发现其密钥为 `"C100 2.0"`；两设备密钥不同但派生方法相同。对 TC60，在 `flashdump.bin` 中 `xxd | grep C60` 可看到 `TC60`、`TC60_4.0` 等型号/版本字符串。
- **哈希函数**：反编译出的循环为：
  ```c
  uVar4 = ((int)cVar2 + uVar3 * 0x1f) % 0x7fffffff;
  ```
  正是 Java `String.hashCode` 的 `h = 31*h + c`（取正模 `0x7fffffff`）。对 `"TC60 4.0"` 计算得到 `KEY: 4cfdad81`。
- **为什么是 DES-ECB**：把 32 位 key 的十六进制字符串视作 8 字节 ASCII（`4cfdad81` → `34 63 66 64 61 64 38 31`）作为 DES 密钥，模式 ECB、无 padding（`-nopad`）即可解密分区；解密结果经 binwalk 可见 Zlib 压缩数据，说明外层可能还有压缩/容器。
- **为什么能离线做**：密钥只依赖公开的型号/版本字符串，不需要逐设备提取；只要拿到 config 分区（SD 卡/编程器/UART dump）就能在本地复现解密，进而读取所有配置（包括账户哈希与 RTSP 加密密文）。

## 触发条件

- 已取得设备的 config 分区或整片 Flash 转储（物理读取/UART root shell/SD 卡）。
- 知道或能猜出型号/硬件版本字符串（固件中 grep 型号可找到，如 `TC60_4.0`）。
- 能识别/复现厂商的 key 派生函数（本例为 Java hashCode 变体）；同族设备（C100/C200/TC60）方法可迁移。
- 配置加密算法为 DES-ECB 且无额外完整性校验（可离线解密）。

## 利用步骤

1. 从设备转储 config 分区（如 mtdblock3）或整片 `flashdump.bin`。
2. 在固件中搜索型号/版本字符串：`xxd flashdump.bin | grep C60` 或用 `strings` 找 `TC60 4.0`。
3. 复现 key 派生（哈希函数）：
   ```c
   unsigned int hash(char *str) {
       unsigned int h = 0;
       while (*str) { h = ((int)*str + h * 0x1f) % 0x7fffffff; str++; }
       return h;
   }
   // hash("TC60 4.0") = 0x4cfdad81
   ```
4. 用 openssl 离线解密：
   ```bash
   openssl enc -d -des-ecb -nopad -K 3463666461643831 -in mtdblock3.bin -out test.bin
   binwalk test.bin
   ```
5. 解压/解析得到 `uc_conf`，读取 `user_management`（root/third_account 的 username、passwd、ciphertext）、`server rtsp port 554`、`media_encrypt on` 等。

## PoC

```c
// hash 函数（原文 Binary Ninja 还原）
unsigned int hash(char *str) {
    unsigned int uVar3 = 0;
    unsigned int uVar4 = 0;
    do {
        char c = *str++;
        if (c == '\0') break;
        if (0xb < uVar4) return uVar3;
        if (c != '\\') {
            uVar4 = uVar4 + 1;
            uVar3 = ((int)c + uVar3 * 0x1f) % 0x7fffffff;
        }
    } while (c);
    return uVar3;
}
// main: char buf[0xc] = "TC60 4.0"; printf("KEY: %08x\n", hash(buf));
// KEY: 4cfdad81
```

```bash
openssl enc -d -des-ecb -nopad -K 3463666461643831 -in mtdblock3.bin -out test.bin
binwalk test.bin
# 24: Zlib compressed data / 0x10018: Zlib compressed data
```

## 变体与关联

- **同族设备**：TC100 密钥 `"C100 2.0"`、TC200 密钥 `"C200 1.0"`；方法相同、字符串不同，说明厂商用型号/版本派生而非随机密钥。其他 Tapo 型号可按同样思路在固件中 grep 型号字符串并复现哈希。
- **算法识别**：若不确定 DES/3DES，可参考 `[[code-analysis-reverse-des-3des-identification-decrypt]]`；本卡的特色是 **key 来源 = 型号字符串 hash**，而非算法本身。
- **其他 DES-ECB 配置**：Snake keylogger 用 MD5 key 派生 DES-ECB 配置，见 `[[code-analysis-reverse-windows-snake-keylogger-des-ecb-md5-key-config]]`，可与本卡的“型号 hash key”对比。
- 关联：`[[iot-hardware-tapo-tc60-uart-uboot-init-sh-root-shell-sd-dump]]`（如何拿到 config 分区）、`[[iot-tapo-third-account-rtsp-config-ciphertext-backdoor]]`（解密后如何改 third_account 后门）。

## 检测与防御

- **设计**：不要用型号/版本等公开字符串派生密钥；使用每设备唯一随机密钥/安全芯片/KMS，算法用 AES-GCM 并提供完整性校验（HMAC/签名），防止离线解密与篡改回写。
- **检测**：固件中若存在硬编码派生逻辑，视为可离线解密；审计 config 分区是否可被物理读取；监测设备是否接受被修改的配置（无签名校验）。
- **取证**：解密后的 `user_management` 可确认账户哈希与 RTSP ciphertext，用于判断是否被植入后门账户；结合固件版本字符串可复现同族设备的密钥。
