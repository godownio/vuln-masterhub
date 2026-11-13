---
id: code-analysis-reverse-firmware-shrs-container-aes-cbc-sha512-repack
title: SHRS 加密固件容器解析：分段 dd + SHA512 校验 + AES-128-CBC 解密与尾部 key 追加重组
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: shrs-firmware-container-aes-cbc-sha512-repack
aliases:
- SHRS 固件格式
- D-Link 加密固件
- FW110B02_FW_Encrypt 解密
- 加密固件分段解密
- 固件尾部追加 key
- SHA512 固件校验
tags:
- firmware
- container
- aes-cbc
- sha512
- dd
- openssl
- binwalk
- dlink
- iot
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V646
  verified_at: '2026-11-13T03:56:16+08:00'
  notes: 已对照原文与36张图（源图缺03.png，全部逐张读取，无失败）：图24/25/36 头部与卡内布局一致：magic 53 48 52 53 00、解密区大小 00CA6ABB=13265595、加密区大小 00CA6AC0=13265600、IV 67C6697351FF4AEC29CDBAABF2FBE346、三组 SHA512 偏移 0x1D/0x5D/0x9D 与值 0A4E../A324../2811.. 均吻合，加密区自 0x6DC(1756) 开始；图26 大写 -K 解出 key=C05FBF1936C99429CE2A0781F08D6AD8，图27 小写 -k 走 EVP_BytesToKey 得 27CFF066D55FBF75A37CC766D338AAD8 与卡内'参数陷阱'一致；图28 dd count=13265595，图29 sha512sum Bin_Firmware.bin=a3248ff2a0cd3b7f0440a07189d20a0dedd4e7d2dc8c4e887d7dd46109c13a1d3aad7b8faca449a3c3c765a374f81d68dca36eeef4e4923cb04f56857c5，图33 追加 key 后整体 sha512=0a4ecafa...20bba692f 与头部一致；图34 binwalk -Me 成功解出 uImage/LZMA/cpio，链路完整。已修正卡内 PoC 注释一处笔误：Bin_Firmware.bin 的 SHA512 截断尾部原写作 8f34a35aac7c5，按图29 改为 f56857c5（KB 与 staging 同步）。dedup：与 AES-ECB 派生、OpenSSL Salted 字典爆破、NOE-FWP KDF、尾部 0x80 异或卡均 related 但容器格式与步骤不同，非同链；dup-scan 无涉及 pair。原文未标注受影响版本。未验证点：未复跑。未 commit/index/embed。
---

# 一句话结论

SHRS 加密固件是"自定义头 + AES-128-CBC 加密区"的容器：头部给出解密区/加密区大小、IV、三组 SHA512（解密固件+key、解密固件、加密区）与两个 512 字节算法区；按头部偏移用 `dd` 切出加密区、用 key+IV 做 AES-128-CBC 解密、按解密区大小截取并校验 SHA512、再把 16 字节 key 追加到尾部匹配整体哈希，即可得到可被 binwalk 正常解包的明文固件。

# 原理

- **容器布局**（以样本 `FW110B02_FW_Encrypt.bin` 为例）：
  - 0x00：magic `53 48 52 53 00`（"SHRS\0"）；
  - 0x05：解密区域大小，大端 `00 CA 6A BB` = 13,265,595 字节；
  - 0x09：加密区域大小，大端 `00 CA 6A C0` = 13,265,600 字节（16 字节对齐）；
  - 0x0D：16 字节 IV `67 C6 69 73 51 FF 4A EC 29 CD BA AB F2 FB E3 46`；
  - 0x1D：64 字节 SHA512 = SHA512(解密固件 ‖ key)（`0A 4E CA FA ...`）；
  - 0x5D：64 字节 SHA512 = SHA512(解密固件)（`A3 24 8F F2 ...`）；
  - 0x9D：64 字节 SHA512 = SHA512(加密区)（`28 11 F7 8B ...`）；
  - 之后是未使用区与两个 512 字节算法区，加密区从 0x6DC（1756）开始。
- **为什么先切加密区**：加密区大小是 16 的倍数，包含 AES 块填充；它从固定头部长度处开始，直接 `dd skip=1756 count=<加密区大小>` 即可精确取出，先用头部第三组 SHA512 校验提取正确性。
- **为什么解密后还要再截断**：AES-CBC 解密出的长度等于加密区长度（13,265,600），而头部记录的解密区大小是 13,265,595（差 5 字节填充）；按 `count=<解密区大小>` 截取后，第二组 SHA512 才能匹配，说明截断位置正确。
- **为什么尾部要追加 key**：第一组 SHA512 覆盖"解密固件 + 16 字节 key"，说明该格式的最终镜像把 key 作为校验/签名材料附在固件尾部（原文称重打包时必须有正确签名，否则解密失败）。把 key 的二进制追加到截断后的固件，整体 SHA512 与头部第一组值一致，binwalk 也能正常解析出 uImage/LZMA/cpio。
- **openssl 参数陷阱**：必须用大写 `-K`（十六进制密钥）；小写 `-k` 会把字符串当口令走 EVP_BytesToKey 派生，得到完全不同的 key（原文错例为 `27CFF066...`），后续 SHA512 必然不匹配。

# 触发条件

- 固件以 `SHRS\0` 开头、binwalk 只能识别出零散签名或 QNX4 误报，熵值高且几乎无变化（加密特征）。
- 已知固件 key（可从同系列未加密固件中的 imgdecrypt 取得，见 [[code-analysis-reverse-firmware-imgdecrypt-aes-key-rsa-qemu-recover]]）与头部中的 IV。
- 有 dd/openssl/sha512sum/binwalk 等基础工具，无需专用解密器。

# 利用步骤

1. 十六进制查看头部，记录 magic、两个大小、IV、三组 SHA512 与加密区起始偏移。
2. 切出加密区并校验：
   ```bash
   dd iflag=skip_bytes,count_bytes if=FW110B02_FW_Encrypt.bin \
     of=Bin_Encrpted.bin skip=1756 count=13265600
   sha512sum Bin_Encrpted.bin
   ```
3. 用 key+IV 做 AES-128-CBC 解密（`-nopad`，不做填充处理）：
   ```bash
   openssl aes-128-cbc -d -p -nopad -nosalt \
     -K C05FBF1936C99429CE2A0781F08D6AD8 \
     -iv 67C6697351FF4AEC29CDBAABF2FBE346 \
     -in Bin_Encrpted.bin -out Bin_Decrpted.bin
   ```
4. 按解密区大小截取固件并校验第二组 SHA512：
   ```bash
   dd iflag=skip_bytes,count_bytes if=Bin_Decrpted.bin of=Bin_Firmware.bin count=13265595
   sha512sum Bin_Firmware.bin
   ```
5. 追加 16 字节 key，校验整体 SHA512：
   ```bash
   cp Bin_Firmware.bin Unencrypted_Firmware.bin
   perl -e 'print pack "H*", "C05FBF1936C99429CE2A0781F08D6AD8"' >> Unencrypted_Firmware.bin
   sha512sum Unencrypted_Firmware.bin
   ```
6. 用 binwalk 解包明文固件：
   ```bash
   binwalk -Me Unencrypted_Firmware.bin
   ```

# PoC

```bash
# 0) 头部：SHRS + sizes + IV + 3x SHA512 + 算法区，加密区从 0x6DC 开始
xxd -l 0x110 FW110B02_FW_Encrypt.bin

# 1) 切加密区并校验 SHA512（与头部第三组一致）
dd iflag=skip_bytes,count_bytes if=FW110B02_FW_Encrypt.bin \
  of=Bin_Encrpted.bin skip=1756 count=13265600
sha512sum Bin_Encrpted.bin
# 2811f78b...86336a6fb1

# 2) AES-128-CBC 解密
openssl aes-128-cbc -d -p -nopad -nosalt \
  -K C05FBF1936C99429CE2A0781F08D6AD8 \
  -iv 67C6697351FF4AEC29CDBAABF2FBE346 \
  -in Bin_Encrpted.bin -out Bin_Decrpted.bin

# 3) 截取固件并校验
dd iflag=skip_bytes,count_bytes if=Bin_Decrpted.bin of=Bin_Firmware.bin count=13265595
sha512sum Bin_Firmware.bin
# a3248ff2...f56857c5

# 4) 追加 key 后整体校验
cp Bin_Firmware.bin Unencrypted_Firmware.bin
perl -e 'print pack "H*", "C05FBF1936C99429CE2A0781F08D6AD8"' >> Unencrypted_Firmware.bin
sha512sum Unencrypted_Firmware.bin
# 0a4ecafa...20bba692f

# 5) 解包
binwalk -Me Unencrypted_Firmware.bin
```

# 变体与关联

- 格式变体：其他厂商的自定义头可能把大小/哈希字段换成小端、CRC32 或 SHA-256；先按 magic 找头部，再对照 dd 结果与哈希逐一验证字段边界。
- 脚本化：用 Python `struct` 解析头部、`hashlib.sha512` 校验、`cryptography`/`pycryptodome` 做 AES-CBC 解密，可避免手工 dd 偏移出错。
- 识别阶段：`binwalk -E` 熵值接近 1 且平坦多为加密或压缩；`binwalk -Me` 能解出则是压缩，否则为加密（原文经验规则）。
- 密钥来源：见 [[code-analysis-reverse-firmware-imgdecrypt-aes-key-rsa-qemu-recover]]；其他加密包形态见 [[code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt]] 与 [[code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery]]。
- 明文固件的后续分析：[[code-analysis-reverse-firmware-openwrt-squashfs-jffs2-overlay]]。

# 检测与防御

- 检测：固件升级包出现 `SHRS` 等自定义 magic、头部含多组哈希与高熵加密区；设备/更新服务器上出现与官方哈希不符的固件；升级后文件系统被修改。
- 防御：升级包做厂商签名并在设备端强制验证（不要只依赖包内 SHA512）；使用每设备唯一密钥或安全启动链；对解密后的镜像做二次完整性校验；避免在固件中硬编码全局 key 与 IV；发布前移除调试/解密工具。
