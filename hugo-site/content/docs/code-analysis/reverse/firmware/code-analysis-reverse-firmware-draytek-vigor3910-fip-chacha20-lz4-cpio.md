---
id: code-analysis-reverse-firmware-draytek-vigor3910-fip-chacha20-lz4-cpio
title: DrayTek Vigor3910 固件解密：THUNDER 分段定位 FIP、bl33 ChaCha20 与 LZ4/cpio 解包
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: draytek-vigor3910-fip-chacha20-lz4-cpio
tags:
- firmware
- decryption
- chacha20
- fip
- atf
- arm64
- lz4
- cpio
- iot
- draytek
- reverse
cve: []
severity: medium
confidence: high
affected_versions: Vigor 4.x.x（原文：vigor 4.x.x 版本固件有加密）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:26+08:00'
  notes: 已对照原文与 26 张图核对：THUNDER 分段、stage1 0x3FFF0 定位 FIP TOC（0xAA640001/0x12345678）、fiptool unpack 得 nt-fw.bin；BL33 ChaCha20 key 0DraytekKd5Eason3DraytekKd5Eason、nonce UODAjyXZOzH0、长度 0x034A1A00；LZ4 0x9DFC18/0x2A0B6D6；cpio 070701/TRAILER!!!。卡片已修正：不再断言“去掉前 4 字节”，按原文脚本整体解密；原文正文写 cpio 070707 而截图为 070701，以截图为准。未复跑解密。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-draytek-vigor3910-fip-chacha20-lz4-cpio/
draft: false
kb_aliases:
- Vigor3910 固件解密
- THUNDER 关键字分段
- fip.bin 定位
- fiptool unpack
- nt-fw.bin ChaCha20
- LZ4 cpio 解包
---

## 一句话结论

DrayTek Vigor3910（Cavium THUNDERX ARM64）固件把启动链拆成多段并用关键字分隔：按 `THUNDER` 定位 ATF stage1，用 FIP TOC 头魔数 `0xAA640001`/序列号 `0x12345678` 找到 `fip.bin`，`fiptool unpack` 取出 BL33（`nt-fw.bin`）；BL33 用硬编码 ChaCha20 密钥和镜像头里的 12 字节 nonce 解密 `enc_Image`，再按解密流中的压缩描述符截取 LZ4 数据解压，最后得到 cpio 归档的完整 rootfs。

## 原理

- **固件分段**：升级包由 boot、init、ATF stage1 等多个组件拼接，组件之间用 `THUNDER` 关键字分隔。按关键字偏移与固定块大小 `dd` 切分，可以先把启动链拆开，避免在整包上盲搜。
- **FIP 定位**：ARM Trusted Firmware 把 BL2/BL31/BL32/BL33 打包进 FIP。`fiptool` 写 FIP 时会填入 `TOC_HEADER_NAME=0xAA640001` 与 `TOC_HEADER_SERIAL_NUMBER=0x12345678`；这两个常量在 stage1 中定位到 TOC 头，即得到 `fip.bin` 的起始偏移。
- **为什么看 BL33**：BL31 之后跳转到正常世界的 BL33（U-Boot 或厂商改造的加载器）；Vendor 的镜像解密/加载逻辑通常放在这里，因此 `nt-fw.bin` 是寻找解密算法与密钥的首选。
- **硬编码密钥 + 镜像内 nonce**：BL33 的解密函数不再随机生成 nonce，而是从待解密镜像的固定头部读取 12 字节 nonce（`ext4load` 到内存的 `/nonce`），密钥直接以字符串常量存在于二进制中。固件加密的安全性因此退化为“密钥藏在固件里”，拿到固件即可解密。
- **长度字段与对齐**：镜像头中 `enc_Image` 标识后有 4 字节长度字段（本例值 `0x034A1A00`）；原文只说明“加密从长度记录之后开始”，未给出密文相对该字段的精确字节偏移。截取/解密时应按 BL33 的 `filesize`/头部读取逻辑确认起点，否则 ChaCha20 流会整体错位，解出乱码。
- **二级压缩与归档**：解密后的数据不是标准文件系统，而是厂商自定义的“智能解压/解包”容器：头部记录压缩算法与数据长度，BL33 中的分发函数按首字节/描述符选择解压器。本例在偏移 `0x9DFC18` 处是 LZ4 数据，长度 `0x2A0B6D6`；LZ4 解压后是 `070701` 魔术（newc）的 cpio 归档，用 `cpio -idm` 展开即得 rootfs。
- **验证方法**：解密前后用 binwalk 熵图对比；解密前整体高熵、binwalk 无有效签名，解密后出现文件系统/压缩结构；再用 `file`、`binwalk`、魔术字段与 `TRAILER!!!` 结束标记确认解包完整。

## 触发条件

- 已取得 Vigor3910 固件升级包（原文使用 `v3910_3972.all` 与 `v3910_4325.all`），且固件为加密版本（原文称 Vigor 4.x.x 版本有加密）。
- 目标为 Cavium THUNDERX ARM64 平台的 Vigor3910；其他型号/平台的偏移、密钥与 nonce 位置可能不同。
- 分析环境具备 `dd`、`fiptool`（`arm-trusted-firmware-tools`）、`binwalk`、`lz4`、`cpio`、Python `pycryptodome` 与反汇编工具（IDA/Ghidra）。
- 需要能够对 ARM64 BL33 做静态分析，以确认密钥、nonce 读取方式与压缩描述符布局。

## 利用步骤

1. **按 THUNDER 分段**：在整包中搜索 `THUNDER`，按偏移切出 boot、init、stage1：
   ```bash
   dd if=v3910_3972.all of=boot1.bin skip=8198 count=12288 bs=16
   dd if=v3910_3972.all of=boot2.bin skip=20486 count=79552 bs=16
   dd if=v3910_3972.all of=init.bin skip=100038 count=162112 bs=16
   dd if=v3910_3972.all of=stage1.bin skip=262150 bs=16
   ```
   在 stage1 中可见 `BL1: Booting BL2` 等 ATF 字符串，确认其为 ATF 镜像。
2. **定位 FIP**：在 stage1 中搜索 TOC 头魔数；原文在 `0x3FFF0` 命中 `01 00 64 AA`（`0xAA640001` 小端）与 `78 56 34 12`（`0x12345678`）：
   ```bash
   dd if=stage1.bin of=fip.bin skip=16383 bs=16
   ```
3. **解包 FIP**：安装 `arm-trusted-firmware-tools` 后执行 `fiptool unpack fip.bin`，得到 `nt-fw.bin`、`soc-fw.bin`、`tb-fw.bin` 等；逐个识别后确认 `nt-fw.bin` 对应 BL33。
4. **分析 BL33 解密逻辑**：在 IDA 中定位 ChaCha20 初始化与文件加载函数，确认：
   - 密钥为二进制中的 32 字节字符串常量（IDA 中显示为 `0DraytekKd5Jason3DraytekKd5Jason`，原文可用密钥为把 `J` 换成 `E` 的 `0DraytekKd5Eason3DraytekKd5Eason`）；
   - nonce 从镜像头部读取，原文样本为 12 字节 `UODAjyXZOzH0`；
   - 解密函数按 64 字节块处理，长度来自 `filesize` 环境变量/镜像头长度字段。
5. **截取加密镜像**：原文从整包偏移 `0xF0`（`skip=15 bs=16`）截取 `0x034A1A00` 字节：
   ```bash
   dd if=v3910_4325.all of=enc_Image skip=15 count=3449248 bs=16
   ```
   原文脚本直接对整个 `enc_Image` 做 ChaCha20 解密；文中另述“加密从长度记录之后开始”，但未给出应剥离的字节数。下面按原文脚本整体解密；若实际镜像头包含在 `enc_Image` 中，需按 BL33 的头部读取逻辑先剥离头部再解密：
   ```python
   from Crypto.Cipher import ChaCha20
   key = b"0DraytekKd5Eason3DraytekKd5Eason"
   nonce = b"UODAjyXZOzH0"
   data = open("enc_Image", "rb").read()
   pt = ChaCha20.new(key=key, nonce=nonce).decrypt(data)
   open("enc_Image_decrypted.bin", "wb").write(pt)
   ```
6. **定位二级压缩数据**：在 BL33 中找到解压分发函数（原文 `sub_991C1C`），其参数为数据起点与总长度；根据数据指针 `qword_9DFC18` 与长度 `qword_33EB2F0=0x2A0B6D6`，从解密文件截取 LZ4 数据：
   ```bash
   dd if=enc_Image_decrypted.bin bs=1M iflag=skip_bytes skip=10353688 \
      | head -c 44086998 > lz4.bin
   lz4 -d lz4.bin lz4_decompress
   ```
7. **解 cpio**：确认输出的魔术为 `070701`、结尾含 `TRAILER!!!`，然后解包：
   ```bash
   cpio -idm --no-absolute-filenames < lz4_decompress
   ```
   得到 `bin`、`etc`、`lib`、`sbin`、`usr` 等目录；`usr/sbin/httpd` 即 Web 服务。
8. **可选动态验证**：原文从厂商 GPL 源码中的 `qemu-2.12.1.tar.bz2` 编译带 `-dtb` 参数的 `qemu-system-aarch64`（`--target-list=aarch64-softmmu`），以 `sohod64.bin` 为 `-kernel`、`-dtb DrayTek`、`-M virt,gic_version=3 -cpu cortex-a57` 启动纯 Linux 模式，并用 `run_linux.sh` 建桥接网络。该部分原文未给出成功启动日志，本卡不把它当作已验证步骤。

## PoC

无漏洞 PoC；最小复现是上面的 `dd`/`fiptool`/ChaCha20/LZ4/cpio 命令链。关键常量：

```text
FIP TOC_HEADER_NAME       = 0xAA640001
FIP TOC_HEADER_SERIAL     = 0x12345678
ChaCha20 key（可用）      = 0DraytekKd5Eason3DraytekKd5Eason
ChaCha20 nonce（样本）    = UODAjyXZOzH0
镜像长度字段              = 0x034A1A00
LZ4 数据偏移/长度         = 0x9DFC18 / 0x2A0B6D6
```

## 变体与关联

- **变体：nonce 不硬编码**。不同固件版本的 nonce 位于镜像头不同位置，正确做法是从 BL33 的读取逻辑解析头部，而不是固定样本值；密钥也可能随版本替换。
- **变体：压缩算法分派**。BL33 的解压分发函数可能按首字节或描述符选择 LZ4/gzip/LZMA 等；若 `lz4 -d` 失败，回到分发函数确认算法标识与长度字段。
- **关联**：[[code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt]]（AES 固件解密）、[[code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery]]（自定义包 KDF）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（固件仿真跑 httpd）；本卡针对 ARM64 ATF/FIP 启动链与 ChaCha20+LZ4+cpio 组合。
- **边界**：密钥、nonce、偏移均来自特定固件样本，跨型号/版本不可直接复用；固件解密属于分析前置步骤，最终危害取决于解出的组件中是否存在可利用漏洞。

## 检测与防御

- **厂商侧**：不要把长期不变的对称密钥硬编码在 BL33 等可读镜像中；使用每设备唯一密钥与安全启动/加密启动（BL1 验签、密钥存 OTP）；固件升级包使用带认证的加密格式，避免“拿到固件即可解密”。
- **检测**：固件镜像中出现 `THUNDER`、`fip.bin` TOC 魔数、`enc_Image`、`nonce` 等结构；攻击者/分析者反复对固件做分段 `dd`、`fiptool unpack`、熵分析。
- **防御效果评估**：仅靠私有压缩格式/自定义容器不能提供机密性；应把固件解密视为可公开能力来设计威胁模型。
