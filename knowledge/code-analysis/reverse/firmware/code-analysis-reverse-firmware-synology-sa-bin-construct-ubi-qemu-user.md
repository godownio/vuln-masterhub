---
id: code-analysis-reverse-firmware-synology-sa-bin-construct-ubi-qemu-user
title: Synology TC500 .sa.bin 固件解包与 QEMU user-mode 仿真：construct 头解析 + UBI/SquashFS 提取 + webd 运行
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: synology-sa-bin-firmware-unpack-qemu-user
aliases:
- Synology .sa.bin 解包
- TC500 固件仿真
- construct 固件格式解析
- ubireader_extract_images
- qemu-arm user-mode webd
tags:
- firmware
- reverse
- synology
- construct
- ubifs
- squashfs
- binwalk
- qemu
- user-mode
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:40+08:00'
  notes: 已对照原文核对：construct 头(version8/firmware_version16/model8/padding56/16B/padding16/4B/partition_count2 LE/pre_post zlib)、分区 name64+script_len+image_len+zlib、512B 签名、ubireader_extract_images+binwalk -Me、qemu-arm -L ./ ./bin/webd、file/checksec/netstat，与原文脚本/截图一致。未验证点：未本机解包/仿真；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

Synology 摄像头固件 `.sa.bin` 是自定义容器：头部包含版本/型号/分区数，以及 zlib 压缩的 pre/post 脚本；随后是若干分区，每个分区由名称、zlib 压缩的脚本和 zlib 压缩的镜像组成，末尾为 512 字节签名。用 construct 按该结构解析即可提取各分区与 rootfs，再用 `ubireader_extract_images` 和 `binwalk -Me` 还原 UBI/SquashFS 文件系统，最后用 `qemu-arm -L ./ ./bin/webd` 以 user-mode 直接运行目标 Web 服务进行分析。

## 原理

- **容器格式**：`.sa.bin` 的 header 为 `version(8) + firmware_version(16) + model(8) + padding(56) + 16 字节 + padding(16) + 4 字节 + partition_count(2, little-endian)`，后接长度前缀的 zlib 压缩 pre_script/post_script；分区数组每项为 `name(64) + script_length(4) + image_length(4) + zlib(script) + zlib(image)`；文件末尾 512 字节签名。
- **UBI/SquashFS**：rootfs 分区镜像通常是 UBI 卷，`ubireader_extract_images` 按 UBI 卷提取出 `img-*_vol-rootfs.ubifs`；`binwalk -Me` 识别其中的 SquashFS（xz 压缩）并递归解包，得到完整 rootfs。
- **user-mode 仿真**：`qemu-arm -L <sysroot> ./bin/webd` 让 32 位 ARM 程序在当前主机上运行，`-L` 指定 rootfs 作为动态链接器/库搜索路径；适合只分析单个服务，不依赖内核与硬件外设。
- **替代方案**：把 rootfs 打包成 Docker 镜像或用 qemu-system 全系统仿真，适合需要网络栈/内核行为的场景；user-mode 更轻量，但系统调用与设备节点可能缺失。
- 该固件容器带 512 字节签名，但解析脚本通常不校验签名；攻击者/研究者可直接解包并修改分区内容，说明固件完整性与安全启动需要独立验证。

## 触发条件

- 可从厂商归档站点下载对应型号固件（如 Synology TC500）。
- 本机有 Python + construct、ubireader、binwalk、qemu-arm（或 Docker/qemu-system）。
- 目标是分析固件中的服务、配置或漏洞，不依赖真实设备。

## 利用步骤

1. 下载 `.sa.bin`，用 construct 定义容器结构并解析 header/分区。
2. 按 `partition_count` 遍历分区，分别写出 `script` 和 `image`；同时导出 pre/post 脚本。
3. 对 rootfs 镜像运行 `ubireader_extract_images <image> -o ubi_out`，再用 `binwalk -Me` 解出 SquashFS。
4. 在 `squashfs-root` 中定位目标服务（如 `bin/webd`），用 `file`/`checksec` 确认架构与保护。
5. 运行 `qemu-arm -L ./ ./bin/webd`，用 `curl`/`netstat` 验证 HTTP 端口与服务行为。
6. 如需完整系统，将 rootfs 打包为 tar 构建 Docker 镜像，或用 qemu-system 启动内核。

## PoC

construct 容器结构（关键字段）：

```python
firmwareFormat = Struct(
    "header" / Struct(
        "version" / PaddedString(8, 'ascii'),
        "firmware_version" / PaddedString(16, 'ascii'),
        "model" / PaddedString(8, 'ascii'),
        Padding(56),
        Bytes(16),
        Padding(16),
        Bytes(4),
        "partition_count" / BytesInteger(2, swapped=True),
        "pre_script" / Prefixed(BytesInteger(4, swapped=True), Compressed(GreedyBytes, "zlib")),
        "post_script" / Prefixed(BytesInteger(4, swapped=True), Compressed(GreedyBytes, "zlib")),
    ),
    "partitions" / Array(this.header.partition_count, Struct(
        "name" / PaddedString(64, 'ascii'),
        "script_length" / BytesInteger(4, swapped=True),
        "image_length" / BytesInteger(4, swapped=True),
        "script" / FixedSized(this.script_length, Compressed(GreedyBytes, "zlib")),
        "image" / FixedSized(this.image_length, Compressed(GreedyBytes, "zlib")),
    )),
    "signature" / Bytes(512),
)
```

解包与仿真命令：

```bash
python parse_sa_bin.py Synology_TC500_1.1.1_0383.sa.bin
ubireader_extract_images Synology_TC500_1.1.1_0383.sa.bin_rootfs.bin -o ubi_out
binwalk -Me img-1656200229_vol-rootfs.ubifs
cd squashfs-root && qemu-arm -L ./ ./bin/webd
curl -v http://127.0.0.1:8080/
```

## 变体与关联

- 其他 Synology 摄像头/型号可能使用相同 `.sa.bin` 容器，仅 header 字段或分区布局不同。
- 系统级仿真可用 qemu-system + 内核/initramfs；Docker 方案适合把 rootfs 作为用户态环境。
- 关联：MIPS/AArch64 固件的 UBI + SquashFS 解包、QEMU user-mode + LD_PRELOAD 伪造依赖、路由器 httpd 系统级仿真。
- 解包后可在 webd 中发现格式字符串等漏洞，见 Synology TC500 webd 格式字符串 RCE 链。

## 检测与防御

- 厂商应对固件容器签名做严格校验并启用安全启动，防止离线解包/篡改后重刷。
- 研究/防御方可基于解包结果做静态扫描、依赖版本比对与服务仿真复现。
- 生产环境限制摄像头管理端口暴露，及时更新修复固件。
