---
id: code-analysis-reverse-firmware-tvt-custom-xz-header-qiling-repack
title: TVT 固件魔改 XZ 解包与重打包：内核解压器 tvt 头/尾校验逆向、Qiling 模拟解压取 vmlinux、patch mksquashfs 重打包
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: tvt-custom-xz-header-qiling-decompress-repack
tags:
- firmware
- reverse
- xz
- squashfs
- uimage
- uboot
- qiling
- emulation
- arm
- iot
- unpack
- repack
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T13:51:52+08:00'
  notes: 已对照原文与15张图核对：图02 自编译 uImage 中标准 xz magic FD 37 7A 58 5A 00；图03 TVT 固件 IDA 数据 0x8000E4D8 处 E2 74 56 74 00 50 4B 47 B3 E3（tvt 头）；图04-10 xz 流/头/块/索引/页脚结构；图11 字节替换后仅解出目录骨架（cpio-root 只有 dev/root）；图12 result 中仍有 /sbin 关键字符串；图13 decompress_kernel 反编译与 xz_decompress 调用；图14 自编译内核对照；图15 Qiling dump 的 vmlinux_qiling strings 含 /sbin/init、/sbin/reboot 等。修正：tvt 尾按原文“严谨地说”一节与 mksquashfs 补丁统一为 8 字节 05 C5 00 74 56 74 5E 00（Python 脚本仍按前 7 字节匹配，已加注释）。植入后门（失败）已如实排除：原文明确因删除传输工具、改大小启动失败、芯片级安全码而未打通，仅作为重打包风险提示保留。原文无组件受影响版本，未设 affected_versions。dedup 唯一命中为卡片自身，其余候选均 new；dup-scan 无本卡 pair。未复跑 Qiling/重打包；重打包仅以 unsquashfs 可解验证、未验证设备启动。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-tvt-custom-xz-header-qiling-repack/
draft: false
kb_aliases:
- TVT 固件解包
- 魔改 xz 头
- tvt 头校验
- E2 74 56 74 magic
- Qiling 模拟内核解压
- vmlinux_to_elf
- mksquashfs 魔改重打包
---

## 一句话结论

TVT NVR 固件把内核 zImage 和解包出的 SquashFS 块里标准 XZ 流的 6 字节 magic `FD 37 7A 58 5A 00` 改成 10 字节 `E2 74 56 74 00 50 4B 47 B3 E3`、把页脚 `YZ` 改成 `05 C5 00 74 56 74 5E 00`，并相应修改内核自带 XZ 解压器的头尾 memcmp 常量；逆向定位这两个常量后，可用字节替换脚本做初步还原，或在 Qiling 中直接执行被改过的 `decompress_kernel/xz_decompress` 解出 vmlinux，最后 patch squashfs-tools 的 `xz_compress` 以 tvt 头尾输出从而重打包固件。

## 原理

- **镜像布局**：`binwalk` 与 `strings | grep bootargs` 可还原 MTD 分区：`0x0-0xE0000` 为 boot、`0xE0000-0x300000` 为 kernel（Legacy uImage，64 字节头 + zImage，内含 Linux-4.9.37 ARM）、`0x300000-0x1A00000` 为 23M app（SquashFS/xz）、之后为 JFFS2。uImage 头之后不是 ELF，而是"自解压小程序 + 压缩的 vmlinux"。
- **标准 XZ 流结构**：Stream Header 由 6 字节 magic、2 字节 Stream Flags 与 CRC32 组成；中间是若干 Block（Block Header 记录压缩/未压缩大小与 filter flags，后接压缩数据）；结尾 Index + Stream Footer（CRC32、Backward Size、Stream Flags、magic `YZ`）。内核 `lib/xz/xz_dec_stream.c` 的 `dec_stream_header`/`dec_stream_footer` 分别 `memeq` 校验头 magic 和页脚 magic，CRC 校验仍按标准算法。
- **魔改点只在常量**：把 TVT 的 uImage 与同版本 4.9.37 源码自行编译的 uImage 对比，可在相同位置看到标准 magic `FD 37 7A 58 5A 00` 被换成 10 字节 tvt magic；页脚处要求最后 8 字节为 `05 C5 00 74 56 74 5E 00`。反编译 `decompress_kernel`/`xz_decompress` 可见 `off_8000B50C` 指向的 tvt 头和 `tvt_header+0x8000AA5C` 指向的 tvt 尾参与逐字节比较，CRC 计算逻辑未动。因此数据体仍是合法 XZ 流，只是头尾标识被替换。
- **为什么脚本替换只能解出目录**：把 tvt 头换回标准 8 字节（magic + flags）、截掉 tvt 尾并补 `YZ` 后，标准 xz 解码只能得到目录骨架（原文 `result` 中可见 `/sbin` 等字符串但文件内容缺失），说明头尾之外还有解压器依赖的字段/流程差异，单靠字节拼接不可靠；要么逐字段对齐 Index/Backward Size，要么直接模拟厂商解压器。
- **为什么 Qiling 可行**：uImage 中的解压器是位置相关代码（地址硬编码 0x8000xxxx），以镜像加载地址 0 映射后从 `decompress_kernel` 相关入口执行，按函数约定设置 `r0`=输出缓冲区（解压后的 vmlinux）、`r1/r2`=malloc 区起止、`r3`=arch_id，并在 `xz_decompress` 前后 hook 读取输入区间和返回码；解压成功后在结束 hook 里把预留的输出内存整体 dump，即得到 vmlinux 原始镜像（非 ELF，需再转换）。
- **为什么重打包要改 mksquashfs**：SquashFS 的 `-comp xz` 由 squashfs-tools 的 `xz_compress()` 对每个块调用 liblzma 生成标准 XZ 流；TVT 设备只认 tvt 头尾的流。在压缩完成后、写回前把每块缓冲替换为 tvt 头 + 原块去掉 xz 头尾的内容 + tvt 尾，即可生成设备可解析的 SquashFS；tvt 头比 xz 头长 4 字节，需重新申请缓冲（原文用 mmap，malloc/free 在多线程场景失败）。

## 触发条件

- 拿到 TVT 系列设备（原文 NVR）的 SPI Flash 全量镜像，`binwalk` 能识别 uImage/SquashFS/JFFS2，但标准 `xz`/`unxz` 或 `unsquashfs` 无法正常解出内容。
- 内核为厂商修改过 XZ 解压器常量的版本（原文 Linux-4.9.37 ARM），且能在二进制中定位头/尾比较常量（IDA 搜 `FD 37 7A 58 5A` 或 tvt 字节串、xref 到 `dec_stream_header`/`dec_stream_footer`）。
- 分析环境具备 binwalk、IDA/Ghidra、Python + Qiling（ARM）、`vmlinux-to-elf`、squashfs-tools 源码与编译工具链；若要完整重打包，还需知道各 MTD 分区偏移。
- Qiling 方案需要 uImage 载荷入口地址、输出/malloc 内存布局与解压成功返回码，可从反编译 `decompress_kernel` 与 `xz_decompress` 调用约定得到。

## 利用步骤

1. `binwalk` 拆出 uImage（0xE0000）与 SquashFS（0x300000），`strings` 找 `bootargs` 确认 `mtdparts=hi_sfc:896K(boot),2176K(nva...),23M(app),4M(config),2M(log)` 与 `rootfstype=squashfs`。
2. 用同版本内核源码（同 config，Kernel compression mode=xz）编译对照 uImage，在 IDA 中定位 `decompress_kernel` → `xz_decompress` → `dec_stream_header`/`dec_stream_footer`，确认头 magic 被替换为 `E2 74 56 74 00 50 4B 47 B3 E3`、页脚被替换为 `05 C5 00 74 56 74 5E 00`。
3. 方案 A（快速试探）：脚本扫描 tvt 头，替换为标准 XZ 头 `FD 37 7A 58 5A 00 00 01`，在 tvt 尾处截断并补 `YZ`，得到 `result.xz` 后 `binwalk`/`unxz` 查看；注意此方案原文只解出目录，不能作为最终产物。
4. 方案 B（可靠）：用 Qiling 加载 uImage 载荷，映射输出区与 malloc 区，设置 `r0-r3`，hook `xz_decompress` 前后与结束点，成功时 dump 输出内存为 `vmlinux_qiling`。
5. `python vmlinux_to_elf/main.py ./vmlinux_qiling vmlinux_elf` 转成 IDA 可分析的 ELF；`strings vmlinux_qiling | grep /sbin` 验证解压完整性（应出现 `/sbin/init`、`/sbin/reboot` 等）。
6. 重打包 SquashFS：给 squashfs-tools 的 `xz_wrapper.c` 打补丁，在 `xz_compress()` 生成标准流后替换为 tvt 头/尾（mmap 新缓冲），`mksquashfs squashfs-root out.squashfs -comp xz`，再用打过补丁的 unsquashfs 验证可解。
7. 拼接固件：`dd` 复制原始镜像 0x300000 之前部分，`dd` 把新 SquashFS 写到输出偏移 0x300000，再按原始 JFFS2 偏移（0x1A00000）把后半段追加到新文件系统之后。

## PoC

关键字节与脚本骨架（按原文精简）：

```python
# tvt 头/尾；头比标准 xz 头长 4 字节
tvt_head = bytes([0xE2,0x74,0x56,0x74,0x00,0x50,0x4B,0x47,0xB3,0xE3,0x00,0x00,0x01])
tvt_tail = bytes([0x05,0xC5,0x00,0x74,0x56,0x74,0x5E])  # 原文脚本按这 7 字节匹配；mksquashfs 补丁写入 8 字节（含尾 0x00）
data = open("firmware.BIN","rb").read()
off = data.find(tvt_head)
# 头部还原：标准 magic+flags + tvt 头之后的内容
std = b"\xFD\x37\x7A\x58\x5A\x00\x00\x01" + data[off+len(tvt_head):]
end = std.find(tvt_tail)
open("result.xz","wb").write(std[:end] + b"YZ")
# 注意：原文该方案只解出目录骨架，完整提取改用 Qiling 执行解压器
```

Qiling 模拟解压（核心参数，省略异常处理）：

```python
from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

dec = 0x1000000 + 0x80000000           # 解压输出区
ql = Qiling(code=open("uImage","rb").read()[0x40:], archtype=QL_ARCH.ARM,
            ostype=QL_OS.BLOB, profile="uboot_bin.ql", verbose=QL_VERBOSE.DEBUG)
ql.mem.map(dec, 0x1000000)             # 100M 输出预留
ql.mem.map(0x2000000 + 0x80000000, 0x1000000)
ql.arch.regs.write("r0", dec)          # output_start
ql.arch.regs.write("r1", 0x2000000 + 0x80000000)
ql.arch.regs.write("r2", 0x3000000 - 1 + 0x80000000)
ql.arch.regs.write("r3", 1)            # arch_id
ql.hook_address(debug_hook, 0x8000B51C - 0x80008000)  # 记录输入起止
ql.hook_address(end_hook,   0x8000B5D4 - 0x80008000)  # r0==1 成功，dump 输出
ql.run(0x80008AAC - 0x80008000, 0x80008B40 - 0x80008000)
```

```bash
python ~/tools/vmlinux-to-elf/vmlinux_to_elf/main.py ./vmlinux_qiling vmlinux_elf
```

重打包核心 diff（squashfs-tools `xz_wrapper.c`，mmap 新缓冲避免 malloc/free 失败）：

```c
size_t new_size = selected->length + 4 + 6;
char *new_buff = mmap(NULL, ((new_size/1024)+1)*1024, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
const char *tvt_head = "\xe2\x74\x56\x74\x00\x50\x4b\x47\xb3\xe3";
const char *tvt_tail = "\x05\xc5\x00\x74\x56\x74\x5e\x00";
memcpy(new_buff, tvt_head, 10);
memcpy(new_buff+10, selected->buffer+5, selected->length-2-5);
memcpy(new_buff+10+selected->length-2-5, tvt_tail, 8);
selected->buffer = new_buff;
selected->length = new_size;
```

```bash
mksquashfs ./squashfs-root ./squashfs-root.squashfs -comp xz
dd if=original.BIN bs=1 skip=0 count=3145728 of=new_firm.BIN          # 0x300000 之前
dd if=./squashfs-root.squashfs bs=1 seek=3145728 of=new_firm.BIN     # SquashFS 写到 0x300000
dd if=original.BIN bs=1 skip=27262976 seek=<新FS末尾> of=new_firm.BIN # 原 JFFS2 之后部分
```

## 变体与关联

- **同思路的其他固件**：厂商改 SquashFS magic（如华为 `qshs`）见 [[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]；改 XZ/LZMA 容器头尾、AES 加密容器、尾部 XOR 等分别见 [[code-analysis-reverse-firmware-shrs-container-aes-cbc-sha512-repack]]、[[code-analysis-reverse-firmware-draytek-vigor3910-fip-chacha20-lz4-cpio]]、[[code-analysis-reverse-firmware-tail-0x80-single-byte-xor-decrypt]]。先确认是"改 magic"还是"真加密"：前者数据体仍是标准压缩流，后者需要密钥。
- **提取变体**：若目标架构/入口与 Qiling 支持匹配，直接模拟厂商解压器最稳；也可用 Unicorn 或静态还原 `dec_stream_header` 的常量后写独立解码器；`vmlinux_to_elf` 也适用于其他非 ELF 的 vmlinux 原始镜像。
- **重打包注意**：改固件长度可能触发启动校验（原文后门实验中文件大小变化导致启动失败，且有芯片级安全码保护），实际刷机前需确认分区大小、填充和签名/校验要求；本次重打包仅用 unsquashfs 验证了文件系统可解，未验证设备启动。
- **同源样本**：原文参考项目 `tvt-firmware-decryptor` 提供了另一套 TVT 解密/unsquashfs 补丁实现，可与本卡的头尾常量互相印证。

## 检测与防御

- 研究侧检测：`binwalk` 熵图显示 uImage 载荷高熵但开头存在非标准 magic；`strings` 出现 `/sbin/init` 等路径却无法用标准 `unxz` 完整解出；IDA 中 `dec_stream_header` 附近出现非 `FD 37 7A 58 5A 00` 的常量比较，都是魔改压缩流的特征。
- 防守侧：修改压缩格式 magic/头尾只是增加分析成本，不构成安全边界；设备安全仍依赖固件签名校验、安全启动与升级包认证。
- 加固建议：启用安全启动与固件镜像签名（覆盖 kernel 与 rootfs），升级包加入厂商私钥签名并在刷机时验签；对 SPI Flash 开启读保护，避免攻击者直接离线读取镜像提取密钥与文件系统。
- 研究注意：重打包固件只在授权设备上验证，注意芯片级安全码/分区校验导致的变砖风险；Qiling 模拟参数（入口、内存布局、返回码）必须与目标版本匹配。
