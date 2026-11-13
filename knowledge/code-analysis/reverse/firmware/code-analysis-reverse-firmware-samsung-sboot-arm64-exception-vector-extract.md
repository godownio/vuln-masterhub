---
id: code-analysis-reverse-firmware-samsung-sboot-arm64-exception-vector-extract
title: 从三星固件 BL_ 的 sboot.bin 提取安全世界：扁平二进制中按 0x800 对齐识别 ARM64 异常向量表，顺藤摸到 EL3 引导与 TEEgris 安全内核
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: samsung-sboot-arm64-exception-vector-table-extraction
aliases:
- sboot.bin 分析
- BL_ 固件解包
- ARM64 异常向量表识别
- EL3 引导提取
- TEEgris 安全内核提取
- 三星安全世界启动链
tags:
- firmware
- android
- samsung
- arm64
- bootloader
- trustzone
- tee
- reverse
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:51:20+08:00'
  notes: 已对照原文第十一节与图08核对：固件zip中BL_ tar含sboot.bin、可能加密但本目标未加密、ARM64异常向量表0x800对齐/每项0x80/NOP填充/自跳死循环、aarch64 svc向量at+0x400与aarch32 at+0x600、EL3引导→TEEgris安全内核启动链均一致。原文该部分仅两段总体描述，confidence medium合理；无版本标记。未实际提取固件验证。
---

## 一句话结论

三星固件 zip 中以 `BL_` 开头的文件包含 `sboot.bin`——BootROM 用来启动安全世界的引导镜像（可能加密，但部分目标未加密）。对扁平 ARM64 二进制，可按架构约定快速定位异常向量表：与 0x800 对齐、每项 0x80 字节、未用项用 NOP 填充、部分项为跳转到自身的死循环；找到处理同步异常（`svc`/`smc`）的向量后顺着分发逻辑即可定位 EL3 引导程序与 TEEgris 安全内核的系统调用实现，为安全世界漏洞分析提供代码。

## 原理

- **启动链**：设备上电后 BootROM 校验并加载 EL3 bootloader（sboot.bin），后者初始化安全世界（EL3 trusted firmware）并加载 S-EL1 的 TEEgris 安全内核，之后才进入普通世界内核。要分析 TEE 的系统调用实现，必须先拿到 EL3/安全内核镜像。
- **固件包结构**：固件 zip 中多个 tar 归档，`BL_` 前缀文件包含 sboot.bin。它可以是加密的，但本目标未加密，可直接作为平面 ARM64 镜像分析（无文件头/段表时也可用基址假设加载）。
- **ARM64 异常向量表特征**：AArch64 规定向量表基址需 2KB（0x800）对齐，共 16 项、每项 0x80 字节（0x400 字节的同步/IRQ/FIQ/SError 四组 × 4 个异常级别）。在平面二进制中搜索满足以下特征的区域即可定位：起始地址对齐 0x800；每 0x80 处有指令序列；未使用条目填充 NOP；部分条目是 `b .`（跳转到自身）死循环。
- **同步异常入口**：低异常级别执行 `svc`（aarch32 在偏移 +0x600、aarch64 在偏移 +0x400）会进入相应向量，该向量再跳到统一的调度逻辑，按系统调用标识符调用具体实现——这就是 TEEgris syscall 的入口，与普通世界分析中从 libtzsl.so 提取的 syscall 表可以互相印证。
- **分析方法**：在 IDA 中以 ARM64 加载 sboot.bin（或从固件中 binwalk 提取的子镜像），按 0x800 对齐扫描向量表，识别 `b`/`bl` 目标，跟进调度器与 syscall 表；遇到加密镜像则需先从 bootloader 或硬件侧找解密密钥。

## 触发条件

- 拿到目标设备的固件包（zip/tar/odin 包等），其中含 `BL_` 文件且 sboot.bin 未加密或已解密。
- 具备 ARM64 反汇编与裸机启动知识（异常级别、向量表、链接基址）。
- 需要分析安全世界（TEEgris）系统调用实现或寻找 EL3 漏洞。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 解包固件 zip，定位 `BL_` 开头的归档并解出 sboot.bin；binwalk/hexdump 确认是否加密（熵、魔数、可读字符串）。
2. 用 IDA/Ghidra 以 ARM64 小端、合理基址加载；若为平面文件，先按候选基址（0x0、0xF0000000 等）试反汇编。
3. 扫描 0x800 对齐区域，寻找 16 项 × 0x80 的向量表特征（NOP 填充、`b .` 死循环、连续的分支指令）。
4. 定位 aarch64 `svc` 向量（at+0x400）与 aarch32 `svc` 向量（at+0x600），跟到统一调度器。
5. 在调度器中识别系统调用号比较/跳转表（switch/表驱动），输出 `sysno -> handler` 映射，与 libtzsl.so 提取的 syscall 表对照验证。
6. 继续跟进 TEES_* 敏感调用（如 `TEES_ExecuteCustomHandler`、`TEES_RegisterCustomHandler`）的权限校验函数，评估绕过点；记录 EL3/安全内核的缓解措施。

## PoC

```text
# 固件包结构（示意）
firmware.zip
├── BL_xxxx.tar  -> sboot.bin   # BootROM 加载的 EL3 引导，可加密
├── ...
└── 其他 tar（modem、system 等）

# ARM64 异常向量表特征（在平面二进制中）
- 基址 0x800 对齐
- 16 项，每项 0x80 字节
- 未用项 NOP 填充；部分项 b .（死循环）
- 同步异常向量：aarch64 svc -> base+0x400；aarch32 svc -> base+0x600
```

```text
# 调度逻辑示意
vector_sync -> dispatch(table, sysno) -> TEES_* / TEE_* handler
# 与 libtzsl.so 的 syscall 表（r7=sysno, svc #0）交叉对照
```

## 变体与关联

- 变体：sboot.bin 加密时，需从 BootROM/引导头或已解密分区获取密钥与解密流程；也可通过设备内存 dump 拿到运行中的安全内核。
- 变体：不同 SoC 的 EL3 固件布局不同（ARM Trusted Firmware 的 BL1/BL2/BL31 结构更规整，可从 FIP 容器解析）。
- 变体：没有向量表特征时，用已知字符串/系统调用名在二进制中定位，再回溯调用链。
- 关联：[[code-analysis-reverse-firmware-samsung-teegris-ta-extraction]]（安全世界用户空间）、[[code-analysis-reverse-firmware-qiling-teegris-syscall-emulation]]（用 syscall 表搭模拟器）、[[binary-pwn-format-string-teegris-stst-driver-arbitrary-rw-custom-printf-rce]]（利用 TEES_* 权限校验缺陷的驱动链）。

## 检测与防御

- 检测：厂商侧对固件镜像做签名与加密，BootROM 强校验；设备完整性检测（AVB/dm-verity）阻止未签名引导镜像运行。
- 防御：sboot/安全内核加密存储；最小化调试信息与符号；对 EL3 系统调用做严格权限与参数校验（如 TEES_RegisterCustomHandler 的进程身份验证）；安全启动逐级校验。
- 说明：本文是三星固件 sboot.bin 的 ARM64 异常向量表识别与安全内核提取方法，severity low、confidence medium（原文为两段总体描述，PoC 为通用分析步骤）；仅用于授权测试与自有设备研究。
