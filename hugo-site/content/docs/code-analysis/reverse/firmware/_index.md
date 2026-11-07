---
title: 固件逆向
weight: 1
---

# 固件逆向

## 这层是什么

固件提取、文件系统、启动链、模拟/仿真与漏洞分析（含 IoT 固件）。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [8051 + EEPROM 固件逆向：逐指令模拟还原 AUTH/MAC 状态机，暴力 nonce 后解密 EEPROM 记录](code-analysis-reverse-firmware-8051-eeprom-protocol-mac/) | verified | high | 2026-11-05 |
| [MIPS 路由器固件系统级仿真：QEMU malta + binwalk rootfs + 桥接网络 + httpd](code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd/) | verified | high | 2026-11-06 |
| [QEMU user-mode MIPS 固件仿真：LD_PRELOAD 伪造 apmib 依赖 + gdb 远程调试](code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb/) | verified | high | 2026-11-06 |
| [STM32 HAL 固件函数识别：RCC 系统时钟计算与 GPIO BSRR digitalWrite](code-analysis-reverse-firmware-stm32-hal-function-identification/) | verified | high | 2026-11-06 |
| [VMware 挂起内存 vmem 等长字符串补丁：替换控制台脚本路径获取加密设备 Shell](code-analysis-reverse-firmware-vmem-patch-console-script-shell/) | verified | high | 2026-11-06 |
| [VxWorks 初始化结构恢复基址：_sysInit 初始栈指针与 usrInit BSS 清零](code-analysis-reverse-firmware-vxworks-base-sp-bss/) | verified | high | 2026-11-06 |
| [VxWorks 固件加载基址恢复：switch 跳转表绝对地址减文件偏移](code-analysis-reverse-firmware-vxworks-base-jump-table/) | verified | high | 2026-11-06 |
| [VxWorks 符号表/字符串表恢复加载基址：符号名地址减字符串偏移 + IDA 脚本恢复函数名](code-analysis-reverse-firmware-vxworks-symbol-table-base/) | verified | high | 2026-11-06 |
| [华为魔改 SquashFS 固件解包与 MIPS 服务仿真](code-analysis-reverse-firmware-huawei-squashfs-mips-emulation/) | verified | high | 2026-11-04 |
| [固件升级包 AES-128-ECB 解密：16 字节 passwd 与 4 字节 xor_key 派生密钥](code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt/) | draft | high | 2026-11-06 |
| [小米 AX9000（AArch64）UBI 固件解包、Lua 反编译与 QEMU 系统级仿真](code-analysis-reverse-firmware-xiaomi-ax9000-ubi-aarch64-qemu-emulation/) | verified | high | 2026-11-06 |
| [自定义固件包 NOE-FWP 逆向：updater KDF 解 AES-256-CBC 载荷，恢复 Feistel/Digest/校验和三处被抹字段](code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
