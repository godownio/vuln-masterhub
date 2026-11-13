---
id: code-analysis-reverse-firmware-samsung-teegris-ta-extraction
title: 三星 TEEgris 可信小程序提取与逆向：/system/tee 的 UUID 文件是 SEC2 头 + ARM32 ELF，startup.tzar 藏 TEE 用户空间
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: samsung-teegris-trusted-applet-extraction
tags:
- firmware
- android
- trustzone
- tee
- teegris
- trusted-application
- reverse
- arm
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:51:11+08:00'
  notes: 已对照原文与图01/02/03核对：/system/tee UUID命名、SEC2魔数+偏移0x8起ELF（hexdump示例）、startup.tzar解出bin/arm库与libtzld.so、GlobalPlatform五回调、TA main在libteesl.so、stilib/pycparsert类型库流程均一致；已把“尾部附数字签名”改为“很可能”（原文为推测语气）。该提取流程非漏洞，affected_versions不适用，未设置版本。dedup与本篇qiling/sboot/keymst卡为同篇不同场景，非同链。未在真实设备/固件上复现提取。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-samsung-teegris-ta-extraction/
draft: false
kb_aliases:
- TrustZone 可信小程序提取
- TEEgris TA 提取
- /system/tee 分析
- startup.tzar 解包
- SEC2 ELF
- GlobalPlatform TEE API 逆向
---

## 一句话结论

在部分三星 Exynos 设备上，安全世界的可信小程序（TA）与驱动以 UUID 命名的文件明文存放在普通世界的 `/system/tee/`：文件头是 `SEC2` 魔数，偏移 8 处才是真正的 ARM32 ELF，ELF 尾部附加数据很可能是数字签名；同目录的 `startup.tzar` 是一个非 tar 的自定义归档，解开后包含 TEE 用户空间库（`libtzsl.so`、`libteesl.so`、动态链接器 `libtzld.so`）和启动驱动——拿到这些文件就可以静态逆向整个 TEE 用户空间，再用 GlobalPlatform TEE API 的回调结构定位每个 TA 的入口与命令分发。

## 原理

- **TrustZone 划分**：ARMv7-A/v8-A 的 TrustZone 把 CPU 分为普通世界与安全世界。异常级别上普通世界是 N-EL0/EL1/EL2，安全世界是 S-EL0（TA）/S-EL1（TEE OS，此处为 TEEgris）/S-EL3（trusted firmware）。普通世界用户态不能执行 `smc`，必须经 EL1 内核的驱动转发。
- **通信路径**：用户态守护进程（如 `tzdaemon`，带专用 SELinux 配置）打开内核设备 `/dev/tz_wormhole`；内核驱动 `drivers/misc/tzdev` 实现 EL3 触发与数据清洗，再用 `smc` 进入 EL3/S-EL1。普通世界与安全世界的边界由这条链路定义。
- **文件即 TA**：`/system/tee/` 下的文件按 UUID 命名（如 `00000000-0000-0000-0000-4b45594d5354`，后半段是 `KEYMST` 的 ASCII hex），`hexdump` 可见开头 `SEC2` 魔数，`0x8` 起是 `7f 45 4c 46`（ELF），架构 ARM32。ELF 之外的头部/尾部数据大概率是数字签名，用于在普通世界失陷时校验 TA 完整性——不影响提取与逆向。
- **startup.tzar**：名字像 tar 但不是 tar，是 TEEgris 专用的归档格式。解开后得到 `bin/arm/` 下的 TEE 用户空间库（GlobalPlatform TEE API 实现、socket 库、debug 库）与 `libtzld.so` 动态链接器，以及 `bin/` 下的启动驱动/TA。库是纯 ELF，无额外头尾。
- **入口点定位**：GlobalPlatform TEE 规定 TA 导出五个回调：`TA_CreateEntryPoint`/`TA_DestroyEntryPoint`（创建/销毁）、`TA_OpenSessionEntryPoint`/`TA_CloseSessionEntryPoint`（会话开关）、`TA_InvokeCommandEntryPoint`（命令分发，普通世界每次请求都到这里）。TA 的 `main` 不在 TA 二进制里，而在 `libteesl.so`：它初始化 TA 后进入消息循环，收到请求再调用上述导出函数。
- **逆向增强**：用 GlobalPlatform 头文件生成 IDA 类型库（Hexrays stilib 生成 `tee_arm.til`，pycparsert 生成函数签名脚本），加载后 IDA 能按 TEE API 的 `TEE_*` 原型显示参数与结构，快速区分命令解析、密钥管理与内存操作。

## 触发条件

- 目标为使用 TEEgris 的三星 Exynos 设备，且 `/system/tee/` 对 root（或可读系统分区）可见；部分固件未加密 TA 文件。
- 能获取固件包（BL_/boot.img 等）或在已 root 设备上直接读取系统分区。
- 具备 IDA/Ghidra 等 ARM32 反汇编能力；分析 TA 需要理解 GlobalPlatform TEE API。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 在设备上 `ls -lR /system/tee` 或从固件镜像提取 system 分区，收集 UUID 文件与 `driver/`、`startup.tzar`。
2. 对 UUID 文件做 `hexdump -C`/`binwalk`，确认 `SEC2` 头与 ELF 偏移；按偏移截取 ELF（或让 IDA 直接以 ARM32 加载并手动调整基址）。
3. 解开 `startup.tzar`（使用公开的 tzar 解包脚本或自行解析），得到 `bin/arm/*.so`、`libtzld.so` 与启动组件。
4. 在 IDA 中加载 TA ELF，定位 `TA_InvokeCommandEntryPoint`，沿命令分发（`tz_process_command` 一类）枚举 command id 与处理函数。
5. 加载 `libteesl.so`/`libtzsl.so`，用 TEE 类型库/签名脚本恢复 `TEE_MemMove/TEE_MemFill/TEE_*` 原型，标注 TA 与 OS 的交互；结合 syscall 包装（`svc #0`）理解安全内核服务。
6. 对高价值 TA（密钥管理、支付、DRM）做数据流审计：外部可控的 key blob/长度字段是否进入 `memcpy`、索引计算、命令分发；为后续动态模拟或漏洞利用做准备。

## PoC

```bash
# 设备上（root）
ls -lR /system/tee
hexdump -C /system/tee/00000000-0000-0000-0000-4b45594d5354 | head
# 00000000  53 45 43 32 ... 7f 45 4c 46 01 01 01 00  |SEC2....ELF.....|
#                          ^ 偏移 0x8 起为 ARM32 ELF

# 解包 startup.tzar（tzar 解包脚本，公开实现）
python unpack_startup_tzar.py /system/tee/startup.tzar
tree startup_tzar
# bin/arm/libteesl.so  libtzsl.so  libtzld.so  libteesock.so ...
```

```text
# TA 导出回调（GlobalPlatform TEE）
TA_CreateEntryPoint / TA_DestroyEntryPoint
TA_OpenSessionEntryPoint / TA_CloseSessionEntryPoint
TA_InvokeCommandEntryPoint   <- command id 分发入口
# main 不在 TA 内，位于 libteesl.so 的消息循环
```

## 变体与关联

- 变体：不同厂商 TEE 的 TA 存放位置不同（QSEE 在 /firmware/image、Kinibi 在 /system/tima_measurement_info 等）；文件封装可能是 MBN/ELF/SEC2，需按魔数识别。
- 变体：TA 文件加密或签名校验严格时，需先从 bootloader/固件中找解密密钥，或改用动态侧（普通世界守护进程）攻击。
- 变体：只有固件包没有设备时，可用 binwalk 从 boot.img/system.img 提取；`tzar` 解包脚本可从公开研究获取。
- 关联：[[code-analysis-reverse-firmware-qiling-teegris-syscall-emulation]]（提取后的 TA 放进 qiling 模拟）、[[code-analysis-reverse-firmware-samsung-sboot-arm64-exception-vector-extract]]（从 sboot.bin 提取安全内核）、[[binary-pwn-stack-teegris-keymst-rsa-pubexp-overflow-secure-world-rop]]（KEYMST TA 的栈溢出利用）。

## 检测与防御

- 检测：设备完整性检测关注 /system/tee 文件被读取/复制；企业 MDM 可检测 root 与系统分区挂载；厂商侧监控 TA 文件外泄。
- 防御：厂商应加密/签名 TA 并对普通世界隐藏（SELinux 限制 /system/tee 访问）；启用 dm-verity；TA 内做最小权限与输入校验；研究侧建议在隔离环境解包分析。
- 说明：本文是 TEEgris TA/库提取与逆向的分析流程，severity low（信息获取/分析阶段）；仅用于授权测试与自有设备研究。
