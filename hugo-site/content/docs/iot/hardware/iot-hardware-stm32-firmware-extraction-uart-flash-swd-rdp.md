---
id: iot-hardware-stm32-firmware-extraction-uart-flash-swd-rdp
title: STM32 固件提取三条路径：UART 引脚定位、外部 Flash 芯片夹读取与 SWD/JTAG 调试接口（含 RDP 读保护分级）
type: scenario
domain: iot
path: iot/hardware
technique: stm32-firmware-extraction-uart-flash-swd-rdp
tags:
- iot
- hardware
- firmware-extraction
- uart
- swd
- jtag
- stm32
- flash
- rdp
- chip-clip
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V511
  verified_at: '2026-11-11T05:02:22+08:00'
  notes: 已通读原文 13408 并逐张核对全部 15 张图：01 FT232 USB-UART 模块、02 FT232 与目标板接线、03 杜邦线、04 ECU 探针+操作台、05 芯片测试夹、06 STM32CubeProgrammer Erasing & Programming/ST-LINK 已连接、07 电子显微镜查看板上芯片丝印、08 SOP8/SOP16 引脚定义（/CS、DO(IO1)、/WP(IO2)、GND、DI(IO0)、CLK、/HOLD(/RESET)、VCC）、09 STM32F302xB/C LQFP48 Pinouts、10 F302 引脚定义表（PB8/PB9/PE0/PE1/VSS/VDD）、11 PA14=SWCLK-JTCK、12 PA13=SWDIO-JTMS、13 NRST 复位脚、14 芯片夹夹持 QFP、15 Option bytes Read Out Protection 界面（未勾选=未读保护）。核对结论：原文确为入门级硬件提取操作指南（UART 引脚万用表定位、外部 SOP/QFP Flash 芯片夹、MCU 内部 Flash 经 SWD/JTAG + STM32CubeProgrammer，以及 RDP 0xAA/0xBB/0xCC 分级），未给出成功 dump 的完整演示，正文以遇到 RDP=BB 受阻收尾；卡片如实标注 confidence medium 与'入门级操作指南、未给出成功 dump'边界，未夸大。三条路径与 RDP 分级、SOP8 引脚、F302 SWD 引脚与原文/图一致；QFN/BGA 芯片夹不适用、Level 1 解除会全片擦除且可能变砖等描述与原文一致。dedup 报告 recommendation=new（related=0），BES2300 UART、ZKTeco eMMC、Saleae UART 等候选非同链。图片 11 用 img_small 1200 JPEG，其余未超限，无读取失败。原文无 CVE/组件受影响版本（硬件提取方法），未设 affected_versions。
url: /docs/iot/hardware/iot-hardware-stm32-firmware-extraction-uart-flash-swd-rdp/
draft: false
kb_aliases:
- STM32 固件提取
- IoT 固件提取
- UART 引脚定位
- SWD 提取固件
- 芯片夹读 Flash
- STM32 RDP 读保护
- STM32CubeProgrammer 读取
---

## 一句话结论

从 STM32 类设备直接提取固件有三条路径：①通过 UART 串口（用万用表定位 GND/VCC/TX/RX，FT232+杜邦线/焊接/ECU 探针/芯片夹连接）获取串口日志、shell 或 bootloader dump；②外部独立 Flash（SOP/QFP 封装可用芯片夹免拆读取，QFN/BGA 不适用）；③MCU 内置 Flash（按 Datasheet 的 Pinouts 找到 SWD/JTAG 调试引脚，用 ST-Link + STM32CubeProgrammer 读取）。可行性最终取决于 STM32 读保护（RDP）等级：0xAA 无保护可读；0xBB（Level 1）调试读取被拒，解除保护会触发全片擦除；0xCC（Level 2）不可逆且禁止调试，基本无法直接提取。

## 原理

- **存储位置决定路径**：固件在外部独立 SPI Flash 中时可离线读取；集成在 MCU 内部 Flash 时需经调试接口或芯片自带 bootloader（UART/USB 等）；UART 同时是获取运行日志、shell 和 bootloader 交互的入口。
- **UART 引脚定位（无丝印时）**：
  - GND：万用表蜂鸣档，黑表笔接板子电源地/背面焊锡点，红表笔逐个碰 UART 焊盘，导通鸣响者为 GND；
  - VCC：设备通电，万用表直流 20V 档，红表笔接候选脚、黑表笔接 GND，稳定约 3.3V 者为 VCC；
  - TXD：重启设备时该脚有电压波动（发送数据）；
  - RXD：剩余引脚，或观察有外部数据输入时的电压变化；无法区分时可对 RX/TX 做排列组合遍历。
  - 连接方式：焊接杜邦线、ECU 探针+操作台、SOP/QFP 芯片夹；连接不稳定会导致乱码/无法进入 bootloader。
- **外部 Flash 读取**：先通过丝印/电子显微镜确认封装与型号（如 SOP8、SOP16），按引脚定义连接（SOP8：/CS、DO(IO1)、/WP(IO2)、GND、DI(IO0)、CLK、/HOLD(/RESET)、VCC；SOP16 类似但引脚更多）。SOP/QFP 等引脚外露封装可用通用芯片夹免拆读取；QFN/BGA 引脚在底部，芯片夹无能为力，需要拆焊/植球或其它手段。
- **MCU 内置 Flash 提取**：查对应型号的 Datasheet「Pinouts and pin description」确定调试引脚（如 STM32F302xB/C LQFP48：PA13=SWDIO-JTMS、PA14=SWCLK-JTCK、NRST 复位、VSS 接地、VDD 供电），用芯片夹/探针连接 ST-Link，再用 STM32CubeProgrammer 连接、读取/擦除/编程 Flash。
- **RDP 读保护分级（关键决策点）**：
  - Level 0（0xAA）：无读保护，调试/任意自举均可读 Flash 与备份 SRAM；
  - Level 1（0xBB）：使能读保护，调试连接或从 RAM/系统存储器自举时不能读/擦除/编程 Flash，读请求触发总线错误；把 RDP 编程回 Level 0 会先对 Flash 与备份 SRAM 执行全片擦除（固件清零，操作不当可能变砖）；
  - Level 2（0xCC）：禁止调试/读保护，Level 1 的保护全部有效，且禁止从 RAM/系统存储器自举、禁用 JTAG/SWV/ETM/边界扫描、选项字节不可再改，不可逆——基本断绝调试口提取。
- **为什么有效**：物理接触绕过了软件层的访问控制；能否成功取决于厂商是否启用 RDP Level 2、是否外置 Flash 且未加密、调试/UART 焊盘是否引出。RDP Level 1 的“解除即全擦”是评估时必须先确认的点，否则会丢失目标固件。
- **边界**：本文为入门级操作指南，未给出成功 dump 的完整演示；不同 STM32 型号/封装的引脚与选项字节地址不同，必须以对应 Datasheet/Reference Manual 为准；加密固件即使读出也可能无法直接分析。

## 触发条件

- 拥有设备的物理接触与拆机条件；目标板 UART 焊盘/外部 Flash/调试接口可接触。
- 目标 STM32 的 RDP 为 Level 0（可直接读）；Level 1 需接受全片擦除代价（且要有固件备份/重刷方案）；Level 2 不可行。
- 具备 FT232/杜邦线/万用表/焊接工具/ECU 探针或芯片夹、ST-Link 与 STM32CubeProgrammer 等工具。
- 评估场景需有设备所有者授权。

## 利用步骤

1. 工具准备：FT232 USB-UART、杜邦线、万用表、焊烙/ECU 探针/芯片夹、ST-Link、STM32CubeProgrammer；下载对应型号 Datasheet 与 Reference Manual。
2. 判断固件位置：目视/显微镜找外部 Flash 芯片与 UART/SWD 焊盘；若 Flash 与 MCU 分离优先走外部 Flash，若集成在 MCU 内走调试接口。
3. UART 路径：按万用表法定位 GND/VCC/TX/RX，连接 FT232（TX↔RX 交叉），用串口工具观察启动日志或尝试进入 bootloader。
4. 外部 Flash 路径：确认封装与型号，按引脚定义用芯片夹/探针连接编程器读取；SOP/QFP 可免拆，QFN/BGA 需拆焊。
5. MCU 路径：按 Datasheet Pinouts 找到 SWDIO/SWCLK/NRST/VSS/VDD，连接 ST-Link；在 STM32CubeProgrammer 中连接，先查看 Option bytes 的 RDP 值。
6. RDP 判定：Level 0 直接读取/导出；Level 1 先评估是否接受全片擦除以解除保护（需有重刷方案），不要贸然改选项字节；Level 2 放弃调试口提取，转向其它途径。
7. 导出后记录固件哈希、版本与提取路径，交给 binwalk/逆向流程分析文件系统与密钥。

## PoC

无软件 PoC（硬件操作流程）。关键判据与界面字段：

```text
STM32CubeProgrammer → Option bytes → Read Out Protection:
  RDP = 0xAA（Level 0）: 未保护，可读 Flash/备份 SRAM
  RDP = 0xBB（Level 1）: 读保护，解除会触发全片擦除
  RDP = 0xCC（Level 2）: 不可逆，禁止调试/自举，无法直接提取

SWD 引脚示例（STM32F302xB/C LQFP48）:
  PA13 = SWDIO-JTMS
  PA14 = SWCLK-JTCK
  NRST = 复位；VSS = GND；VDD = 电源

UART 引脚定位:
  GND=蜂鸣档导通；VCC=直流 20V 档稳定 3.3V；
  TXD=重启时电压波动；RXD=剩余脚/有数据时波动
```

## 变体与关联

- **同层固件提取卡**：`iot-hardware-bes2300-rom-bootloader-uart-dump`（UART ROM Bootloader 协议 dump）、`iot-hardware-zkteco-emmc-dump-binwalk-shadow-ssh`（eMMC 拆读取）、`iot-hardware-saleae-logic-uart-decode`（逻辑分析仪解 UART）、`code-analysis-reverse-firmware-openwrt-squashfs-jffs2-overlay`（固件解包）。
- **变体**：外部 Flash 用 CH341A/flashrom 等编程器读取；MCU 支持 UART/USB bootloader 时经 bootloader 导出；RDP Level 1 采用漏洞/故障注入绕过（不在本文范围）；拆焊后用编程器直读。
- **边界**：QFN/BGA、灌封/环氧、RDP Level 2、加密固件、调试口未引出都会阻断该流程；不同型号引脚与选项字节地址必须查手册。

## 检测与防御

- **设备厂商防御**：启用 RDP Level 2（不可逆）或至少 Level 1；关闭/隐藏调试接口；启用 Secure Boot 与固件加密；对固件中的密钥做安全存储；PCB 灌封、屏蔽罩与防拆开关提高物理提取成本。
- **评估与检测**：资产方应盘点暴露的 UART/SWD 焊盘与调试口；对返修/回收设备做固件擦除与密钥轮换；监控异常固件读取/重刷行为。
- **操作安全**：改 RDP 前确认全片擦除风险并备份可重刷固件；焊接/探针操作避免短路与静电损坏；仅在授权设备上操作。
