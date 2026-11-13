---
id: iot-hardware-tapo-tc60-uart-uboot-init-sh-root-shell-sd-dump
title: Tapo TC60 摄像头硬件入口：定位 Ingenic T31 UART 焊盘 + 逻辑分析仪确认，U-Boot 中断后 setenv bootargs init=/bin/sh 进入 root shell，再用 SD 卡转储固件/配置分区
type: scenario
domain: iot
path: iot/hardware
technique: tapo-tc60-uart-uboot-init-sh-root-shell-sd-firmware-dump
aliases:
- Tapo TC60 UART
- Ingenic T31 UART
- isvp_t31 U-Boot
- setenv bootargs init=/bin/sh
- 摄像头 UART root shell
- SD 卡固件转储
- Tapo 硬件破解
tags:
- iot
- hardware
- uart
- uboot
- root-shell
- firmware-dump
- sd-card
- tapo
- camera
- physical-access
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:54:00+08:00'
  notes: 已对照原文与25图核对：图05/07/08 主板前后两面、Ingenic T31 与 UART 焊盘、XMC 25QH64C SPI Flash；图06 示波器 125MSa 波形；图09 Saleae Logic 2 Async Serial 解出 'U-Boot SPL 2013.07 (Sep 30 2022)'；图10 Saleae/Tigard 接线；图18 shell.py 显示 Boot confirmed→U-Boot shell→追加 init=/bin/sh→root shell→D/C/B(固件/配置/后门)菜单。setenv bootargs(console=ttyS1,115200n8 ... init=/bin/sh)、printenv(bootdelay=1)、sf probe/sf read 0x80700000 0x80200 0x175000/bootm 与原文一致，最终 uid=0(root)。SD 卡转储与 mtdblock3 config 分区按原文（具体命令原文引用外部博客未展开，卡片未杜撰）。dedup top（GRUB init=/bin/bash、ZKTeco eMMC、BES2300 ROM bootloader、Saleae UART decode 等）非同一条链。原文无版本标记，未设 affected_versions。未在本环境复现。
---

## 一句话结论

Tapo TC60 摄像头主板上 Ingenic T31 SoC 上方有一组 UART 焊盘；用万用表/示波器/逻辑分析仪确认 TX 并抓到 `U-Boot SPL 2013.07` 启动日志后，用同系列 TC100/TC200 研究公开的转义序列打断 autoboot，在 `isvp_t31#` 下 `setenv bootargs ... init=/bin/sh` 再 `bootm` 启动内核，即可直接得到 `uid=0(root)` 的 `/bin/sh`；随后挂载 `/proc`、`/dev`，利用设备 SD 卡槽把 SPI Flash 分区（含 config 分区）转储成文件，为离线配置解密/固件分析提供素材。整个过程需要物理接触设备。

## 原理

- **板卡与存储**：主板正面为 Ingenic T31（系统级视频处理器）与 RTL8188FTV Wi-Fi 芯片，背面摄像头组件下方是 XMC 25QH64C 串行 SPI Flash（固件与配置存储）。Flash 与主 IC 共享电源轨且位于镜头组件下，直接夹取/编程器读取比 UART 麻烦，作者选择 UART 路线。
- **UART 发现**：T31 上方有 4 个疑似 UART 焊盘；万用表确认一个接地、一个疑似 Vcc，示波器在剩余两脚上看到数据波形，逻辑分析仪用 Async Serial 解码得到 U-Boot SPL 2013.07 启动日志，确认波特率/引脚（日志显示 `console=ttyS1,115200n8`）。
- **打断 autoboot**：U-Boot 默认 `bootdelay=1` 自动启动；该机型没有明显按键中断方式，作者沿用 TC100/TC200 研究（tplink-tapo-c200-re 项目）公开的 U-Boot 转义序列，在启动窗口内进入 `isvp_t31#` 命令行。
- **init=/bin/sh 绕过正常启动**：U-Boot 环境里 `bootargs=console=ttyS1,115200n8 mem=45M@0x0 rmem=19M@0x2d00000 root=/dev/mtdblock6 rootfstype=squashfs spdev=/dev/mtdblock7 noinitrd init=/bin/sh`。把 `init=/bin/sh` 写进 bootargs 后，内核不会执行正常 init/服务，而是直接启动一个 root shell；`sf probe; sf read 0x80700000 0x80200 0x175000; bootm 0x80700000` 从 Flash 读出内核并引导。
- **为什么是 root**：内核命令行指定 `init=/bin/sh` 时，`/bin/sh` 以 PID 1、uid 0 运行；BusyBox 提示 `can't access tty; job control turned off`，但 `id` 已是 `uid=0(root)`。
- **SD 卡转储**：设备带 microSD 槽；root shell 下挂载 `/proc`、`/dev`、`/tmp` 后，可把 `/dev/mtdblock*`（或 flash 映射）用 `dd`/`cat` 写到 SD 卡上的 `flashdump.bin`；作者也单独转储了 config 分区（mtdblock3）用于离线解密。binwalk 随后能识别 u-boot、Linux 内核、SquashFS 等结构。

## 触发条件

- 能物理接触摄像头并拆开外壳（前面板 4 个卡扣，用撬片可开）。
- 能找到并焊接/接触 UART 焊盘；有 USB-UART（如 Tigard）与逻辑分析仪/示波器。
- 目标 U-Boot 允许中断 autoboot（或有已知转义序列）；同系列设备的研究资料可复用。
- 设备有 SD 卡槽或可通过串口传输（如 base64/zmodem）导出分区。
- 设备未对 U-Boot 命令行/启动参数做签名校验或锁定。

## 利用步骤

1. 拆机，识别 SoC/Flash，找到 T31 附近的 UART 焊盘；万用表确认 GND/Vcc，示波器确认 TX 波形。
2. 逻辑分析仪 Async Serial（115200 8N1）解码，确认 U-Boot 启动日志与 `isvp_t31#` 提示。
3. 在 autoboot 窗口发送公开的 U-Boot 转义序列（参考 TC100/TC200 项目）进入命令行。
4. 修改 bootargs 并启动：
   ```text
   isvp_t31# setenv bootargs console=ttyS1,115200n8 mem=45M@0x0 rmem=19M@0x2d00000 root=/dev/mtdblock6 rootfstype=squashfs spdev=/dev/mtdblock7 noinitrd init=/bin/sh
   isvp_t31# sf probe; sf read 0x80700000 0x80200 0x175000; bootm 0x80700000
   ```
5. 进入 root shell 后挂载 `/proc`、`/dev`、`/tmp`，用 SD 卡转储固件/config：
   ```sh
   mount -t proc none /proc
   mount -t tmpfs tmpfs /dev -o mode=0755,size=512K
   mount tmpfs /tmp -t tmpfs -o size=20633600,nosuid,nodev,mode=1777
   # 将 /dev/mtdblock* 或 flash 映射 dd 到 SD 卡
   ```
6. 用 binwalk 分析 `flashdump.bin`（可识别 u-boot/Linux/SquashFS），为后续配置解密与固件审计做准备。

## PoC

```text
# U-Boot 控制台（原文）
------Firmware check pass!-----
Autobooting in 1 seconds
isvp_t31# setenv bootargs console=ttyS1,115200n8 mem=45M@0x0 rmem=19M@0x2d00000 root=/dev/mtdblock6 rootfstype=squashfs spdev=/dev/mtdblock7 noinitrd init=/bin/sh
isvp_t31# sf probe; sf read 0x80700000 0x80200 0x175000; bootm 0x80700000

BusyBox v1.19.4 ... built-in shell (ash)
/bin/sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root)
```

```sh
# root shell 下准备挂载并转储
mount -t proc none /proc
mount -t tmpfs tmpfs /dev -o mode=0755,size=512K
mount tmpfs /tmp -t tmpfs -o size=20633600,nosuid,nodev,mode=1777
```

## 变体与关联

- **不同 SoC/引导**：BES2300 用 ROM Bootloader `BE 50/BE 03` 协议 dump；STM32 走 UART/SWD/JTAG；ZKTeco 直接拆 eMMC。见 `[[iot-hardware-bes2300-rom-bootloader-uart-dump]]`、`[[iot-hardware-stm32-firmware-extraction-uart-flash-swd-rdp]]`、`[[iot-hardware-zkteco-emmc-dump-binwalk-shadow-ssh]]`。
- **Linux 主机侧同类思路**：GRUB 编辑启动项加 `init=/bin/bash` 绕过登录，见 `[[pentest-privilege-escalation-linux-grub-init-bash-password-bypass]]`；本质都是控制 bootloader 参数改变 init。
- **无 UART 时**：可直接夹取 SPI Flash（SOP8 夹/编程器）；本机 Flash 在镜头组件下且共享电源轨，作者选择 UART 更省事。
- 后续：转储的 config 分区用于离线解密（`[[iot-hardware-tapo-config-des-ecb-model-version-hash-key]]`），root shell 也用于写入 RTSP 后门账户（`[[iot-tapo-third-account-rtsp-config-ciphertext-backdoor]]`）。

## 检测与防御

- **硬件**：量产固件关闭/移除 UART 调试焊盘或加锁；启用安全启动并校验 bootloader/内核；对 U-Boot 环境与 bootargs 做签名/锁定，禁止 `init=/bin/sh`。
- **存储**：Flash 加密 + 每设备唯一密钥；配置分区加完整性校验（HMAC/签名），防止离线修改后回写。
- **检测**：物理拆机痕迹/防拆开关；启动日志异常（bootargs 被改、init=/bin/sh）；设备启动后出现交互式 shell 或 SD 卡异常写入。
- **响应**：发现物理接触可能时，检查 Flash 内容/配置哈希、U-Boot 环境变量与启动参数，轮换设备凭据并升级固件。
