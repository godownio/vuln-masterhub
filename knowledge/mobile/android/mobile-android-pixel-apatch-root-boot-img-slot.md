---
id: mobile-android-pixel-apatch-root-boot-img-slot
title: Pixel 8 Android 16 APatch Root：按 Build 取 boot.img 修补、核对 slot 后 fastboot 刷入
type: scenario
domain: mobile
path: mobile/android
technique: pixel-apatch-root-boot-img-slot
aliases:
- APatch
- KernelPatch
- Pixel 8
- Android 16
- boot.img 修补
- fastboot flashing unlock
- ApatchGoGo
tags:
- android
- root
- apatch
- kernelpatch
- pixel
- bootloader
- fastboot
- slot
cve: []
severity: medium
confidence: high
status: verified
affected_versions: Pixel 8 / Android 16（原文测试 Build BP3A.251005.004.B2）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:20:04+08:00'
  notes: 已对照原文与20张截图核对：Pixel 8/Android 16/Build BP3A.251005.004.B2、OEM 解锁、fastboot unlocked/Boot slot、官方出厂镜像 boot.img、APatch 超级密钥修补、fastboot flash boot、系统补丁安装、slot 切换丢 root 均一致；affected_versions 与原文明确标注一致。未验证点：未实际刷机。
---

## 一句话结论

Pixel 8（Android 16）解锁 BL 后，按“型号 + Android 版本 + Build 号”下载官方出厂镜像，取出 `boot.img` 交给 APatch 修补，再 `fastboot flash boot` 刷入即可获得 KernelPatch Root；关键坑是 A/B slot：刷入的槽可能在多次重启后切换，需按当前槽和系统版本重新刷对应 boot。

## 原理

- **BL 解锁**：`adb reboot bootloader` → `fastboot flashing unlock` → 音量键选择、电源键确认；解锁会清空数据，之后需重新开启开发者选项/USB 调试。`fastboot` 界面会显示 `Device state: unlocked` 和 `Boot slot: a/b`。
- **APatch/KernelPatch**：APatch 通过修补内核/boot 映像注入 KernelPatch，提供 `su` 与模块能力；需要与设备当前系统版本完全匹配的 `boot.img`，否则可能无法启动或丢 root。
- **镜像匹配**：在 `设置 → 关于手机` 记录 Android 版本与 Build 号，到 Google 官方 factory images 页面按机型代号（Pixel 8 = shiba）和 Build 下载出厂镜像；解压后从内层 zip 取 `boot.img`。
- **修补流程**：APatch 安装 → 右上角安装图标 → 选择 `boot.img` → 设置超级密钥 → 开始修补 → 输出 `apatch_patched_*.img` → 拉回电脑 → `fastboot flash boot <img>` → 重启 → 在 APatch 输入超级密钥 → 安装系统补丁。
- **slot 坑**：A/B 设备默认刷当前 slot；多次重启后可能因另一个槽系统损坏/回滚而切换。若 root 掉了，先 `fastboot getvar current-slot` 看当前槽，再按该槽系统版本重新取 boot.img 修补/刷入；不要只反复刷原来的槽。
- **工具**：官方 platform-tools 的 adb/fastboot 最稳；作者用 AYA 传文件、ApatchGoGo 自动化 `open_oem`/`unlock`/`apatch_ios` 等步骤，但解锁确认和 USB 调试仍需手动。

## 触发条件

- Pixel 设备已开启开发者选项和 OEM 解锁（`OEM 解锁` 开关可用）。
- 电脑有官方 platform-tools 和 USB 驱动；能进入 bootloader/fastboot。
- 能下载与设备型号/Android 版本/Build 完全匹配的官方出厂镜像。
- 接受解锁清空数据、失去保修、部分银行/支付应用无法使用。

## 利用步骤

1. 开启开发者选项、USB 调试、OEM 解锁；确认 `adb devices` 能识别。
2. `adb reboot bootloader`，执行 `fastboot flashing unlock`，按音量/电源键确认；记录 `Device state` 和 `Boot slot`。
3. `fastboot reboot`，重新配置设备并开启 USB 调试。
4. 在关于手机记录 Android 版本/Build；下载对应出厂镜像，解压取出 `boot.img`。
5. 把 `boot.img` 推到手机 Download 目录；APatch 选择安装 → 选 boot.img → 设超级密钥 → 修补；把 `apatch_patched_*.img` 拉回电脑。
6. `adb reboot bootloader` → `fastboot flash boot <patched.img>` → `fastboot reboot`。
7. 打开 APatch 输入超级密钥，安装系统补丁；用 `su`/模块验证 root。
8. 若多次重启后 root 丢失，检查当前 slot 和系统版本，按当前槽重新匹配 boot.img 修补/刷入。

## PoC

```bash
adb devices
adb reboot bootloader
fastboot flashing unlock
# 手动音量键选择 Unlock，电源键确认
fastboot getvar current-slot
fastboot reboot

# 修补后
adb reboot bootloader
fastboot flash boot apatch_patched_11142_0.12.2_xxxx.img
fastboot reboot
```

## 变体与关联

- **Root 方案变体**：Magisk（patch boot.img）、KernelSU、APatch/KernelPatch；A/B 设备都要注意 slot。
- **设备变体**：Pixel 8 = shiba、Pixel 8a = akita、Pixel 9 系列代号不同；Build 必须匹配。
- **自动化变体**：ApatchGoGo 等脚本可自动开 OEM/重启/修补/刷入，但解锁确认、USB 调试授权仍需手动。
- **关联卡片**：[[mobile-android-adbd-tcp-userdebug-root]]（adbd root）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（root 后抓包）、[[mobile-android-anti-detection-root-emulator-proxy]]（root 隐藏/反检测）。
- **边界**：Bootloader 不可解锁的运营商版、系统更新后 boot.img 变化、AVB/安全启动校验、slot 切换都可能导致失败；刷错镜像可能变砖。

## 检测与防御

- **企业/防守方**：启用硬件 attestation/Play Integrity、检测 unlocked bootloader、KernelPatch/APatch 痕迹、`su` 与模块目录；对敏感应用拒绝 root 设备。
- **个人测试**：只在授权测试机上解锁；保留原厂 boot.img 以便回滚；记录 slot/Build，系统更新后重新修补。
- **风险**：解锁清空数据、失去保修、银行/支付/DRM 应用不可用；刷错 slot/镜像可能无法启动。
