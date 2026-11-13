---
id: mobile-android-aosp-root-detection-evasion-su-rename-build-fingerprint-adb-root
title: AOSP 8 源码级 root 隐藏：su 改名（fs_config/file_contexts 同步）+ 构建指纹 test-keys/userdebug 去除 + adb root 固化
type: scenario
domain: mobile
path: mobile/android
technique: aosp-source-root-detection-evasion
aliases:
- 自定义 ROM 过 root 检测
- su 改名
- test-keys 改 release-keys
- userdebug 改 user
- 永久开启 adb root
- AOSP 去构建指纹
tags:
- android
- aosp
- root-detection
- bypass
- su
- build-prop
- adb
- sepolicy
- rom
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: AOSP 8.1.0_r1（原文修改/验证的源码版本）
verification:
  verified_by: verifier-V676
  verified_at: '2026-11-13T12:08:27+08:00'
  notes: 已对照原文与全部13张截图核对：su 改名三处（img01 system/extras/su/Android.mk LOCAL_MODULE:=su、img02 fs_config.cpp { 04750, AID_ROOT, AID_SHELL, 0, "system/xbin/su" }、img03 file_contexts /system/xbin/su u:object_r:su_exec:s0）与原文及卡内 PoC 一致；构建指纹链 buildinfo.sh ro.build.tags/flavor（img04/06/08）、Makefile BUILD_KEYS/BUILD_VERSION_TAGS（img05）、TARGET_BUILD_TYPE=$(TARGET_BUILD_VARIANT)（img07）、TARGET_BUILD_FLAVOR := $(TARGET_PRODUCT)-$(TARGET_BUILD_VARIANT)（img09）一致，其中 BUILD_KEYS 条件已按 img05 修正为『使用默认 testkey 证书（DEFAULT_SYSTEM_DEV_CERTIFICATE=build/target/product/security/testkey）时为 test-keys，否则 dev-keys』（staging 与 knowledge 同步）；adb root 两法：main.mk ro.secure=1（img10）、adb/Android.mk filter userdebug eng→加 user（img11）、sepolicy/Android.mk 注释 exit 1（img12）、should_drop_privileges 返回 0（img13）一致。affected_versions 保留 AOSP 8.1.0_r1（原文『安卓8源码』与 aosp810r1 路径）。dedup：与运行时 Shamiko/Frida 隐藏卡、adbd 固件暴露卡非同链。未验证点：未在本机编译验证；原文未提供检测 APP 端到端验证结果。
---

## 一句话结论

当 APP 的 root 检测主要基于 su 路径/包名、`test-keys`/`userdebug` 构建属性与 `/system` 可写等静态指纹时，可直接修改 AOSP 8 源码重新编译镜像来规避：把 su 模块改名并同步 `fs_config.cpp` 与 `file_contexts`；把 `BUILD_KEYS` 从 `test-keys` 改为 `release-keys`、`TARGET_BUILD_VARIANT`/`TARGET_BUILD_FLAVOR` 从 `userdebug` 改为 `user`；再通过 `ro.secure=0`、`ALLOW_ADBD_ROOT`、去掉 sepolicy 的 user 构建阻断、清空 `should_drop_privileges()` 固化 adb root，使镜像在构建期就不带常见 root 指纹。

## 原理

- **被规避的检测项**：原文归纳了 11 类 Android root 检测——su 路径/文件遍历（`/sbin/su`、`/system/bin/su`、`/system/xbin/su`、`/su/bin/` 等）；常见 root 管理/危险/隐藏应用包名（SuperSU、Magisk、KingRoot、RootCloak、Xposed 等）；`ro.debuggable=1`、`ro.secure=0` 属性；`mount` 后 `/system` 等目录可读写；编译标签 `test-keys`；Build 指纹（`ro.build.type`/`display.id`/`flavor`/`description`/`fingerprint` 含 `userdebug`）；直接执行 `su`；native 层检查；Magisk 二进制路径。源码级改造针对的正是这些构建产物。
- **su 改名**：`system/extras/su/Android.mk` 的 `LOCAL_MODULE := su` 改为自定义名，产物二进制即改名；`system/core/libcutils/fs_config.cpp` 中 `system/xbin/su` 的文件权限/属主条目要同步改名；`system/sepolicy/private/file_contexts` 中 `/system/xbin/su` 的 SELinux 标签（`u:object_r:su_exec:s0`）也要同步。三处必须一致，否则新名字的文件没有预期权限或标签、SELinux 下不可执行。
- **去构建指纹**：`ro.build.tags` 由 `build/make/tools/buildinfo.sh` 从 `BUILD_VERSION_TAGS` 写入，后者来自 `build/core/Makefile` 的 `BUILD_KEYS`（使用默认 testkey 证书即 `DEFAULT_SYSTEM_DEV_CERTIFICATE=build/target/product/security/testkey` 时 `:= test-keys`，否则 `:= dev-keys`），改为 `release-keys` 后 `test-keys` 消失；`ro.build.type` 来自 `TARGET_BUILD_TYPE`（Makefile 中取 `TARGET_BUILD_VARIANT`），`ro.build.flavor=$(TARGET_PRODUCT)-$(TARGET_BUILD_VARIANT)`，把 `TARGET_BUILD_VARIANT` 相关赋值/过滤改为 `user`（或直接在 buildinfo.sh 把 `ro.build.type` 赋 `user`、Makefile 中 `TARGET_BUILD_FLAVOR := $(TARGET_PRODUCT)-user`），`display.id`/`description`/`fingerprint` 里的 `userdebug` 也随之消失。
- **adb root 固化（方法一）**：`build/core/main.mk` 中 `ADDITIONAL_DEFAULT_PROPERTIES += ro.secure=1` 改为 `0`；`system/core/adb/Android.mk` 的 `ALLOW_ADBD_ROOT` 过滤条件把 `user` 加入（`userdebug eng` → `userdebug user eng`），否则 user 构建根本不按 `ro.secure` 选择、直接返回 shell 权限；`system/sepolicy/Android.mk` 中 user 构建对 permissive domains 的 `exit 1` 注释掉，避免编译失败。
- **adb root 固化（方法二）**：`system/core/adb/daemon/main.cpp` 的 `should_drop_privileges()` 直接 `return 0`，跳过 `ro.secure`/`ro.debuggable` 判断，adbd 始终保留 root。
- **为什么成立**：检测读取的是镜像里的文件名、SELinux 标签、系统属性与编译产物；源码级修改让这些特征在构建时就不存在，不依赖 Shamiko 等运行时隐藏或 Frida Hook。代价是只能对抗静态指纹类检测。

## 触发条件

- 已获取 AOSP 8 源码并能编译、刷入测试设备。
- 目标 APP 的 root 检测以文件/属性/构建指纹为主，未使用 Play Integrity/Key Attestation、native 完整性校验或服务端风控。
- 需要保留 adb root 便于后续调试。
- 能接受整包编译与 sepolicy 改动带来的复杂度。

## 利用步骤

1. 改 su 名：`system/extras/su/Android.mk` 的 `LOCAL_MODULE`；`fs_config.cpp` 对应条目；`sepolicy/private/file_contexts` 对应行，三处使用同一新名字与标签。
2. 去 `test-keys`：`build/core/Makefile` 的 `BUILD_KEYS := test-keys` 改为 `release-keys`。
3. 去 `userdebug`：`TARGET_BUILD_TYPE`/`TARGET_BUILD_FLAVOR` 与 `buildinfo.sh` 中 `ro.build.type`/`ro.build.flavor` 改为 `user`，并核对 `ro.build.display.id`、`description`、`fingerprint` 不再含 `userdebug`。
4. 固化 adb root：`main.mk` 设 `ro.secure=0`；`adb/Android.mk` 的 filter 加 `user`；`sepolicy/Android.mk` 注释 user 构建的 `exit 1`；或直接让 `should_drop_privileges()` 返回 0。
5. 编译刷机，用检测 APP 或脚本逐项核对：su 路径/包名、`build.prop` 各属性、`mount` 读写、`adb shell id`。

## PoC

```text
# 1) su 改名（三处同步，示例名 mysu）
system/extras/su/Android.mk           LOCAL_MODULE := mysu
system/core/libcutils/fs_config.cpp   { 04750, AID_ROOT, AID_SHELL, 0, "system/xbin/mysu" },
system/sepolicy/private/file_contexts /system/xbin/mysu u:object_r:mysu_exec:s0

# 2) 去 test-keys / userdebug
build/core/Makefile:            BUILD_KEYS := release-keys
build/core/Makefile:            TARGET_BUILD_FLAVOR := $(TARGET_PRODUCT)-user
build/make/tools/buildinfo.sh:  ro.build.type=user（或改 TARGET_BUILD_VARIANT 赋值/过滤）

# 3) 固化 adb root
build/core/main.mk:         ADDITIONAL_DEFAULT_PROPERTIES += ro.secure=0
system/core/adb/Android.mk: ifneq (,$(filter userdebug user eng,$(TARGET_BUILD_VARIANT)))
system/sepolicy/Android.mk: # exit 1（注释 user 构建失败分支）
system/core/adb/daemon/main.cpp: should_drop_privileges() { return 0; }
```

（原文含完整上下文与源码截图；此处为关键片段，未在本机编译验证。）

## 变体与关联

- 运行时隐藏（不改镜像）：[[mobile-android-anti-detection-root-emulator-proxy]]（Shamiko/HideMyApplist/PlayIntegrityFork 与透明代理）、[[mobile-android-frida-hook-isrooted-issimulator-bypass]]（Hook Java 检测方法）。
- 设备 root 获取：[[mobile-android-pixel-apatch-root-boot-img-slot]]、[[mobile-android-adbd-tcp-userdebug-root]]。
- 变体：只改 su 名可过路径/名称遍历；只去构建指纹可过 `test-keys`/`userdebug` 检测；adb root 固化便于调试，但 `ro.secure=0`/`ro.debuggable` 本身可能被检测，需按目标检测项取舍。
- 边界：Play Integrity/硬件证明、native 层 `/proc/self/maps` 或文件哈希校验、服务端设备指纹仍能发现；sepolicy 改动需整包编译且可能触发 neverallow。

## 检测与防御

- 检测（防守方）：`ro.build.tags`/`type`/`flavor`/`fingerprint` 与官方发布版不符；su 二进制改名但权限/行为相似；`fs_config`/`file_contexts` 出现非标准 exec 标签；`ro.secure=0` 或 adbd 常驻 root；system 分区可写。
- 防御：APP 侧结合 Play Integrity/Key Attestation、native 校验关键属性与文件哈希、服务端比对设备指纹；检测挂载状态与调试属性；对异常构建指纹降权或风控。
