---
id: mobile-android-360-hardening-fundex-lsposed-dump
title: 360 加固 APK 脱壳：PKID 查壳 + FunDex/LSPosed dump（frida-dexdump 被检测时的替代）
type: scenario
domain: mobile
path: mobile/android
technique: android-360-hardening-fundex-lsposed-dump
aliases:
- 360 加固脱壳
- FunDex
- LSPosed 脱壳
- frida-dexdump 失败
- PKID 查壳
- am monitor 包名
tags:
- android
- apk
- packer
- unpacking
- 360-hardening
- lsposed
- fundex
- jadx
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:08:55+08:00'
  notes: 已对照原文与30张截图核对：PKID《360》加固、FunDex2/LSPosed 勾选目标APP、am monitor 取包名、/data/data/<包名> dex dump、tar 打包与 JADX 反编译均与图文一致；Magisk Zygisk/排除列表绕过 root 检测亦与截图相符。未验证点：未复跑脱壳流程，FunDex Hook ClassLoader 属工具通用原理描述。
---

## 一句话结论

APK 经 PKID 查壳确认是 360 加固后，若 `frida-dexdump` 因 Frida 特征检测无法脱壳，可改用 LSPosed 的 FunDex 模块：启用模块并勾选目标 APP，启动 APP 后在 `/data/data/<包名>` 下得到解密后的 dex，打包拉回后用 JADX 反编译审计。

## 原理

- 360 加固会在启动时解密真实 dex 并加载到内存；磁盘上的 `classes.dex` 只是壳代码，直接反编译看不到业务逻辑。
- `frida-dexdump` 依赖 Frida 注入；若 APP 检测 Frida（进程名、端口、maps、线程、字符串等），注入会失败或 APP 退出，因此需要非 Frida 的内存 dump 方式。
- FunDex（`com.zhenxi.FunDex2`）是 LSPosed 模块，通过 Hook Android ClassLoader/运行时把加载后的 dex 写到 APP 私有目录；只需在 LSPosed 中启用模块、勾选目标 APP，然后正常启动 APP。
- 包名未知时可用 `adb shell am monitor`，启动 APP 后观察 `Activity starting: <包名>`；dump 出的文件在 `/data/data/<包名>/` 下，常见为 `<size>.dex`。
- 打包命令 `tar -cvf dump.tar *.dex`，`adb pull` 回本地后用 JADX-GUI 打开；若 dump 不完整，可能是加固版本差异/多 dex 未全部加载，需要换工具或多次启动。
- 第二道 APP 同样 360 加固且有 root 检测；先用 Magisk 的 Zygisk + 配置排除列表（denylist）隐藏 root，再启动 APP 并用 FunDex2 脱壳。

## 触发条件

- APK 被 360 加固（PKID 显示 `《360》加固`），磁盘 dex 为壳代码。
- 设备已 Root 并安装 LSPosed + FunDex/FunDex2 模块。
- `frida-dexdump` 因 Frida 检测失败，或不想在目标进程注入 Frida。
- APP 有 root 检测时，需要 Magisk Zygisk/denylist 或 Shamiko 等先绕过。

## 利用步骤

1. 用 PKID/APKiD 查壳，确认 360 加固及版本特征。
2. 安装 FunDex/FunDex2，在 LSPosed 中启用模块并勾选目标 APP（不要只勾系统框架）。
3. 若不知道包名，执行 `adb shell am monitor`，启动 APP，记录 `Activity starting:` 后的包名。
4. 正常启动 APP，等待壳解密/加载；在 `/data/data/<包名>/` 下查看新生成的 `*.dex`。
5. `adb shell "cd /data/data/<包名> && tar -cvf /sdcard/dump.tar *.dex"`，`adb pull /sdcard/dump.tar`。
6. 解压后用 JADX-GUI 打开 dex，全局搜索接口路径、参数名、签名函数、`root`/`frida` 检测等关键词。
7. 若 dump 不完整，尝试多次启动、换 FunDex 版本、或用其他 LSPosed dump 模块；root 检测导致启动失败时先配置 Magisk denylist/Zygisk。

## PoC

```bash
# 1) 查壳（PKID/APKiD 均可）
#    PKID 输出：Shell: 《360》加固

# 2) 找包名
adb shell am monitor
# 启动 APP 后看到：** Activity starting: com.example.target/...

# 3) LSPosed 启用 FunDex2 并勾选目标 APP，启动 APP

# 4) 查看并打包 dump 出的 dex
adb shell "su -c 'ls -al /data/data/com.example.target/*.dex'"
adb shell "su -c 'cd /data/data/com.example.target && tar -cvf /sdcard/dump.tar *.dex'"
adb pull /sdcard/dump.tar
tar -xvf dump.tar
# 5) JADX-GUI 打开 dex 目录
```

## 变体与关联

- 变体：其他加固（梆梆、腾讯乐固、阿里聚安全）可用对应 LSPosed dump 模块或 Frida-dexdump/BlackDex 等。
- 变体：frida-dexdump 被检测时，先魔改 Frida 或改用非注入式 dump（见 Frida 魔改卡片）。
- 变体：多 dex/动态加载时需在 APP 各功能页面触发加载后再 dump。
- 关联：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APKiD + frida-dexdump + JADX）、[[tools-frida-source-patch-anti-detection]]（Frida 魔改反检测）、[[mobile-android-anti-detection-root-emulator-proxy]]（root/环境隐藏）。

## 检测与防御

- 检测：APP 启动时 ClassLoader 加载大量 dex、私有目录出现新 dex、LSPosed/FunDex 模块痕迹。
- 防御：加固壳完整性校验、反注入/反 Hook、Frida/Xposed 检测、RASP；不要把敏感逻辑只放在客户端 dex。
- 响应：确认脱壳后，视为客户端逻辑泄露，轮换接口密钥并加强服务端校验。
