---
id: mobile-android-packer-apkid-frida-dexdump-jadx
title: Android 加固 APK 查壳与脱壳：APKiD 识别 + frida-dexdump 内存 dump + jadx/apktool 审计
type: scenario
domain: mobile
path: mobile/android
technique: android-packer-unpacking-static-audit
aliases:
- APK 查壳
- APKiD
- frida-dexdump
- Android 脱壳
- jadx 反编译
- apktool 解包
- 加固 APP 逆向
tags:
- android
- apk
- packer
- unpacking
- frida-dexdump
- apkid
- jadx
- apktool
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:22:58+08:00'
  notes: 已对照原文正文核对：APKiD 字段表（packer/protector/anti_hook syscalls/anti_debug ptrace/compiler/manipulator）、frida-dexdump spawn 模式 dump、jadx 只读审计、apktool 解包改 Manifest/资源、重打包签名触发校验、加固时 smali 仅壳代码，均与原文一致；文章后半部分图片为远程 xzfile 链接，本地 img 仅到 61（环境/证书章节），无法用截图二次核对 APKiD 输出。未验证点：未对具体 APK 复跑 APKiD/frida-dexdump/jadx；无版本/CVE；文章为工具流程教程。
---

## 一句话结论

加固 APP 的 `classes.dex` 在磁盘上是壳代码，真实业务 dex 只在运行时解密到内存；先用 APKiD 识别壳/保护 SDK/反调试，再用 frida-dexdump 以 spawn 模式从内存 dump 出解密后的 dex，最后用 jadx 审计 Java 逻辑、apktool 改 Manifest/资源/Smali，即可绕过“直接反编译只看到壳”的问题。

## 原理

- APK 本质是 zip：`classes.dex` 是 Java/Kotlin 字节码，`AndroidManifest.xml` 是二进制 XML，`lib/` 是 native .so；加固壳会在启动时解密真实 dex 并加载到内存。
- APKiD 通过特征匹配识别 `packer`（加壳）、`protector`（保护 SDK）、`anti_hook`、`anti_debug`、`compiler`、`manipulator` 等字段，决定后续脱壳方式。
- frida-dexdump 在 APP spawn 启动后遍历内存中的 dex，把解密后的 dex 落盘；必须用 spawn 模式（`-f`）以赶在壳完成加载后、检测生效前 dump。
- jadx 把 dex 还原为近似 Java 源码，适合只读审计；apktool 解包为 Smali + 资源，适合改 Manifest、资源、网络配置，但有壳时 Smali 仍是壳代码，改不了业务逻辑。
- 重打包会改变签名，触发签名校验/闪退，因此加固 APP 通常以 Frida 运行时 Hook 为主，apktool 只做 Manifest/资源级修改。

## 触发条件

- 已获得目标 APK，测试设备已 Root 并运行与 PC 端版本一致的 frida-server。
- APP 使用常见加固壳（梆梆、360、腾讯乐固、阿里聚安全等），且未使用无法绕过的 native 反调试/RASP。
- 需要审计业务逻辑、定位检测/pinning 实现或修改 Manifest/资源。

## 利用步骤

1. 安装 APKiD：`pip install apkid`，执行 `apkid target.apk`，记录 `packer`/`protector`/`anti_hook`/`anti_debug` 字段。
2. 启动 frida-server，确认 `frida-ps -H 127.0.0.1:6789` 可列出进程。
3. 安装 frida-dexdump：`pip install frida-dexdump`，以 spawn 模式执行 `frida-dexdump -H 127.0.0.1:6789 -f <包名>`，输出多个 dex 到当前目录。
4. 用 jadx-gui 打开 dump 出的 dex/目录，全局搜索 `root`、`emulator`、`ssl`、`needLogin` 等关键词定位检测与业务逻辑。
5. 需要改 Manifest/资源时用 apktool 解包原始 APK（`apktool d target.apk -o out/`），修改后重打包；有壳时仅改 Manifest/资源，不改业务 Smali。
6. 需要运行时改逻辑时改用 Frida Hook（见关联卡），避免重打包触发签名校验。

## PoC

```bash
# 1. 查壳
source app-venv/bin/activate
pip install apkid
apkid target.apk
# packer: 梆梆/360/腾讯乐固/阿里聚安全...
# anti_hook: syscalls / anti_debug: ptrace ...

# 2. 启动 frida-server（版本必须与 PC 端一致）
adb push frida-server-17.11.0-android-arm64 /data/local/tmp/sf
adb shell "su -c 'chmod 755 /data/local/tmp/sf'"
adb shell "su -c '/data/local/tmp/sf -l 0.0.0.0:6789 &'"
adb forward tcp:6789 tcp:6789
frida-ps -H 127.0.0.1:6789

# 3. 内存 dump 解密后的 dex
pip install frida-dexdump
frida-dexdump -H 127.0.0.1:6789 -f <包名>

# 4. 静态审计
jadx-gui            # 打开 dump 出的 dex 目录
# 或命令行：jadx -d out/ <dex或apk>

# 5. 解包修改 Manifest/资源
apktool d target.apk -o apk_output/
# 修改 AndroidManifest.xml / res/ 后
apktool b apk_output/ -o repacked.apk
```

## 变体与关联

- **壳类型差异**：不同壳的 dex 加载时机、反调试/反 Hook 强度不同；APKiD 的 `anti_hook: syscalls`、`anti_debug: ptrace` 提示需要 native 层对抗。
- **native 层分析**：核心检测/加密在 `.so` 时，用 IDA/Ghidra 分析 `lib/arm64-v8a/*.so`，Frida native Hook 替代 Java Hook。
- **重打包限制**：签名校验、完整性校验、Split APK、资源混淆都会阻碍 apktool 重打包；优先 Frida 运行时 Hook。
- **关联**：[[mobile-android-ssl-pinning-bypass-cert-frida]]（脱壳后定位 pinning 实现并 Hook）、[[mobile-android-anti-detection-root-emulator-proxy]]（定位环境检测逻辑）、[[code-analysis-reverse-unpacking-upx-manual]]（通用二进制脱壳思路）。

## 检测与防御

- APP 使用商业加固/RASP，结合 native 反调试、反 Hook、完整性校验与签名校验，提高脱壳与重打包成本。
- 关键逻辑下沉到 native 层并做控制流混淆，减少 Java 层可读信息；服务端做设备/环境风险评分。
- 检测：设备出现 frida-server/frida-dexdump 进程或 27042/6789 端口；APP 被 spawn 调试；内存中出现多个 dex；APK 被重打包导致签名变化。
