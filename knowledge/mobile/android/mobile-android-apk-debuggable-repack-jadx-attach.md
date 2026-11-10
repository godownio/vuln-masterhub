---
id: mobile-android-apk-debuggable-repack-jadx-attach
title: APK 补 android:debuggable="true" 重打包重签 + jadx/JDWP 附加：让依赖调试状态的应用输出隐藏逻辑
type: scenario
domain: mobile
path: mobile/android
technique: apk-debuggable-repack-jadx-attach
aliases:
- AndroidManifest debuggable
- APK 开启调试
- 重打包重签名
- jadx 附加调试
- JDWP 附加
- MT 管理器改 Manifest
- 动态调试 APK
tags:
- android
- apk
- debuggable
- repack
- resign
- jadx
- jdwp
- adb
- dynamic-analysis
- reversing
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:29:01+08:00'
  notes: 已对照原文与图34-47核对：ezapk 4.38M/V1+V2+V3/未加固（35）、Manifest application 原无debuggable（39）与加入android:debuggable=true（38）、jadx混淆onCreate（40）、Waiting For Debugger（41）、jadx ADB面板online且com.xyctf.ezapk pid4334（44）、附加日志（45）、Click me后XYCTF{d3bugg3r_15_v3ry_u53ful}（47）均一致。已修正两处：原文adb devices首次显示emulator-5554 offline（图42），非online；jadx截图仅提示可升级1.5.0。未验证点：未复跑重打包/附加；原文无组件影响版本，未设affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

发布版 APK 默认 `android:debuggable="false"`，系统不会为它开启 JDWP，jadx/adb 无法附加调试；把 APK 解包后在 `AndroidManifest.xml` 的 `<application>` 上加入 `android:debuggable="true"`，保存并重新签名安装，再把该应用选为调试应用，即可用 jadx 的调试器按进程名附加、下断点，触发只在调试器连接时才执行的分支（示例点击按钮后输出 flag）。

## 原理

- **debuggable 控制调试能力**：`android:debuggable` 是应用级清单属性，决定系统是否允许该进程被调试。发布版为 `false` 时，应用进程不会暴露 JDWP，`adb`/jadx/Android Studio 不能附加；改为 `true` 后，系统在启动进程时开启 JDWP 并允许调试器连接。
- **为什么必须重签名**：修改 `AndroidManifest.xml` 会改变 APK 内容，原签名失效；Android 安装时校验签名，必须用 MT 管理器的“自动签名”或 apksigner 重新签名（V1/V2/V3）后才能安装。重签名后的应用与原应用签名不同，可被应用自身的签名校验发现。
- **jadx 的调试方式**：jadx GUI 通过 ADB 连接设备，枚举可调试进程（`adb jdwp` 等价），选择目标包名的进程后附加；附加成功后可在反编译代码中下断点、查看寄存器/局部变量/调用栈。示例在 `MainActivity.onCreate` 下断点，附加后点击 `Click me!`，应用检测到调试器并输出 `XYCTF{d3bugg3r_15_v3ry_u53ful}`。
- **“等待调试器”机制**：在开发者选项里把目标应用设为调试应用后，启动时会显示 `Waiting For Debugger`，进程暂停等待调试器附加；这正是确认 `debuggable=true` 生效、且可被 jadx 看到的信号。
- **边界**：加固/加壳应用可能校验 Manifest、签名或 `ApplicationInfo.FLAG_DEBUGGABLE`；修改后可能无法启动。部分应用会检测 JDWP/调试器并退出，需要配合 Frida/静态补丁。Android 高版本对重打包和调试权限有更多限制，需真机 root/模拟器环境。

## 触发条件

- 目标 APK 未加固，或加固层不影响 Manifest 修改与重签名；应用可被重新安装。
- 有可控的 Android 模拟器/真机（示例为 root 的雷电模拟器 9、Android 9），并开启开发者选项/USB 调试。
- 已安装 MT 管理器（或 apktool/apksigner）用于解包、改 Manifest、重签名。
- jadx 版本支持调试（原文截图提示可升级到 1.5.0，实际以本地版本为准），ADB 能正常识别设备。

## 利用步骤

1. 在模拟器安装 MT 管理器，定位目标 APK（应用信息 → APK 路径/安装包提取）。
2. 用 MT 管理器打开 APK，进入 `AndroidManifest.xml`，选择反编译（XML 文本），在 `<application>` 标签中加入 `android:debuggable="true"`，保存。
3. 返回后选择“自动签名”，生成重签名后的 APK 并安装（覆盖原应用需卸载或同签名；重签后签名不同，通常需先卸载原应用）。
4. 打开系统设置 → 开发者选项 → 打开 USB 调试；在“选择调试应用”中选择目标应用（若 Manifest 修改生效，列表中可见）。
5. 电脑端执行 `adb devices` 确认设备连接（原文首次显示 `emulator-5554 offline`，jadx 的 ADB 面板显示 `online` 后可附加）；必要时替换模拟器自带的有问题 adb。
6. 启动目标应用，确认出现 `Waiting For Debugger`；打开 jadx 加载 APK，点击调试按钮，选择目标进程（如 `com.xyctf.ezapk`）并附加。
7. 在 jadx 中定位关键方法（示例 `MainActivity.onCreate`）下断点，回到应用触发按钮/输入；断点命中后观察变量与控制流，继续运行得到隐藏输出（示例 flag）。

## PoC

无独立脚本；以下为操作要点：

```text
# 1) MT 管理器：提取 APK -> 查看 -> AndroidManifest.xml -> 反编译
#    在 <application ...> 中加入：
#    android:debuggable="true"

# 2) 保存 -> 自动签名 -> 安装

# 3) 开发者选项：USB 调试开；选择调试应用 = com.xyctf.ezapk

# 4) 电脑端：
adb devices
# 原文首次为 emulator-5554   offline；jadx ADB 面板显示 online 后附加

# 5) jadx-gui 打开 APK -> 点击调试图标 -> 选择进程 com.xyctf.ezapk -> 附加
# 6) 在 MainActivity.onCreate 下断点 -> 点击应用中的 Click me! -> 查看 flag
```

示例应用启动后显示 `Waiting For Debugger`，jadx 附加到 `com.xyctf.ezapk`（pid 4334）后在 `onCreate` 命中，点击按钮即输出 `XYCTF{d3bugg3r_15_v3ry_u53ful}`。

## 变体与关联

- 变体（工具链）：apktool 解包 + 手工改 `AndroidManifest.xml` + `apksigner` 重签；或用 `uber-apk-signer`。MT 管理器只是把解包/编辑/签名集成到移动端。
- 变体（调试器）：用 Android Studio/LLDB、Frida、或 `adb shell am set-debug-app -w <pkg>` 等待调试器；Frida 不需要 debuggable，但需要 root/注入能力。
- 变体（绕过应用自检）：应用若校验签名或 `FLAG_DEBUGGABLE`，可在 smali 层 patch 校验函数，或用 Frida hook `PackageManager.getPackageInfo`/`ApplicationInfo` 返回原始值。
- 关联：[[mobile-android-login-codesign-md5-burp-auto-resign]]（重签名用于 Burp 抓包的同类操作）；[[mobile-android-anti-detection-root-emulator-proxy]]（重打包/模拟器环境的应用自检与对抗）；[[tools-ida-fork-child-loop-patch-attach]]（另一类“先让进程停住再附加”的调试思路）。
- 边界：加固应用可能校验 Manifest/签名导致改后闪退；Android 10+ 对 `debuggable` 与非 debuggable 进程的 JDWP 行为更严格；生产设备上无法随意重装。

## 检测与防御

- 检测（应用侧自检）：比较运行时签名哈希与预期值（重签名会不匹配）；读取 `ApplicationInfo.FLAG_DEBUGGABLE`/`BuildConfig.DEBUG`；检测 JDWP 端口/`Debug.isDebuggerConnected()`；检测 `adb`/调试器进程或 `ro.debuggable`；完整性校验 Manifest/dex。
- 检测（分发侧）：应用商店/企业 MDM 可校验 APK 签名与原始证书指纹，发现重打包/重签名版本；监控 `debuggable=true` 的生产包。
- 防御：生产包禁用 `debuggable`；使用 Play Integrity/SafetyNet 或服务端证明；关键逻辑与 flag 不要依赖“检测到调试器才输出”的客户端分支；对重打包应用做签名绑定与证书固定。
- 分析侧注意：重签会破坏原签名相关校验，遇到校验需先定位并 patch；调试完成后恢复原应用，避免影响其他测试。
