---
id: mobile-android-frida-hook-isrooted-issimulator-bypass
title: 反编译定位 isRootPhone() 并 Frida 覆盖 isRooted()/isSimulator() 绕过 root/模拟器检测弹窗
type: scenario
domain: mobile
path: mobile/android
technique: frida-hook-root-simulator-detection-methods
aliases:
- Hook isRooted
- Hook isSimulator
- MiscUtil.isRooted 绕过
- root 检测弹窗绕过
- 模拟器检测 Hook
- isRootPhone 绕过
tags:
- android
- frida
- root-detection
- emulator-detection
- hook
- bypass
- mobile
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:30:31+08:00'
  notes: 已对照原文全文与 28/28 张截图核对：img16/img25 弹窗「温馨提示…在Root设备或模拟器上,将威胁您的数据安全…退出」、img26 jadx 搜索「威胁您」命中构造 DialogFactory 的代码、img27 isRootPhone() 中 if (MiscUtil.isSimulator(this) || MiscUtil.isRooted()) 且 setCancel(false)/show()/return、img28 bh.y="su" 与 su 路径数组，均与卡一致；isRooted 的 indexOf/lastIndexOf root 判定与 isSimulator 的 Build/TelephonyManager 判据逐项对应原文代码。卡内同时给出 Hook isRooted/isSimulator 与覆盖入口 isRootPhone 两种写法，属同一检测门禁的绕过，不判拆分；与 14085 另一张更新弹窗卡目标/机制不同，不重复。img17/18 antiroot.js 与 img20-24 Shamiko/Magisk 方案已在 skipped 中按既有卡覆盖处理（复核成立）。原文无 APP/组件版本，affected_versions 已 --clear。PoC 未在真实目标运行。
---

## 一句话结论

当 APP 在启动时用 Java 方法做 root/模拟器检测并在命中时弹出不可取消的“威胁您的数据安全”对话框时，可用 jadx 按提示文案定位入口（如 `isRootPhone()`），看清它调用 `MiscUtil.isSimulator()` 与 `MiscUtil.isRooted()`，再用 Frida 覆盖这两个方法返回 `false`（或直接覆盖入口方法为空），即可跳过弹窗、继续测试。

## 原理

- **检测结果决定 UI 分支**：典型代码是 `if (MiscUtil.isSimulator(this) || MiscUtil.isRooted()) { DialogFactory...setCancel(false)...show(); return; }`。两个方法都是普通 Java 静态方法，返回值直接控制是否弹窗与 `return`；Frida 在方法入口替换实现并返回 `false`，分支即不成立。
- **isRooted 的实现细节**：遍历 `"/system/xbin/", "/system/bin/", "/system/sbin/", "/sbin/", "/vendor/bin/", "/su/bin/"` 等目录，拼接常量 `bh.y`（反编译可见其值为 `"su"`）后判断 `new File(path).exists()`；若存在则执行 `ls -l <path>`，只有当输出中 `"root"` 出现至少两次（属主和属组均为 root）时才返回 true，否则返回 false。也就是说，单靠一个 su 文件存在并不必然判定 root，`ls -l` 输出或文件属性异常都会让它漏判。
- **isSimulator 的实现细节**：检查 `Build.FINGERPRINT`（`generic` 前缀、包含 `vbox`/`test-keys`）、`Build.MODEL`（`google_sdk`/`Emulator`/`MuMu`/`virtual`）、`Build.SERIAL` 是否为 `android`、`Build.MANUFACTURER` 是否含 `Genymotion`、`BRAND`/`DEVICE` 是否均为 `generic`、`Build.PRODUCT` 是否为 `google_sdk`，以及 `TelephonyManager.getNetworkOperatorName()` 是否为 `android`。
- **为什么 Hook 有效**：这些检查全在 Java 层完成，没有 native 校验/完整性保护时，Frida 的 `Java.use(...).method.implementation` 可以在调用点之前拦截并给出任意返回值；比起逐个伪造系统属性/文件，直接改返回值成本最低。
- **边界**：若检测在 native 层（so 里读 `/proc/self/maps`、`/system/bin/su`、Build 属性）或由加固/RASP 完成，Hook Java 方法无效，需要改环境或 native Hook；若服务端也做环境风控，绕过客户端弹窗不等于通过服务端。

## 触发条件

- APP 使用 Java/Kotlin 层方法做 root/模拟器检测，检测结果控制弹窗或退出逻辑。
- 检测方法名可被反编译定位（文案字符串“威胁您”“Root设备或模拟器”等通常保留），且未被强混淆到无法从调用关系追踪。
- 设备已 root 并能运行 frida-server，或 APP 可调试；能够 spawn/attach 目标进程。
- APP 未启用会让 Frida 直接闪退的 native 反调试，或已先绕过。
- 仅限授权测试环境。

## 利用步骤

1. jadx 打开 APK，搜索提示文案（如“威胁您”“Root设备或模拟器”“温馨提示”），定位引用处的方法（示例为 `isRootPhone()`）。
2. 阅读方法体，确认检测入口：常见为 `MiscUtil.isSimulator(context) || MiscUtil.isRooted()`；记录类全名、方法签名与是否静态。
3. 进入 `isRooted()`/`isSimulator()` 查看具体判据（su 路径 + `ls -l`、Build 字段、TelephonyManager 等），确认没有 native 调用。
4. 启动 frida-server、端口转发，用 spawn 方式加载 Hook 脚本；将两个方法实现改为 `return false`。若入口方法本身可定位，也可直接覆盖 `isRootPhone()` 为空函数。
5. 观察 APP 是否还弹窗/退出；若仍检测，检查是否有其他检测类/so、是否调用了 native、是否有 Frida 反调试。
6. 如需从环境层解决，可改用 Shamiko/Magisk 排除列表/隐藏 Magisk 应用，或用 antiroot.js 这类 Hook `File.exists` 的脚本隐藏 su（见关联卡）。

## PoC

```javascript
Java.perform(function () {
    var MiscUtil = Java.use("com.example.app.MiscUtil");   // jadx 定位到的类
    MiscUtil.isRooted.implementation = function () {
        console.log("[*] isRooted -> false");
        return false;
    };
    MiscUtil.isSimulator.implementation = function (ctx) {
        console.log("[*] isSimulator -> false");
        return false;
    };
});
```

若入口方法更直接：

```javascript
Java.perform(function () {
    var Launcher = Java.use("com.example.app.Launcher");
    Launcher.isRootPhone.implementation = function () {
        console.log("[*] isRootPhone skipped");
    };
});
```

Python 侧仍使用 `frida.get_remote_device()` → `spawn([包名])` → `attach(pid)` → `create_script` → `load` → `resume(pid)` 的 spawn 流程，确保检测在脚本加载后才执行。

## 变体与关联

- **环境层隐藏**：Magisk + Shamiko + 排除列表 + 隐藏 Magisk 应用，让 su/Magisk 痕迹对目标进程不可见；见 [[mobile-android-anti-detection-root-emulator-proxy]]。
- **Hook File.exists 隐藏 su**：antiroot.js（FridaAntiRootDetection）等脚本 Hook `java.io.File.exists`，对 su 路径返回 false，适合不想逐个 Hook 业务检测方法时使用；与 [[mobile-android-anti-detection-root-emulator-proxy]] 中 Frida Hook `File.exists` 兜底一致。
- **模拟器属性伪造**：Hook `Build` 字段或使用 Pixel Props/resetprop 伪造机型；见 [[mobile-android-anti-detection-root-emulator-proxy]]。
- **native 检测**：若检测在 so 层，需用 dlopen 监控定位检测 SO 并阻断加载/替换线程；见 [[mobile-android-native-frida-antidebug-thread-bypass]]。
- **改包方案**：直接修改 smali 让 `isRooted()` 返回 false 或删除弹窗分支，适合无需动态调试、可分发的场景。

## 检测与防御

- **不要只依赖单个 Java 检测方法**：把 root/模拟器判断放在 native 层、与完整性校验和风控评分组合，降低单点 Hook 的成功率。
- **服务端风控**：结合设备指纹、Play Integrity、行为特征在服务端评分，客户端弹窗只作为提示而非唯一门禁。
- **加固/反调试**：RASP、Frida 检测、代码混淆提高定位与 Hook 成本，但不能根除（客户端代码始终可被分析）。
- **检测**：监控 Frida 特征、异常 spawn/attach、同一设备在短时间内切换多套设备属性；对关键接口做版本/环境绑定校验。
