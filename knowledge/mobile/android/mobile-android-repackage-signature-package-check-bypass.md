---
id: mobile-android-repackage-signature-package-check-bypass
title: 重打包后「请使用官方APP」检测绕过：jadx 定位 MainActivity.checkPackage，注释调用或对 if 取反
type: scenario
domain: mobile
path: mobile/android
technique: android-repackage-signature-package-check-bypass
aliases:
- 重打包签名校验绕过
- 请使用官方版本APP
- checkPackage 绕过
- AppUtil.checkoutAPP
- 包名校验绕过
- APK 完整性检测绕过
tags:
- android
- apk
- smali
- repack
- signature-check
- integrity
- jadx
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:11:56+08:00'
  notes: 对照原文与13张本地截图：img02 为 MainActivity.checkPackage 中 if (!AppUtil.checkoutAPP(this)) 弹“请使用官方版本APP”，与原文 checkoutPackageName(activity) && app_signature.equals(getSignature(activity)) 一致；img03 onResume 中调用 checkPackage()，img04 smali :cond_1a invoke-direct {p0} ...->checkPackage()V，卡片给出的注释调用与 if 取反两条绕过路径与原文表述一致。原文未附绕过后的运行截图，卡内已注明按代码重建、未复跑；检测逻辑确在 Java 层，confidence high 可接受。原文未标版本，affected_versions 为空正确。与 smali-branch-invert 通用卡及 VIP 卡为 related 非同链，dedup 报告 new，保留。
---

## 一句话结论

应用在 `MainActivity.onResume()` 里调用 `checkPackage()`，用 `AppUtil.checkoutAPP(this)` 同时比对包名与当前签名是否等于 `R.string.app_signature` 内置值；重打包重签后签名必然变化，于是弹出“请使用官方版本APP”。由于检测完全在 Java 层，用 apktool 把 `checkPackage()` 内的判断取反、或直接注释掉 `onResume` 里对它的 `invoke-direct` 调用，重编译重签即可继续使用修改后的包。

## 原理

- **检测位置**：`MainActivity.onResume()` 中有一行 `checkPackage(); // 调用检查安装包是否被修改的函数`，每次回到前台都会执行。
- **检测逻辑**：`checkPackage()` 内是 `if (!AppUtil.checkoutAPP(this)) { ToastDialog...setContent("请使用官方版本APP")... }`；`AppUtil.checkoutAPP` 的判定为 `checkoutPackageName(activity) && activity.getString(R.string.app_signature).equals(getSignature(activity));`——先比包名，再比当前 APK 签名与资源里写死的原签名。
- **为什么重打包一定触发**：apktool 回编译后必须用新密钥重签，签名与官方不同，`equals` 为 false；若改过包名（`applicationId`/Manifest package），包名检查也为 false。两者任一失败都会让 `checkoutAPP` 返回 false，`!false` 为真，弹窗并阻塞。
- **为什么绕过容易**：判断与调用都在客户端 Java/smali 层，没有服务端参与，也没有把结果用于加密/校验链；改控制流或删调用即可。注释掉 `invoke-direct {p0}, ...->checkPackage()V` 后整个检测函数不会被调用，效果等价于“从未检测”。
- **边界**：若检测逻辑被搬进 native（SO 里比对签名摘要）或服务端（登录时校验签名哈希），改 Java 层无效；部分应用还会在 native 或其它 Activity 重复检测，需要全局搜索调用点。

## 触发条件

- APK 未加固或可脱壳，`MainActivity`/检测类可反编译为 smali。
- 签名/包名检测在 Java/Kotlin 层实现，且没有第二处 native/服务端校验（或可一并绕过）。
- 允许重打包重签安装（无系统级完整性校验）。

## 利用步骤

1. 重打包安装后若出现“请使用官方版本APP”之类提示，用 jadx 搜关键词（提示文案、`checkPackage`、`getSignature`、`checkoutAPP`、`app_signature`）定位检测方法。
2. 查看 `checkPackage()` 的调用点（本例 `MainActivity.onResume()`），确认它是每次回前台都调用的常驻检测。
3. `apktool d target.apk`，打开对应 `MainActivity.smali`，在 `onResume` 中定位 `invoke-direct {p0}, Lcom/<pkg>/ui/MainActivity;->checkPackage()V`。
4. 二选一：
   - 删除/注释该 `invoke-direct` 行（smali 注释用 `#`），让检测永不执行；
   - 或进入 `checkPackage.smali`，把 `if (!checkoutAPP)` 对应的条件跳转取反（如 `if-eqz` ↔ `if-nez`）。
5. `apktool b` 回编译、重签、`zipalign`，卸载原包后安装；回到前台确认不再弹“官方版本”提示，且原修改（去广告/VIP 等）继续生效。
6. 若仍被拦，全局搜索 `getSignature`/`checkoutPackageName` 的其它调用点、检查 native 层与服务器登录校验。

## PoC

```smali
# MainActivity.smali onResume 中（示意，类名/寄存器按样本）
:cond_1a
invoke-direct {p0}, Lcom/example/ui/MainActivity;->checkPackage()V

# 绕过：整行删除或注释
# invoke-direct {p0}, Lcom/example/ui/MainActivity;->checkPackage()V
```

```java
// 或改 checkPackage 内的判断方向：未修改的官方包才提示
// 原： if (!AppUtil.checkoutAPP(this)) { show("请使用官方版本APP"); }
// 改： if (AppUtil.checkoutAPP(this)) { show("请使用官方版本APP"); }
```

```text
预期：重签后的包不再弹“请使用官方版本APP”，应用按修改后的逻辑运行。
（原文仅展示检测代码、onResume 调用与 smali 调用点，未附绕过后的运行截图；本卡按代码重建，未在真实应用复现。）
```

## 变体与关联

- 变体：Frida hook `AppUtil.checkoutAPP` 直接 `return true`（需可注入），或 hook `getSignature` 返回内置签名——不用重打包，但会被反调试/反注入拦。
- 变体：只改包名检测（保持原包名）不能绕过签名比对；必须同时处理签名或直接砍调用。
- 关联：[[mobile-android-smali-branch-invert-expected-constant-bypass]]（通用分支取反）、[[mobile-android-smali-vip-check-force-true-repack]]（同样的 apktool 重打包/重签工作流）、[[mobile-android-apk-manifest-launcher-vip-charge-bypass]]。
- 边界：若应用用签名派生密钥解密资源/协议（签名参与密码学），改签会导致解密失败，此时只能 hook 而不能重签。

## 检测与防御

- 检测：APK 签名证书指纹/序列号与官方不一致；包名被改；dex 中 `invoke-direct ...->checkPackage` 被删除或条件指令被取反。
- 防御：把完整性校验放到服务端（登录/接口调用时校验签名哈希或 Play Integrity 令牌）；native 层做 dex/签名摘要校验并参与后续解密；使用加固与控制流混淆；对关键功能做服务端权益校验，客户端检测只作为辅助。
