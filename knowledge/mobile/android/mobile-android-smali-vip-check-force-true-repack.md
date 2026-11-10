---
id: mobile-android-smali-vip-check-force-true-repack
title: smali 静态改会员判断 u()/a() 返回 true：重打包绕过客户端 VIP 校验解锁付费功能
type: scenario
domain: mobile
path: mobile/android
technique: apk-smali-entitlement-check-patch
aliases:
- smali 改 VIP 判断
- 会员校验 return true
- u()/a() 强制返回 true
- 重打包解锁会员功能
- 客户端权益校验绕过
tags:
- android
- apk
- smali
- repack
- vip
- entitlement-bypass
- reverse
- jadx
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:38:25+08:00'
  notes: 已对照原文13689及21个媒体核对：u()/a()/h()/x()源码语义、smali const/4 v0,0x1修改点、Frida被libart pthread_create检测阻断、VIP功能前后对比截图均一致；未本机重打包执行；原文包名打码，卡片已用示例包名
---

## 一句话结论

当 App 的会员状态完全由客户端 Java 方法决定（本例 `u()` 先判 VIP 信息非空、再返回 `a()`；`a() = h() && !x()`，`h()` 判断 `vipStatus ∈ {2,3,4}`，`x()` 判断会员是否过期）时，无需 Frida，直接用 apktool 反编译，把 `u()` 空值分支和 `a()` 的失败分支 smali 里的 `const/4 v0, 0x0` 改成 `const/4 v0, 0x1`，重打包重签安装后，所有走这两个方法的功能门禁都判定为会员，付费功能（完整音频转换、语音翻译等）在客户端被解锁。

## 原理

- **会员判断集中在两个方法**：`u()` 的语义是"本地是否有有效 VIP 信息"——`Pair p2 = ...p()`，若 `p2 == null` 或其 `f()`（VIP 信息对象）为 null 返回 false，否则返回 `f2.a()`；`a()` 的语义是"会员状态有效且未过期"——`return h() && !x()`，其中 `h()` 读 `this.vipStatus` 并判断是否为 2/3/4，`x()` 用 `f() - System.currentTimeMillis() < 0` 判断是否已过期。因此只要让 `u()` 的 false 分支返回 1（或让 `a()` 恒返回 true），整条会员判断就恒真。
- **为什么改 smali 而不是 Hook**：目标 App 有反调试/反 Frida 逻辑，Frida 注入后 `pthread_create` 相关调用（libart.so 的 `CreateNativeThread`）触发检测，进程被终止；TracerPid 的 `fgets` 替换绕过也无效。改包是静态的，不依赖注入框架，能绕开这类检测。
- **smali 布尔返回值的写法**：Java 的 `boolean` 方法在 smali 里仍以整数寄存器返回，`.method ... a()Z` 用 `const/4 v0, 0x1` 后 `return v0`；不能在 smali 里直接写 `return 1` 字面量，必须先给寄存器赋值再返回——这是改返回值时最常见的语法坑。
- **改哪里**：`u()` 的失败路径是 `:cond_18/:goto_18` 下的 `const/4 v0, 0x0`，改成 `0x1` 即让"VIP 信息为空"也返回 true；`a()` 的失败路径是 `:cond_e` 的 `const/4 v0, 0x0`，改成 `0x1` 即让"状态不符/已过期"也返回 true。两处都改可覆盖不同调用链。
- **为什么能解锁功能**：界面与功能开关在客户端读取这些方法的返回值决定是否显示"开通会员"、是否允许完整转换/翻译；返回值被固定为 true 后，本地门禁全部放行。若具体功能接口在服务端二次校验权益，则只会解锁 UI 与纯客户端能力，这是本手法的边界。

## 触发条件

- APK 未加固、Java/Kotlin 逻辑可反编译（本例 PKID 显示未加固，仅代码混淆，但关键业务类未混淆）。
- 会员状态与功能门禁由客户端方法（如 `u()`/`a()`/`h()`/`x()`）决定，服务端未对每个受限动作二次校验。
- 应用未做签名/完整性校验，允许重打包重签安装。
- 动态 Hook 被反调试/反 Frida 阻断，或环境中无 root/Frida 条件，需要静态改包。

## 利用步骤

1. jadx 打开 APK，从 Activity（本例 XsrdSplashActivity）的 `zr()` 进入，沿 `w.f1188w.u()` 找到 VIP 信息读取类与方法。
2. 阅读 `u()`、`a()`、`h()`、`x()` 的源码，确认返回值语义（空值判断、vipStatus 取值、过期判断），记录调用它们的界面/功能点。
3. `apktool d target.apk` 解包，按包路径找到对应 smali（如 `smali/com/xinshang/recording/...`），定位 `u()` 与 `a()` 方法。
4. 修改 `u()` 失败分支的 `const/4 v0, 0x0` 为 `const/4 v0, 0x1`；修改 `a()` 的 `:cond_e` 分支同样把 `0x0` 改为 `0x1`。若只想改一处，优先改 `a()`（更接近最终判定）。
5. `apktool b` 回包，重新签名（keytool/jarsigner/zipalign 或 MT 重签名），卸载原 App 后安装。
6. 打开 App 验证：会员状态可能仍显示"未开通"，但原本提示"非会员只能转换 300 字/录音不超过 60 秒"的功能应可直接使用，语音翻译等 VIP 功能也应放开。
7. 记录边界：对仍需服务端鉴权的接口，本地改动无效；若 App 崩溃或无法启动，检查是否改错了方法签名/分支或存在签名校验。

## PoC

修改前的关键 smali（示意，行号与寄存器按样本）：

```smali
# u() 失败分支
:goto_18
const/4 v0, 0x0
return v0

# a() 失败分支
:cond_e
const/4 v0, 0x0
:goto_f
return v0
```

修改后：

```smali
:goto_18
const/4 v0, 0x1    # VIP 信息为空也返回 true
return v0

:cond_e
const/4 v0, 0x1    # 状态不符/过期也返回 true
:goto_f
return v0
```

重打包与签名：

```bash
apktool d target.apk -o target_src
# 编辑 smali 中 u()/a() 的 const/4 v0, 0x0
apktool b target_src -o patched.apk
keytool -genkey -keystore demo.keystore -alias demo -keyalg RSA -keysize 2048 -validity 3650
jarsigner -keystore demo.keystore -sigalg SHA1withRSA -digestalg SHA1 patched.apk demo
zipalign -v 4 patched.apk patched_aligned.apk
adb uninstall com.example.app && adb install patched_aligned.apk
```

原文在真机验证：改后界面仍显示非会员提示，但"转换完整音频"、语音翻译等功能可用（截图对比）。

## 变体与关联

- 变体：若只想跳过启动时的会员引导页，可改 Manifest 启动 Activity（见 [[mobile-android-apk-manifest-launcher-vip-charge-bypass]]），不必改判断逻辑。
- 变体：若有 Frida 注入条件，可 hook VIP 模型构造器或方法返回值（见 [[mobile-android-frida-vipinfo-constructor-forge-membership]]），无需重打包但会被反调试拦截。
- 变体：改 `h()` 的 `vipStatus` 比较或 `x()` 的时间比较，效果等价；也可让 `u()` 直接 `return v0` 前赋 1。
- 关联：[[mobile-android-apk-version-spoof-bypass-forced-update]]（同样的 apktool 重打包/重签工作流）、[[mobile-android-apk-debuggable-repack-jadx-attach]]（Manifest 修改类重打包）。
- 边界：加固、签名校验、服务端权益二次校验会让本地 patch 失效或仅剩 UI 效果；代码混淆可能导致类/方法定位困难，需结合运行时 Activity 记录与字符串搜索。

## 检测与防御

- 检测：安装包签名/证书指纹与官方不一致；APK 的 smali 中布尔方法返回常量被改为 1；完整性校验失败告警。
- 防御：关键权益在服务端校验（购买、鉴权、内容密钥）；启动时做签名/完整性校验（Play Integrity、自建证书指纹）；代码加固、控制流混淆提高定位成本。
- 边界：客户端只应作为展示层；把授权判断放在客户端本质上不可信，本地 patch 无法防住。
