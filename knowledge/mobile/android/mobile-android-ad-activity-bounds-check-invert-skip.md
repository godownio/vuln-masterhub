---
id: mobile-android-ad-activity-bounds-check-invert-skip
title: 多广告 Activity 跳过：把 position >= data.size() 播放结束判断取反，首条广告即跳转 MainActivity
type: scenario
domain: mobile
path: mobile/android
technique: android-ad-playlist-bounds-check-invert
aliases:
- 广告 Activity 去广告
- AdvertActivity 跳过
- 广告列表越界判断取反
- initAdsInfo 改判断
- 开屏广告直入主界面
- MT Activity 记录器定位广告页
tags:
- android
- apk
- smali
- repack
- ad-removal
- jadx
- reverse
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:11:58+08:00'
  notes: 对照原文与13张本地截图：AdvertActivity 代码截图显示 initAdsInfo(position) 开头 if (position >= this.data.size()) { startActivity(MainActivity); finish(); return; }，且 onFinish 中 if (position + 1 < this.data.size()) { initAdsInfo(position+1); return; } 的链式下一条广告逻辑与卡片描述完全一致；取反后 position=0 落入已播完分支的推理成立。Activity 记录器定位 Splash0Activity→AdvertActivity 为原文文字描述（无截图）。原文未附修改后 smali 与运行截图，卡内 confidence medium 并注明按代码重建。原文未标版本，affected_versions 为空正确。与 SplashAdActivity 布尔导航门禁卡、Fragment return-void 卡机制不同，dedup 报告 new，保留。
---

## 一句话结论

App 用一个独立 `AdvertActivity` 轮播多条广告：`initAdsInfo(position)` 开头 `if (position >= this.data.size())` 命中时表示“广告列表已播完”，跳转 `MainActivity` 并 `finish()`；把这个越界判断取反（`position < data.size()`），position=0 的首条广告就会直接走“已播完”分支进入主界面，从而跳过整个广告轮播。注意 `onFinish` 里还有 `position+1 < size` 的链式下一条广告逻辑，只改单条广告的显示条件无效。

## 原理

- **广告页与启动页分离**：启动 Activity（`Splash0Activity`）只停留几秒做线路选择，随后进入 `AdvertActivity` 播广告；用 MT 管理器的 Activity 记录器可以直接看到这条跳转链，从而定位广告 Activity。
- **退出条件就是广告列表的越界判断**：`initAdsInfo(final int position)` 中 `if (position >= this.data.size()) { startActivity(new Intent(this, MainActivity.class)); finish(); return; }`——本意是当前 index 超过广告数组长度时结束广告页。首条广告的 position=0，只要让该条件在 position=0 时成立（把 `>=` 改反为 `<`，或把对应 smali 条件跳转取反），就会立刻进入主界面。
- **为什么不能只改单条广告**：倒计时结束的 `onFinish()` 中有 `if (position + 1 < this.data.size()) { initAdsInfo(position + 1); return; }`，会链式播放下一条广告，所以真正的“总开关”是 `initAdsInfo` 入口的越界/结束判断，而不是某一条广告的展示代码。
- **smali 层形态**：Java 的 `if (position >= size)` 编译为类似 `array-length v0, v1; if-lt p1, v0, :cond_normal` 的比较跳转；要让“越界”分支在 position=0 命中，把 `if-lt` 改为 `if-ge`（或按样本把 `if-ge`/`if-lt` 方向对调），其余广告展示代码保持不动。
- **边界**：广告数据由服务端强制下发、或广告页与初始化强耦合（跳过会导致后续页面缺数据）时可能引起功能异常；若重打包后弹出官方版本检测，需同时绕过签名/包名校验。

## 触发条件

- 广告轮播由客户端 Activity + 本地/接口返回的广告数组控制，不是独立的强制 SDK 进程。
- APK 未加固或可脱壳，`AdvertActivity` 可反编译为 smali。
- 允许重打包重签安装（无签名/完整性校验，或可绕过）。

## 利用步骤

1. 启动 APP，用 MT 管理器的 Activity 记录器观察启动链，确认广告页 Activity（本例 `Splash0Activity` → `AdvertActivity`）。
2. jadx 打开 APK，定位广告 Activity 的 `initAdsInfo`（或用“广告数据/倒计时/跳过”等关键词搜索），确认 `position >= data.size()` 的结束分支与 `onFinish` 的链式下一条逻辑。
3. `apktool d target.apk`，打开对应 `AdvertActivity.smali`，找到 `initAdsInfo` 中的比较跳转指令。
4. 把越界判断取反（如 `if-lt` → `if-ge`），使 position=0 时直接落入 `startActivity(MainActivity); finish(); return;` 分支；不要动 `onFinish` 里的广告链逻辑。
5. `apktool b` 回编译、重签、`zipalign`、卸载重装；冷启动验证是否不再展示广告、直接进入主界面。
6. 若出现“请使用官方APP”提示，说明触发了重打包检测，按关联卡处理。

## PoC

```smali
# 改前（示意，寄存器/标签按样本）：position < size 时跳到正常播放分支
array-length v0, v1              # v1 = data
if-lt p1, v0, :cond_show_ad     # p1 = position

# 改后：position >= size 才跳，position=0 直接走“已播完→MainActivity”
if-ge p1, v0, :cond_show_ad
```

```text
预期：冷启动后广告页立即 finish 并进入 MainActivity，不再轮播广告。
（原文只描述“把 if (position >= this.data.size()) 的判断取反”并称可以直接过掉广告，
未展示修改后的 smali 与运行截图；本卡按代码重建，未在真实应用复现。）
```

## 变体与关联

- 变体：把 `startActivity(MainActivity); finish(); return;` 分支复制到方法最开头无条件执行；或在 `onCreate` 直接跳主界面并 finish 广告 Activity。
- 变体：若广告页是启动页的一部分，可改 Manifest 的 MAIN/LAUNCHER 直挂主界面 Activity：[[mobile-android-apk-manifest-launcher-vip-charge-bypass]]。
- 关联：[[mobile-android-splash-ad-navigation-boolean-gate-shortcircuit-repack]]（布尔导航门禁短路跳过开屏广告）、[[mobile-android-apk-ad-fragment-return-void-disable]]（Fragment 层 return-void 去广告）、[[mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip]]（动态路线）。
- 边界：广告与启动初始化耦合、或广告由服务端强制下发时，本改法可能只跳过展示而影响业务；签名检测见 [[mobile-android-repackage-signature-package-check-bypass]]。

## 检测与防御

- 检测：APK 签名与官方不一致；`AdvertActivity`/广告控制类的比较指令被改；启动后无广告曝光上报或曝光与展示不一致；重打包特征（zipalign/签名差异）。
- 防御：关键展示决策由服务端控制；对安装包做签名/完整性校验（Play Integrity、证书指纹、dex 校验和）；广告与启动流程解耦，避免客户端单一判断即可跳过；加固与混淆提高定位成本。
