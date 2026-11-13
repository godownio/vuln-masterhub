---
id: mobile-android-apk-ad-fragment-return-void-disable
title: 广告 Fragment 自动弹窗去除：布局查看器反查资源 id + smali onViewCreated/onCreate 插入 return-void
type: scenario
domain: mobile
path: mobile/android
technique: android-apk-ad-fragment-smali-return-void
tags:
- android
- apk
- smali
- repack
- ad-removal
- fragment
- jadx
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:09:22+08:00'
  notes: 已对照原文12951及全部23张图（含gif抽帧）核对：布局查看器R.id.mAdCoverImg、jadx命中com.idaddy.ilisten.pull.ui.PullADFragment.onViewCreated、smali onCreate(.registers 3)/onViewCreated(.registers 9)插入return-void、setStyle(2,FullScreenDialog)与重打包重签流程均与图06-12一致；未本机重打包执行；dedup top候选(改会员判断/objection跳过开屏广告/Frida更新弹窗)均为related非同链，理由成立；app版本6.4.1211010为测试环境非受影响版本，未设versions。
url: /docs/mobile/android/mobile-android-apk-ad-fragment-return-void-disable/
draft: false
kb_aliases:
- 去应用内广告弹窗
- Fragment return-void 禁用
- 布局查看器反查资源 id
- PullADFragment 去广告
- mAdCoverImg 定位
- smali 禁用 Fragment
---

## 一句话结论

当 App 的开屏/应用内广告弹窗不是 Dialog 而是由 Fragment（如 `PullADFragment`）自动展示的 ImageView 时，先用布局查看器拿到控件资源 id（`R.id.mAdCoverImg`/`mAdCloseImg`），在 jadx 里反查该 id 所在 Fragment，再在 apktool 反编译出的 smali 中给 `onViewCreated()`/`onCreate()` 方法开头插入 `return-void`，重打包签名后 Fragment 完全不初始化，广告弹窗不再出现。

## 原理

- **广告不是 Dialog 而是 Fragment**：用开发助手/布局查看器实时查看弹窗，属性面板显示元素是 `android.widget.ImageView`、`View Id Name = R.id.mAdCoverImg`，说明没有对应 Dialog 类逻辑，弹窗由某个 Fragment 的布局（全屏 Dialog 主题的 Fragment，`setStyle(2, R$style.FullScreenDialog)`）自动呈现。
- **从 UI 反查代码**：jadx 全局搜索资源 id 名 `mAdCoverImg`/`mAdCloseImg`，命中 `PullADFragment.onViewCreated()` 中的 `view.findViewById(R$id.mAdCoverImg)`；类名语义（PullAD）也直接表明是广告拉取页。
- **为什么改点击逻辑没用**：广告由 Fragment 自动展示，关闭按钮的 `onClick` 只是 `dismiss()`；要"不显示"必须阻止 Fragment 初始化本身。
- **return-void 的作用**：smali 的 `.method public onCreate(...)V` / `onViewCreated(...)V` 开头（`.registers` 之后）插入 `return-void`，方法直接返回，跳过 `super.onCreate`、`setStyle`、`findViewById` 与广告数据绑定，Fragment 视图不会建立，弹窗不出现。原文在 `onCreate` 与 `onViewCreated` 两处都加了 `return-void`。
- **生命周期风险**：`onCreate` 提前返回会跳过 `super.onCreate`，个别 App 可能在后续生命周期回调中因状态缺失崩溃；若崩溃，仅保留 `onViewCreated` 的 `return-void`（此时 Fragment 已创建但不建视图）通常更稳。

## 触发条件

- APK 未加固或可脱壳，Fragment/广告逻辑在 Java/Kotlin 层可见（本例 NP 管理器显示"未加固"）；
- 广告弹窗由客户端 Fragment/Activity 自动展示，且没有"广告加载失败即崩溃"之类的强依赖；
- App 未做签名/完整性校验，允许重打包重签安装。

## 利用步骤

1. NP 管理器确认未加固，jadx 打开 APK，查看 `AndroidManifest.xml` 中启动 Activity 与主 Activity。
2. 安装运行 App，在弹窗出现时用布局查看器（开发助手/Android Studio Layout Inspector）选中弹窗元素，记录 `View Id Name`（`R.id.mAdCoverImg`）与类（`ImageView`）。
3. jadx 搜索 `mAdCoverImg`，定位到 `com.idaddy.ilisten.pull.ui.PullADFragment`；阅读 `onCreate`/`onViewCreated` 确认广告展示逻辑。
4. `apktool d target.apk`，在 smali 中找到 `PullADFragment.smali`（`smali/com/idaddy/ilisten/pull/ui/PullADFragment.smali`）。
5. 在 `onViewCreated` 方法 `.registers N` 后插入 `return-void`；如仍显示，在 `onCreate` 的 `invoke-super` 之前同样插入 `return-void`。
6. `apktool b` 重新打包，重签名（keytool/jarsigner/zipalign 或 MT 签名），卸载原包后安装，验证弹窗消失、app 其它功能正常。

## PoC

```text
# PullADFragment.smali（onViewCreated）
.method public onViewCreated(Landroid/view/View;Landroid/os/Bundle;)V
    .registers 9
    return-void          # 新增：跳过整个视图初始化
    ...
.end method

# PullADFragment.smali（onCreate）
.method public onCreate(Landroid/os/Bundle;)V
    .registers 3
    return-void          # 新增：不执行 super.onCreate/setStyle
    ...
.end method
```

```bash
apktool d target.apk -o out
# 编辑 out/smali/.../PullADFragment.smali
apktool b out -o patched.apk
keytool -genkey -keystore test.jks -alias test -keyalg RSA -keysize 2048 -validity 3650 -storepass pass -keypass pass -dname "CN=test"
jarsigner -keystore test.jks -storepass pass -keypass pass patched.apk test
zipalign -f 4 patched.apk patched-aligned.apk
adb install -r patched-aligned.apk
```

## 变体与关联

- 变体：弹窗若是纯 Activity（无 Fragment），同样在 `onCreate` 中 `return-void` 或把 Manifest 中该 Activity 的 intent-filter 移除；启动广告去重见 [[mobile-android-apk-manifest-launcher-vip-charge-bypass]]（改 Manifest 启动 Activity 直入主界面）。
- 变体：动态环境可用 Frida hook `onViewCreated` 直接返回，或 hook 广告 SDK 的加载方法；已有 [[mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip]]。
- 关联：会员校验解锁见 [[mobile-android-smali-vip-check-force-true-repack]]（同类 smali 重打包思路）；完整反编译/打包流程与验证方法同源。
- 边界：服务端强制下发广告（展示上报/激励校验）或广告嵌入原生 SDK 时，改 Fragment 可能只去 UI，原生层仍会加载。

## 检测与防御

- 检测：App 启动时校验签名/安装包完整性（签名比对、V2/V3 校验、二次打包检测），比对关键类的 dex 校验和；检测 `return-void` 篡改导致的生命周期异常；服务端广告曝光上报与实际展示不一致告警。
- 防御：代码加固与反调试、签名校验、服务端校验广告展示与权益；把广告与功能门禁下沉到原生层/服务端下发，减少纯客户端可改逻辑。
