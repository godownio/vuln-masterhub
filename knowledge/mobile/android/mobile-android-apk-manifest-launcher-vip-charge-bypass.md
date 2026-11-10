---
id: mobile-android-apk-manifest-launcher-vip-charge-bypass
title: 重打包改 AndroidManifest 启动 Activity：跳过会员开通引导页直入主界面
type: scenario
domain: mobile
path: mobile/android
technique: apk-manifest-launcher-activity-repoint
aliases:
- 修改启动 Activity
- AndroidManifest LAUNCHER 重定向
- 跳过会员开通页
- 绕过启动广告/付费引导
- XsrdTabPageActivity
- MT Activity 记录器
tags:
- android
- apk
- repack
- androidmanifest
- launcher-activity
- vip
- entitlement-bypass
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:38:24+08:00'
  notes: 已对照原文13689及21个媒体核对：MT Activity记录器跳转链、Manifest MAIN/LAUNCHER 迁移到XsrdTabPageActivity、GIF启动直入主界面均与原文一致；apktool/jarsigner/zipalign为等价通用流程（原文用MT签名），未本机执行；服务端权益边界原文只提未验证
---

## 一句话结论

未加固 BUT 代码混淆的 App 常把"启动 → 会员开通页"的跳转写在 SplashActivity 里；由于桌面入口完全由 `AndroidManifest.xml` 中 `MAIN`+`LAUNCHER` 的 intent-filter 决定，用 apktool/MT 把 LAUNCHER 改挂到真正的业务主界面 Activity（本例 `XsrdTabPageActivity`），重打包重签安装后，App 启动即直接进入主界面，不再经过会员购买引导页。

## 原理

- **启动 Activity 由清单决定**：Android 桌面点击图标时解析的是带 `android.intent.action.MAIN` + `android.intent.category.LAUNCHER` 的 intent-filter，系统启动该 filter 所在 `<activity android:name="...">`。谁持有这个组合，谁就是入口，与代码里跳转到哪个页面无关。
- **原设计的付费引导链**：应用入口是 SplashActivity，其 `zr()` 在启动时判断本地会员状态 `w.f1188w.u()`；未开通时按配置跳转 `XsrdVipChargeActivity`（start_up_1/2），已开通才进主界面。因此只要入口仍是 Splash，正常启动就会先落在购买页。
- **改清单即可换入口**：把 `MAIN`+`LAUNCHER` 的 intent-filter 从 Splash/收费页所在的 activity 移到主界面 Activity，系统不再执行 Splash 的跳转逻辑，直接创建主界面；这是纯客户端控制，不涉及服务端权益校验。
- **混淆不妨碍定位**：包名/类名被混淆时，静态读代码困难，但运行时 Activity 跳转仍以真实类名出现；MT 管理器的 Activity 记录器可直接记录 `SplashActivity → XsrdVipChargeActivity` 与主界面 `XsrdTabPageActivity` 的类名，再回 jadx/MT 按类名搜索即可找到清单节点。
- **前提是清单可改、签名可换**：APK 未加固（PKID 显示"未采用加固"），`AndroidManifest.xml` 可反编译修改；应用未做签名/完整性校验，重签后能正常启动。

## 触发条件

- APK 未加固或可直接解包，`AndroidManifest.xml` 可读可改。
- 应用未校验签名/完整性（或校验可绕过），允许安装同包名不同签名的重打包 APK。
- 付费引导只由客户端 Activity 跳转控制，目标主界面 Activity 已存在且可独立启动（不依赖 Splash 传入的初始化状态）。
- 能确定目标 Activity 的完整类名（Activity 记录器、jadx 清单、`dumpsys activity` 等）。

## 利用步骤

1. 用 PKID/MT/jadx 确认未加固；jadx 打开 APK 观察代码结构，记录混淆情况。
2. 打开 MT 管理器的 Activity 记录器，启动一次目标 App，记录实际跳转链（如 Splash → `XsrdVipChargeActivity`，以及主界面 `XsrdTabPageActivity`）。
3. 在 jadx 中按类名搜索主界面 Activity，确认它不依赖 Splash 的额外参数即可完成初始化；必要时读 `onCreate` 检查。
4. `apktool d target.apk` 解包，编辑 `AndroidManifest.xml`：把 `MAIN`+`LAUNCHER` 的 intent-filter 移到 `XsrdTabPageActivity` 节点下（或直接把原 launcher activity 的 `android:name` 改成主界面类名）；注意同文件里可能有多个 activity 的 intent-filter，改错节点会得到"应用未安装/无启动入口"。
5. `apktool b` 回包，用 keytool 生成临时签名并用 jarsigner/zipalign 签名对齐（或直接用 MT 管理器"重签名"功能）。
6. 卸载原应用后安装重打包 APK（签名不同不能覆盖安装），启动验证是否直接进入主界面。
7. 记录边界：主界面可以打开，但依赖 VIP 的在线接口（如音频转文字 API）若服务端二次校验权益，仍会被拒绝。

## PoC

清单改法（把 LAUNCHER 归属到主界面 Activity）：

```xml
<activity android:name="com.example.app.home.XsrdTabPageActivity" ...>
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

重打包与签名（示例命令，签名参数按环境调整）：

```bash
apktool d target.apk -o target_src
# 编辑 target_src/AndroidManifest.xml
apktool b target_src -o patched.apk
keytool -genkey -keystore demo.keystore -alias demo -keyalg RSA -keysize 2048 -validity 3650
jarsigner -keystore demo.keystore -sigalg SHA1withRSA -digestalg SHA1 patched.apk demo
zipalign -v 4 patched.apk patched_aligned.apk
adb uninstall com.example.app && adb install patched_aligned.apk
```

原文在真机上验证：改清单后启动直接进入主界面（动图演示），未展示服务端功能是否仍受限。

## 变体与关联

- 变体：不改清单，而是 patch SplashActivity 里的会员判断（见 [[mobile-android-smali-vip-check-force-true-repack]]），保留原启动链路但让跳转条件永远不成立。
- 变体：用 Frida 直接 `startActivity` 拉起内部/隐藏 Activity，无需重打包，但需要注入能力（见 [[mobile-android-frida-jump-internal-activity]]）。
- 关联：[[mobile-android-apk-debuggable-repack-jadx-attach]]（同一类 Manifest 重打包手法，目的为开调试）、[[mobile-android-apk-version-spoof-bypass-forced-update]]（重打包改版本号绕过强制更新，同一"改清单/重签"工作流）、[[mobile-android-apk-static-entry-layout-resource-locate]]（清单入口定位基础）。
- 边界：加固/签名校验/完整性校验（Play Integrity）会使清单修改失效；服务端权益校验使本地入口绕过只影响界面；改错 intent-filter 会导致无启动入口。

## 检测与防御

- 检测：安装包签名与官方不一致、包名相同但证书指纹不同；Manifest 中 LAUNCHER 指向非发布入口 Activity；重打包常见的 zipalign/签名差异。
- 防御：启动时校验签名/完整性（Play Integrity、SafetyNet、自建证书指纹校验）；关键权益放服务端校验，客户端只做展示；代码加固与资源混淆提高改包成本。
- 边界：本地绕过只影响"引导页/界面"，不改变服务端授权；评估时应区分 UI 绕过与真实权益绕过。
