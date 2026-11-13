---
id: mobile-android-splash-ad-navigation-boolean-gate-shortcircuit-repack
title: 启动广告去除：SplashAdActivity 组合布尔导航条件短路验证 + smali 双条件改真直入主界面
type: scenario
domain: mobile
path: mobile/android
technique: apk-splash-ad-navigation-boolean-gate-patch
aliases:
- 开屏广告去除
- SplashAdActivity 跳过启动广告
- repository.p() && repository.j() 短路
- Frida hook 布尔条件短路求值
- TopOn 开屏广告绕过
- 启动广告 smali 改判断
tags:
- android
- apk
- smali
- repack
- ad-removal
- splash-ad
- frida
- short-circuit
- topon
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V580
  verified_at: '2026-11-12T12:31:49+08:00'
  notes: 已对照 content.md 全文与全部 24 图(含 11.gif/17.gif 首帧)核对：SplashAdActivity.onPolicyAgreed 中 repository.p() && repository.j() 导航门禁(图04)、Frida hook p 返回 false 且 j 未被调用的短路现象(图05/06)、强制 p 为 true 后 j 返回 false(图07/08)、最终 smali 两处 if-eqz 改 if-nez(图09)、重打包后直入 MainActivity(图11) 均一致。已修正卡内'文章两处分别用了这两种写法'为原文两种改法均有标注、最终 smali 截图两处均用 if-eqz->if-nez，并移除原文未提的 PKID。登录+VIP 与 initAds return-void 两场景合并到既有卡合理。dedup 复核与 objection 动态路线、Manifest 改入口、ad-fragment return-void 卡均为 related 非同链；affected_versions 原文未给，保持空。未验证点：未实际反编译/重打包该 APK。
---

## 一句话结论

当启动页（如 `SplashAdActivity`）在隐私政策同意回调里用 `if (repository.p() && repository.j()) { navigateToMainActivity(); return; }` 决定"直入主界面还是走广告 SDK 展示开屏广告"时，不必碰广告 SDK 本身：先用 Frida hook 这两个布尔方法确认短路关系（`p()` 为 false 时 `j()` 根本不会被调用，必须先强制 `p()` 返回 true 才能观测 `j()`），再把 smali 里两个判断分别改为恒真（`move-result` 后 `const/4 vX, 0x1`，或把 `if-eqz` 改 `if-nez`），重打包重签安装后启动直接进入主界面，TopOn 等广告 SDK 的展示调用成为不可达路径。

## 原理

- **开屏广告的控制点在导航条件，不在广告 SDK**：本例 `SplashAdActivity.onPolicyAgreed()` 中先判断 `repository.p() && repository.j()`，为真则 `navigateToMainActivity()` 并 `return`；为假才继续执行 `com.ad.topon.kt.g.a(this, frameLayout, textView, callback)` 展示开屏广告。广告 SDK 只负责"被调用后展示"，是否调用由上一层布尔门禁决定，因此 patch 门禁即可，无需逆向 SDK 内部。
- **Java `&&` 的短路求值会误导动态验证**：`a() && b()` 先求 `a()`，为 false 时结果已确定为 false，`b()` 不会被调用。只 hook `j()` 时日志里完全没有调用记录，容易被误判为"没走这条链路"；正确做法是先把 `p()` 的 Frida implementation 改为 `return true`，再触发启动流程，才能看到 `j()` 被调用并拿到其真实返回值（本例同样为 false）。
- **编译产物形态**：`if (p() && j())` 在 smali 中表现为两次 `invoke-virtual ...->p()Z` / `j()Z` + `move-result` + `if-eqz vX, :cond_xx`（非零即真，假则跳到广告分支）。要让组合条件恒真，两个条件都必须为真，只改一个仍会被短路成 false。
- **两种等价改法**：一是在 `move-result vX` 之后、`if-eqz vX, :cond_xx` 之前插入 `const/4 vX, 0x1`，把结果直接覆盖为 true；二是把条件跳转取反（`if-eqz` 改 `if-nez`），让"假"不再跳去广告分支。原文对两种改法都做了标注，其最终 smali 截图（img/09）对 `p()`、`j()` 两处判断均采用 `if-eqz` → `if-nez`。
- **前提**：APK 未加固、无签名/完整性校验，允许反编译、回编译与重签安装；布尔方法在 Java/Kotlin 层实现，未被壳抽取到 native。

## 触发条件

- 启动广告由客户端自身 Activity 逻辑和布尔门禁控制，不是纯服务端强制下发，也不是无法改包的独立进程广告展示。
- APK 未加固或可脱壳，`SplashAdActivity` 等类可反编译为 smali。
- 应用无签名/完整性校验（或可绕过），允许重打包重签安装。
- 能定位决定"进主界面还是展示广告"的布尔方法（本例 `Repository.p()`、`Repository.j()`；`j()` 同时是会员判断，被多处复用）。

## 利用步骤

1. 用 MT 管理器查看加固状态；启动 APP，用 MT 的 Activity 记录器确认启动链：`SplashAdActivity`（启动页）→ `MainActivity`（主界面）。
2. jadx 打开 APK，按类名进入 `SplashAdActivity`，在隐私政策回调 `onPolicyAgreed()` 中定位关键分支：`if (repository.p() && repository.j()) { navigateToMainActivity(); return; }`，其后是 `topOnSplash.a(...)` 的广告展示调用（TopOn SDK）。
3. adb shell 启动 frida-server，`frida-ps -U` 找到应用进程，以 attach 或 spawn 方式注入；hook `com.didikee.gifparser.data.Repository` 的 `p()` 与 `j()`，打印调用与返回值。
4. 第一次触发：`p()` 返回 false，`j()` 无任何日志——这是短路求值；把 `p()` 的 implementation 改为 `return true` 后重新触发，确认 `j()` 被调用且返回 false，证明两个条件都是通往主界面的门禁。
5. 反编译：`apktool d target.apk`（或 NP 管理器直接编辑 dex）。在 `SplashAdActivity.smali` 的 `onPolicyAgreed` 方法中找到两处判断：
   - `invoke-virtual {p1}, ...Repository;->p()Z` 后 `move-result v0`，在 `if-eqz v0, :cond_xx` 前插入 `const/4 v0, 0x1`（或把 `if-eqz` 改为 `if-nez`）；
   - `invoke-virtual {p1}, ...Repository;->j()Z` 后 `move-result p1`，把 `if-eqz p1, :cond_xx` 改为 `if-nez p1`（或同样插 `const/4 p1, 0x1`）。
6. 保存回编译、重签名、卸载原包后安装；冷启动验证：不再出现开屏广告，直接进入 `MainActivity`，并回归登录、会员、导出等其它功能未被意外影响。

## PoC

Frida 验证脚本（先观测，再强制前件为真复测）：

```javascript
Java.perform(function () {
    var Repo = Java.use("com.didikee.gifparser.data.Repository");
    Repo.p.implementation = function () {
        var ret = this.p();
        console.log("p() = " + ret);
        return ret;   // 第二次改为 return true，绕过短路以观测 j()
    };
    Repo.j.implementation = function () {
        var ret = this.j();
        console.log("j() = " + ret);
        return ret;
    };
});
```

smali 修改（示意，寄存器与标签以实际样本为准）：

```smali
# 改前
invoke-virtual {p1}, Lcom/didikee/gifparser/data/Repository;->p()Z
move-result v0
if-eqz v0, :cond_2f

# 改法一：判断前赋真
const/4 v0, 0x1
if-eqz v0, :cond_2f

# 改法二：条件取反
if-nez v0, :cond_2f
```

重打包与签名：

```bash
apktool d target.apk -o target_src
# 编辑 target_src/smali/.../SplashAdActivity.smali 两处判断
apktool b target_src -o patched.apk
keytool -genkey -keystore demo.keystore -alias demo -keyalg RSA -keysize 2048 -validity 3650
jarsigner -keystore demo.keystore -sigalg SHA1withRSA -digestalg SHA1 patched.apk demo
zipalign -v 4 patched.apk patched_aligned.apk
adb uninstall com.example.app && adb install patched_aligned.apk
```

## 变体与关联

- 变体：不 patch 调用点，直接让 `p()`/`j()` 函数内部恒返回 true。本例 `j()` 是会员判断（被导出等流程复用），改内部会连带解锁其它门禁，"一劳永逸"但影响面更大；对应 [[mobile-android-smali-vip-check-force-true-repack]]。
- 变体：若启动广告是独立 Activity，可直接把 Manifest 的 MAIN/LAUNCHER 改挂到主界面 Activity，绕过整个启动页，见 [[mobile-android-apk-manifest-launcher-vip-charge-bypass]]。
- 关联：[[mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip]] 用 objection 追触摸事件/广告日志并伪造 MotionEvent 或 hook 广告请求开关，属动态路线；本卡是"Frida 验证 + 静态改包"路线，产物安装后无需每次挂脚本。
- 边界：服务端强制下发广告、广告与启动初始化强耦合（跳过广告会导致后续页面缺数据）时，仅改导航条件可能引起功能异常；加固壳把 `onPolicyAgreed` 抽到 native、或存在签名/完整性校验时改包失效。

## 检测与防御

- 检测：APK 签名/证书指纹与官方不一致；smali/字节码中布尔判断被改为常量 1 或条件指令被取反；启动页广告曝光上报与实际展示不一致；重打包特征（zipalign/签名差异）。
- 防御：启动流程关键判定放服务端（下发是否展示广告及页面配置）；对安装包做签名/完整性校验（Play Integrity、证书指纹、dex 校验和）；代码加固与控制流混淆提高定位与改包成本；不要用单一客户端布尔方法同时承载广告、会员等多类决策。
