---
id: mobile-android-realname-antiaddiction-smali-bypass
title: 手游实名认证客户端门禁绕过：改 isVerified 分支与 RidCheck 回调布尔值后重打包
type: scenario
domain: mobile
path: mobile/android
technique: apk-smali-client-side-realname-gate-bypass
aliases:
- 实名认证绕过
- 防沉迷客户端绕过
- IDCheckDialog 改判断
- isVerified 取反
- RidCheckCallback 强制 true
- 游客模式限制绕过
tags:
- android
- apk
- smali
- repack
- anti-addiction
- realname-verification
- client-side-trust
- reverse
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V561
  verified_at: '2026-11-12T07:40:37+08:00'
  notes: 已对照原文13005逐图核对：IDCheckDialog.onCreate 游客按钮 setVisibility(8)、preLaunchNextIntent 的 !isVerified() 分支、RidCheckCallback.onResult(z) 与 Settings.isTestEnvironment 固定测试身份分支均与截图/代码一致；作者实测仅到改 isVerified 后以游客模式进入并弹'不支持游客模式'，回调取反后'任意信息通过'无确认截图，属未完全实证点（卡内边界已说明）；未本机执行改包。
---

## 一句话结论

当游戏的实名/防沉迷判定完全在客户端完成时，可以在 jadx 定位 `MyStartActivity.preLaunchNextIntent` 中的 `!verificationStorageManager.isVerified()` 分支和 `IDCheckDialog` 里 `RidCheckCallback.onResult(boolean z)` 的 `if (z)` 判断，用 apktool 修改 smali 把布尔判断强制为 true 后重打包重签，跳过实名弹窗或以任意格式信息"认证通过"；作者实测可进入游戏，但服务端下发真实结果时该改动只影响本地状态。

## 原理

- **客户端门禁的两种形态**：
  - `preLaunchNextIntent` 中 `if (!verificationStorageManager.isVerified()) { new IDCheckDialog(...).show(); return; }` 决定是否弹出实名窗口；
  - `IDCheckDialog` 调用 `AntiAddictionManager.doRidCheck(...)` 后，在回调 `onResult(boolean z, int age)` 中 `if (z) { saveVerification(...) } else { setGuestMode(true) }`，`z` 来自网络响应 `playerDataResponse.getAge() != -1`。
- **改法**：把 `isVerified()` 判断取反（或强制返回 true）可跳过弹窗；把 `onResult` 的 `if (z)` 改成恒真（或把 z 来源改为常量 true）可让任意信息通过本地校验。两者不能同时保留——作者先把弹窗逻辑改掉后游戏进入游客模式并弹"不支持游客模式"提示，必须把前一修改改回、再改回调判断，才会走到实名流程。
- **为什么有效**：实名结果被保存到本地 `VerificationStorageManager`，后续启动只看本地 `isVerified()`，不再重复请求；客户端没有对判定代码做完整性校验。
- **边界与合规**：真实实名请求发往第三方服务（`requestRidCheck` POST，返回年龄字段决定 z）。重打包只能篡改客户端对响应的处理，不能伪造服务端已认证状态；若服务端在关键玩法/时长限制上以服务端记录为准，绕过效果有限。此类改动还涉及实名制相关法律法规，仅限授权的安全测试与研究。
- **测试环境遗留**：`IDCheckDialog.onCreate` 中存在 `if (Settings.INSTANCE.isTestEnvironment()) { txtID.setText("11010120100701421x"); txtName.setText("张伟"); }` 的测试分支，说明 APK 内置了测试身份自动填充逻辑；若该开关可被外部触发，等于内置后门式绕过。

## 触发条件

- APK 未加固，可 apktool 反编译并重打包；
- 实名/防沉迷判定在客户端 Java/Kotlin 层完成，且本地保存认证状态；
- 攻击者可安装重签名的 APK；
- 服务端未对客户端认证状态做强校验（否则仅本地跳过）。

## 利用步骤

1. jadx 搜索 `实名`/`IDCheckDialog`/`isVerified`/`RidCheck` 定位入口 Activity 与 Dialog。
2. 记录调用链：`preLaunchNextIntent → IDCheckDialog.show() → doRidCheck() → RidCheckCallback.onResult(z, age)`。
3. `apktool d` 反编译，改 `MyStartActivity.smali` 中 `isVerified` 判断（如把 `if-eqz` 改为无条件跳转或把返回值强制 0x1），验证跳过弹窗后的行为。
4. 若要"任意信息通过"，恢复上一步修改，改 `IDCheckDialog$...$1.smali`（回调内部类）中 `if (z)` 对应判断，使恒走 `saveVerification` 分支。
5. `apktool b` 重编译，重签名安装，输入任意符合格式的身份证号测试是否进入游戏。
6. 测试完成后恢复原包，不要用于实际规避实名制。

## PoC

入口判断（jadx 反编译视图）：

```java
if (!verificationStorageManager.isVerified()) {
    new IDCheckDialog(this, new AnonymousClass10(intent)).show();
    return;
}
```

回调判断：

```java
public void onResult(boolean z, int i) {
    if (z) {  // smali 中把该分支改为恒真，或把 z 置为 0x1
        new VerificationStorageManager(IDCheckDialog.this.getContext()).saveVerification(upperCase, obj);
        AntiAddictionManager.INSTANCE.get().setUserData(new UserData.Builder(obj, i).build());
    } else {
        AntiAddictionManager.INSTANCE.get().setGuestMode(true);
    }
    IDCheckDialog.this.dismiss();
    IDCheckDialog.this.callback.onCheckCompleted();
}
```

测试环境自动填充：

```java
if (Settings.INSTANCE.isTestEnvironment()) {
    this.txtID.setText("11010120100701421x");
    this.txtName.setText("张伟");
}
```

## 变体与关联

- smali 改会员权益布尔判断，见 [[mobile-android-smali-vip-check-force-true-repack]]（同为客户端布尔门禁，但目标功能与服务端依赖不同）；
- 重打包改启动 Activity 跳过付费引导，见 [[mobile-android-apk-manifest-launcher-vip-charge-bypass]]；
- Frida 动态 hook 对应判断可免重打包，适合有签名校验的场景（见 [[mobile-android-frida-hook-isrooted-issimulator-bypass]] 的 hook 思路）；
- 服务端风控/实名接口本身的安全问题不属于本卡范围。

## 检测与防御

- 实名与防沉迷状态以服务端记录为准，客户端只做展示与引导；关键玩法/时长校验必须服务端复核；
- 对 APK 做签名与完整性校验，检测重打包；加固/反调试提高改包成本；
- 移除或严格保护测试环境分支，避免固定测试身份被触发；
- 服务端记录并风控异常认证请求（同设备多账号、短时间大量认证、年龄字段异常等）；
- 合规角度：客户端绕过不代表服务端失守，防护重点应放在服务端权威判定。
