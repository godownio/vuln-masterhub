---
id: mobile-android-update-dialog-cancel-button-boolean-bypass
title: 强制更新弹窗取消按钮禁用绕过：定位 UpdateAppDialog 布尔设置函数 + Frida 强制 true / smali 去 xor 取反
type: scenario
domain: mobile
path: mobile/android
technique: update-dialog-cancel-button-boolean-bypass
aliases:
- 强制更新取消按钮
- UpdateAppDialog c(boolean)
- 取消更新按钮不可点击
- xor-int/lit8 取反修复
- Frida hook boolean 参数改 true
- 以后再说 按钮置灰
tags:
- android
- frida
- smali
- repack
- update-dialog
- bypass
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:11:07+08:00'
  notes: 已对照原文与截图核对：图19以后再说按钮灰色不可点、图20 c(boolean z)内setEnabled/setClickable/文字颜色、图21 frida日志z:false、图22 hook内zz=true二次调用、图23修改后按钮恢复可点均一致，smali xor-int/lit8取反删除步骤与原文一致；与frida-hook-update-dialog弹窗抑制卡落点/触发条件不同非同链；未验证点：未实际重打包复现
---

## 一句话结论

当强制更新弹窗的“以后再说”按钮被代码置灰不可点时，可在 jadx 中定位 `UpdateAppDialog` 的布尔设置函数 `c(boolean z)`（内部执行 `setEnabled(z)`/`setClickable(z)`），用 Frida hook 把 `z` 强制改为 `true` 后调用原方法，或在 smali 中删除调用点对 `!"1".equals(is_force)` 结果做取反的 `xor-int/lit8 v0, v0, 0x1`，重打包后取消按钮即可点击并跳过本次更新。

## 原理

- **按钮状态由单一布尔控制**：弹窗类 `com.dalongtech.cloud.wiget.dialog.UpdateAppDialog` 中，`c(boolean z)` 对取消按钮 `this.f12837i`（`(Button) a(R.id.update_dialog_cancelBtn)`）执行 `setEnabled(z)` 与 `setClickable(z)`，并按 `z` 切换文字颜色（可用色/灰色）。只要让 `z` 为 true，按钮就恢复可点。
- **调用点传入的是取反结果**：调用处为 `this.f12120c.c(!"1".equals(data.getIs_force()))`。当服务端返回 `is_force="1"` 时，`"1".equals(...)` 为 true，取反为 false，按钮被禁用；非强制更新时取反为 true，按钮可点。
- **动态验证**：用 Frida `overload('boolean')` hook `c`，打印入参；触发弹窗得到 `z: false`，证明禁用来自该布尔参数而非别处逻辑。
- **两种改法**：① Frida 在 hook 内把 `z` 改为 `true` 再 `this.c(zz)`，运行时生效、不落盘；② 持久化修改 smali：`xor-int/lit8 v0, v0, 0x1` 对 v0 最低位取反，删除该指令（或把立即数改为 0x0）后取反失效，`is_force="1"` 时传给 `c` 的变为 true。
- **前提**：Java/Kotlin 层实现、未加固或已脱壳，可反编译 smali 并重打包；应用未做严格签名/完整性校验（或可绕过）。

## 触发条件

- 启动时出现强制更新弹窗，但“以后再说/取消更新”按钮被置灰或点击无效。
- 更新弹窗逻辑在 Java/Kotlin 层，`setEnabled`/`setClickable` 的布尔来源可在 jadx 中定位。
- 能运行 Frida（root/可调试包）或能反编译重打包并绕过签名校验。
- 服务端未对旧版本接口做硬性拒绝（否则跳过弹窗后功能仍不可用）。

## 利用步骤

1. 触发强制更新弹窗，确认取消按钮状态（灰/不可点）。
2. jadx 根据弹窗文案/Activity 定位 `com.dalongtech.cloud.wiget.dialog.UpdateAppDialog`，找到 `c(boolean z)` 及按钮成员 `f12837i = (Button) a(R.id.update_dialog_cancelBtn)`。
3. Frida 验证：hook `c` 的 boolean 重载，打印 `z`；本例日志 `c is called, z: false`。
4. 动态绕过：hook 内把参数改为 true 后调用原方法，观察按钮恢复可点、点击可暂不更新。
5. 持久化绕过：找到唯一调用点 `this.f12120c.c(!"1".equals(data.getIs_force()))`，在 smali 中删除 `xor-int/lit8 v0, v0, 0x1`（或改为 `xor-int/lit8 v0, v0, 0x0`），重打包、去签名校验、安装。
6. 验证：重新触发更新弹窗，取消按钮可点，点击后进入应用。

## PoC

Frida（原文脚本，类名/方法名按目标实际值替换）：

```javascript
function carhook3() {
    let UpdateAppDialog = Java.use("com.dalongtech.cloud.wiget.dialog.UpdateAppDialog");
    UpdateAppDialog["c"].overload('boolean').implementation = function (z) {
        console.log('c is called' + ', ' + 'z: ' + z);
        var zz = true;          // 强制按钮可用
        let ret = this.c(zz);
        console.log('c ret value is ' + ret);
        return ret;
    };
}
```

smali（删除取反指令，使 `is_force="1"` 时传入 true）：

```smali
# 原指令
xor-int/lit8 v0, v0, 0x1
# 处理：删除该行，或改为 xor-int/lit8 v0, v0, 0x0
```

- 动态 hook 只对当前进程有效；smali 修改需重打包并处理签名校验。
- 原文通过 Frida 日志确认 `z: false`，并在 smali 修改后实测取消按钮可点击。

## 变体与关联

- **弹窗直接抑制**：不处理按钮状态，直接 hook `UpdateDialog.show()` 不显示弹窗，见 [[mobile-android-frida-hook-update-dialog-bypass]]；本条针对“弹窗必须出现、但取消被禁用”的实现，机制与落点不同。
- **改版本号**：修改 `versionName`/`versionCode` 让客户端自认最新，见 [[mobile-android-apk-version-spoof-bypass-forced-update]]。
- **同类布尔门禁**：广告/引导页的布尔短路修改思路可参考 [[mobile-android-splash-ad-navigation-boolean-gate-shortcircuit-repack]]。
- **边界**：若服务端对旧版本接口返回错误，按钮可点也无法继续使用；若应用有签名校验，需先去除或改用 Frida。

## 检测与防御

- 检测：客户端 `UpdateAppDialog.c(boolean)` 被 Frida 替换、进程存在 frida-server 特征；重打包 APK 证书与官方不一致；同一账号在旧版本上的异常调用。
- 防御：强制更新应由服务端对旧版本 API 直接拒绝，而不是仅靠客户端按钮状态；启用签名/完整性校验（Play Integrity、证书指纹）与 RASP/反调试。
