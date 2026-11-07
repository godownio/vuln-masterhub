---
id: mobile-android-exported-activity-unauth-changepassword-phishing
title: Android 组件导出：未登录启动 ChangePasswordActivity 用于钓鱼/未授权页面
type: scenario
domain: mobile
path: mobile/android
technique: android-exported-activity-unauth-changepassword-phishing
aliases:
- Android exported Activity
- 未授权启动修改密码页
- 组件导出漏洞
- am start 调用导出组件
- 恶意 App 钓鱼
tags:
- android
- exported-activity
- component-exposure
- phishing
- intent
- misconfiguration
- mobile
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:17:23+08:00'
  notes: 已对照原文与截图核对：Manifest 中 ChangePasswordActivity 等 exported=true、未登录状态 am start 拉起修改密码页、可被恶意 App 用于钓鱼均与图文一致。未验证点：未构造恶意 App 实测；页面内是否可实际提交改密原文未验证。
---

## 一句话结论

应用把 `ChangePasswordActivity` 等敏感页面设为 `android:exported="true"` 且未在页面内校验登录态时，任何应用或 `adb shell am start` 都能在未登录情况下拉起该页面；攻击者可将其嵌入恶意 App 做钓鱼（诱导输入原密码/新密码），或触发页面内的未授权操作。

## 原理

- Android 组件导出：`android:exported="true"` 的 Activity 可被其他应用通过显式/隐式 Intent 启动；未设置权限保护时，任何应用都能调用。
- 若 Activity 在 `onCreate`/`onResume` 中没有检查登录态/调用者身份，即使应用未登录，页面也会正常显示并可交互；页面内的“修改密码”“确认修改”等按钮可能直接调用后端接口。
- 攻击方式：
  - 恶意 App 用 `startActivity(new Intent().setComponent(new ComponentName(pkg, activity)))` 拉起正版应用的修改密码页，伪装成正版流程诱导用户输入原密码/新密码（钓鱼）；
  - 或通过 `adb shell am start -n pkg/activity` 直接验证未授权访问；
  - 若页面支持 Intent 参数（如账号、token、跳转 URL），还可能被注入/重定向。
- 为什么可行：Android 组件暴露是显式配置问题；很多开发者为了“外部唤醒/深链/测试”把页面导出，却忘了加权限或登录校验。
- 影响：凭据钓鱼、未授权页面访问、品牌仿冒；若页面执行敏感操作，可能进一步导致账号/数据风险。

## 触发条件

- Manifest 中敏感 Activity `android:exported="true"`（或未显式设置但含 intent-filter 导致默认导出）。
- Activity 没有登录态校验/调用者校验/权限保护。
- 页面可被外部 Intent 启动，且 UI/操作对攻击者有价值（修改密码、账号信息、支付、设置）。
- 攻击者能安装恶意 App 或拥有 ADB 访问。

## 利用步骤

1. 反编译 APK，检查 `AndroidManifest.xml` 中 `exported="true"` 的 Activity/Service/Receiver/Provider。
2. 筛选敏感页面：修改密码、账号详情、支付、设置、WebView。
3. 未登录状态下执行：
   ```bash
   adb shell am start -n com.example.app/com.example.app.ui.profile.ChangePasswordActivity
   ```
4. 观察页面是否正常显示、是否可操作；若可，记录截图/日志作为证据。
5. 构造恶意 App：用显式 Intent 启动该 Activity，配合仿冒 UI/说明文字诱导用户输入凭据；或分析页面接收的 Intent extras 是否可注入。
6. 评估影响（钓鱼/未授权操作/数据泄露），提交修复建议。

## PoC

```bash
# 未登录状态直接启动导出的修改密码页
adb shell am start -n com.example.app/com.example.app.ui.profile.ChangePasswordActivity

# 查看当前前台 Activity（确认页面被拉起）
adb shell dumpsys activity activities | grep -i mResumedActivity
```

```java
// 恶意 App 内显式启动导出组件（示意）
Intent i = new Intent();
i.setComponent(new ComponentName("com.example.app",
        "com.example.app.ui.profile.ChangePasswordActivity"));
startActivity(i);
```

说明：PoC 为原文流程的结构化复现，未在本机执行；原文在未登录状态下用 `am start` 拉起修改密码页，说明可被恶意 App 用于钓鱼。

## 变体与关联

- 变体（组件）：导出的 Service/Receiver/ContentProvider 可导致后台操作、广播注入、数据读取；Provider 还可 path traversal/SQL 注入。
- 变体（Intent）：隐式 Intent + intent-filter、deep link、PendingIntent 劫持、task hijacking（StrandHogg）。
- 变体（钓鱼）：恶意 App 复制正版 UI/包名相似图标，诱导输入账号密码/验证码。
- 关联：[[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]（exported ProxyActivity + WebView 凭证窃取）；[[mobile-android-allowbackup-adb-backup-restore-account-takeover]]（同属 Android 配置错误）；[[mobile-android-spyware-clouddisk-contact-sms-photo-exfil]]（恶意 App 行为）。
- 边界：Activity 未导出、加了 signature 权限、页面内校验登录态/调用者、或操作需要二次验证时，钓鱼/未授权访问会受限。

## 检测与防御

- 检测：Manifest 中敏感 Activity `exported=true`；未登录状态可拉起修改密码/账号页面；外部 Intent 可携带敏感 extras。
- 防御：不需要外部访问的组件设置 `android:exported="false"`；必须导出时加自定义 signature 权限、校验调用者包名/签名。
- 加固：页面内检查登录态与用户身份；敏感操作要求重新认证/二次验证；使用 App Links 并校验域名；避免在导出组件中处理敏感 Intent extras。
- 响应：发现导出组件被滥用时，评估是否有钓鱼/数据泄露，通知用户并更新应用。
