---
id: mobile-android-frida-hook-update-dialog-bypass
title: APP 强制更新弹窗绕过：jadx 按文案定位 UpdateDialog.show() 并用 Frida 覆盖实现
type: scenario
domain: mobile
path: mobile/android
technique: frida-hook-update-dialog-show-bypass
aliases:
- 绕过强制更新弹窗
- UpdateDialog.show hook
- Frida 去更新弹窗
- jadx 搜索最新版本
- 强制更新绕过
tags:
- android
- frida
- jadx
- hook
- update-dialog
- bypass
- mobile
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:30:29+08:00'
  notes: 已对照原文全文与 28/28 张截图核对：img01 强制更新弹窗（版本太旧了/立即更新）、img02 jadx 搜索「最新版本」命中 b.a.d()、img04 d() 中版本比较后 new UpdateDialog(...); updateDialog.show() 分支、img05 Frida spawn+Java.use(UpdateDialog).show.implementation 覆盖脚本（原文 show 带 ctx 参数，卡内注明按签名匹配重载），均与卡一致；spawn/attach/resume 与 27042/27043 转发同原文。img06 显示加载 libmsaoaidsec.so 后崩溃的反调试，卡内作为边界/关联说明。卡内未断言旧接口一定可用（触发条件要求旧接口仍可访问）。原文无产品/版本，affected_versions 已 --clear。与另一张 14085 卡（isRooted/isSimulator Hook）目标类与目的不同，不重复；亦不与 apk 版本伪造卡重复（dedup related 0.912，机制不同）。PoC 未在真实目标运行。
---

## 一句话结论

当旧版 APP 启动时因服务端版本检查弹出不可取消的更新对话框、但旧版接口仍可用时，可用 jadx 搜索弹窗文案（如“最新版本”“立即更新”“版本太旧”）定位构造 `UpdateDialog` 并调用 `show()` 的代码，再用 Frida `Java.use(<类名>).show.implementation` 把弹窗方法覆盖为空实现，使弹窗不再出现，从而继续测试旧版接口。

## 原理

- **强制更新弹窗是客户端 UI**：版本检查通常由客户端发起（请求最新版本号 → 与本地版本比较 → 若落后则 `UpdateDialog.show()`）。服务端是否真的拒绝旧版接口是另一回事；很多应用只在前端用弹窗遮挡界面，接口并不校验版本，因此阻断弹窗显示即可恢复操作。
- **Frida Java 层覆盖**：`Java.use("类名").show.implementation = function(...) { ... }` 会把该 Java 方法的实现替换为给定 JS 函数；不调用原方法即完全不弹窗。类名/方法名可能被混淆（如 `UpdateDialog`、`b.a.d()`），但弹窗文案字符串通常保留在代码中，可作为定位锚点。
- **定位方法**：jadx 搜索弹窗文案（“最新版本”“立即更新”“版本太旧”等）→ 找到引用该字符串的方法/类 → 查看其构造与 `show()` 调用点 → 记录类全名与方法签名。若 `show` 有参数（如 `show(Context)`），Hook 时需匹配重载。
- **为什么有效**：版本判断与弹窗都在客户端执行，Frida 在方法入口替换实现即可跳过 UI；服务端如果只按 `App-Version` 提供数据而不强制拒绝，旧版本仍能正常调用接口。
- **边界**：若服务端对旧版本返回错误/降级数据或强制踢下线，仅 Hook 弹窗无效，需要改版本号/重打包（见变体）；若应用有 Frida 反调试，Hook 脚本加载可能导致闪退，需要先绕过反调试。

## 触发条件

- 拿到旧版本 APK，启动后出现覆盖界面的强制更新弹窗（可取消或不可取消均可），且旧版本接口仍可访问。
- 应用未使用 Flutter/React Native 等把 UI 完全放在 native/JS 层的框架，或弹窗逻辑仍可从 Java 层 Hook；纯 native 弹窗需改 Hook native/UI 层。
- 测试设备可运行 frida-server（root 或可调试包），能 spawn/attach 目标进程并转发 27042/27043 端口。
- 应用未启用会让 Frida 直接闪退的反调试，或已先完成反调试绕过。

## 利用步骤

1. 用 jadx 打开 APK，全局搜索更新相关文案（“最新版本”“立即更新”“版本太旧”“发现新版本”等），定位引用处的方法与类。
2. 阅读代码确认弹窗触发条件：常见结构是 `if (serverVersion > localVersion) { UpdateDialog d = new UpdateDialog(ctx); d.show(); }`；记录 `UpdateDialog` 的完整类名（混淆名如 `com.x.y.a` 也可）与 `show` 的方法签名。
3. 启动 frida-server 并做端口转发：
   ```bash
   adb shell su -c /data/local/tmp/frida-server-<ver>-android-arm64 &
   adb forward tcp:27042 tcp:27042
   adb forward tcp:27043 tcp:27043
   ```
4. 使用 spawn 方案加载脚本（避免 attach 时弹窗已显示）：
   ```python
   import frida, sys
   rdev = frida.get_remote_device()
   pid = rdev.spawn(["com.example.app"])
   session = rdev.attach(pid)
   script = session.create_script("""
   Java.perform(function () {
       var UpdateDialog = Java.use("com.example.app.UpdateDialog");
       UpdateDialog.show.implementation = function () {
           console.log("[*] update dialog suppressed");
       };
   });
   """)
   script.on("message", lambda m, d: print(m, d))
   script.load()
   rdev.resume(pid)
   sys.stdin.read()
   ```
5. 若脚本加载后 APP 闪退，先排查 Frida 反调试（dlopen 监控定位检测 SO、删除/阻断加载、strongR-frida 改名 server 等，见关联卡）。
6. 弹窗不再出现后，继续抓包/测试旧版接口；若接口被服务端拒绝，改用版本号伪造/重打包方案。

## PoC

Frida 脚本（类名按 jadx 定位结果替换；`show` 若有参数需写成对应签名）：

```javascript
Java.perform(function () {
    var UpdateDialog = Java.use("com.example.app.UpdateDialog");
    UpdateDialog.show.implementation = function () {
        console.log("[*] UpdateDialog.show() suppressed");
        // 不调用 this.show()，弹窗不显示
    };
});
```

Python 侧 spawn + attach + resume 的骨架见上文利用步骤；原文使用 `frida.get_remote_device()`、`spawn([包名])`、`attach(pid)`、`create_script`、`load`、`resume` 的流程。

## 变体与关联

- **改版本号/重打包**：如果服务端校验版本，直接修改 `versionName`/`versionCode` 并重签，使客户端自认最新，不再触发弹窗；见 [[mobile-android-apk-version-spoof-bypass-forced-update]]。
- **旧版 APK + 重写版本检测接口**：严格 pinning 场景下用旧版 APK 并劫持版本检测响应；见 [[mobile-android-ssl-pinning-downgrade-version-check-rewrite]]。
- **Hook 版本比较方法**：除弹窗 `show()` 外，也可 Hook `isNeedUpdate()`/版本比较函数返回 false，效果相同但依赖具体实现。
- **断网进入再联网**：若弹窗只在首页且启动时请求版本，可先断网进入应用再恢复网络，弹窗不再出现；该方法依赖具体实现，稳定性差，可作为临时手段。
- **Frida 反调试**：Hook 前若应用检测 Frida，参考 [[mobile-android-native-frida-antidebug-thread-bypass]]、[[tools-frida-source-patch-anti-detection]]。

## 检测与防御

- **不要在客户端做唯一的版本门禁**：强制更新应由服务端对旧版本 API 返回明确错误/降级，并配合签名/证书校验，不能只靠客户端弹窗遮挡。
- **服务端策略**：按 `App-Version` 做最小版本校验、下架旧接口、对旧版本令牌缩短有效期；对关键接口做版本绑定。
- **客户端加固**：代码混淆/字符串加密提高定位成本，RASP/反调试提高 Hook 成本，但无法从根本上阻止 Frida（客户端代码可被分析）。
- **检测**：留意客户端 `UpdateDialog` 类被动态替换、Frida 特征、异常 spawn/attach 行为；服务端监控同一账号/设备在旧版本上的异常调用。
