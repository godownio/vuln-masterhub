---
id: mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip
title: 用 objection 追 Activity 触摸与启动日志定位开屏广告入口，再以 frida 伪造 MotionEvent 或强改广告请求开关布尔值跳过广告
type: scenario
domain: mobile
path: mobile/android
technique: objection-method-trace-frida-forged-motionevent-ad-gate-bypass
aliases:
- 跳过开屏广告
- 伪造 MotionEvent 模拟点击
- dispatchTouchEvent 注入触摸
- Splash Ad 开关 hook
- objection hooking watch class_method
- smali 删除判断跳转
tags:
- android
- frida
- objection
- jadx
- apktool
- motionevent
- splash-ad
- hook
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:35:04+08:00'
  notes: 已对照原文核对；本次核对未读取图片；Activity 顺序、objection watch class_method、f42.a.b 强改 true 生效、apktool 删 smali 判断等与正文一致；路径一（伪造 MotionEvent）原文明确只说「理论上可以」，未给出实测成功证据，已在利用步骤标注；PoC 中包名/类名做了通用化替换（<pkg>），坐标 469.13/48.95 取自正文 MotionEvent 打印文本；未执行文内任何命令
---

## 一句话结论

要跳过 APP 开屏广告，先用 `objection` 的 `android hooking watch class_method` 同时挂住主 Activity 的 `dispatchTouchEvent` 和广告模块的日志方法，从"手动点跳过时多出的两个触摸事件 + 广告时长变短"确认跳过动作的落点；之后有两条路：在内存里 `Java.choose` 拿到 Activity 实例、用 `MotionEvent.obtain` 构造 ACTION_DOWN/ACTION_UP 直接调 `dispatchTouchEvent` 伪造点击；或顺着广告日志字符串（如 `>>> Splash Ad`）在 jadx 里上溯到"是否请求开屏广告"的判断，把其中那个恒为假的布尔方法强制返回 `true`（或直接删掉 smali 里对应分支）让广告请求整段被跳过。

## 原理

- **为什么先挂 `dispatchTouchEvent`**：跳过广告在业务上就是"点在跳过按钮上"，这个动作必然经过 Activity 的 `dispatchTouchEvent`。挂它并 `--dump-args`，对比"不点"与"手点跳过"两次启动的事件序列，就能确认跳过需要什么样的事件（本例手点后多两个事件，对应 DOWN + UP）。
- **为什么还要挂日志方法**：只看触摸事件不知道广告生命周期走到哪一步，也不知道何时该注入。挂广告模块的静态日志方法（本例 `Startup.log`）后，`>>> Splash Ad OnNotifyAdShow...` 之类字符串会把"广告已展示/已结束"的时间点打出来，注入时机就有了锚点；日志字符串同时是 jadx 里搜索调用链的入口。
- **`Java.choose` 而非 `Java.use` 的原因**：`dispatchTouchEvent` 是实例方法，需要真实的 Activity 对象。`Java.choose` 能在堆里枚举已存在的实例，拿到后直接 `instance.dispatchTouchEvent(event)`；因为实例与广告界面都不是启动瞬间就有，示例用两层 `setTimeout`（先等 1s 找实例，再等 1s 发事件）避开时序问题。
- **`MotionEvent.obtain` 的构造要点**：必须给全 `downTime`/`eventTime`/`action`/`pointerCount`/`PointerProperties[]`/`PointerCoords[]`/`metaState`/`buttonState`/`xPrecision`/`yPrecision`/`deviceId`/`edgeFlags`/`source`/`flags`；坐标取跳过按钮位置，`source` 用触摸屏（`0x1002`），`flags` 带 `0x2`（window-obscured 之类的真实事件标志）。伪造事件缺字段时业务侧常在 `onTouchEvent` 里判 null 或判 `pointerCount`，导致无效。
- **hook 返回值的思路**：真正决定"要不要请求开屏广告"的往往是一个开关函数（本例 `f42.a.b()`）；把它挂成恒 `true`，前面的 `if` 直接 `return`，广告请求（`requestSplashAd`）根本不会发出，比伪造点击更彻底、也更稳。
- **smali 修改是"免 frida"版本**：把 smali 里对那个方法的调用与判断删掉，等价于让布尔常量参与判断，重打包 + 签名后即可永久生效——不用每次启动都挂脚本，但会改动 APP 签名，可能触发完整性校验。

## 触发条件

- APP 的开屏广告由客户端自身的"是否请求"开关控制（不是纯服务端下发强制展示），且跳过按钮是原生 View 而非无法注入的独立进程/系统级广告 SDK。
- 设备可运行 frida-server / objection（已 root 或用可调试包），或能反编译重打包并自签名安装。
- 目标方法未被加固壳抽取（本例方法体在 dex 中可读，jadx 能看到 `dispatchTouchEvent` 与开关函数实现）。

## 利用步骤

1. 用 MT 管理器/`adb shell dumpsys activity` 观察启动时的 Activity 顺序，确认启动页与主 Activity 类名。
2. objection 挂主 Activity 方法并挂广告日志方法：`objection -g <pkg> explore -s "android hooking watch class_method <MainActivity>.dispatchTouchEvent --dump-args" -s "android hooking watch class_method <pkg>.startup.Startup.log --dump-args"`。
3. 对比"不点跳过"与"手点跳过"两次启动的事件序列，记录 ACTION_DOWN/ACTION_UP 的坐标、`source`、`flags` 等参数。
4. 路径一（伪造点击，原文标注为"理论上"可行、未给出实测成功记录）：写 frida 脚本，`Java.choose` 找到 Activity 实例，用 `MotionEvent.obtain` 依次构造 DOWN 与 UP 并调 `dispatchTouchEvent`；用 `setTimeout` 处理实例与界面出现的延迟。
5. 路径二（改开关）：在 jadx 里用日志字符串（如 `>>> Splash Ad`）定位广告模块，上溯到请求广告前的条件判断，找到恒假的布尔方法；frida 把它 `implementation` 成 `return true`。
6. 路径三（重打包）：`apktool d` 反编译，删除 smali 中该判断对应的比较与跳转（等价于只保留另两个条件），`apktool b` 回编译后重新签名安装。
7. 验证：冷启动多次观察是否仍有开屏广告，并确认跳过逻辑没有连带影响首页加载。

## PoC

```javascript
// 路径一：伪造 DOWN/UP 触摸事件，直接喂给已存在的 Activity 实例
Java.perform(function () {
    var MainActivity = Java.use('<pkg>.MainActivity');
    var MotionEvent = Java.use('android.view.MotionEvent');
    var PointerProperties = Java.use('android.view.MotionEvent$PointerProperties');
    var PointerCoords = Java.use('android.view.MotionEvent$PointerCoords');
    var SystemClock = Java.use('android.os.SystemClock');

    var props = [PointerProperties.$new()];
    props[0].id.value = 0;
    props[0].toolType.value = MotionEvent.TOOL_TYPE_FINGER.value;
    var coords = [PointerCoords.$new()];
    coords[0].x.value = 469.13;   // 跳过按钮坐标，取自 hook 到的真实事件
    coords[0].y.value = 48.95;

    setTimeout(function () {
        Java.choose('<pkg>.MainActivity', {
            onMatch: function (instance) {
                setTimeout(function () {
                    var down = SystemClock.uptimeMillis();
                    var me1 = MotionEvent.obtain.call(MotionEvent, down, down,
                        MotionEvent.ACTION_DOWN.value, 1, props, coords,
                        0, 0, 0, 0, 2, 0, 0x1002, 0x2);
                    instance.dispatchTouchEvent(me1);
                    var me2 = MotionEvent.obtain.call(MotionEvent, down, SystemClock.uptimeMillis(),
                        MotionEvent.ACTION_UP.value, 1, props, coords,
                        0, 0, 0, 0, 2, 0, 0x1002, 0x2);
                    instance.dispatchTouchEvent(me2);
                }, 1000);
            }
        });
    }, 1000);
});
```

```javascript
// 路径二：把"是否请求开屏广告"的开关方法硬改为 true
var Gate = Java.use('<pkg>.f42.a');
Gate.b.implementation = function () {
    return true;   // 原实现恒为 false，导致广告请求被放过
};
```

```text
# 路径三：重打包删判断
apktool d app.apk
# 在 smali 中删除对 f42.a.b() 的调用与 if 跳转，只保留另外两个条件
apktool b app
# 重新签名后安装
```

## 变体与关联

- 关联：[[mobile-android-frida-vipinfo-constructor-forge-membership]]（同为"注入既有对象/方法改业务判定"的 frida 手法，但落点是会员态而非广告开关）、[[mobile-android-apk-debuggable-repack-jadx-attach]]（重打包 + 可调试化的通用流程）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（若方法被抽取需先脱壳再静态定位）。objection 的类方法追踪本身也可复用于任意"某按钮点击后走了哪些方法"的定位。
- 变体：广告走独立 SDK 时把 hook 点换到 SDK 的展示回调或"是否展示"返回处；跳过按钮为 WebView/H5 时可改为注入 JS 点击；也可用 `android hooking set return_value` 直接改开关，不必写脚本。
- 边界：纯服务端强制展示、或跳过动作走系统级无障碍点击的其他进程时，伪造 `dispatchTouchEvent` 无效；APP 有签名/完整性校验时重打包版本会被拒；触摸坐标随分辨率变化，需按实际设备重新取。

## 检测与防御

- 检测（APP 侧）：`dispatchTouchEvent` 收到 `deviceId`/`eventTime` 与真实输入设备序列不符的事件；同一进程内 `MotionEvent.obtain` 被反射调用；检测 frida/objection 特征（端口、`frida-server`、`/proc/self/maps` 中的 gadget、线程名 gum-js-loop）。
- 防御（APP 侧）：关键开关放服务端判定，客户端开关只作降级；对广告展示/跳过做服务端校验与埋点比对；加壳与完整性校验（签名、dex 校验和）抵抗重打包；检测 hook 框架与内存注入。
- 说明：此手法用于自有 APP 的逆向学习与广告体验优化，对第三方 APP 使用需遵守其用户协议与当地法律。
