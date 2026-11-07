---
id: mobile-android-frida-kotlin-coroutine-delay-bypass
title: Frida Hook Kotlin 协程 DelayKt.delay 绕过 96 小时时间锁
type: scenario
domain: mobile
path: mobile/android
technique: frida-kotlin-coroutine-delay-bypass
aliases:
- kotlinx.coroutines.DelayKt.delay
- 协程延时绕过
- 96 小时时间锁
- Frida hook delay
- 催眠 APP 越狱
- Kotlin Unit INSTANCE
tags:
- android
- frida
- kotlin
- coroutine
- delay
- time-lock
- ctf
- dynamic-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T22:44:56+08:00'
  notes: 已对照原文及图01/02核对：Frida hook kotlinx.coroutines.DelayKt.delay、345600000ms、返回kotlin.Unit.INSTANCE、flag NSSCTF{you_v_been_hypnotized!!} 均一致；未在目标App复跑。
---

## 一句话结论

当 Android App 用 Kotlin 协程 `delay(345600000L)`（96 小时）作为“时间锁”才显示 flag 时，可以用 Frida hook 静态扩展函数 `kotlinx.coroutines.DelayKt.delay(long, Continuation)`，对目标延时直接返回 `kotlin.Unit.INSTANCE`，协程会立即恢复执行并展示 flag；其他较短的动画/网络延时仍调用原函数。

## 原理

- Kotlin 协程的 `delay(timeMillis, continuation)` 是挂起函数：它注册定时器并挂起当前协程，时间到后通过 `Continuation` 恢复。调用点被编译为对 `kotlinx.coroutines.DelayKt.delay` 的静态方法调用。
- 如果 App 把敏感内容（flag/解锁状态）放在 `delay` 之后执行，那么时间锁只是客户端逻辑，不构成访问控制；绕过 `delay` 即可让协程“立即醒来”。
- Frida 的 `Java.use("kotlinx.coroutines.DelayKt")` 可以拿到该类的 Java 包装，替换 `delay.implementation`；当 `timeMillis` 等于目标值（如 345600000）时不调用原函数，直接返回 `kotlin.Unit.INSTANCE`，协程的挂起状态被当作已完成，继续执行后续代码（如设置 `showBannerState = true`）。
- 对其他延时（如 16ms 动画）透传原函数，避免破坏 App 的正常 UI 逻辑。
- 该手法依赖类/方法未被混淆、目标进程可附加 Frida；若 `DelayKt` 被混淆或内联，需要改 hook 具体调用点或 `Thread.sleep`/`Handler.postDelayed` 等替代点。

## 触发条件

- App 使用 Kotlin 协程，且以长 `delay` 实现时间锁/冷却/倒计时后才显示敏感内容。
- 目标进程可被 Frida 附加（root/可调试 APK/模拟器），`kotlinx.coroutines.DelayKt` 类存在。
- 时间锁值已知或可通过反编译/枚举确定（本例 345600000L = 96 小时）。
- 没有服务端校验或完整性保护；客户端逻辑即唯一门槛。

## 利用步骤

1. 反编译 APK（jadx/apktool）定位调用 `delay(...)` 的位置，确认目标延时值与后续 flag 展示逻辑。
2. 启动 App，使用 Frida attach 或 spawn 注入脚本。
3. Hook `kotlinx.coroutines.DelayKt.delay`，对 `timeMillis == 345600000` 返回 `kotlin.Unit.INSTANCE`，其余透传。
4. 触发页面重绘/重新进入页面，让协程重新执行；观察 `showBannerState` 被置为 true、flag 显示。
5. 如果 hook 不生效，检查类名是否被混淆（用 `Java.choose`/枚举 loaded classes）、`delay` 是否被内联、或改用 hook `Thread.sleep`/`SystemClock.sleep`/`Handler.postDelayed`。
6. 授权测试中只针对测试 APK，不绕过生产/他人应用的时间锁。

## PoC

```javascript
Java.perform(function () {
  var DelayKt = Java.use("kotlinx.coroutines.DelayKt");
  var TARGET = 345600000; // 96h

  DelayKt.delay.implementation = function (timeMillis, continuation) {
    console.log("[>] delay called: " + timeMillis + " ms");
    if (timeMillis.valueOf() === TARGET) {
      console.log("[!] 96h time lock detected, bypassing");
      return Java.use("kotlin.Unit").INSTANCE;
    }
    return this.delay(timeMillis, continuation);
  };
  console.log("[+] DelayKt.delay hooked");
});
```

运行：`frida -U -f <package> -l hook.js --no-pause`。原文使用该脚本后，App 的 96 小时限制被跳过，页面直接显示 `NSSCTF{you_v_been_hypnotized!!}`。本卡未在目标环境复跑；不同 Kotlin/协程版本类名可能变化。

## 变体与关联

- 延时 API 变体：`Thread.sleep`、`SystemClock.sleep`、`Handler.postDelayed`、`CountDownTimer`、`AlarmManager`；均可作为 hook 点。
- 逻辑变体：时间锁可能比较 `System.currentTimeMillis()` 或存储的首次启动时间；可 hook 时间函数或直接改存储值。
- 加固变体：类名混淆/内联/抽取后，需要定位真实调用点或使用 native hook；Frida 检测（端口、maps、线程名）可能阻断附加。
- 关联卡：Frida 还原本地 HTTP 二阶段校验（`mobile-android-frida-local-http-uri-check-recover`）；Frida 反调试线程绕过（`mobile-android-native-frida-antidebug-thread-bypass`）；Unity IL2CPP Frida Gadget（`mobile-android-unity-il2cpp-frida-gadget-infinite-revival`）。
- 边界：该卡是 CTF/客户端时间锁绕过，不是通用 App 破解；服务端控制的内容不受影响。

## 检测与防御

- 不要把敏感内容/权限判断放在客户端时间锁之后；时间锁只做 UX，服务端必须独立校验资格。
- 对关键逻辑做服务端签发（flag 由服务端在满足条件时下发），客户端只展示。
- 增加 Frida/RASP 检测（端口、注入痕迹、方法实现校验），但只能提高门槛，不能替代服务端控制。
- 代码混淆/内联降低 hook 可读性；对时间锁值做完整性校验、避免固定常量。
- 监控异常调试附加与 App 完整性校验失败事件。
