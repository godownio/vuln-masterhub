---
id: tools-frida-java-hook-static-instance-field-choose
title: Frida Java 层六类校验驱动：改参 Hook、静态/实例方法主动调用、静态/实例字段改写与 Java.choose 枚举
type: scenario
domain: tools
path: tools/frida
technique: frida-java-implementation-call-field-choose
aliases:
- Frida 0x1-0x6
- Java.use
- implementation 改参
- $new 实例化
- Java.choose
- 静态字段修改
- 主动调用静态方法
- 主动调用实例方法
tags:
- frida
- java
- android
- hook
- reverse
- implementation
- java-choose
- static-field
- instance
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:07:05+08:00'
  notes: 已对照原文与38张图核对：frida-server/client 16.4.2、0x1 check需i*2+4==i2改参、0x2 get_flag(4919)静态调用、0x3 Checker.code=512静态字段、0x4 Check.().get_flag(1337)、0x5 Java.choose MainActivity.flag(1337)、0x6 Checker(num1=1234,num2=4321)对象参数，六个flag截图与卡内入口矩阵一致。未验证点：未在本机复跑；frontmatter无sources/source_url；原文环境版本非受影响版本，卡未设affected_versions。
---

## 一句话结论

本地校验类 crackme 不必先逆算法：先判断目标是静态方法还是实例方法、实例是否已存在、校验读的是静态字段还是实例字段、参数是基本类型还是对象，再分别用 `Java.use` 直接调用、`$new()` 构造实例、`Java.choose` 枚举存活实例、`field.value` 改写字段或 `method.implementation` 改写参数/返回值，就能直接驱动原程序的成功分支（flag 生成/解密逻辑）拿到结果。

## 原理

- Frida 的 Java 桥接在运行时通过 ART 访问类：`Java.use("pkg.Class")` 返回类包装；`Class.staticMethod(...)` 调用静态方法；`Class.$new()` 调构造器创建实例；`instance.method(...)` 调用实例方法；`Java.choose("pkg.Class", {onMatch, onComplete})` 枚举进程中该类所有存活实例。
- `method.implementation = function(...) {...}` 用自定义函数替换方法实现，可在其中修改入参、修改返回值，或调用 `this.method(...)` 继续走原逻辑；同名重载需 `.overload('int','int')` 精确指定。
- 静态字段用 `Class.field.value` 读写，实例字段用 `instance.field.value` 读写；字段为 `final` 时可在构造后经实例包装改写（视 ART 实现）。
- 关键点在于很多校验的“成功分支”本身就会生成并显示明文 flag：只要让分支条件成立，就无需复现后续 AES/Blowfish/XOR 算法。
- 入口选择矩阵：
  - 静态方法 → `Java.use(Class).method(args)` 主动调用；
  - 实例方法且实例不存在 → `Java.use(Class).$new()` 后调用；
  - 实例方法且实例已存在（如 Activity）→ `Java.choose` 拿 `onMatch` 的实例调用；
  - 校验读静态字段 → `Class.field.value = 期望值`；
  - 校验读实例字段 → 构造/枚举实例后 `instance.field.value = 期望值`；
  - 只想保留原逻辑改输入 → hook `.implementation`，改参后 `this.method(...)`。

## 触发条件

- 设备已 root 且 frida-server 与客户端版本一致，或 APK 可调试/可注入 gadget。
- 校验与 flag 生成逻辑在 Java 层，类名/方法名/字段名可由 jadx 静态分析得到（未混淆或已定位）。
- 校验条件依赖可写的字段、可控入参或可主动调用的方法；核心逻辑在 native 时需改用 native hook。

## 利用步骤

1. jadx 打开 APK，定位校验入口（按钮 `onClick`、`MainActivity`）与被调用的校验类/方法，记录方法签名与字段类型。
2. 判断方法是 `static` 还是实例方法、实例是否由系统创建（Activity/Service 通常已有实例）、校验读的是字段还是比较返回值。
3. 按入口选择 Frida 写法：
   - **改参 Hook**：`Class.method.implementation = function (a, b) { return this.method(合法参数); }`，或直接 `return true`；
   - **静态方法主动调用**：`Java.use(Class).method(参数)`；
   - **实例字段/方法且无实例**：`var o = Java.use(Class).$new(); o.field.value = 期望值; o.method(参数);`；
   - **实例已存在**：`Java.choose(Class, { onMatch: function (o) { o.method(参数); } })`；
   - **对象参数**：先 `$new()` 构造参数对象并设置其字段，再调用目标方法。
4. 执行脚本后观察 logcat/Toast/TextView；若方法返回 void，可 hook 目标方法或 UI setText 旁路打印结果。

## PoC

```javascript
// 0x1 改参 Hook：check(i, j) 要求 i*2+4 == j
var M = Java.use("com.ad2001.frida0x1.MainActivity");
M.check.implementation = function (i, j) {
  return this.check(2, 8);   // 2*2+4=8，走成功分支
};
// 也可以不调用原方法，直接 return true
```

```javascript
// 0x2 主动调用静态方法；0x3 改写静态字段
Java.use("com.ad2001.frida0x2.MainActivity").get_flag(4919);
Java.use("com.ad2001.frida0x3.Checker").code.value = 512;
```

```javascript
// 0x4 实例不存在：$new 后调用实例方法
var C = Java.use("com.ad2001.frida0x4.Check");
console.log(C.$new().get_flag(1337));

// 0x5 实例已存在：Java.choose 枚举 Activity 实例并调用 void 方法
Java.choose("com.ad2001.frida0x5.MainActivity", {
  onMatch: function (activity) { activity.flag(1337); },
  onComplete: function () { console.log("done"); }
});
```

```javascript
// 0x6 参数是对象：构造 Checker，改实例字段，再把对象传给 MainActivity.get_flag(Checker)
var Checker = Java.use("com.ad2001.frida0x6.Checker");
var c = Checker.$new();
c.num1.value = 1234;
c.num2.value = 4321;
Java.choose("com.ad2001.frida0x6.MainActivity", {
  onMatch: function (activity) {
    activity.get_flag(c);          // 方法返回 void，结果由程序 setText 显示
  }
});
```

说明：以上为原文六个练习的最小化调用方式，原文均在 Nexus 6P（LineageOS 17.1 + Magisk + frida 16.4.2）上实际跑通并显示 flag；未在本机复跑。

## 变体与关联

- **返回布尔/字符串的校验方法**：直接 `implementation = function () { return true; }` 或返回期望字符串，比改参更稳。
- **字段为 final 或类被混淆**：用 `Java.choose` 枚举实例、`Java.enumerateLoadedClasses` 找类名，必要时用 `$init` hook 构造器。
- **native 层同类入口**：JNI 函数的导出/未导出定位、NativeFunction 主动调用、retval 修改见 [[tools-frida-native-hook-export-unexport-retval-constructor]]（同系列 0x7-0xA）。
- **校验在 native + Java 混合**：Java 侧只做包装时先 hook Java 入参/返回值定位 native 函数，再转 native hook；见 [[mobile-android-jni-native-unicorn-emulation-constant-extraction]]。
- **环境前提**：frida-server 与客户端版本必须一致；Android 9+ 的 frida 兼容性问题可能要求升级 ROM，文中用 Nexus 6P 刷 LineageOS 17.1 + Magisk 解决。

## 检测与防御

- **分析侧**：校验条件与成功分支在同一方法内、flag 解密在 Java 层、字段/方法可反射访问，都是可直接驱动的信号。
- **防守侧**：把校验结果放服务端；关键逻辑下沉 native 并做混淆/完整性校验；检测 frida-server/端口/注入线程；不要在客户端成功分支里直接解密并显示敏感结果。
- **局限**：强壳/native 反调试/RASP 会让 Java 层注入失败或进程退出，此时需要先做反检测或改 native hook。
