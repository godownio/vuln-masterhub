---
id: tools-frida-art-registernatives-dynamic-so-offset-locate
title: Hook libart.so RegisterNatives 定位动态加载 so 名称与 native 函数偏移（绕过 ASLR 供 IDA 定位）
type: scenario
domain: tools
path: tools/frida
technique: frida-art-registernatives-so-offset-locate
tags:
- frida
- android
- jni
- register-natives
- libart
- dynamic-so
- offset
- aslr
- ida
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-7
  verified_at: '2026-11-08T01:10:40+08:00'
  notes: 已对照原文核对；原文图13 Hook RegisterNatives 输出 libpdd_secure.so 与 offset 0xc901、图14 IDA 导出表 device_info2 位于 0xC900 相互印证，打通证据充分；dedup为new、唯一related的Native Hook合集方向相反（已知偏移定位函数 vs 函数地址反查so名与偏移），dedup_review成立；卡内已明确边界（只到so名加偏移、不包装成算法还原或RCE）；PoC为最小化占位、未实际运行。
url: /docs/tools/frida/tools-frida-art-registernatives-dynamic-so-offset-locate/
draft: false
kb_aliases:
- RegisterNatives Hook
- 动态注册 JNI 枚举
- libart.so 符号
- JNINativeMethod
- findModuleByAddress
- 基址加偏移
- 动态加载 so 定位
- JNI_OnLoad
---

## 一句话结论

当 App 的 native 方法通过 `System.loadLibrary` 动态加载、在 `JNI_OnLoad` 里调用 `RegisterNatives` 动态注册，导致 Java 代码里看不到 so 文件名、IDA 里也难直接找到目标函数时，可用 Frida 在 `libart.so` 中定位并 Hook `RegisterNatives`，在回调里解析 `JNINativeMethod` 数组拿到 native 函数地址，用 `Process.findModuleByAddress` 反查所属 so 模块名、用「函数地址 − 模块基址」算出固定偏移，从而精确得到动态 so 名称与函数偏移供 IDA 静态定位。

## 原理

- ART 的 `RegisterNatives(JNIEnv*, jclass, const JNINativeMethod* methods, jint nMethods)` 是 Java native 方法与 so 内函数建立映射的必经点；动态注册发生在 so 加载之后，因此在这里拦截，即使 so 是运行时 dlopen 的也能捕获。
- `libart.so` 中可能有多个 `RegisterNatives` 符号（含调试用 `CheckJNI` 版本），需遍历 `Module.enumerateSymbolsSync("libart.so")`，挑同时含 `art`/`JNI`/`RegisterNatives` 且不含 `CheckJNI` 的那个地址。
- `args[2]` 指向 `JNINativeMethod` 数组，每项三个指针宽成员：方法名字符串、签名字符串、native 函数指针；用 `Memory.readPointer`/`readCString` 逐项读出；`args[1]` 的 jclass 可用 `Java.vm.tryGetEnv().getClassName` 过滤只关注目标类。
- `Process.findModuleByAddress(fnPtr)` 遍历进程已加载模块，判断地址落在哪个 `[base, base+size)` 区间并返回模块名；因 ASLR 每次加载基址不同，但函数在 so 内的偏移固定，故 `offset = fnPtr - module.base` 是稳定值，可直接用于在 IDA 中跳转到该函数。
- 文章据此拿到动态加载的 `libpdd_secure.so` 与 `info2` 偏移 `0xc901`，IDA 导出表中 `device_info2` 位于 `0xC900`，相互印证。

## 触发条件

- 目标 App 的 native 方法为动态注册（`JNI_OnLoad` + `RegisterNatives`）而非静态 `Java_包名_方法名` 导出，Java 侧看不到 so 名称。
- 可注入 Frida，并能枚举 `libart.so` 符号、Hook 其函数（需匹配设备 ART 版本与符号名）。
- 已知目标 Java 类名（用于过滤注册事件）。

## 利用步骤

1. 由 Java 层跟进到 `native` 方法声明（如 `DeviceNative.info2`），记下类名与参数签名。
2. 遍历 `libart.so` 符号定位 `RegisterNatives` 地址，`Interceptor.attach`。
3. `onEnter` 里用 `getClassName(args[1])` 过滤目标类；读 `args[3]` 方法数，遍历 `args[2]` 的 `JNINativeMethod` 数组，读出 name/sig/函数指针。
4. 对每个函数指针 `Process.findModuleByAddress` 得 so 名，`sub(base)` 得偏移并打印。
5. 用得到的 so 名从设备提取文件，IDA 打开并按偏移（或导出表地址）定位目标函数。

## PoC

```javascript
var syms = Module.enumerateSymbolsSync("libart.so");
var addr = null;
for (var i = 0; i < syms.length; i++) {
  var n = syms[i].name;
  if (n.indexOf("art") >= 0 && n.indexOf("JNI") >= 0 &&
      n.indexOf("RegisterNatives") >= 0 && n.indexOf("CheckJNI") < 0) {
    addr = syms[i].address; break;
  }
}
Interceptor.attach(addr, {
  onEnter: function (args) {
    var cls = Java.vm.tryGetEnv().getClassName(args[1]);
    if (cls !== "com.xunmeng.pinduoduo.secure.DeviceNative") return;
    var n = parseInt(args[3]), p = ptr(args[2]), ps = Process.pointerSize;
    for (var i = 0; i < n; i++) {
      var name = Memory.readCString(Memory.readPointer(p.add(i * ps * 3)));
      var fn = Memory.readPointer(p.add(i * ps * 3 + 2 * ps));
      var m = Process.findModuleByAddress(fn);
      console.log(name, "module_name:", m.name, "offset:", ptr(fn).sub(m.base));
    }
  }
});
```

（最小化示意，类名为占位，未执行任何 PoC。）

## 变体与关联

- 变体：静态注册的 native 可直接看 `Java_类名_方法名` 导出，无需本技巧；加密/加固 so 运行时解密 dlopen 的场景（库内另有对应卡）也可配合本技巧拿到解密后模块信息。
- 关联：与「Frida Native 层 Hook：基址+偏移、NativeFunction 主动调用」互补——本卡解决「偏移从哪来」；与「OLLVM 字符串解密 / 控制流平坦化分析」卡同属 native 逆向的前置定位步骤。
- 边界：本卡只到「拿到 so 名 + 函数偏移」，不含还原 native 算法；原文作者面对 OLLVM 控制流平坦化明确放弃细抠，故不把「算法还原」包装成打通，也不把本技巧说成漏洞利用。

## 检测与防御

- 检测：监控 `libart.so` 的 `RegisterNatives` 被 `Interceptor.attach`、`Module.enumerateSymbolsSync` 遍历、进程内异常模块枚举与批量打印方法名/偏移。
- 防御：反调试/Frida 检测、对 libart 关键函数做完整性校验、so 加壳与符号/导出名混淆、关键 native 逻辑用静态注册 + 控制流混淆提高定位与还原成本。
