---
id: tools-frida-native-hook-export-unexport-retval-constructor
title: Frida Native 层 Hook：导出/未导出函数定位、NativeFunction 主动调用、retval 修改与构造函数 $init
type: scenario
domain: tools
path: tools/frida
technique: frida-native-hook-export-unexport-nativefunction-retval-constructor
tags:
- frida
- native
- android
- jni
- hook
- nativefunction
- retval
- constructor
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:08:41+08:00'
  notes: 已对照原文及24张图核对：JNI命名、findExportByName、base+offset、retval.replace(1337)、NativeFunction(1,2)、$init改参均与原文一致；原文get_flag实为导出函数(_Z8get_flagii)，卡片同时给出两种定位方式；PoC未本机执行；Frida 16.4.2仅为环境版本，无受影响版本
url: /docs/tools/frida/tools-frida-native-hook-export-unexport-retval-constructor/
draft: false
kb_aliases:
- Frida 0x8/0x9/0xA/0x7
- findExportByName
- 基址+偏移
- NativeFunction
- retval.replace
- strcmp hook
- $init 构造函数
---

## 一句话结论

Frida 可以 Hook 导出的 JNI/native 函数（`Module.findExportByName`）或未导出函数（`Module.findBaseAddress + IDA 偏移`），用 `Interceptor.attach` 打印参数、在 `onLeave` 用 `retval.replace(1337)` 修改返回值，用 `new NativeFunction(ptr, retType, argTypes)` 主动调用目标函数；Java 层构造函数用 `$init.overload(...)` 修改参数，而不是用类名。

## 原理

- **JNI 命名与实现**：Java 中 `public native int cmpstr(String str);` 只是签名，真实实现在 `.so` 中，通常命名为 `Java_包名_类名_方法名`（如 `Java_com_ad2001_frida0x8_MainActivity_cmpstr`），也可能是 `JNI_OnLoad` + `RegisterNatives` 动态注册。
- **导出 vs 未导出**：
  - 导出函数在 `.so` 符号表中可见，`Module.findExportByName("libxxx.so", "函数名")` 直接拿地址；C++ 导出名可能是 `_Z8get_flagii` 这类 mangled 名。
  - 未导出函数在符号表中不可见，需要 IDA 中的偏移 + `Module.findBaseAddress("libxxx.so").add(offset)`。
- **Interceptor.attach**：`onEnter(args)` 读参数（`Memory.readUtf8String(args[0])`），`onLeave(retval)` 读/改返回值；`retval.replace(1337)` 可把 `check_flag()` 的返回值改为 1337，绕过 Java 层 `== 1337` 判断。
- **NativeFunction 主动调用**：`new NativeFunction(ptr, 'void', ['int','int'])` 包装原生函数后可直接 `get_flag(1,2)` 调用；如果只想监控调用，用 `Interceptor.attach` 即可，不必创建 NativeFunction。
- **strcmp Hook**：`Module.findExportByName("libc.so","strcmp")` 拿到地址，`onEnter` 读 `args[0]`/`args[1]`；用输入包含特定前缀过滤日志，避免输出过多；可直接看到 native 层比较的期望字符串。
- **Java 构造函数**：Frida 用 `$init` 表示构造函数；`Checker.$init.overload('int','int').implementation = function(a,b){ a=513;b=513; this.$init(a,b); }` 修改参数后再调用原构造函数。写成 `$Checker` 是常见错误。
- **为什么可行**：Frida 在运行时修改函数入口/返回值，不依赖静态补丁；导出/未导出只是地址定位方式不同，Hook 与主动调用的 API 一致。

## 触发条件

- Android App 含 native/JNI 方法，且关键校验/逻辑在 `.so` 中。
- 测试设备已 Root 或可运行 Frida server，目标未启用强反调试/反 Frida。
- 能通过 JADX/IDA 找到 JNI 函数名、偏移或导出符号。
- 目标函数未被内联/优化到无法定位，或可通过符号/偏移找到。

## 利用步骤

1. JADX 中找 `native` 方法（如 `cmpstr`、`check_flag`、`stringFromJNI`、`getFlag`），确认 `System.loadLibrary` 的库名。
2. IDA 打开 `.so`，搜索 `Java_...` 符号或 `JNI_OnLoad`/`RegisterNatives`；记录函数偏移与是否导出。
3. 对导出函数用 `Module.findExportByName`；对未导出函数用 `base.add(offset)`。
4. 用 `Interceptor.attach` 打印参数/返回值；需要绕过校验时在 `onLeave` 用 `retval.replace(<目标值>)`。
5. 需要主动触发隐藏函数时，用 `new NativeFunction(ptr, retType, argTypes)` 调用（如 `get_flag(1,2)` 满足 `result+a2==3`）。
6. Java 层需要改构造参数时，Hook `$init.overload(...)`，修改参数后 `this.$init(...)`。
7. 用 logcat/Frida console 观察输出；若函数无日志，Hook 其内部 `__android_log_print` 或返回值。

## PoC

```javascript
// 1) Hook libc strcmp，打印期望字符串（s2）
var target = Module.findExportByName("libc.so", "strcmp");
Interceptor.attach(target, {
    onEnter: function (args) {
        var input = Memory.readUtf8String(args[0]);
        if (input.includes("aaa")) {
            console.log(Memory.readUtf8String(args[1]));
        }
    }
});
```

```javascript
// 2) 修改 JNI 返回值：check_flag() 返回 1337
var target = Module.findExportByName("liba0x9.so",
    "Java_com_ad2001_a0x9_MainActivity_check_1flag");
Interceptor.attach(target, {
    onEnter: function (args) { console.log("----"); },
    onLeave: function (retval) { console.log(retval); retval.replace(1337); }
});
```

```javascript
// 3) 主动调用未导出函数 / 导出函数
var base = Module.findBaseAddress("libfrida0xa.so");
var ptr1 = base.add(0x1DD60);                       // 未导出：基址+偏移
var ptr2 = Module.findExportByName("libfrida0xa.so", "_Z8get_flagii"); // 导出
var get_flag = new NativeFunction(ptr2, 'void', ['int', 'int']);
Interceptor.attach(ptr2, { onEnter: function (args) { console.log("called"); } });
get_flag(1, 2);
```

```javascript
// 4) Hook Java 构造函数 $init，修改参数
Java.perform(function () {
    var Checker = Java.use("com.ad2001.frida0x7.Checker");
    Checker.$init.overload('int', 'int').implementation = function (a, b) {
        console.log("orig:", a, b);
        a = 513; b = 513;
        this.$init(a, b);
    };
});
```

## 变体与关联

- 定位变体：导出符号、`base+offset`、`RegisterNatives` 枚举、`dlopen`/`dlsym` 跟踪；C++ mangled 名可用 `c++filt` 还原。
- Hook 变体：`Interceptor.attach` 修改参数（`args[0] = ptr(...)`）、`retval.replace`、`Interceptor.replace` 替换整个函数。
- 主动调用变体：`NativeFunction`、`NativeCallback`、`Module.getExportByName`；注意 ABI/参数类型。
- Java 层变体：`$init` 构造函数、`overload` 重载选择、`implementation` 替换、`this.$init` 调用原实现。
- 关联：[[tools-frida-arm64writer-nop-conditional-branch]]（动态改汇编）、[[code-analysis-reverse-obfuscation-ollvm-cff-frida-trace]]（Frida 追踪 native 逻辑）、[[tools-frida-source-patch-anti-detection]]（Frida 反检测）。

## 检测与防御

- 检测：Frida server 端口/进程/线程/maps 特征；`libart.so`/`libc.so` 函数被 inline hook；异常返回值（如校验函数恒定 1337）；Java 方法/构造函数被替换。
- 防御：反调试/反 Frida/完整性校验；strip 符号、隐藏导出；关键校验放 native 并做多路径校验；服务端校验结果。
- 加固：OLLVM/字符串加密、代码段只读（W^X）、SELinux、检测 Hook 框架并拒绝运行。
