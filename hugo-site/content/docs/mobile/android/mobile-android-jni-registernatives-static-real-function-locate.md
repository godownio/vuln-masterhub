---
id: mobile-android-jni-registernatives-static-real-function-locate
title: JNI RegisterNatives 静态定位真实 native 函数：JNI_OnLoad → JNINativeMethod{name,signature,fnPtr}
type: scenario
domain: mobile
path: mobile/android
technique: jni-registernatives-static-real-function-locate
tags:
- android
- jni
- register-natives
- jni-onload
- ida
- reverse
- obfuscation
- native
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T12:08:35+08:00'
  notes: 已对照原文核对：img/01 JEB Libraries 含 x86/libnative-lib.so；img/02 Java_com_example_ndktest2_MainActivity_Encrypt 伪代码为 strcpy flag{/wllm/welcome/newbee + base64_encode + strcat（诱饵）；img/03 下断点 0x9F20 不命中；img/04 NewStringUTF 断点 A53C9093；img/05 调用栈 NewStringUTF+0x3→test+0x2F7；img/07 RegisterNatives thunk；img/08 off_38008 表项为 Encrypt/()Ljava/lang/String;/test。修正：原文正文误称 name 为 getNativeString，已按 IDA 表项改为 Encrypt 并加注。dedup 与 tools-frida-art-registernatives-dynamic-so-offset-locate 为 related（cos 0.8938，Frida 动态枚举 vs IDA 静态解析），其余为 JNI hook/Unicorn 等 related，非同一方法；dup-scan 与 16398（jni strcmp 目标逆向）为 related、与 16528（JNI_OnLoad 导出执行载荷）为 related，均非同一链，保留双方。路径 mobile/android 合法。CTF 教程无产品版本，affected_versions 为空。未验证点：未复现 APK/IDA。无 sources/source_url。
url: /docs/mobile/android/mobile-android-jni-registernatives-static-real-function-locate/
draft: false
kb_aliases:
- RegisterNatives 找真实函数
- JNINativeMethod 表解析
- JNI_OnLoad 静态分析
- native 方法动态注册
- 假 Encrypt 函数
- JNI 注册表 fnPtr
---

## 一句话结论

Java 层声明 `native String Encrypt()` 时，符号 `Java_com_example_ndktest2_MainActivity_Encrypt` 不一定是真实实现：如果 so 在 `JNI_OnLoad` 里调用 `RegisterNatives`，真实函数由 `JNINativeMethod` 表项 `{name="Encrypt", signature="()Ljava/lang/String;", fnPtr=test}` 的 `fnPtr` 指定。原文中静态符号指向一个只做 base64 拼接的假 Encrypt，而注册表把 `Encrypt` 绑定到 `test`；在 `JNIEnv::NewStringUTF` 下断点看调用栈（`test+0x2F7`）即可确认真实加密函数在 `test`。

## 原理

- **JNI 的两种注册方式**：静态注册按 `Java_<包名>_<类名>_<方法名>` 命名导出，IDA 能直接搜到；动态注册在 `JNI_OnLoad`（`System.loadLibrary` 时由 ART 调用）里用 `RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)` 把 Java 方法名、签名、函数指针绑定起来，so 中不一定存在同名导出符号。
- **JNINativeMethod 结构**：数组中每项三个指针宽字段——`char* name`（Java 方法名）、`char* signature`（如 `()Ljava/lang/String;`，`()` 表示无参数、`Ljava/lang/String;` 表示返回 String）、`void* fnPtr`（真正执行的 native 函数地址）。
- **静态定位链路**：IDA 打开 so → 找 `JNI_OnLoad` → 跟进 `GetEnv` 后的初始化函数 → 找到 `RegisterNatives` 调用 → 参数指向 `.data` 里的 `JNINativeMethod` 数组（原文 `off_38008`）→ 依次读出 name/signature/fnPtr。原文表中 name 为 `"Encrypt"`、signature 为 `"()Ljava/lang/String;"`、fnPtr 为 `test`，所以 Java 的 `Encrypt()` 实际执行 `test`（原文正文一处误称 name 为 `getNativeString`，以 IDA 表项/截图为准）。
- **为什么静态 `Java_..._Encrypt` 是假的**：该函数只是把 `"flag{"`、`"wllm"`、`"newbee"`、`"welcome"` 等字符串做 base64 后拼接，返回结果永远不可能等于用户输入，属于诱饵；直接逆向它会走偏。
- **调用栈确认**：`NewStringUTF` 是 JNI 把 C 字符串转 Java String 的函数，真实加密函数最终也会调用它。在 `JNIEnv::NewStringUTF` 入口下断点，触发登录后看栈回溯，若上一帧是 `test+0x2F7` 而非假 `Java_..._Encrypt`，即可确认 `test` 才是实际执行路径；`JNI_OnLoad` 注册表与调用栈两条证据互相印证。
- **边界**：该方法适用于“动态注册 + 静态符号诱饵”的混淆；若 so 被加固/加密、`JNI_OnLoad` 被混淆或函数指针运行时才填充，需要配合 Frida Hook `RegisterNatives` 动态枚举（见关联卡）。

## 触发条件

- 目标 APK 未加壳或已脱壳，能拿到 `libnative-lib.so`（或对应 x86/arm so）。
- Java 层 native 方法由 `JNI_OnLoad` + `RegisterNatives` 动态注册，静态符号函数行为异常（返回值不符合预期、断点不命中）。
- 有 IDA/JEB 等静态分析工具，能解析 `.data` 中的 `JNINativeMethod` 数组；有可运行环境可下断点验证。

## 利用步骤

1. JEB/jadx 反编译 APK，定位 `System.loadLibrary("native-lib")` 与 `public native String Encrypt()`。
2. 从 APK 的 `lib/<abi>/` 导出 `libnative-lib.so`，IDA 打开；先在函数窗口搜 `Java_..._Encrypt`，阅读其逻辑（判断是否为诱饵）。
3. 找 `JNI_OnLoad`，跟进其调用的初始化函数，定位 `RegisterNatives` 调用与 `JNINativeMethod` 数组地址（原文 `.data:00038008 off_38008`）。
4. 按三指针结构解析数组：name、signature、fnPtr；得到真实函数 `test`。
5. 可选验证：在 `JNIEnv::NewStringUTF` 入口下断点，触发 Java 调用后看栈回溯，确认上一帧为 `test+偏移`。
6. 进入 `test` 逆向/动态调试（见关联卡 IDA 调试 Android .so），或直接 Hook 其返回值。

## PoC

`JNINativeMethod` 表（IDA 视图，原文）：

```text
.data:00038008 off_38008   dd offset aEncrypt          ; "Encrypt"
.data:0003800C             dd offset aLjavaLangStrin   ; "()Ljava/lang/String;"
.data:00038010             dd offset test
```

`JNI_OnLoad` 链路（原文伪代码）：

```c
int __cdecl JNI_OnLoad(JavaVM *a1) {
  void *v3;
  if (_JavaVM::GetEnv(a1, &v3, 65542)) return -1;
  if (sub_A570(v3)) return 65542;
  return -1;
}
// sub_A570 -> sub_A5F0(env, "com/example/ndktest2/MainActivity", off_38008, 1)
// sub_A5F0: FindClass + RegisterNatives
```

## 变体与关联

- 动态枚举：用 Frida Hook `libart.so` 的 `RegisterNatives`，在回调中读 `JNINativeMethod` 数组并 `Process.findModuleByAddress(fnPtr)` 反查 so 与偏移，见 `tools-frida-art-registernatives-dynamic-so-offset-locate`。
- 静态注册的常规路径：直接搜 `Java_<包>_<类>_<方法>` 导出；本卡针对“动态注册 + 静态诱饵”的绕过。
- 找到真实函数后，可静态逆向算法，或用 IDA 动调（android_x86_server + JEB attach），或用 objection/Frida hook 直接取返回值。

## 检测与防御

- 逆向侧：遇到 `System.loadLibrary` 后的 native 方法，优先检查 `JNI_OnLoad`/`RegisterNatives`，不要只信 `Java_...` 符号；用调用栈/断点验证真实执行路径。
- 防护侧（App 开发者）：动态注册、符号剥离与字符串加密可提高分析成本，但不能替代真正的密钥保护；敏感逻辑应放在服务端或使用硬件安全能力。
- 检测：APK 中存在 `RegisterNatives` 动态注册且静态符号行为异常，可作为混淆/加固特征；结合 so 的字符串加密、反调试判断分析难度。
