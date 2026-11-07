---
id: code-analysis-reverse-obfuscation-ollvm-string-decrypt-frida
title: Frida 辅助 OLLVM 字符串解密：.datadiv_decode/.init_array + RegisterNatives 枚举
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ollvm-string-decrypt-frida-datadiv-init-array-registernatives
aliases:
- OLLVM 字符串加密
- .datadiv_decode
- .init_array
- RegisterNatives
- JNI_OnLoad
- Frida hexdump
- 动态注册 JNI
tags:
- reverse
- obfuscation
- ollvm
- string-encryption
- frida
- android
- jni
- datadiv
- init-array
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:14:16+08:00'
  notes: 已对照原文与40张截图核对：ycmd; 密文、.datadiv_decode 的 .init_array 交叉引用、Frida hexdump 解密字符串、RegisterNatives 枚举 sign1/(Ljava/lang/String;)Ljava/lang/String;/libhello-jni.so!0xe76c 均一致。未验证点：未在设备上复跑 Frida 脚本。
---

## 一句话结论

OLLVM 字符串加密会把明文常量加密后放在 `.data`，由 `.datadiv_decode` 在 `.init_array` 中于进程启动时解密；用 Frida 在初始化后按 `模块基址 + 偏移` dump 目标地址，或 hook `libart.so` 的 `RegisterNatives` 枚举动态注册的 JNI 方法（名称/签名/函数指针），即可拿到解密后的字符串与真实函数地址。

## 原理

- **OLLVM 字符串加密**：编译期 Pass 把字符串常量替换为密文，并在二进制中生成 `.datadiv_decode`（或类似名称）的解密函数；IDA 中直接看 `.data` 只能看到乱码（如 `ycmd;`），交叉引用会指向 `.datadiv_decode`。
- **`.init_array` 自动执行**：`.datadiv_decode` 的地址被放进 `.init_array` 指针数组，动态链接器在加载 `.so` 时会遍历执行 `.init_array` 中的函数，因此字符串在 `JNI_OnLoad`/Java 调用之前就已被解密到内存。
- **动态注册 JNI**：`JNI_OnLoad` 中调用 `RegisterNatives(env, clazz, methods, count)`，`JNINativeMethod` 数组每项为 `{name, signature, fnPtr}`；导出表里可能没有 `Java_...` 符号，但 `.data.rel.ro` 中能看到数组与函数指针。
- **Frida dump**：在目标进程启动后，用 `Module.findBaseAddress("libhello-jni.so")` 得到基址，加 IDA 中的偏移，`hexdump` 读取解密后的字符串；也可以在 `.datadiv_decode` 返回后 dump 整个字符串区。
- **Hook RegisterNatives**：`libart.so` 中符号名含 `RegisterNatives`（过滤 `CheckJNI`）；`Interceptor.attach` 的 `args[1]` 是 Java class，`args[2]` 是 `JNINativeMethod*`，`args[3]` 是数量；按 `pointerSize*3` 步长读取 name/signature/fnPtr，并用 `Process.findModuleByAddress(fnPtr)` 把函数指针换算成 `模块!偏移`。
- **为什么可行**：加密只保护静态文件，运行时必然在内存中出现明文；`.init_array` 的解密时机早于业务调用，Frida 只要在解密后读取即可。

## 触发条件

- Android native 库使用 OLLVM/字符串加密 Pass，存在 `.datadiv_decode` 与 `.init_array` 引用。
- JNI 方法通过 `JNI_OnLoad` + `RegisterNatives` 动态注册（导出表无 `Java_` 符号）。
- 测试设备已 Root，可运行 Frida server（或使用可注入的调试环境）。
- 目标未启用强反调试/反 Frida/完整性校验，或可绕过。

## 利用步骤

1. 在 IDA 中搜索字符串/`.data`，找到可疑密文（如 `ycmd;`）；交叉引用定位 `.datadiv_decode`。
2. 查看 `.datadiv_decode` 的交叉引用，确认它被 `.init_array` 引用；记录目标字符串在 `.data`/`.bss` 的偏移。
3. 启动 App，用 Frida `Module.findBaseAddress` + 偏移 `hexdump` 读取解密后的内存；必要时在 `.datadiv_decode` 返回处 dump 更大范围。
4. 在 `libart.so` 中枚举符号，找到 `RegisterNatives` 地址；hook 并打印 `JNINativeMethod` 数组的 name/signature/fnPtr。
5. 用 `Process.findModuleByAddress(fnPtr)` 把 fnPtr 转成 `libhello-jni.so!0x...`，与 IDA 中的 `sub_E76C` 对应，确认 `sign1` 的真实实现地址。
6. 继续用 Frida 在真实函数入口/返回处 dump 参数与结果，进入后续算法分析。

## PoC

```javascript
// 1) 初始化后 dump 解密字符串（地址按 IDA 偏移）
function print_hex_dump(addr) {
    var base = Module.findBaseAddress("libhello-jni.so");
    console.log(hexdump(base.add(addr)));
}
function main() { print_hex_dump(0x037070); }
setImmediate(main);
```

```javascript
// 2) Hook libart.so 的 RegisterNatives，枚举动态注册方法
function hook_libart() {
    var libart = Process.findModuleByName("libart.so");
    var addr = null;
    libart.enumerateSymbols().forEach(function (s) {
        if (s.name.indexOf("CheckJNI") === -1 && s.name.indexOf("JNI") > 0
            && s.name.indexOf("RegisterNatives") > 0) {
            addr = s.address;
        }
    });
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var cls = Java.vm.tryGetEnv().getClassName(args[1]);
            var methods = args[2], count = parseInt(args[3]);
            console.log("class:", cls, "count:", count);
            for (var i = 0; i < count; i++) {
                var p = methods.add(i * Process.pointerSize * 3);
                console.log(p.readPointer().readCString());                       // name
                console.log(p.add(Process.pointerSize).readPointer().readCString()); // signature
                var fn = p.add(Process.pointerSize * 2).readPointer();
                var m = Process.findModuleByAddress(fn);
                console.log(m.name + "!" + fn.sub(m.base));
            }
        }
    });
}
setImmediate(hook_libart);
```

```text
# 典型输出
# class: com.example.hellojni.HelloJni count: 1
# sign1
# (Ljava/lang/String;)Ljava/lang/String;
# libhello-jni.so!0xe76c
```

## 变体与关联

- 静态解密变体：用 Unicorn 模拟 `.datadiv_decode` 或直接复现其异或/加减算法，在本地还原字符串，不依赖设备。
- Hook 点变体：`JNI_OnLoad`、`RegisterNatives`、`__system_property_get`、`pthread_create`；也可 hook `dlopen`/`dlsym` 跟踪动态加载。
- 字符串使用点变体：在业务函数入口/`NewStringUTF`/`strcmp` 处 dump 参数，直接拿明文。
- 关联：[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]（OLLVM 编译期原理）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（Unicorn 提取 native 常量）、[[mobile-android-apk-xor-string-batch-deobfuscation]]（字符串批量去混淆）。

## 检测与防御

- 检测：`.datadiv_decode`/`.init_array` 的异常解密函数；`RegisterNatives` 注册的方法名/签名与导出表不一致；Frida/Xposed 特征；进程内存中出现明文敏感字符串。
- 防御：字符串加密使用运行时派生密钥并延迟解密；strip 符号、隐藏 `.init_array` 痕迹；反调试/反 Frida/完整性校验；敏感字符串不落内存明文或使用后立即擦除。
- 加固：关键逻辑 native 化 + 多层混淆；服务端校验；对注入框架做检测与阻断。
