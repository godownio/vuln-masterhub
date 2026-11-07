---
id: code-analysis-dynamic-fuzzing-android-jni-env-emulation-harness
title: Android JNI 原生库内存安全模糊测试：调用序列捕获 + 自动 C harness + JNIEnv 模拟 + AFL++
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: android-jni-env-emulation-harness-fuzzing
tags:
- android
- fuzzing
- jni
- native
- afl
- harness
- memory-safety
- emulation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T12:58:48+08:00'
  notes: 已对照原文与7张图核对：图06 JNIEnv 模拟三步（FindClass 建无字段假类→GetFieldID 登记字段→Get/SetFieldValue 用 fuzzer 输入填对象字段）、233 个 JNIEnv 函数/40 个复杂对象操作、调用序列捕获→C harness→AFL++、Fresco 圆角图像 off-by-one 均与卡片一致；卡内 C 代码为按原文示意图整理的结构化示意，已注明原文未给完整 mock/harness。affected_versions 原为说明性文字、无版本，已 --clear。dedup 与 Unicorn 常量提取卡为 related（目的不同：算法常量恢复 vs 内存安全 fuzzing），判 new 成立。未验证点：未实现/复跑 mock 与 AFL++，Fresco off-by-one 为原文结论。
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-android-jni-env-emulation-harness/
draft: false
kb_aliases:
- JNIEnv 模拟
- JNI harness 生成
- JNI 内存安全 fuzzing
- Android native library fuzzing
- JNI 调用序列捕获
- Fresco off-by-one
---

## 一句话结论

对 Android 应用通过 JNI 调用的原生库，可以运行时捕获 Java→native 的 JNI 调用序列（函数、参数类型、返回值），自动生成保留数据依赖的 C fuzz harness，并用 JNIEnv 模拟器（实现 233 个 JNIEnv 函数，其中 40 个复杂对象操作如 `FindClass`/`GetFieldID`）替代真实 Android 运行时，让 AFL++ 直接 fuzz 原生库；原文用该机制在 Fresco 的圆角图像处理路径中发现 off-by-one 写入。

## 原理

- **为什么需要模拟器**：JNI 原生函数签名形如 `JNIEXPORT void JNICALL Java_pkg_Class_method(JNIEnv *env, jobject thiz, ...)`；`env` 是指向 JNI 函数表（`JNINativeInterface`）的指针，native 代码通过 `(*env)->FindClass(env, "...")`、`(*env)->GetFieldID(...)`、`(*env)->GetStringUTFChars(...)` 等调用与 Java 对象交互。脱离 Android 运行时直接加载 `.so` 时，这些函数指针不可用，必须提供一套可工作的 mock JNIEnv。
- **调用序列捕获**：在真实应用运行/测试时记录每次 JNI 调用的函数名、参数类型、返回值与对象关系（如 `FindClass` 返回的 classID 被后续 `GetFieldID` 使用）。这些记录决定 harness 需要按什么顺序、以什么类型调用原生函数，以及哪些返回值要透传。
- **harness 自动生成**：把捕获到的调用序列翻译成 C harness：按序构造 JNI 参数（字符串、数组、对象），把 fuzzer 数据映射到对象字段/缓冲区/长度参数，保持数据依赖（例如先用 fuzzer 字节填充 `GetFieldValue` 返回的字段，再调用目标函数）。
- **JNIEnv 模拟的关键三步**：
  1. `FindClass("com.pkg.Class")`：创建一个“无字段”的假 Java 类对象，返回可区分的 classID；
  2. `GetFieldID(classID, "fieldName")`：把字段名/签名登记到该类，返回可区分的 fieldID；
  3. `Get/SetFieldValue(fieldID, objectID)`：按 fieldID 读写对象内存槽，值来自 fuzzer 输入或前一步返回值。
  复杂对象操作（`FindClass`、`GetFieldID`、`GetObjectClass`、`GetMethodID`、`NewObject`、`Call*Method` 等）需要维护类/字段/方法/对象的映射表；简单类型与数组直接映射到内存缓冲区。
- **内存错误检测**：把生成的 harness 与目标 `.so` 链接/加载，用 AFL++（闭源二进制可用 QEMU/FRIDA 模式，或从可获取的源码编译插桩版本）以 harness 为入口做覆盖率引导 fuzzing；ASan/UBSan 或 AFL++ 自带崩溃检测捕获越界写、off-by-one、UAF 等。原文在 Fresco 的圆角图像处理路径中发现 off-by-one 写入。
- **为什么有效**：原生库的输入往往受 Java 层约束（字段类型、数组长度、对象状态），纯黑盒 fuzz `.so` 很难构造合法调用序列；从真实 Java 执行中抽取的序列天然满足前置条件，JNIEnv 模拟器补齐运行时依赖，fuzzer 再在合法调用骨架内变异数据，能深入原生解析/图像处理等逻辑。
- **边界**：模拟器只覆盖被调用到的 JNIEnv 子集；涉及真实系统服务、文件/网络、线程、JNI 全局引用/弱引用语义时，mock 行为可能与 ART 不一致；加固/反调试可能阻止运行时捕获；闭源 `.so` 的插桩覆盖率获取比源码编译困难。

## 触发条件

- 目标 APK 含通过 `System.loadLibrary`/`JNI_OnLoad`/`RegisterNatives` 加载的原生库，且 Java 层会以可控参数调用 native 方法。
- 能在测试设备/模拟器上运行应用并捕获 JNI 调用序列（Frida、eBPF、ART instrumentation 或自建 agent）。
- 原生库可在独立进程中加载（依赖库齐全、无强 Android 专有符号依赖），或可用模拟器补齐符号。
- 能实现/复用覆盖目标 JNIEnv 调用子集的 mock；目标 `.so` 可用 AFL++ 插桩（源码/QEMU/FRIDA 模式）。
- 授权测试；fuzz 产生的崩溃需能复现并映射回 Java 调用路径。

## 利用步骤

1. 枚举 APK 的 `lib/<abi>/*.so`，定位 `JNI_OnLoad`、`RegisterNatives` 与 `Java_*` 导出函数，确认 Java 侧调用点与参数类型。
2. 在真实设备上运行应用，hook/插桩 JNI 函数表或 ART，记录 Java→native 调用序列：函数、参数类型、返回值、对象字段与数组长度。
3. 从序列中提取最小可复现调用链，生成 C harness 骨架：构造 JNI 参数、按序调用、保存返回值与对象引用。
4. 实现 JNIEnv mock：按 `JNINativeInterface` 表填充所需函数；`FindClass`/`GetFieldID`/`GetMethodID`/`GetFieldValue`/`SetFieldValue`/`GetStringUTFChars`/`GetArrayLength` 等维护类-字段-对象映射；未实现的函数返回明确错误或 abort，避免静默误判。
5. 把 fuzzer 输入映射到对象字段、字符串缓冲区、数组长度、文件/图像数据；保留真实调用顺序与数据依赖。
6. 编译 harness（ASan/UBSan），用 AFL++ 运行：源码可用 `afl-clang-fast`，二进制可用 QEMU/FRIDA 模式；设置合理超时与内存上限。
7. 收集崩溃/挂起，最小化输入，确认是原生库内存错误而非 mock 缺陷；映射回 Java 调用路径，评估实际可达性与影响。
8. 用同类图像/解析/编解码输入继续扩展语料；修复后回归。

## PoC

JNIEnv 模拟三步（按原文示意图整理）：

```c
/* 1. FindClass：创建一个无字段的假类 */
jclass FindClass(JNIEnv *env, const char *name) {
    FakeClass *c = calloc(1, sizeof(FakeClass));
    c->name = strdup(name);
    return (jclass)c;
}

/* 2. GetFieldID：把字段名/签名登记到假类，返回稳定 fieldID */
jfieldID GetFieldID(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    FakeClass *c = (FakeClass *)clazz;
    FakeField *f = calloc(1, sizeof(FakeField));
    f->name = strdup(name);
    f->sig = strdup(sig);
    f->offset = c->field_count++;      /* 对象内存槽偏移 */
    return (jfieldID)f;
}

/* 3. Get/SetFieldValue：按 fieldID 读写对象内存，值由 fuzzer 提供 */
void SetIntField(JNIEnv *env, jobject obj, jfieldID fid, jint value) {
    FakeObject *o = (FakeObject *)obj;
    *(jint *)(o->data + ((FakeField *)fid)->offset) = value;
}
```

harness 入口（示意）：

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    JNIEnv env = make_mock_env();
    jobject thiz = new_fake_object("com/example/ImageProcessor");
    set_field_bytes(thiz, "bitmap", data, size);      /* fuzzer 数据 -> 对象字段 */
    set_field_int(thiz, "width", size % 4096);
    Java_com_example_ImageProcessor_process(&env, thiz); /* 调用捕获到的 native 方法 */
    return 0;
}
```

说明：原文未给出完整 mock 代码与 harness 生成器；以上是按原文“233 个 JNIEnv 函数、40 个复杂对象操作”描述整理的结构化复现。实际实现需按目标 `.so` 的导入表补齐函数，`JNINativeInterface` 的函数表布局必须与 ABI 一致，否则会直接崩溃。

## 变体与关联

- 变体：用 Frida 在真实进程中 hook JNI 调用并直接喂变异数据（在线 fuzz），省去 mock，但速度慢、易被检测。
- 变体：用 Unicorn/Qiling 模拟 ARM64 原生库与 JNIEnv，适合无法在 x86 主机直接加载的 `.so`；覆盖与崩溃检测需额外集成。
- 变体：只 mock 目标函数实际使用的 JNIEnv 子集，减少实现量；但遗漏的调用会导致误报/漏报，需在 harness 中对未实现函数显式失败。
- 变体：闭源 `.so` 用 AFL++ QEMU/FRIDA 模式；若有源码或可重编译，直接用 `afl-clang-fast` + ASan 获得更高覆盖精度。
- 关联：[[code-analysis-dynamic-fuzzing-malintent-jvmti-intent-greybox]]（JNI oracle 所属的 Intent 灰盒框架）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（Unicorn 模拟 JNI/native 代码）、[[mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer]]（JNI 原生算法逆向）。
- 边界：原生库依赖大量 Android 系统符号/服务、JNI 全局引用与线程语义、硬件 GPU/媒体栈时，mock 难以完整复现；未实现函数导致的崩溃不能当作漏洞；fuzz 结果需在真实设备复核。

## 检测与防御

- 开发侧：对 native 入口做长度/边界/类型校验，使用安全字符串与数组 API，开启 ASan/UBSan 与 libFuzzer/AFL 回归；JNI 层对 Java 传入的数组长度、字符串、对象字段做二次校验。
- 开发侧：避免把不可信输入直接传入图像/解析/编解码原生库；对已知 off-by-one/越界模式做代码审计。
- 测试侧：把 JNI harness 生成纳入 CI，对每个 native 库维护调用序列语料；对 mock 未实现函数做告警，避免把 mock 缺陷误判为漏洞。
- 检测：设备上出现 Frida/注入框架、异常 JNI 调用序列、非官方包加载原生库、频繁崩溃；服务端/客户端日志出现异常 native 崩溃栈。
- 加固：对 `.so` 做混淆/加固与完整性校验仅提高分析成本；不能替代原生代码的内存安全修复。
