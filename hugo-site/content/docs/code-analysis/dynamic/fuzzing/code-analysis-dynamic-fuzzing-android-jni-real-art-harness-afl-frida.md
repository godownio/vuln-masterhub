---
id: code-analysis-dynamic-fuzzing-android-jni-real-art-harness-afl-frida
title: Android JNI 函数真机灰盒 fuzz：native harness 经 libandroid_runtime 初始化真实 ART JVM，jbyteArray 包装输入
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: android-jni-real-art-jnienv-harness
tags:
- android
- fuzzing
- jni
- art
- jnienv
- afl
- frida
- harness
- aarch64
- native
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502-fix
  verified_at: '2026-11-11T03:40:35+08:00'
  notes: V502 修正：性能数字改为标准原生 harness 约 10.8k exec/s（stability 100.00%）、JNI harness 约 8849 exec/s（stability 87.71%），恢复原文图03/04 对应关系。
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-android-jni-real-art-harness-afl-frida/
draft: false
kb_aliases:
- JNI_CreateJavaVM Android
- libandroid_runtime.so 初始化 JVM
- JniInvocationCreate JniInvocationInit
- registerFrameworkNatives
- JNI 函数 fuzz
- NewByteArray SetByteArrayRegion
- 强链接 JNI 函数
---

## 一句话结论

要在真机上 fuzz 一个 JNI 函数，harness 不能只拿到 `.so`，还必须提供可用的 `JNIEnv`：在 native 进程里 `dlopen("libandroid_runtime.so")`，依次调用 `JniInvocationCreate`/`JniInvocationInit` 初始化运行时调用层，再用 `JNI_CreateJavaVM` 创建真实 JavaVM/JNIEnv（并调用 `registerFrameworkNatives` 注册框架 native 部分），之后用 `NewByteArray` + `SetByteArrayRegion` 把 fuzzer 数据包装成 `jbyteArray` 调用目标 `Java_*` 函数，最后 `DeleteLocalRef`；配合 AFL++ Frida 模式与持久化钩子即可对 JNI 入口做覆盖率引导 fuzz。

## 原理

- **JNI 函数需要真实 JNIEnv**：`Java_pkg_Class_method(JNIEnv*, jobject, ...)` 中 `env` 是函数表指针，native 代码通过它调用 `GetArrayLength`、`GetByteArrayElements` 等。直接加载 `.so` 时没有 ART，`env` 为空无法执行；与"假 JNIEnv 模拟"不同，本方法在设备上创建**真实** JavaVM，因此能覆盖使用应用专有 Java 对象的强链接 JNI 函数。
- **Android 上的 JNI 调用 API**：`JNI_CreateJavaVM` 由 `libandroid_runtime.so` 提供。创建前要先初始化调用层：`JniInvocationCreate()` 返回 `JniInvocationImpl*`，`JniInvocationInit(invoc, "libandroid_runtime.so")` 告诉运行时从哪里加载调用实现；随后 `JNI_CreateJavaVM(&vm, &env, &args)` 创建 VM。`JavaVMInitArgs` 的 `JavaVMOption` 数组可传 `-Djava.class.path=...` 等选项；`registerFrameworkNatives(env)` 把框架 native 方法注册进 VM，避免目标函数用到框架功能时抛 `UnsatisfiedLinkError`。
- **上下文结构**：用一个 `JavaCTX { JavaVM *vm; JNIEnv *env; JniInvocationImpl *invoc; }` 保存句柄，便于后续清理；harness 全局持有一个 ctx。
- **输入包装**：`fuzz_one_input(const uint8_t *buffer, size_t length)` 里 `NewByteArray(env,length)` 创建 Java 字节数组，`SetByteArrayRegion(env,jBuffer,0,length,(const jbyte*)buffer)` 填充 fuzzer 数据，然后调用目标 JNI 函数 `Java_qb_blogfuzz_NativeHelper_fuzzMeArray(env,NULL,jBuffer)`，最后 `DeleteLocalRef` 释放局部引用。
- **性能与配置**：真实 ART 初始化很重，必须用 Frida 模式的持久化循环（进程只启动一次），并用模块白名单排除 `libandroid_runtime.so` 等大模块的插桩；原文对比同一环境下标准原生 harness 约 10.8k exec/s（stability 100.00%），而 JNI harness（含 Java 环境）约 8849 exec/s（stability 87.71%），说明越贴近 Java 层越慢、且稳定性下降（原文结论：目标与 Java 元素链接越多，性能越差）。
- **为什么值得**：JNI 函数是 Java 可调用面的真实入口，fuzz 它可以直接发现"Java 层可控参数 → native 内存错误"的问题，崩溃还能从 Java 侧复现；相比纯 native 函数，省去逆向了解调用约束的成本。弱链接 JNI（只用基本类型/数组）与强链接 JNI（操作应用专有对象）都可覆盖，后者正是模拟 JNIEnv 难以完整复现的场景。

## 触发条件

- Root 的 Android 设备/模拟器（aarch64，与目标 `.so` ABI 一致），可执行自建 native harness。
- 目标 APK 的 native 库导出 `Java_*` 或通过 `RegisterNatives` 注册 JNI 方法，且可从 native 侧调用。
- 已按目标平台构建 AFL++ Frida 模式（`afl-fuzz` + `afl-frida-trace.so`），并具备 afl.js 持久化配置能力。
- 目标函数所需的 Java 类/框架 native 可由 `registerFrameworkNatives` 或最小 classpath 满足。

## 利用步骤

1. 从 APK 提取 `lib/<abi>/*.so`，`objdump -T` 查看 `Java_*` 导出与 `JNI_OnLoad`，记录目标函数签名（如 `(JNIEnv*, jobject, jbyteArray)`）。
2. 实现 `init_java_env`：`dlopen("libandroid_runtime.so")`，dlsym `JniInvocationCreate`、`JniInvocationInit`、`JNI_CreateJavaVM`、`registerFrameworkNatives`，按序初始化并创建 VM，保存 `JavaCTX`；按需传入 classpath 等 `JavaVMOption`。
3. 编写 `fuzz_one_input`：用 `NewByteArray`/`SetByteArrayRegion` 把 fuzzer 输入转成 `jbyteArray`，调用目标 `Java_*` 函数，`DeleteLocalRef` 清理。
4. 编译 harness 并推送目标 `.so`；在 `afl.js` 中把 `fuzz_one_input` 设为入口/持久化地址，用 `CModule` 钩子写 `x0/x1`，白名单只保留 `fuzz` 与目标库、排除 `libandroid_runtime.so`，设置 `Afl.setPersistentCount`。
5. 运行 `./afl-fuzz -O -G 256 -i in -o out ./fuzz`；观察 stability（JNI 环境可能引入抖动）、exec speed 与 crash。
6. 对 crash 用 `xxd` 查看输入（示例崩溃输入以目标 magic 开头），在真机/Java 层复现，确认是 native 缺陷而非 JVM 初始化错误。

## PoC

```c
/* 初始化真实 ART JVM（按原文流程精简，示意） */
typedef jint (*JNI_CreateJavaVM_t)(JavaVM **, JNIEnv **, void *);
void *rt = dlopen("libandroid_runtime.so", RTLD_NOW);
JniInvocationImpl *(*invCreate)() = dlsym(rt, "JniInvocationCreate");
bool (*invInit)(JniInvocationImpl *, const char *) = dlsym(rt, "JniInvocationInit");
JNI_CreateJavaVM_t createVM = (JNI_CreateJavaVM_t)dlsym(rt, "JNI_CreateJavaVM");
jint (*regFramework)(JNIEnv *) = dlsym(rt, "registerFrameworkNatives");

ctx.invoc = invCreate();
invInit(ctx.invoc, "libandroid_runtime.so");
JavaVMInitArgs args = { .version = JNI_VERSION_1_6, .nOptions = 0, .options = NULL, .ignoreUnrecognized = JNI_TRUE };
createVM(&ctx.vm, &ctx.env, &args);
regFramework(ctx.env);
```

```c
/* 持久化循环入口：fuzzer 数据 -> jbyteArray -> 目标 JNI 函数 */
void fuzz_one_input(const uint8_t *buffer, size_t length) {
    jbyteArray jBuffer = (*ctx.env)->NewByteArray(ctx.env, length);
    (*ctx.env)->SetByteArrayRegion(ctx.env, jBuffer, 0, length, (const jbyte *)buffer);
    Java_qb_blogfuzz_NativeHelper_fuzzMeArray(ctx.env, NULL, jBuffer);
    (*ctx.env)->DeleteLocalRef(ctx.env, jBuffer);
}
```

说明：类名/函数名取自原文示例；实际使用时替换为目标 JNI 导出，并确保 classpath/框架注册满足目标依赖。原文未给出完整 harness 工程，PoC 为按原文代码片段整理的最小示意，未执行。

## 变体与关联

- 关联：不依赖真实 ART、用 mock JNIEnv + 自动生成调用序列的路线见 [[code-analysis-dynamic-fuzzing-android-jni-env-emulation-harness]]；本卡用真实 JVM，能覆盖强链接 JNI 但速度慢。
- 关联：Frida 模式构建、afl.js 持久化入口与 aarch64 参数注入见 [[code-analysis-dynamic-fuzzing-afl-frida-android-native-persistent-hook]]；本卡只补 JNI 环境初始化部分。
- 变体：可用 `-Djava.class.path=` 指向目标 APK/dex，或加载应用自己的 classloader 以实例化专有对象；也可在 Frida 注入模式下直接在应用进程内调用 JNI 函数（省去 JVM 初始化但更慢、更易被检测）。
- 变体：仅 mock 目标函数用到的 JNIEnv 子集可提高速度，但强链接对象语义需自行实现，容易产生假崩溃。
- 边界：ART 版本、JNI 全局/弱引用、线程附着（AttachCurrentThread）、系统服务依赖会影响稳定性；反调试/加固会阻止在真机上初始化 VM。

## 检测与防御

- 测试侧：在专用 root 设备/模拟器运行；对每次 crash 先排除 JVM 初始化失败、引用未释放与持久化状态污染；用 ASan 版本复核 native 内存错误。
- 防护侧（被测应用）：检测 Frida 注入、`/data/local/tmp` 可执行文件、异常 `JNI_CreateJavaVM` 调用与 native 崩溃；加固/完整性校验提高真机 fuzz 成本。
- 修复侧：对 JNI 入口的数组长度、字符串、对象字段做二次校验，使用安全 API，开启 ASan/UBSan 与回归 fuzz。
