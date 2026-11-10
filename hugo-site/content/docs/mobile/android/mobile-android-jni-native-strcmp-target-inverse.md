---
id: mobile-android-jni-native-strcmp-target-inverse
title: JNI native 校验定位与逆运算：IDA Exports 找 Java_ 导出函数、提取 strcmp 目标串并按字符交换逆序还原
type: scenario
domain: mobile
path: mobile/android
technique: jni-native-strcmp-target-inverse-transform
tags:
- android
- native
- jni
- ida
- so
- strcmp
- reverse
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:43:22+08:00'
  notes: 已对照原文核对：JNI 命名规则导出表定位（IDA Exports 中 Java_com_testjava_jack_pingan2_cyberpeace_CheckString，原文图一致）、GetStringUTFChars→malloc/memcpy→strcmp 目标串 f72c5a36569418a20907b55be5bf95ad、两段自逆置换均与本篇原文一致。核对时修正了逆运算顺序：代码先做前后半段交换再做两两交换，故脚本必须先撤销两两交换再撤销半段交换；修正后实跑得 flag{90705bb55efb59da7fc2a5636549812a}，回代正向变换可复现目标串。未验证点：未载入真实 .so 样本复现 IDA 流程。
url: /docs/mobile/android/mobile-android-jni-native-strcmp-target-inverse/
draft: false
kb_aliases:
- JNI native 校验逆向
- IDA Exports Java_ 函数
- strcmp 目标串逆运算
- 每 16 字符交换逆运算
- .so 校验函数定位
---

## 一句话结论

当 Java 层只剩 `public static native int CheckString(String)` 这类声明、`System.loadLibrary` 加载的 `.so` 里才是真校验时，可在 `.so` 的导出表按 `Java_<包名>_<类名>_<方法名>` 命名规则定位实现，从 `GetStringUTFChars` → 字符变换 → `strcmp(chunk, 硬编码目标串)` 的结构读出目标串和变换顺序，再按相反顺序做逆运算（先撤销每 16 字节前后半段交换、再撤销相邻两两交换）即可得到正确输入。

## 原理

- **JNI 命名规则给出入口**：静态注册的 native 方法由 `javac -h` 生成的头文件约定，符号名是 `Java_` + 包名 + `_` + 类名 + `_` + 方法名（包名点替换为下划线，名字里的下划线转义成 `_1`）。所以 `.so` 的动态符号表/导出表里能直接搜到 `Java_com_example_app_Checker_CheckString`，无需在成千上万个函数里瞎找。
- **IDA 视角**：`Exports` 窗口列出这些 `Java_*` 函数及地址；函数第一个参数是 `JNIEnv*`，第二个是 `jobject`/`jclass`（静态方法），第三个才是真正的 `jstring`。`JNIEnv` 是函数指针表，`a1->functions->GetStringUTFChars(a1, a3, 0)` 即把 Java 字符串转成 C 字符串，之后就是普通 C 逻辑。
- **校验结构可识别**：`strlen` + `malloc(size)` + `memcpy` 得到可变副本；随后是成对的字符交换（典型汇编形态是两个 `ldrb`/`strb` + 一次循环），最后 `strcmp(chunk, "hardcoded")` 相等即通过。目标串以明文出现在 `.rodata`，汇编里以 `ADRP + ADD` 或 `adr` 引用，因此可以直接在 IDA 里读到。
- **为什么逆运算成立**：相邻两两交换与「前 16 字节与后 16 字节整体交换」都是自逆置换（做两次等于恒等），因此只要按代码执行顺序的**相反顺序**对目标串重新施加同样的置换，就能还原原始输入；两者不可交换顺序，先做哪个就要后撤哪个。
- **易错点**：第一段循环条件写作 `strlen(chunk1) >> 1 > idx`、循环体内却访问 `chunk1[idx + 16]`，只有长度恰为 32 时（`len>>1 = 16`，跑 16 次，末次访问下标 31）才等价于「前 16 个字符与后 16 个字符整体交换」；长度不是 32 时该条件与 `idx + 16` 会越界或语义错位，逆运算脚本必须按实际长度分组。

## 触发条件

- APK 的 `lib/<abi>/` 下存在未被加壳/未强混淆的 `.so`，且 Java 层通过 `System.loadLibrary` 静态注册 native 方法（符号可见）。
- 校验由固定模板 + 内嵌常量组成，不依赖服务端或时间/设备因子。
- 能静态读取 `.so`（IDA/Ghidra/objdump）；有反调试时需先绕过。

## 利用步骤

1. jadx 里找到声明 native 方法的类与方法名，记录完整包名，拼出期望的 JNI 符号。
2. 解压 APK 取 `lib/arm64-v8a/*.so`（或其他 ABI），载入 IDA；在 `Exports` 窗口按 `Java_` 前缀过滤，命中目标函数。
3. 若不熟悉结构体，先导入 `jni.h` 让 `JNIEnv*` 参数变成可读的 `a1->functions->...` 调用，否则在反汇编里只是间接跳转。
4. 跟到 `GetStringUTFChars` 之后：记录 `malloc/memcpy` 的缓冲区、每段交换循环的边界与步长、末尾 `strcmp` 的第二个参数（明文目标串）。
5. 写成逆运算脚本：按代码执行顺序的**倒序**对目标串施加同样的置换——代码先做「前后半段交换」再做「相邻两两交换」，所以脚本要**先撤销两两交换、再撤销前后半段交换**（两个置换各自自逆）。
6. 运行脚本得到候选输入，回填 App 验证；若还差一层（如再叠一层凯撒/XOR），按同样思路继续撤销。

## PoC

```c
/* IDA 中该导出函数的骨架（地址与变量名随样本变化） */
_BOOL8 Java_com_testjava_jack_pingan2_cyberpeace_CheckString(JNIEnv *a1, jobject a2, jstring a3)
{
    const char *s   = a1->functions->GetStringUTFChars(a1, a3, 0);
    size_t      len = strlen(s);
    char       *buf = malloc(len);
    memcpy(buf, s, len);
    /* 第一段：把 buf[idx] 与 buf[idx+16] 交换，idx 从 0 走到 len/2 */
    for (size_t i = 0; len >> 1 > i; i++) {
        char t = buf[i]; buf[i] = buf[i + 16]; buf[i + 16] = t;
    }
    /* 第二段：先交换前两个字符，再每隔两个字符成对交换 */
    char t0 = buf[0]; buf[0] = buf[1]; buf[1] = t0;
    for (size_t j = 2; len > j; j += 2) {
        char t = buf[j]; buf[j] = buf[j + 1]; buf[j + 1] = t;
    }
    return strcmp(buf, "f72c5a36569418a20907b55be5bf95ad") == 0;
}
```

```python
s = list("f72c5a36569418a20907b55be5bf95ad")   # strcmp 的硬编码目标串

# 代码执行顺序：先前后半段交换，再相邻两两交换；逆序撤销要反过来
# 1) 先撤销相邻两两交换（代码里的第二段）
for i in range(0, len(s) - 1, 2):
    s[i], s[i + 1] = s[i + 1], s[i]

# 2) 再撤销前后半段整体交换（代码里的第一段）
for i in range(len(s) // 2):
    s[i], s[i + 16] = s[i + 16], s[i]

print("flag{" + "".join(s) + "}")
```

```bash
# 定位导出函数（IDA 之外的等价做法）
unzip -o target.apk 'lib/*' -d apk_libs
readelf -sW apk_libs/lib/arm64-v8a/libcyberpeace.so | grep -i 'Java_'
```

## 变体与关联

- **动态注册变体**：`JNI_OnLoad` 里用 `RegisterNatives` 注册时导出表没有 `Java_*` 符号，需在 `JNI_OnLoad` 或初始化函数里找 `JNINativeMethod` 数组（方法名字符串 + 函数指针）。
- **字符串加密变体**：`strcmp` 目标串被异或/分段拼接时，静态读不到明文，需 hook `strcmp`/`memcmp` 或在 `GetStringUTFChars` 后 dump 缓冲区。
- **强校验变体**：`.so` 内做指令级常量构造（`MOVZ`/`MOVK`）、控制流平坦化或 Unicorn 才能跑通时，见 [[mobile-android-jni-native-unicorn-emulation-constant-extraction]]；多层自定义加密见 [[mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer]]。
- **前置链路**：Java 层如何定位到调用 `CheckString` 的按钮事件，见 [[mobile-android-apk-static-entry-layout-resource-locate]]；`.so` 被壳加密时先走 [[mobile-android-encrypted-so-runtime-dlopen-extraction]]。
- **边界**：ABI 不同（arm64/armv7/x86）指令形态不同但逻辑等价；校验依赖密钥时单靠逆运算不可解。

## 检测与防御

- 检测（分析侧）：用 `readelf -s`/IDA Exports 确认 `Java_` 符号存在；确认 `strcmp` 目标串是明文且变换是自逆置换，否则需要动态 hook 验证。
- 防御（开发侧）：不要把口令/校验目标以明文常量放在 `.so`（易被 `.rodata` 直读）；用 `RegisterNatives` 动态注册、字符串加密、常量拆分构造提高静态成本。
- 防御：把关键校验放到服务端；native 层加完整性校验、反调试与应用签名校验，阻断 IDA/动态 hook。
- 检测信号：`.so` 中出现 `Java_` 导出符号 + 明文 `strcmp` 目标串 + 成对 `ldrb/strb` 交换循环，是典型客户端校验模板。
