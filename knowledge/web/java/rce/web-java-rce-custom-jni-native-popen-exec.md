---
id: web-java-rce-custom-jni-native-popen-exec
title: 自定义 JNI native 方法执行命令：声明 native exec + C 侧 popen 导出 Java_ 符号，System.load 后调用绕过 Java 层 RASP
type: scenario
domain: web
path: web/java/rce
technique: custom-jni-native-popen-exec
aliases:
- 自定义 JNI 执行命令
- native 方法 popen
- Java_com_jni_test_Exec_exec
- System.load 后用 native 方法执行命令
- JNI 绕过 RASP 命令执行
tags:
- java
- jni
- native
- popen
- rce
- rasp
- bypass
- command-execution
- dll
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:52:11+08:00'
  notes: 已对照原文与30张幻灯片逐张核对：slide21 JNI 五步（声明 native→javac -h 头文件→C include→编译 dll→System.load/loadLibrary 调用）、slide22 Java 声明 public native void exec(String) 与 C 侧 JNIEXPORT jstring JNICALL Java_com_jni_test_Exec_exec + popen/fgets/pclose/NewStringUTF、slide23 利用代码均与卡内一致；卡内已如实标注原文 Java void 与 C jstring 返回类型不一致需修正为 String exec。dedup 与既有 JNI_OnLoad 加载即执行、DllMain、反射 ClassLoader 加载卡均为 related/new：本卡是'Java_ 导出方法调用时 popen 执行'，覆盖声明到调用的完整链路，属不同原子。原文未标受影响版本，affected_versions 留空正确。未验证点：未编译/加载 DLL/SO 实测；slide 未展示命令输出验证；popen 在 Windows 上行为与 POSIX 不同（原文 C 代码为 POSIX 风格，step 4 写编译 dll，卡内已按双平台表述但 Windows 下 popen 可用性未验证）。path web/java/rce 存在；无 sources/source_url/文章ID/URL/长段摘录。
---

## 一句话结论

在拿到 Java 代码执行与文件落地能力后，可以自己写一个 JNI 方法：Java 侧声明 `native String exec(String cmd)`，C 侧按 `Java_<包>_<类>_<方法>` 导出函数并用 `popen` 执行命令、`fgets` 读回输出，编译成 DLL/SO 后 `System.load/loadLibrary` 加载并调用；命令执行完全发生在 native 代码中，`Runtime.exec`/`ProcessBuilder` 等 Java 层 RASP hook 全程不触发。

## 原理

- **JNI 调用机制**：Java 类声明 `native` 方法后，JVM 在 `System.load/loadLibrary` 加载原生库时，按 `Java_<package>_<class>_<method>` 的符号命名规则把 native 方法绑定到 C 函数；调用该 Java 方法即进入 native 代码。
- **示例实现**：Java 侧 `package com.jni.test; public class Exec { public native String exec(String cmd); }`；C 侧 `JNIEXPORT jstring JNICALL Java_com_jni_test_Exec_exec(JNIEnv *env, jclass clazz, jstring str)`，用 `GetStringUTFChars` 取命令，`popen(cmd, "r")` 执行，`fgets` 循环读输出并拼接，`pclose` 关闭，`NewStringUTF` 返回结果。
- **为什么绕过 RASP**：RASP 的 instrumentation 只覆盖 Java 字节码，hook 点在 `Runtime.exec`、`ProcessBuilder.start`、`ProcessImpl` 等 Java 方法；`popen` 由 libc 直接 fork/exec，JVM 内没有这些 Java 调用帧，命令执行对 Java 层不可见。
- **落地要求**：需要把编译好的库写到目标可读路径（任意文件写、上传、日志写入等），架构与目标匹配（Windows x64 DLL / Linux x86_64 `.so`），并能调用 `System.load`（绝对路径）或 `System.loadLibrary`；若加载 API 被 RASP hook，可改用反射 `ClassLoader.loadLibrary` / `ClassLoader$NativeLibrary#load`。
- **签名一致性**：示例 Java 侧写作 `void exec(String)` 而 C 侧返回 `jstring`，实际落地时两侧返回类型必须一致（建议 `String exec(String)`），否则可能出现 `UnsatisfiedLinkError` 或未定义行为。
- **与加载即执行的区别**：本方法在 Java 调用 native 方法时才执行命令；`JNI_OnLoad`、`DllMain`、ELF constructor 式载荷则在库加载瞬间执行，二者可以组合使用。

## 触发条件

- 已获得 Java 代码执行能力，并具备把原生库写到目标可读路径的能力（文件写/上传/替换已有库）。
- 目标 OS/架构与编译产物匹配，库路径可加载（Linux 注意 `noexec` 挂载与 `dlopen` 限制）。
- 能调用 `System.load`/`System.loadLibrary` 或反射 `ClassLoader.loadLibrary`。
- RASP 未拦截 JNI 方法调用，也未在 OS 层监控 `popen`/`fork`/`exec`。

## 利用步骤

1. 编写 Java 类声明 native 方法（返回类型与 C 侧保持一致，建议 `String exec(String cmd)`）。
2. 用 `javac -h` 生成头文件（或按 `Java_<package>_<class>_<method>` 规则手写导出符号）。
3. 编写 C 实现：`GetStringUTFChars` → `popen(cmd, "r")` → `fgets` 读取输出 → `pclose` → `NewStringUTF` 返回。
4. 编译为与目标架构匹配的 DLL/SO（Windows x64 / Linux x86_64）。
5. 将库落地到目标可读路径，`System.load("绝对路径")` 或 `System.loadLibrary("名称")`。
6. 调用 native 方法执行命令并取回输出。
7. 若 `System.load` 被拦，改用反射 `ClassLoader.loadLibrary` / `NativeLibrary.load` 加载。

## PoC

Java 侧：

```java
package com.jni.test;
public class Exec {
    public native String exec(String cmd);   // 与 C 侧 jstring 返回值一致
}
```

C 侧（Windows DLL / Linux SO 通用，Linux 用 `popen` 即可）：

```c
#include <stdio.h>
#include <string.h>
#include "com_jni_test_Exec.h"

JNIEXPORT jstring JNICALL Java_com_jni_test_Exec_exec
  (JNIEnv *env, jclass clazz, jstring str) {
    if (str == NULL) return NULL;
    const char *cmd = (*env)->GetStringUTFChars(env, str, NULL);
    FILE *fd = popen(cmd, "r");
    if (fd != NULL) {
        char buf[128]; char result[4096] = {0};
        while (fgets(buf, sizeof(buf), fd) != NULL) strncat(result, buf, sizeof(result)-strlen(result)-1);
        pclose(fd);
        (*env)->ReleaseStringUTFChars(env, str, cmd);
        return (*env)->NewStringUTF(env, result);
    }
    (*env)->ReleaseStringUTFChars(env, str, cmd);
    return NULL;
}
```

编译后用 `System.load("C:\\path\\exec.dll")` 或 `System.load("/tmp/libexec.so")` 加载，再反射调用 `Exec.exec("id")`。

## 变体与关联

- **载荷变体**：`JNI_OnLoad` 导出（加载即执行）、`DllMain`/ELF constructor（加载即执行）、正常 `Java_` 方法（调用时执行，本卡）。
- **加载变体**：`System.load`、`System.loadLibrary`、反射 `ClassLoader.loadLibrary`、`ClassLoader$NativeLibrary#load`、`com.sun.glass.utils.NativeLibLoader`。
- 关联：[[web-java-rce-jni-onload-export-load-time-exec]]、[[web-java-rce-windows-dllmain-load-time-exec]]、[[web-java-rce-reflect-classloader-nativelibrary-load-dll-bypass-hooks]]、[[web-java-rce-ffm-native-system-rasp-bypass]]。
- 边界：强模块封装限制加载入口、目标目录不可写或 `noexec`、架构不匹配、RASP 对 JNI 方法或 `fork/exec` 做 native 层拦截时失效。

## 检测与防御

- **检测**：JVM 进程加载新增 DLL/SO（`/proc/<pid>/maps` 出现临时路径映射）；`System.load`/`ClassLoader.loadLibrary` 调用与反射链；native 方法调用期间出现 `popen`/`fork`/`execve` 系统调用；子进程存在但调用栈中没有 Java Process 帧。
- **防御**：RASP 用 NativeMethodPrefix 等机制拦截 native 方法（ASM 去掉 native 修饰符、插入检查逻辑后调用 `prefix_forkAndExec` 包装）；在 OS 层用 eBPF/seccomp/EDR 监控 `popen`/`fork`/`exec`；禁止从不可信路径加载原生库并校验哈希/签名；对文件写入 sink 做根因治理，让攻击者无法落地库文件。
