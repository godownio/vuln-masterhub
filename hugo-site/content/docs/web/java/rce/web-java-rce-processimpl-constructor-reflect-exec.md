---
id: web-java-rce-processimpl-constructor-reflect-exec
title: 反射调用 ProcessImpl 构造器直接创建进程执行命令
type: scenario
domain: web
path: web/java/rce
technique: processimpl-constructor-reflect-exec
tags:
- java
- rce
- processimpl
- reflection
- command-execution
- windows
- bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:24:46+08:00'
  notes: 已对照调用链调试与反射构造器弹出计算器截图；未验证点：JDK 9+ 反射 java.base 私有成员需 --add-opens，Linux 类名/签名随版本变化，卡片已标 medium
url: /docs/web/java/rce/web-java-rce-processimpl-constructor-reflect-exec/
draft: false
kb_aliases:
- ProcessImpl 反射执行命令
- java.lang.ProcessImpl
- ProcessImpl.create
- Runtime.exec 替代
- 绕过命令执行 hook
---

## 一句话结论

`Runtime.exec`/`ProcessBuilder` 最终都落到 `java.lang.ProcessImpl` 的私有构造器与 native `create`；在拿到任意 Java 代码执行后，可用反射直接调用该构造器创建进程，绕过只 hook 了 `Runtime.exec`/`ProcessBuilder.start` 的 Java 层监控。

## 原理

- 调用链是 `Runtime.exec` → `ProcessBuilder.start` → `ProcessImpl.start` → `new ProcessImpl(String[] cmd, String envblock, String dir, long[] stdHandles, boolean redirectErrorStream)` → private static native `create(...)` → Windows `CreateProcessW` / Linux `forkAndExec`。
- Java 层的安全检查和 RASP hook 通常挂在 `Runtime.exec`、`ProcessBuilder.start` 或 `ProcessImpl.start` 上。直接反射拿到私有构造器并 `setAccessible(true)` 后 `newInstance`，可以跳过这些 Java 方法，直接进入构造器里的 native `create`。
- Windows 下构造器签名为：

  ```java
  ProcessImpl(String[] cmd, String envblock, String dir, long[] stdHandles, boolean redirectErrorStream)
  ```

  传入 `stdHandles = new long[]{-1L, -1L, -1L}` 表示继承当前进程的标准句柄；`cmd` 为 `{"calc"}` 之类的 argv 数组；`envblock`、`dir` 可传 `null`。
- 该构造器在 JDK 内是 private，且 `ProcessImpl` 只有一个构造器；先 `Class.forName("java.lang.ProcessImpl")`，`getDeclaredConstructor(...)`，再 `setAccessible(true)` 实例化。
- 这是内部 API：JDK 9+ 模块系统默认不允许反射 `java.base` 的私有成员，需要 `--add-opens java.base/java.lang=ALL-UNNAMED` 或同等权限；Linux 的类名/签名也随 JDK 版本变化（JDK 8 为 `java.lang.UNIXProcess`），因此本卡以 Windows 场景为主，置信度标 medium。
- 直接构造的 `Process` 对象只保证进程被创建；若后续要读 stdout/stderr，需要自行准备管道句柄并正确填充 `stdHandles`，否则拿不到输出。

## 触发条件

- 已获得任意 Java 代码执行，可在目标 JVM 内执行反射代码。
- 目标 JDK 允许反射访问 `java.lang.ProcessImpl`（JDK 8 默认可；JDK 9+ 需模块开放）。
- 目标平台与构造器签名匹配（Windows 场景最稳定）。
- JVM 有创建子进程的 OS 权限。

## 利用步骤

1. 确认 JDK 版本与 `ProcessImpl` 构造器签名（`javap -p java.lang.ProcessImpl` 或调试器）。
2. 用 `Class.forName` 加载类，按签名取 `getDeclaredConstructor`。
3. `setAccessible(true)` 后传入命令数组与 `stdHandles` 实例化。
4. 进程被创建并执行命令；需要回显时另建管道/使用流泵方案。

## PoC

```java
import java.lang.reflect.Constructor;

public class CreateTest {
    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("java.lang.ProcessImpl");
        Constructor<?> ctor = clazz.getDeclaredConstructor(
                String[].class, String.class, String.class,
                long[].class, boolean.class);
        ctor.setAccessible(true);
        ctor.newInstance(
                new String[]{"calc"},   // 命令 argv
                null,                   // envblock
                null,                   // working dir
                new long[]{-1L, -1L, -1L}, // 继承 stdin/stdout/stderr
                false);
    }
}
```

调用栈（Windows，原文调试结果）：

```text
create:593, ProcessImpl (java.lang)
<init>:453, ProcessImpl (java.lang)
start:139, ProcessImpl (java.lang)
start:1029, ProcessBuilder (java.lang)
exec:621, Runtime (java.lang)
exec:451, Runtime (java.lang)
exec:348, Runtime (java.lang)
```

## 变体与关联

- Linux 变体：JDK 8 的 `java.lang.UNIXProcess` 构造器签名不同，需按版本调整；高版本 JDK 可能统一到 `ProcessImpl`。
- 句柄变体：若需要回显，可先创建 `PipedInputStream`/`PipedOutputStream` 并把管道句柄填入 `stdHandles`，再接流泵；否则用 `-1` 继承父进程标准流。
- 关联：[[web-java-rce-socket-revshell-stream-pump]]（拿到进程后建立交互通道）；[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]（常规 Runtime.exec 路径与 String 分词问题）。
- 边界：JDK 模块系统拒绝反射、`SecurityManager` 拦截、构造器签名随版本变化、目标为 Linux 且未适配时失败。

## 检测与防御

- 检测：Java 代码反射访问 `java.lang.ProcessImpl`/`java.lang.UNIXProcess`；对私有构造器调用 `setAccessible(true)`；JVM 直接调用 native `create` 创建进程；绕过常规 RASP 的进程创建事件。
- 防御：RASP hook 下沉到 `ProcessImpl` 构造器/native 层而非只 hook `Runtime.exec`；JDK 9+ 保持模块封装，不随意 `--add-opens`；限制 Java 进程创建子进程（seccomp/AppArmor/Windows 作业对象）；监控异常子进程。
