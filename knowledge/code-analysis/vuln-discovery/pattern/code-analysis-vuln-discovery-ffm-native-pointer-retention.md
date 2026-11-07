---
id: code-analysis-vuln-discovery-ffm-native-pointer-retention
title: FFM MemorySegment 裸指针被 native 滞留导致 Arena 关闭后悬挂读写
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: ffm-native-pointer-retention
aliases:
- FFM 悬挂指针
- MemorySegment UAF
- Arena.close 悬挂访问
- 跨语言指针滞留
- Foreign Function Memory 生命周期
tags:
- java
- ffi
- ffm
- native
- use-after-free
- memory-safety
- arena
- jni
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T19:42:34+08:00'
  notes: 已对照原文与15张图核对：JDK 21.0.11-ea/gcc 15.2.0 环境（图1）、libretain.so 符号（图3）、javac 编译（图4）、Arena 关闭后 Java 抛 IllegalStateException 而 C 仍读回 0x1122334455667788（图5-8）、--write 写入 0x4141414142424242（图7/9）、--release-before-close 后 read skipped（图10）、gdb 中 retained 与 Java 传入 p 一致及释放后内容变化（图11-15）均与卡片一致。定性为 FFM 封装层使用错误、非 JDK 缺陷/CVE，正确。未验证点：未本机复跑；仅为已复现的 native UAF 读写，未打通代码执行；frontmatter 无 sources/source_url。
---

## 一句话结论

JDK 21 FFM API 的 `MemorySegment` 通过 `ADDRESS` 参数传给 C 后会退化为普通 `void *`；若 native 代码把该地址存入全局变量、结构体或异步上下文，`Arena.close()` 只能让 Java 侧段对象失效，无法同步清除 native 侧副本，之后 native 仍可对已释放/可能被复用的堆外内存读写，形成跨语言悬挂指针（native UAF）。

## 原理

- `MemorySegment` 的边界、长度、所属 `Arena` 与访问状态只在 Java 侧被跟踪。downcall 描述符中的 `ADDRESS` 在 ABI 上就是指针值，C 函数收到的是 `void *`，Java 运行时不会追踪 native 代码是否复制、保存或转交该地址。
- `Arena.close()` 的作用是释放该 arena 管理的 native 内存并使 Java 侧 segment 失效；Java 侧再访问会抛 `IllegalStateException`。但 native 侧保存的是裸地址，C 代码的 `memcpy` 不经过 Java 的段状态检查，因此仍能读写。
- 释放后的 native 内存可能被 allocator、JVM 或后续 native 分配复用，内容不再稳定；读取可能是信息泄露，写入可能破坏 allocator 元数据、JVM 结构或其他对象，严重时可进一步演化为代码执行。
- 该问题属于 FFM 封装层的生命周期使用错误，不是 JDK 自身缺陷，也不对应 CVE；判断标准是 native API 是否在返回后继续持有传入地址，而不是是否调用了 `Arena.close()`。

## 触发条件

- 应用使用 JDK 21+ FFM（`java.lang.foreign`）做 downcall，且参数/返回值涉及 `ADDRESS`；
- native 库会把传入地址保存到全局变量、结构体、线程/异步任务、第三方库上下文或缓存中；
- Java 侧使用短生命周期 `Arena`（如 `Arena.ofConfined()`）并在 native 仍持有地址时关闭；
- 攻击者能影响传入 segment 的内容、偏移，或在释放后触发 native 的读取/写入路径。

## 利用步骤

1. 在 native 库中实现一个保存指针的函数（如 `retain(void *p, int64_t len, int64_t off)`），把 Java 传入地址写入全局变量。
2. Java 侧在 `try (Arena arena = Arena.ofConfined())` 中分配 `MemorySegment`，写入标记值，并以 `ADDRESS` 参数调用 `retain`。
3. 退出 try 块，`Arena.close()` 释放 native 内存；Java 侧再 `segment.get(...)` 会抛 `IllegalStateException`。
4. 调用 native 的读取函数，确认仍能按保存的地址读出数据；调用写入函数，确认仍能写入释放后的内存。
5. 实际攻击中可结合堆喷/分配复用，让释放后的块被敏感对象或函数指针占用，再把 native 悬挂写变成可控破坏；偏移选择（如跳过块首 64 字节）可避开 allocator 在 free 时改写的元数据。

## PoC

最小结构（Linux x86_64，JDK 21；原文为 Demo，未在本环境执行）：

```c
static uint8_t *retained;
static size_t retained_len, retained_off;

void retain(void *p, int64_t len, int64_t off) {
    retained = (uint8_t *)p;
    retained_len = len > 0 ? (size_t)len : 0;
    retained_off = off >= 0 ? (size_t)off : 0;
}

int64_t read_retained_i64(void) {
    int64_t v = 0;
    if (!retained || retained_off > retained_len ||
        retained_len - retained_off < sizeof(v)) return 0;
    memcpy(&v, retained + retained_off, sizeof(v));
    return v;
}

void write_retained_i64(int64_t v) {
    if (!retained || retained_off > retained_len ||
        retained_len - retained_off < sizeof(v)) return;
    memcpy(retained + retained_off, &v, sizeof(v));  // Arena 关闭后仍可执行
}
```

```java
try (Arena arena = Arena.ofConfined()) {
    MemorySegment seg = arena.allocate(128, JAVA_LONG.byteAlignment());
    seg.set(JAVA_LONG, 64, 0x1122334455667788L);
    retain.invoke(seg, 128L, 64L);          // C 侧保存裸地址
}
// segment.get(...) 抛 IllegalStateException，但 readRetained/writeRetained 仍有效
long v = (long) readRetained.invoke();       // 仍读回标记值
writeRetained.invoke(0x4141414142424242L);   // 对释放后地址写入
```

实测现象：Java 侧输出 `after close denied=IllegalStateException`，C 侧仍输出 `read ... value=0x1122334455667788` 并完成写入；gdb 中可在 Java 拒绝访问后继续观察到 `retained` 指向已释放区域，且释放后内容可能被改写。

## 变体与关联

- JNI 的 `GetDirectBufferAddress`、`GetPrimitiveArrayCritical` 等同样可能把 Java 侧地址交给 native 长期保存，造成同类悬挂访问。
- 使用 `Arena.ofAuto()` 或生命周期覆盖 native 使用期的 arena 可降低风险，但仍需明确所有权。
- 推荐两种安全封装：native 释放函数必须在 `Arena.close()` 之前调用；需要长期持有的对象改为 native 自管所有权，Java 只保存 opaque handle（`ctx_alloc/ctx_free/ctx_use`）。
- 关联：JNI 内存安全、native UAF、堆分配复用、FFM downcall 描述符审计。

## 检测与防御

- 代码审计：搜索 `java.lang.foreign` downcall 描述符中带 `ADDRESS` 的调用，逐一确认 native 函数是否在返回后保存指针；检查 try-with-resources 的 `Arena` 生命周期是否覆盖 native 使用期。
- 若 native 会保存指针，必须在关闭 arena 前显式调用对应 release 函数清零，或改由 native 分配/释放并返回 opaque handle。
- 动态检测：用 ASan/Valgrind 跑 native 库，观察 arena 关闭后的 UAF；对 FFM 路径做 Java 侧与 native 侧日志关联，确认 close 后是否还有 native 访问。
- 防御：禁止短生命周期 arena 作为会被 native 留存地址的 owner；对跨语言 API 明确文档化所有权与生命周期契约；对 native 库中的全局指针缓存做静态检查。
